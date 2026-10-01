#!/usr/bin/env bash
# Renders every Kustomization under cluster/ and validates the result against the real Kubernetes
# and CRD schemas. This is the check that a commit which would break the cluster fails before it
# reaches the cluster -- Argo CD auto-syncs, so CI is the last place a typo can be caught cheaply.
#
# Then it renders every Helm chart Application (scripts/render-charts.sh, hooks included) and runs
# the repository's own Kyverno policies over everything rendered, offline (`kyverno apply`, ADR 0012):
# a policy Kyverno would refuse to load, or a workload that an Enforce rule would reject, fails here
# instead of at the next Argo CD sync.
#
# Everything runs in pinned containers (ADR 0008); nothing has to be installed on the host beyond
# docker and python3. Set DOCKER=... to use a wrapper such as "sudo -n docker".
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT=$PWD

DOCKER=${DOCKER:-docker}

# Pinned by tag and digest.
KUSTOMIZE_IMAGE=${KUSTOMIZE_IMAGE:-registry.k8s.io/kustomize/kustomize:v5.7.1@sha256:937e7832dc0b09288b1398399dadb97382a27bbc35bee8fdcac47c7de4fff14d}
KUBECONFORM_IMAGE=${KUBECONFORM_IMAGE:-ghcr.io/yannh/kubeconform:v0.8.0-alpine@sha256:6b90a5f23d846140ce0194fe050b1995e546eba938f3a6bf10c039dd5e24588f}
# Ships kustomize plus the KSOPS plugin. Same image and digest as the argocd-repo-server init
# container, so a local validation exercises exactly the ksops binary the cluster uses. Its kustomize
# (v5.3.0, ksops build) is no longer the cluster's: the repo-server keeps Argo CD's own v5.8.1 since
# ADR 0013's amendment. Only used when an age key is present; the decryption itself is the same KRM
# function either way.
KSOPS_IMAGE=${KSOPS_IMAGE:-viaductoss/ksops:v4.5.1@sha256:4def9fdd4e2f850265740ebe9592c5455d19b76891e88e602df8b52d74b95334}
# Same Kyverno release as the in-cluster controller (chart 3.9.1 = v1.19.1, cluster/apps/kyverno.yaml),
# so a policy that loads here loads there, with the same PSS check library behind `podSecurity`.
KYVERNO_CLI_IMAGE=${KYVERNO_CLI_IMAGE:-ghcr.io/kyverno/kyverno-cli:v1.19.1@sha256:ced7b2be0b04250cabfe695f15307f69eb715fe23234816388af4f3812915b2a}

# kubeconform ships schemas for built-in Kubernetes kinds only. Gateway, HTTPRoute, ClusterIssuer,
# CiliumNetworkPolicy and Application are CRDs, so their schemas come from the community catalog,
# pinned to a commit so a schema change upstream cannot turn a green build red overnight.
CRDS_CATALOG_REF=${CRDS_CATALOG_REF:-d373c2da9702bc9509a004db83e57263fe3bdfc1}
CRDS_CATALOG_SCHEMA="https://raw.githubusercontent.com/datreeio/CRDs-catalog/${CRDS_CATALOG_REF}/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json"

# Kubernetes version the manifests must be valid against. Matches k3s_version in
# ansible/inventory/group_vars/k3s_nodes.yml, minus the +k3s1 suffix.
KUBERNETES_VERSION=${KUBERNETES_VERSION:-1.35.9}

# For kustomizations that render a Helm chart (`helmCharts`, see the rendering loop).
# shellcheck disable=SC1091  # a one-line pin (HELM_IMAGE), sourced from the repository root
. scripts/lib/helm-image.sh

RENDER_DIR=$(mktemp -d)
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$RENDER_DIR" "$WORK_DIR"' EXIT

info() { printf '  %s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }

kustomize() { $DOCKER run --rm -v "$1":/work -w /work "$KUSTOMIZE_IMAGE" build "$2"; }

# Same thing, but with the KSOPS plugin and the age identity available, so encrypted resources are
# actually decrypted. The key is mounted read-only at a fixed path; it is never copied or printed.
kustomize_ksops() {
  # --user 0: the image runs as uid 65532 and the operator's key file is 0600, so the
  # non-root user inside the container could not read it. Root in a throwaway container is fine.
  $DOCKER run --rm --user 0:0 \
    -v "$1":/work:ro \
    -v "$SOPS_AGE_KEY_FILE":/age/keys.txt:ro \
    -w /work \
    -e SOPS_AGE_KEY_FILE=/age/keys.txt \
    --entrypoint kustomize "$KSOPS_IMAGE" \
    build --enable-alpha-plugins --enable-exec "$2"
}

step "collecting kustomizations under cluster/"
mapfile -t KUSTOMIZATIONS < <(find cluster -name kustomization.yaml -printf '%h\n' | sort)
[ "${#KUSTOMIZATIONS[@]}" -gt 0 ] || { echo "validate-cluster: no kustomizations found" >&2; exit 1; }
printf '  %s\n' "${KUSTOMIZATIONS[@]}"

step "rendering"
for dir in "${KUSTOMIZATIONS[@]}"; do
  name=${dir//\//_}
  source_root=$REPO_ROOT
  build_target=$dir

  # A directory with a KSOPS generator needs both the encrypted files and the age private key. CI has
  # neither, by design (ADR 0006).
  #
  #   both present -> render for real, with the plugin. A file that does not decrypt fails the run,
  #                   which is the check an operator wants before committing a rotation.
  #   otherwise    -> render a throwaway copy with the generator removed, so the plaintext resources
  #                   next to the secret are still validated, and say so.
  if [ -f "$dir/ksops.yaml" ]; then
    if python3 scripts/lib/ksops_files_present.py "$dir" \
       && [ -n "${SOPS_AGE_KEY_FILE:-}" ] && [ -r "${SOPS_AGE_KEY_FILE:-}" ]; then
      kustomize_ksops "$source_root" "$build_target" > "$RENDER_DIR/$name.yaml"
      info "$dir -> $(grep -c '^kind:' "$RENDER_DIR/$name.yaml") objects (KSOPS decrypted)"
      continue
    fi
    info "$dir: KSOPS generator skipped (no readable SOPS_AGE_KEY_FILE, or no *.sops.yaml committed yet)"
    cp -r "$REPO_ROOT/." "$WORK_DIR/$name"
    python3 scripts/lib/strip_generators.py "$WORK_DIR/$name/$dir/kustomization.yaml"
    source_root=$WORK_DIR/$name
  fi

  # A kustomization with `helmCharts` (cluster/infra/falco) is built by Argo CD with
  # `kustomize build --enable-helm` (argocd-cm): kustomize pulls the chart, runs `helm template` and
  # then applies the kustomization's patches - the post-render that a Helm source cannot have
  # (ADR 0013, amendment). No pinned image carries kustomize and helm together, so the same thing
  # happens in two steps on a throwaway copy: the pinned Helm image renders each chart with the
  # entry's values and the arguments kustomize passes, scripts/lib/helm_charts_kustomization.py swaps
  # the helmCharts block for the rendered files, and the pinned kustomize image applies the patches.
  # The result is judged by kubeconform, the hostPath check and `kyverno apply` like everything else.
  if grep -q '^helmCharts:' "$dir/kustomization.yaml"; then
    [ ! -f "$dir/ksops.yaml" ] || { echo "validate-cluster: $dir combines KSOPS and helmCharts; not supported" >&2; exit 1; }
    cp -r "$REPO_ROOT/." "$WORK_DIR/$name"
    charts_dir=$WORK_DIR/$name/$dir
    chart_list=$(python3 scripts/lib/helm_charts_kustomization.py "$charts_dir")
    while IFS=$'\t' read -r chart repo version release namespace values include_crds kube_version out; do
      crd_flag=()
      [ "$include_crds" != true ] || crd_flag=(--include-crds)
      $DOCKER run --rm -v "$charts_dir":/kustomization:ro "$HELM_IMAGE" template "$release" "$chart" \
        --repo "$repo" \
        --version "$version" \
        --namespace "$namespace" \
        --kube-version "${kube_version:-$KUBERNETES_VERSION}" \
        --values "/kustomization/$values" \
        "${crd_flag[@]}" > "$charts_dir/$out"
      info "$dir: helmCharts $chart $version rendered ($(grep -c '^kind:' "$charts_dir/$out") objects)"
    done <<< "$chart_list"
    source_root=$WORK_DIR/$name
  fi

  kustomize "$source_root" "$build_target" > "$RENDER_DIR/$name.yaml"
  info "$dir -> $(grep -c '^kind:' "$RENDER_DIR/$name.yaml") objects"
done

step "rendering the attack scenarios' pod specs as Pods (ADR 0017)"
# The portfolio API creates these pods at run time from ConfigMap `scenarios`, so they exist in git
# only as data inside that ConfigMap. Rendered here, before kubeconform, so their specs are validated
# against the Pod schema and judged by the Kyverno gate below like any other workload; the script also
# checks every entry against the phase 5/6 contract. See its docstring for the image placeholder.
python3 scripts/lib/scenario_pods.py "$RENDER_DIR/cluster_infra_sandbox_scenarios.yaml" \
  cluster/infra/hello/kustomization.yaml "$RENDER_DIR/scenario-pods.yaml"

step "kubeconform (kubernetes $KUBERNETES_VERSION, strict)"
# -strict rejects unknown and duplicated fields, which is where typos hide.
#
# -ignore-missing-schemas is needed for exactly one class of object: CustomResourceDefinition
# itself. No JSON schema for apiextensions.k8s.io/v1 CustomResourceDefinition is published in the
# standalone-strict schema set, so the Gateway API and Argo CD CRD definitions come back as
# "skipped". Everything that is an *instance* of a CRD -- Gateway, HTTPRoute, ClusterIssuer,
# CiliumNetworkPolicy, Application -- does get a schema from the catalog and is validated. The
# summary prints the skip count, so the number growing beyond the CRDs is visible.
#
# Set VERBOSE=1 to list every object instead of just the summary.
VERBOSE_FLAG=()
[ -n "${VERBOSE:-}" ] && VERBOSE_FLAG=(-verbose)
$DOCKER run --rm -v "$RENDER_DIR":/rendered:ro "$KUBECONFORM_IMAGE" \
  -strict \
  -ignore-missing-schemas \
  -kubernetes-version "$KUBERNETES_VERSION" \
  -schema-location default \
  -schema-location "$CRDS_CATALOG_SCHEMA" \
  -summary \
  "${VERBOSE_FLAG[@]}" \
  /rendered

step "rendering chart Applications (helm template, hooks included)"
# After kubeconform on purpose: the chart renders are upstream's manifests, already validated by their
# maintainers against the same API; what this script adds for them is the policy check below. They
# land next to the kustomize renders so that one `--resource` directory holds everything Argo CD
# would apply (observed with CLI v1.19.1: given a directory and further --resource files, it
# evaluated only the directory's resources and silently ignored the files).
DOCKER="$DOCKER" KUBERNETES_VERSION="$KUBERNETES_VERSION" scripts/render-charts.sh "$RENDER_DIR"

step "hostPath mounts are read-only (Falco, kube-bench)"
# The two workloads that are allowed host paths at all (ADR 0012) must not be able to write to them:
# a writable host path in a privileged namespace is a way back onto the node. Pod Security has no
# control for "read-only", so it is asserted on the render (ADR 0013, amendment).
python3 scripts/lib/check_hostpath_readonly.py "$RENDER_DIR" \
  DaemonSet/falco/falco \
  CronJob/kube-bench/kube-bench

step "kyverno apply (cluster/infra/kyverno-policies over every rendered workload)"
# The policies are taken from their kustomize render, i.e. exactly the objects Argo CD applies.
#
# Exit status is the gate:
#   * a policy the CLI cannot load (for example `images:` on a pod-level podSecurity control) is
#     listed under "Policies Skipped" and counted as an error -> exit 1;
#   * a resource that fails an Enforce rule -> exit 1;
#   * a resource that fails an Audit rule is printed as "failed as audit warning" and does not fail
#     the build (--audit-warn). Those lines are the work list for the Audit -> Enforce flip of the
#     phase 4 policies (plan commit 9): that commit is green only once there are none left.
#
# Blind spot: only what is rendered from git is judged. Pods an operator creates at run time (Trivy
# scan Jobs and the like) never reach this check; the PolicyReports in the cluster cover those, which
# is why the Enforce flip needs both (ADR 0012).
#
# Kyverno prints a deprecation warning for every kyverno.io/v1 ClusterPolicy it loads; the migration
# to CEL policies is a recorded later decision (ADR 0012), so the repetition is filtered out here.
#
# --user: the image runs as a fixed non-root uid, and mktemp's directory is 0700 for the invoking
# user, so the CLI could not read it otherwise. Running as the invoking user is the narrower fix than
# opening the directory, which may hold decrypted Secrets (see the KSOPS note above).
#
# verify-portfolio-images is evaluated for real: the CLI fetches the Sigstore trusted root and the
# signature bundles of the digest pinned in cluster/infra/hello over the network, so a commit that
# points hello at an unsigned digest fails here, before Argo CD tries to roll it out. The TUF cache
# goes to $HOME, which for an arbitrary uid is `/` - hence a throwaway tmpfs as HOME.
$DOCKER run --rm --user "$(id -u):$(id -g)" --tmpfs /home/cli -e HOME=/home/cli \
  -v "$RENDER_DIR":/rendered:ro "$KYVERNO_CLI_IMAGE" \
  apply /rendered/cluster_infra_kyverno-policies.yaml \
  --resource /rendered \
  --audit-warn \
  --remove-color \
  2>&1 | grep -v 'ClusterPolicy is deprecated'

step "validate-cluster: ok"
