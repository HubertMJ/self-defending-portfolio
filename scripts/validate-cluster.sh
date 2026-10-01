#!/usr/bin/env bash
# Renders every Kustomization under cluster/ and validates the result against the real Kubernetes
# and CRD schemas. This is the check that a commit which would break the cluster fails before it
# reaches the cluster -- Argo CD auto-syncs, so CI is the last place a typo can be caught cheaply.
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
# container, so a local validation exercises exactly the binary the cluster will use.
KSOPS_IMAGE=${KSOPS_IMAGE:-viaductoss/ksops:v4.5.1@sha256:4def9fdd4e2f850265740ebe9592c5455d19b76891e88e602df8b52d74b95334}

# kubeconform ships schemas for built-in Kubernetes kinds only. Gateway, HTTPRoute, ClusterIssuer,
# CiliumNetworkPolicy and Application are CRDs, so their schemas come from the community catalog,
# pinned to a commit so a schema change upstream cannot turn a green build red overnight.
CRDS_CATALOG_REF=${CRDS_CATALOG_REF:-d373c2da9702bc9509a004db83e57263fe3bdfc1}
CRDS_CATALOG_SCHEMA="https://raw.githubusercontent.com/datreeio/CRDs-catalog/${CRDS_CATALOG_REF}/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json"

# Kubernetes version the manifests must be valid against. Matches k3s_version in
# ansible/inventory/group_vars/k3s_nodes.yml, minus the +k3s1 suffix.
KUBERNETES_VERSION=${KUBERNETES_VERSION:-1.35.8}

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

  kustomize "$source_root" "$build_target" > "$RENDER_DIR/$name.yaml"
  info "$dir -> $(grep -c '^kind:' "$RENDER_DIR/$name.yaml") objects"
done

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

step "validate-cluster: ok"
