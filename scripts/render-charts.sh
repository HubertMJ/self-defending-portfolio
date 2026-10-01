#!/usr/bin/env bash
# Renders every Helm chart that an Argo CD Application under cluster/apps/ deploys, with the values
# that Application passes, into one file per chart source:
#
#   scripts/render-charts.sh <output-dir>      ->  <output-dir>/chart_<app>-<source index>.yaml
#
# Per source, not per Application: cluster/apps/trivy-operator.yaml deploys two charts, and one file
# per Application let the second render overwrite the first, so the operator's own Pods silently
# never reached the `kyverno apply` gate.
#
# Why this exists. scripts/validate-cluster.sh renders every kustomization in the repository, but
# the charts (Cilium, cert-manager, Kyverno, and the phase 4 security tooling) are rendered by Argo CD
# inside the cluster and never appear in git as manifests. Their Pods are exactly what the phase 4
# Pod Security and resource policies judge, so without this render the `kyverno apply` gate in
# `make validate` would only ever see the handful of workloads written by hand (ADR 0012).
#
# Hooks are rendered on purpose (`helm template` includes them unless --no-hooks is given). A hook
# Job - cert-manager's startupapicheck, Kyverno's webhook cleanup - is a Pod created at sync time
# like any other, and under an Enforce policy it is the first thing to be rejected: the chart's
# Deployments are already running, the hook is new. This render is how that is caught before the
# Enforce flip instead of during the next upgrade.
#
# The one hook type that is dropped is `helm.sh/hook: test` (and the Helm 2 test-success /
# test-failure spellings): those Pods only exist when someone runs `helm test`, and Argo CD never
# creates them - Kyverno's chart renders five, and none of them is in the cluster. Judging them would
# make the Enforce gate demand fixes for objects that are never admitted.
#
# Fidelity to Argo CD: the same Helm major/minor Argo CD v3.5.3 bundles (hack/tool-versions.sh:
# helm4_version=4.2.1), the Application's releaseName and destination namespace, --include-crds
# (Argo's default), and the Kubernetes version the cluster runs. Capabilities that the charts probe
# at render time are restated below; anything else that differs from the live API server's answer
# would only change which optional objects a chart renders, not the Pod specs.
#
# Everything runs in pinned containers (ADR 0008). Needs network access to the chart repositories.
set -euo pipefail

cd "$(dirname "$0")/.."

OUT_DIR=${1:?usage: render-charts.sh <output-dir>}
mkdir -p "$OUT_DIR"

DOCKER=${DOCKER:-docker}

# Pinned by tag and digest. Same Helm release Argo CD v3.5.3 renders charts with.
HELM_IMAGE=${HELM_IMAGE:-alpine/helm:4.2.1@sha256:8647f126de3578d74f947ba735e4cfa0ea6aea7d6e2f36bceb86f31415944dca}

# Matches validate-cluster.sh and k3s_version in ansible/inventory/group_vars/k3s_nodes.yml.
KUBERNETES_VERSION=${KUBERNETES_VERSION:-1.35.8}

# API groups the live cluster serves that a chart in this repository checks for at render time.
# Cilium creates its GatewayClass only when gateway.networking.k8s.io/v1 GatewayClass is registered
# (cluster/apps/cilium.yaml); the CRDs come from cluster/infra/gateway-api-crds, wave -2.
API_VERSIONS=(gateway.networking.k8s.io/v1 gateway.networking.k8s.io/v1/GatewayClass)

VALUES_DIR=$(mktemp -d)
trap 'rm -rf "$VALUES_DIR"' EXIT

# One TSV line per chart source; valuesObject blocks land in $VALUES_DIR. See the module docstring
# for what is rejected (valueFiles, OCI repos, ...) and why that is an error rather than a skip.
CHARTS=$(python3 scripts/lib/chart_sources.py cluster/apps "$VALUES_DIR")
[ -n "$CHARTS" ] || { echo "render-charts: no chart Applications found under cluster/apps" >&2; exit 1; }

# Splits the stream on `---` lines and drops every document annotated as a Helm test hook (see the
# header), removes null `initContainers:` keys (see below), and drops every document that holds
# nothing but comments: a chart whose CRD files start with
# their own `---` (trivy-operator's crds/) renders a `# Source:` line as a document of its own, which
# kubectl and Argo CD skip but the kyverno CLI refuses to load ("Object 'Kind' is missing").
# Text-level on purpose: parsing the ~6 MB of rendered CRD schema just to read one
# annotation would multiply the run time, and helm's output is regular enough for a line match.
# shellcheck disable=SC2016  # Python source; the $ is a regex anchor, not a shell expansion
DROP_HELM_TESTS='
import re, sys
docs = re.split(r"^---$", sys.stdin.read(), flags=re.M)
# The annotation value is a comma-separated list ("post-install,test" is legal), so `test` may sit
# anywhere in it; test-success / test-failure are the Helm 2 spellings.
test_hook = re.compile(r"^\s+[\"\x27]?helm\.sh/hook[\"\x27]?:\s*[\"\x27]?([\w-]+\s*,\s*)*test(-success|-failure)?\s*(,|[\"\x27]?\s*$)", re.M)
# A line that is neither blank nor a comment; without one the document is empty YAML.
content = re.compile(r"^[ \t]*[^#\s]", re.M)
# `initContainers:` with no value (the falco chart renders one when no init container is enabled) is
# YAML null. The API server drops a null field, so the Pod Kyverno judges in the cluster has no init
# containers; the kyverno CLI instead matches its `=(initContainers)` patterns against the null and
# reports a missing image tag and missing resources. Dropped here so the gate judges what is admitted.
# Matched only when the next line is a sibling key (same indent, not a `- ` list item).
null_init = re.compile(r"^( *)initContainers:[ \t]*\n(?=\1[^ \t\n-])", re.M)
sys.stdout.write("---".join(null_init.sub("", d) for d in docs
                            if content.search(d) and not test_hook.search(d)))
'

api_flags=()
for api in "${API_VERSIONS[@]}"; do api_flags+=(--api-versions "$api"); done

while IFS=$'\t' read -r app repo chart version release namespace values_file; do
  # values_file is `<app>-<source index>.yaml` (chart_sources.py), unique per chart source.
  out="$OUT_DIR/chart_$values_file"
  $DOCKER run --rm -v "$VALUES_DIR":/values:ro "$HELM_IMAGE" template "$release" "$chart" \
    --repo "$repo" \
    --version "$version" \
    --namespace "$namespace" \
    --kube-version "$KUBERNETES_VERSION" \
    "${api_flags[@]}" \
    --include-crds \
    --values "/values/$values_file" \
    | python3 -c "$DROP_HELM_TESTS" > "$out"
  printf '  %s: %s %s -> %s objects (%s hooks)\n' "$app" "$chart" "$version" \
    "$(grep -c '^kind:' "$out")" "$(grep -c 'helm.sh/hook:' "$out" || true)"
done <<< "$CHARTS"
