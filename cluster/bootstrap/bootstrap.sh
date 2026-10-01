#!/usr/bin/env bash
# Phase 2 bootstrap: the single manual step between `make cluster` and GitOps.
#
# Idempotent by construction: every action is either `create --dry-run | apply` or `apply -k`.
# Run it twice; the second run changes nothing.
#
# It installs Argo CD and the app-of-apps root. It does NOT create the age key, the Cloudflare
# tunnel or the encrypted secrets — those are human steps, see docs/bootstrap.md phase 2.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
ARGOCD_NS=${ARGOCD_NS:-argocd}
ARGOCD_KUSTOMIZATION=${ARGOCD_KUSTOMIZATION:-"$REPO_ROOT/cluster/bootstrap/argocd"}
KUBECTL=${KUBECTL:-kubectl}
WAIT_TIMEOUT=${WAIT_TIMEOUT:-300s}

die() { printf 'bootstrap: %s\n' "$*" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*"; }

command -v "$KUBECTL" >/dev/null || die "kubectl not found; set KUBECTL or export KUBECONFIG and install it"
"$KUBECTL" version --request-timeout=10s >/dev/null 2>&1 \
  || die "cannot reach the cluster; is KUBECONFIG set to the kubeconfig fetched by the k3s role?"

: "${SOPS_AGE_KEY_FILE:?set SOPS_AGE_KEY_FILE to the age private key file (see docs/bootstrap.md)}"
[ -r "$SOPS_AGE_KEY_FILE" ] || die "SOPS_AGE_KEY_FILE=$SOPS_AGE_KEY_FILE is not readable"
grep -q 'AGE-SECRET-KEY-' "$SOPS_AGE_KEY_FILE" \
  || die "$SOPS_AGE_KEY_FILE does not look like an age identity file (no AGE-SECRET-KEY- line)"

if grep -rq --exclude=bootstrap.sh 'REPLACE-ME-GITHUB-OWNER' "$REPO_ROOT/cluster"; then
  die "cluster/ still contains REPLACE-ME-GITHUB-OWNER; set the repository owner first (see cluster/bootstrap/README.md)"
fi

step "namespace $ARGOCD_NS"
"$KUBECTL" create namespace "$ARGOCD_NS" --dry-run=client -o yaml | "$KUBECTL" apply -f -

step "secret $ARGOCD_NS/sops-age (age identity, never printed)"
# --dry-run=client + apply is the idempotent form of `create secret`. The key is piped, so it never
# appears in argv and never reaches the process table or the shell history.
"$KUBECTL" create secret generic sops-age \
  --namespace "$ARGOCD_NS" \
  --from-file=keys.txt="$SOPS_AGE_KEY_FILE" \
  --dry-run=client -o yaml | "$KUBECTL" apply -f -

step "argo cd (kustomize build $ARGOCD_KUSTOMIZATION)"
# The kustomization carries both the Argo CD CRDs and the root Application. On a fresh cluster the
# first apply registers the CRDs but cannot yet create the Application (no REST mapping). Apply,
# wait for the CRD to be established, apply again; both applies are idempotent.
"$KUBECTL" apply -k "$ARGOCD_KUSTOMIZATION" --server-side --force-conflicts || true
"$KUBECTL" wait --for=condition=Established crd/applications.argoproj.io --timeout=120s
"$KUBECTL" apply -k "$ARGOCD_KUSTOMIZATION" --server-side --force-conflicts

step "waiting for argocd-server (timeout $WAIT_TIMEOUT)"
"$KUBECTL" -n "$ARGOCD_NS" rollout status deployment/argocd-server --timeout="$WAIT_TIMEOUT"
"$KUBECTL" -n "$ARGOCD_NS" rollout status deployment/argocd-repo-server --timeout="$WAIT_TIMEOUT"

step "cilium operator restart once the Gateway API CRDs exist"
# The Ansible bootstrap installs Cilium before the Gateway API CRDs reach the cluster (they come
# from the gateway-api-crds Application). The operator only starts its Gateway controller when the
# CRDs are present at startup, so GatewayClass stays "Waiting for controller" until one restart.
"$KUBECTL" wait --for=condition=Established crd/gateways.gateway.networking.k8s.io --timeout="$WAIT_TIMEOUT"
"$KUBECTL" -n kube-system rollout restart deployment/cilium-operator
"$KUBECTL" -n kube-system rollout status deployment/cilium-operator --timeout="$WAIT_TIMEOUT"

cat <<'NEXT'

==> done. Argo CD is running and the root Application is syncing.

Initial admin password (delete the secret once you have rotated the password):

  kubectl -n argocd get secret argocd-initial-admin-secret \
    -o jsonpath='{.data.password}' | base64 -d; echo

UI, LAN only — there is no Ingress, no Gateway and no tunnel route for Argo CD (ADR 0003):

  kubectl -n argocd port-forward svc/argocd-server 8080:80
  # then http://localhost:8080  (plain HTTP on purpose: server.insecure=true)

Watch the app-of-apps come up in sync-wave order:

  kubectl -n argocd get applications -w
NEXT
