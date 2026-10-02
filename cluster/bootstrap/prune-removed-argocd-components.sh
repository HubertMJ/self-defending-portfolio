#!/usr/bin/env bash
# One-off deletes for the Argo CD components the bootstrap kustomization no longer declares.
#
# Why this file exists: `kubectl apply -k cluster/bootstrap/argocd` creates and updates, it never
# prunes. When a `$patch: delete` file removes an upstream object from the rendered set, re-applying
# the bootstrap only stops *declaring* it - the live object keeps running. Argo CD cannot clean up
# after itself here either: the bootstrap is not an Application (ADR 0005, amendment). So every
# object a delete patch removes is listed below, explicitly, by kind and name - the same names as the
# patch files, nothing selected by label or wildcard - and deleted once, by hand.
#
#   ADR 0023  argocd-dex-server-delete.yaml                    (Dex; usually already gone)
#   ADR 0024  argocd-applicationset-controller-delete.yaml     (ApplicationSet controller)
#   ADR 0024  argocd-notifications-controller-delete.yaml      (notifications controller)
#
# Not deleted, on purpose (the patch files say why): CRD applicationsets.argoproj.io, which
# argocd-server still watches, and Secret argocd-notifications-secret, which is empty.
#
# Usage (docs/bootstrap.md, 8.5) - after the bootstrap re-apply, never before it, or the next
# re-apply of an older checkout would simply recreate everything:
#   cluster/bootstrap/prune-removed-argocd-components.sh            # server-side dry run, deletes nothing
#   cluster/bootstrap/prune-removed-argocd-components.sh --delete   # deletes
#
# Idempotent: --ignore-not-found, so a second run, or a cluster bootstrapped after the patches
# existed, is a no-op. Needs the operator kubeconfig (the cluster-scoped ClusterRole/Binding).
set -euo pipefail

KUBECTL=${KUBECTL:-kubectl}
NS=${ARGOCD_NS:-argocd}

die() { printf 'prune-removed-argocd-components: %s\n' "$*" >&2; exit 1; }

case "${1:-}" in
  --delete) mode=() ; label="deleting" ;;
  "")       mode=(--dry-run=server) ; label="dry run (pass --delete to delete)" ;;
  *)        die "usage: $0 [--delete]" ;;
esac

# Preconditions, checked against the live cluster rather than assumed: the reasons each component
# was removed must still hold, or deleting it would break something that started depending on it.
"$KUBECTL" version --request-timeout=10s >/dev/null 2>&1 || die "cannot reach the cluster (KUBECONFIG?)"
appsets=$("$KUBECTL" get applicationsets.argoproj.io -A -o name 2>/dev/null) \
  || die "cannot list ApplicationSets (is the CRD still installed? it must stay - see the patch file)"
[ -z "$appsets" ] || die "ApplicationSets exist, so the controller is in use: $appsets"
notif_cm=$("$KUBECTL" -n "$NS" get configmap argocd-notifications-cm --ignore-not-found -o jsonpath='{.data}')
case "$notif_cm" in ""|"{}") ;; *) die "argocd-notifications-cm has data, so notifications are configured" ;; esac
# Only the deployment of a removed component may be named below: a running Deployment that the
# re-applied bootstrap still declared would mean the kustomization and this list disagree.
# Rendered once into a variable: piping straight into `grep -q` would let grep's early exit kill
# kubectl with SIGPIPE, and pipefail would then turn a match into "no match".
rendered=$("$KUBECTL" kustomize "$(dirname "$0")/argocd") || die "cannot render cluster/bootstrap/argocd"
for d in argocd-dex-server argocd-applicationset-controller argocd-notifications-controller; do
  if grep -qx "  name: $d" <<<"$rendered"; then
    die "$d is still declared by cluster/bootstrap/argocd; refusing to delete it"
  fi
done

printf '==> %s\n' "$label"

# Dex (ADR 0023). Deployment first, so nothing runs with the RBAC that follows it out.
"$KUBECTL" -n "$NS" delete --ignore-not-found "${mode[@]}" \
  deployment/argocd-dex-server \
  service/argocd-dex-server \
  serviceaccount/argocd-dex-server \
  role.rbac.authorization.k8s.io/argocd-dex-server \
  rolebinding.rbac.authorization.k8s.io/argocd-dex-server \
  networkpolicy.networking.k8s.io/argocd-dex-server-network-policy

# ApplicationSet controller (ADR 0024).
"$KUBECTL" -n "$NS" delete --ignore-not-found "${mode[@]}" \
  deployment/argocd-applicationset-controller \
  service/argocd-applicationset-controller \
  serviceaccount/argocd-applicationset-controller \
  role.rbac.authorization.k8s.io/argocd-applicationset-controller \
  rolebinding.rbac.authorization.k8s.io/argocd-applicationset-controller \
  networkpolicy.networking.k8s.io/argocd-applicationset-controller-network-policy
"$KUBECTL" delete --ignore-not-found "${mode[@]}" \
  clusterrolebinding.rbac.authorization.k8s.io/argocd-applicationset-controller \
  clusterrole.rbac.authorization.k8s.io/argocd-applicationset-controller

# Notifications controller (ADR 0024). Its empty ConfigMap goes too; the empty Secret stays.
"$KUBECTL" -n "$NS" delete --ignore-not-found "${mode[@]}" \
  deployment/argocd-notifications-controller \
  service/argocd-notifications-controller-metrics \
  serviceaccount/argocd-notifications-controller \
  role.rbac.authorization.k8s.io/argocd-notifications-controller \
  rolebinding.rbac.authorization.k8s.io/argocd-notifications-controller \
  networkpolicy.networking.k8s.io/argocd-notifications-controller-network-policy \
  configmap/argocd-notifications-cm
