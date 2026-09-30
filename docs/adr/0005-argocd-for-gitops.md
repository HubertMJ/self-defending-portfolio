# ADR 0005: Argo CD for GitOps

Date: 2026-09-30 · Status: accepted

## Context
Flux is lighter; Argo CD has a UI that makes "everything is deployed from git" visible to a visitor
(read-only screenshots / LAN-only UI). The VM has 8 GB RAM, so the ~500 MB Argo CD footprint fits.

## Decision
Argo CD, app-of-apps pattern, sync waves for ordering (CRDs → Cilium/cert-manager → Kyverno →
runtime security → app). Auto-sync with prune and self-heal for infra; the demo app too.
UI is LAN-only, SSO not needed: a single local admin with the initial password rotated by SOPS-managed secret.

## Consequences
- Every change to the cluster is a git commit; kubectl is only used during bootstrap and debugging.
- If RAM becomes tight, Flux is the documented fallback (manifests are plain Kustomize/Helm, so migration is mechanical).
