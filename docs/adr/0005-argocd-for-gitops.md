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
- The hand-over of bootstrap-installed components (Cilium) from Ansible to Argo CD is one-way:
  once the `cilium` Application exists, the Ansible role skips the Helm release (Argo CD creates
  objects without Helm ownership metadata, which `helm upgrade` would refuse to adopt) and only
  keeps the prerequisites in place. A rebuild from zero has no Application and installs normally.

## Amendment 2026-10-01: drift-free diffs and the bootstrap re-apply exception

**Context.** After phase 3 two Applications never reached Synced although nothing had drifted.
`kyverno`: chart 3.9.1 renders its 11 `policies.kyverno.io` CRDs with `metadata.labels: {}` and
`annotations: {}`; the API server stores no empty map, so Argo CD's client-side diff reported a
missing field on every refresh. `root`: Argo CD 3.x adds `pre-delete-finalizer.argocd.argoproj.io`
and `pre-delete-finalizer.argocd.argoproj.io/cleanup` to the `kyverno` Application at runtime
(its chart has a pre-delete hook), while git only declares `resources-finalizer`. Phase 4 also brings
Trivy Operator, which writes one report object per workload and scan type and rewrites them on every
rescan.

**Decision.**
- **Ignore only empty metadata maps on Kyverno's CRDs.** `cluster/apps/kyverno.yaml` ignores
  `.metadata.labels | select(. == {})` and the same for `annotations` on
  `apiextensions.k8s.io/CustomResourceDefinition`. The `select` keeps the ignore exact: an empty map
  rendered by the chart is tolerated, a real label or annotation is still diffed. Tried first and
  rejected: `argocd.argoproj.io/compare-options: ServerSideDiff=true` on the Application; with it
  applied and the app hard-refreshed, the same 11 CRDs stayed OutOfSync.
- **Ignore child Application finalizers on `root`.** `root-application.yaml` ignores
  `.metadata.finalizers` on `argoproj.io/Application` and syncs with `RespectIgnoreDifferences=true`,
  so a sync of a child Application never writes git's shorter list over the runtime one. The ignore is
  explicit rather than a ServerSideDiff on `root`, because it names the tolerated difference and does
  not depend on how SSA merges a list of strings. The whole list is ignored, not the two names:
  finalizers are lifecycle state the controller manages, and the next one Argo CD adds should not
  reopen the drift.
- **Trivy reports are not tracked.** `argocd-cm` `resource.exclusions` lists the eleven
  `aquasecurity.github.io` report kinds (vulnerability, config audit, exposed secret, RBAC, infra
  assessment, SBOM; namespaced and cluster variants). They are generated, never in git, and would cost
  controller memory and UI clutter on an 8 GB node. `ClusterComplianceReport` stays tracked: the
  trivy-operator chart renders those objects itself. Because `resource.exclusions` is one string and a
  kustomize patch replaces it whole, the Argo CD v3.5.3 defaults from `install.yaml` are copied into
  the patch verbatim; an Argo CD bump has to re-diff that block.
- **Bootstrap re-apply is the documented exception to "every change is a git commit to `main`".**
  `root-application.yaml` and `argocd-cm.yaml` belong to the bootstrap kustomization; no Application
  manages them. A change to either is committed first and then reaches the cluster through one manual
  `kubectl apply -k cluster/bootstrap/argocd --server-side --force-conflicts` (the same flags as
`cluster/bootstrap/bootstrap.sh`), run only after `kubectl diff -k` shows changes to those
  objects and nothing else (in particular no Argo CD version change riding along).

**Consequences.**
- `kyverno` and `root` can report Synced, so OutOfSync is a signal again rather than a constant.
- A finalizer removed from a child Application by hand is not reported on `root`; finalizers are not
  the configuration this repository reviews.
- The reverse holds too: a git edit to `finalizers` on an *existing* child Application never reaches
  the cluster (a new Application is still created with what git declares). Such a change needs a
  one-off `kubectl patch` alongside the commit.
- The bootstrap files can drift from git without Argo CD noticing; the `kubectl diff -k` step above is
  the check, and a rebuild from zero applies them as committed.
