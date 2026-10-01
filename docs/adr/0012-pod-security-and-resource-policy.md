# ADR 0012: Pod Security `restricted` and pod resources as Kyverno policies, Audit before Enforce

Date: 2026-10-01 · Status: accepted

## Context
Phase 4 brings in software that cannot run under Pod Security Standards `restricted`: Falco's eBPF
sensor needs capabilities, host paths and root, and kube-bench needs the host PID namespace and the
node's files. Everything else in the cluster already runs `restricted`, enforced by the built-in Pod
Security admission (PSA) labels on each namespace.

PSA is per namespace and all-or-nothing. A namespace that has to admit Falco must be labelled
`privileged`, and `privileged` means no checks at all: anything else placed in that namespace later
is unchecked too, and nothing records how far a workload is from `restricted`. PSA also writes only
audit log lines, while the phase 6 posture page needs a queryable report per workload.

Separately, the cluster is a single 8 GB node. A container without a memory request is invisible to
the scheduler, and one without a memory limit can push the node into the OOM killer, which may pick
Kyverno, Argo CD or Cilium rather than the container that leaked. Argo CD itself (installed by the
bootstrap kustomization from upstream `install.yaml`) and the kube-system add-ons carry no requests
or limits today.

Options considered: PSA labels alone; the upstream `kyverno-policies` chart (17 PSS policies, one per
control); Kyverno CEL `ValidatingPolicy`; Kyverno `ClusterPolicy` with the `podSecurity` rule type.

## Decision

**PSA stays the floor, Kyverno adds per-control precision.** Namespaces keep their PSA labels
(`falco` and `kube-bench` will be `privileged` for enforce and `restricted` for audit, plan §4.1).
`cluster/infra/kyverno-policies/pod-security-restricted.yaml` runs the same upstream PSS check library
through Kyverno's `podSecurity` rule (`level: restricted`, `version: latest`):

- rule `restricted` for every namespace except `kube-system`, `falco` and `kube-bench`;
- rule `restricted-falco`, matched to namespace `falco`, which relaxes Capabilities only through
  `restrictedField: ...capabilities.add` with `values` = the four that `modernEbpf.leastPrivileged`
  adds, for the Falco image; HostPath Volumes, Volume Types, AppArmor; and Running as Non-root /
  Seccomp / Privilege Escalation for the Falco image. There is no images-only Capabilities entry:
  that would switch the whole control off for the image (a Falco container adding SYS_ADMIN then
  passes). So the Falco values must also set `capabilities.drop: [ALL]` next to the four adds; drop
  ALL + the four passes, a fifth capability fails;
- rule `restricted-kube-bench`, matched to namespace `kube-bench`, which relaxes Host Namespaces only
  for `spec.hostPID: true` (hostNetwork / hostIPC still fail), HostPath Volumes, Volume Types and
  Running as Non-root.

"Running as Non-root" covers `runAsNonRoot`; the separate "Running as Non-root user" control
(`runAsUser: 0`) is relaxed nowhere, so the Falco and kube-bench manifests must leave `runAsUser`
unset and rely on the images' default (root) user.

Container-level exclusions are scoped by image, pod-level ones by namespace. That split is a Kyverno
limitation, not a preference: `images:` on a pod-level control (HostPath Volumes, Volume Types, Host
Namespaces, AppArmor) makes Kyverno reject the whole policy. The consequence is that `falco` and
`kube-bench` must each hold their one workload and nothing else; the namespace is the boundary.

Exclusions live inline in the rule, not in `PolicyException` objects: `kyverno.io/v2` exceptions are
deprecated in 1.19, and an exception in another file is a relaxation a reviewer of the rule does not
see.

**Resources.** `require-pod-resources.yaml` requires `requests.cpu`, `requests.memory` and
`limits.memory` on every container and init container. CPU limits are not required: CPU is
compressible, and a CPU limit on a component in the admission path turns into throttling and then
webhook timeouts. Excluded: `kube-system` (not sized by this repository), and **`argocd`, as recorded
debt** (user decision 2026-10-01): sizing Argo CD is a bootstrap patch with its own review, and until
it exists the exclusion keeps an Enforce flip from blocking Argo CD's own rollouts.

**Both start in Audit, with `failurePolicy: Ignore` and background scanning.** Both policies match
nearly every namespace; with `Fail`, a Kyverno outage on a single node would block every Pod
creation, including the pods needed to recover. PSA keeps the floor while the webhook is down. The
opposite trade (`Fail`) stays reserved for the narrowly scoped image policies (ADR 0011).

**The Audit -> Enforce gate is mechanical, and offline.** `make validate` (and the CI `validate` job)
now renders every Helm chart Application with its own values, hooks included
(`scripts/render-charts.sh`, Helm 4.2.1 as bundled by Argo CD v3.5.3), and runs
`kyverno apply` (CLI v1.19.1, the controller's version, pinned by digest per ADR 0008) with the
kustomize-rendered policies over every rendered object. A policy the CLI cannot load, or a
resource that fails an Enforce rule, fails the build; Audit failures are printed as warnings. The flip
to Enforce (plan commit 9) requires both `kubectl get polr,cpolr -A` and this check to show zero
failures for both policies. Hook Jobs are rendered on purpose, because under Enforce they are the
first Pods to be rejected (cert-manager's `startupapicheck` rendered `resources: {}` and now has
explicit resources for that reason). Helm `test` hooks are dropped from the render: Argo CD never
creates them.

Rejected: the upstream `kyverno-policies` chart (one policy per control, noisy reports, and its
exclusions are values rather than reviewable rules); CEL `ValidatingPolicy` (the phase 3 policies are
ClusterPolicies; mixing both in one phase doubles the surface to explain, and migrating all of them is
a later, separate decision now that ClusterPolicy is deprecated in 1.19); PSA labels alone (no
per-control relaxation, no reports).

## Consequences
- Every workload gets a PolicyReport saying how far it is from `restricted` and whether it is sized,
  which is what the phase 6 posture page reads.
- Falco and kube-bench run with precisely listed relaxations instead of an unchecked `privileged`
  namespace. Adding a second workload to either namespace inherits the pod-level relaxations, which
  is why that is not allowed.
- `make validate` (and the CI `validate` job) now needs, at run time, the Helm chart repositories,
  ghcr.io (the kyverno-cli image, and the signature and SBOM bundles of the hello digest, which
  `verify-portfolio-images` really verifies) and the Sigstore TUF CDN (trusted root). It already
  needed GitHub for the Argo CD install manifest and the schema catalog. It fails closed: an outage
  of any of them fails the build rather than skipping the check.
- The offline gate only sees what is rendered from git. Pods created at run time by an operator -
  Trivy scan Jobs, anything an operator spawns from its own templates - never reach it. The Enforce
  flip (plan commit 9) therefore also requires `kubectl get polr,cpolr -A` to be clean *after* the
  scan Jobs have run at least once, not just after the charts synced.
- `render-charts.sh` refuses Application features it cannot reproduce exactly (`valueFiles`,
  `parameters`, OCI or git chart repositories) instead of rendering partially; a later Application
  that needs one has to extend the script first.
- Argo CD runs without requests or limits until the bootstrap is patched; that is debt, visible as the
  `argocd` line in the resources policy's exclusion list.
- Kyverno logs a deprecation warning for every `kyverno.io/v1` ClusterPolicy; migrating all five to CEL
  policies is a candidate for a later phase.
