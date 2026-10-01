# ADR 0013: Runtime detection and response: Falco (modern eBPF, least privilege) -> Falcosidekick -> Falco Talon

Date: 2026-10-01 · Status: accepted

## Context
Phase 3 controls what may start in the cluster; nothing yet watches what a running container does.
The phase 4 Definition of Done is that a manual interactive shell in a test pod (`kubectl exec -it`)
produces a Falco alert and that Falco Talon kills the pod, proven by `tests/runtime/run.sh`.

The sensor has to see every syscall on the node, which normally means a privileged DaemonSet. The
responder has to delete pods, which normally means cluster-wide pod permissions. Both are exactly the
kind of component an attacker would want to subvert, so the design question is how little of each is
enough.

Options considered: Falco's kernel module or legacy eBPF probe vs. the modern eBPF probe, privileged vs.
`leastPrivileged`; Falco's k8smeta collector vs. the container runtime as the source of pod metadata;
falcoctl (rules and plugins downloaded and followed at run time) vs. the content of the pinned image;
Talon's network-policy actionners vs. a label plus a standing Cilium policy for isolation; the
falco-talon chart vs. plain manifests.

## Decision

**Falco 0.45.0, modern eBPF, least privileged** (`cluster/apps/falco.yaml`, chart 9.2.0). One
DaemonSet in namespace `falco`, alone there. The container drops every capability and adds exactly
BPF, PERFMON, SYS_RESOURCE and SYS_PTRACE (no `privileged`); AppArmor is `Unconfined` as the pod-level
field; it runs as the image's root user with `runAsUser` unset. PSA `enforce` is `privileged` in that
namespace (`audit: restricted`); the precise judgement is Kyverno's `restricted-falco` rule (ADR 0012),
which accepts exactly those four capabilities on the Falco image and fails a fifth - verified in
`make validate` both ways. The ServiceAccount is owned in git with `automountServiceAccountToken:
false`: the sensor holds no API token.

Host access is the chart's modern-eBPF set: `/host/proc`, `/host/etc`, `/host/boot`, `/host/usr` and
`/sys/kernel` read-only, k3s's containerd socket directory (the container plugin's metadata source).
`driver.loader.enabled: false` is what makes `/host/proc` read-only - with SYS_PTRACE, a writable host
`/proc` would let the sensor write any host process's memory. Chart 9.2.0 mounts `/host/lib/modules`
read-write in that same mode; that gap is closed by a post-render patch (amendment below), so every
host path the sensor sees is read-only.

**No falcoctl, no k8smeta, no internet.** The image carries the rules (`/etc/falco/falco_rules.yaml`,
including "Terminal shell in container") and the container plugin (`libcontainer.so`), which reads pod
and namespace names from the CRI. Only the `cri` engine on `/run/k3s/containerd/containerd.sock` is on.
Rules change only by a commit: the image's rules, plus one custom rule, "SDP network tool in sandbox"
(`wget`/`nc`/`curl` started in a `sandbox` container, WARNING). Checked offline with the pinned binary:
the rendered `falco.yaml` passes Falco's schema validation, the plugin loads from the image and both
rules files validate.

Alerts are JSON with `k8s.ns.name` and `k8s.pod.name` appended as output fields, on stdout and via
`http_output` to Falcosidekick. Falco's only network egress is DNS and Falcosidekick:2801.

**Falcosidekick 2.32.0 -> Falco Talon 0.3.0 in `falco-response`** (`cluster/apps/falco-response.yaml`).
A separate namespace, PSS `restricted`: the privileged sensor and the component that holds API
permissions never share a namespace. Falcosidekick (chart 0.14.0, one replica, no UI, no Redis)
accepts alerts from the Falco pods only and forwards everything at `notice` or above to Talon, which
accepts them from Falcosidekick only (neither HTTP API is authenticated; the CiliumNetworkPolicies are
what stop a forged alert). Talon's only egress is the API server.

**Talon from plain manifests, not its chart.** The falco-talon chart (0.5.0 and 0.4.2 alike) writes
`image.tag` into the `app.kubernetes.io/version` label, so the tag@digest pin of ADR 0008 renders an
invalid label and the API server would reject the Deployment; the chart has no other place for a
digest. `cluster/infra/falco-response/talon-deployment.yaml` follows the chart's templates otherwise.
Side effects: the chart's always-rendered (here: empty) ClusterRole/ClusterRoleBinding disappear, and
the configuration is a ConfigMap (no secret values) with `LOG_LEVEL=info` and `NAMESPACE` from the
pod's namespace. Talon's embedded NATS needs a writable `/tmp` (emptyDir); the root filesystem is
read-only.

**Leader election stays on**, as it must: the upstream chart renders `leaderElection: false` as true,
and Talon only sets its event publisher once a leader is known. One replica holds Lease `falco-talon`
in `falco-response` (4 s lease, 2 s retry - a small constant API load).

**Two response rules, both scoped to `sandbox`** (`talon/rules.yaml`, validated with
`falco-talon rules check` 0.3.0):
- DoD: "Terminal shell in container" with `k8s.ns.name=sandbox` -> `kubernetes:terminate`,
  `grace_period_seconds: 0`, `ignore_standalone_pods: false`. Terminate only: labelling first would put
  a Pod UPDATE through `verify-portfolio-images` (failurePolicy Fail, 30 s timeout) in front of the kill.
- Isolation: "SDP network tool in sandbox" -> `kubernetes:label sdp.hubertjablon.ski/quarantine=true`.
  The standing CiliumClusterwideNetworkPolicy `quarantine` denies all ingress and egress for that label
  (deny beats allow). Talon's network-policy actionners were rejected: both write egress-only rules, and
  the Cilium one denies the event's remote IP, which means nothing for a shell or `wget` event. Talon's
  label actionner sends a JSON Patch `replace`, which fails on a missing key (source, v0.3.0), so pods in
  `sandbox` carry the label as `"false"` from the start.

**RBAC, from Talon 0.3.0's source for the actionners and notifier in use:**
- Role in `sandbox`: pods `get, patch, delete`; events `create`.
- Role in `falco-response`: leases `create`, and `get, update` on `falco-talon` only.
- ClusterRole `falco-talon-namespace-read`: namespaces `get` with `resourceNames: [sandbox]` (the
  k8sevents notifier reads the acted-on pod's Namespace; user decision 2026-10-01).
- Nothing else: no pods in other namespaces, no exec, no secrets, no nodes, no NetworkPolicies. This is
  narrower than plan section 4.4 (no pods `list`, no events `patch`), because nothing in use calls them.
  `kubectl auth can-i delete pods -n hello --as=system:serviceaccount:falco-response:falco-talon` = no.

**`sandbox`** (`cluster/apps/sandbox.yaml`): PSS `restricted`, already covered by the image policies of
ADR 0011, default-deny with DNS as the only allowed flow, the quarantine policy and Talon's Role.

## Consequences
- An interactive shell in a `sandbox` pod is answered by deletion within seconds, and a network tool by
  isolation, without any human in the loop; every action leaves a Kubernetes Event on the pod.
- Talon can only ever act on pods in `sandbox`. Extending automatic response to another namespace is a
  Role there and a rule here, both reviewed; until then a matching rule elsewhere fails with a 403.
- The sensor is still close to host-equivalent if compromised (BPF and PERFMON read kernel memory,
  SYS_PTRACE, and the containerd socket, whose API a read-only mount does not limit). What this design
  limits is everything around it: no API token, no outbound network beyond Falcosidekick, nothing else
  in its namespace, rules only from git.
- Falcosidekick and Talon are unauthenticated HTTP services; their integrity rests on the Cilium
  policies. A Cilium policy outage would let any pod forge alerts against `sandbox` pods.
- Leader election costs a Lease update every 2 s.
- `tests/runtime/run.sh` (plan commit 8) is the proof; the label-patch behaviour and the time-to-kill
  are measured there, on the live cluster.

## Amendment 2026-10-01: every Falco host mount read-only, via a kustomize post-render

**Problem.** In chart 9.2.0, `/host/proc` is read-only only with `driver.loader.enabled: false`, and that
same setting mounts `/host/lib/modules` read-write. No value changes it. A writable host module tree
plus the kernel's module autoload (`request_module`, triggered by unprivileged actions such as opening
a socket of an unloaded protocol family) is a path to host root for a compromised sensor.

**Options considered**, in the order preferred:
- *Chart values only.* No value sets `readOnly` on that mount. Every switch that removes it (loader
  enabled, driver disabled) makes `/host/proc` writable instead, which with SYS_PTRACE is worse. A
  second mount at the same path through `mounts.volumeMounts` is rejected by API validation (mount
  paths must be unique). A path variant such as a trailing slash passes validation but leaves the
  outcome to the runtime's bind-mount ordering, which is not a control. Rejected.
- *Kustomize `helmCharts` plus a patch* (chosen). Argo CD has no post-render step for a Helm source,
  but it builds kustomizations, and kustomize can render a chart and then patch it. The chart stays
  the source of truth: same chart, version and values, with a strategic-merge patch on top.
- *ConfigManagementPlugin.* A sidecar on the repo-server with its own image and tool chain, for one
  patch. Not needed once the above works.

**Decision.**
- `cluster/apps/falco.yaml` is a single kustomize source, `cluster/infra/falco/`. It holds the chart
  as a `helmCharts` entry (chart 9.2.0, the former `valuesObject` verbatim as `valuesInline`,
  `kubeVersion` 1.35.8), the Namespace, ServiceAccount and network policies as before, and a patch.
- The patch sets `readOnly: true` on `/host/lib/modules`. It also restates it for `/host/proc`, so a
  chart bump that changed the loader logic cannot quietly make it writable, and sets it for the
  containerd socket directory: connecting to a unix socket does not need a writable mount, and that
  directory also holds the runtime state of every container.
- `argocd-cm` gains `--enable-helm` in `kustomize.buildOptions`, and nothing else. The line is now
  `--enable-alpha-plugins --enable-exec --enable-helm`. The first two flags are not new: they have been
  there since phase 2 (ADR 0006) because the KSOPS generators in `cluster/infra/cert-manager-issuers`
  and `cluster/infra/cloudflared` are kustomize exec plugins. They do let a kustomization in this
  repository run a binary inside argocd-repo-server, which is a standing trade-off of KSOPS rather than
  part of this change. `--enable-helm` is global too, but it only does something for a kustomization
  in this repository that declares `helmCharts`.
- Checked offline with the exact pair Argo CD v3.5.3 bundles (`hack/tool-versions.sh`: kustomize 5.8.1,
  helm 4.2.1): `kustomize build --enable-helm` pulls the chart (also tested against a local chart
  repository), renders it with the values and applies the patch.

**Validation.**
- `make validate` renders `helmCharts` kustomizations in two steps with the existing pinned images: the
  Helm image renders the chart with the arguments kustomize passes, then the kustomize image applies the
  patches (`scripts/lib/helm_charts_kustomization.py`, with an allowlist of `helmCharts` keys). The output
  was checked to be identical to a direct kustomize 5.8.1 `--enable-helm` build.
- kubeconform and `kyverno apply` judge the result as before (`restricted-falco`: 0 fail, 0 warn).
- A new step, `scripts/lib/check_hostpath_readonly.py`, fails the build if the Falco DaemonSet or the
  kube-bench CronJob mounts any hostPath writable, or if either workload is missing from the render. It
  was verified to fail with the patch entry removed.

**Consequences.**
- One bootstrap change, applied by hand once (ADR 0005 amendment), after `kubectl diff -k
  cluster/bootstrap/argocd` shows only `argocd-cm`:
  `kubectl apply -k cluster/bootstrap/argocd --server-side --force-conflicts`. It has to land before
  the falco Application syncs: without `--enable-helm` the kustomize build fails and the Application
  stays in an error state, rather than deploying an unpatched chart.
- The repo-server pulls the chart into the build directory (`charts/`, git-ignored), from the same chart
  repository the Helm source used.
- A chart bump is reviewed as before. If the chart stops rendering one of the patched mounts, the patch
  would add a volumeMount without a name, which kubeconform rejects; a newly added writable host mount
  fails the hostPath check.

### Correction 2026-10-01: the repo-server was not running Argo CD's kustomize

After deployment the falco Application failed with `unable to run: 'helm version -c --short' ...
unknown shorthand flag: 'c'`. The offline check above had used Argo CD's own kustomize 5.8.1. The
repo-server, however, ran kustomize **v5.3.0**: the KSOPS bootstrap patch
(`cluster/bootstrap/argocd/argocd-repo-server-ksops.yaml`) ran `ksops install --with-kustomize` and
mounted the ksops image's kustomize over `/usr/local/bin/kustomize`. Kustomize up to v5.7.1 checks the
helm version with `helm version -c --short`, which Helm 4 (bundled with Argo CD v3.5.3) rejects. v5.8.1
calls `helm version --short` and accepts Helm 3 and 4. The failure was reproduced offline with the
ksops image's binary and Argo CD's exact flags. It failed closed: nothing was applied, and the
unpatched chart never ran.

**Options considered:**
1. A wrapper script that strips `-c` before calling helm, plus `--helm-command`. It works around a
   kustomize that is three minors behind Argo CD's, and leaves a hand-written shim in the build path.
2. A ConfigManagementPlugin sidecar: a second image and tool chain in the repo-server for one patch.
3. (chosen) Stop shadowing Argo CD's kustomize. The KSOPS init container now runs
   `ksops install /custom-tools` (plugin only), and only `/usr/local/bin/ksops` is mounted. The
   repo-server runs the kustomize v5.8.1 that Argo CD v3.5.3 ships with Helm 4.2.1. There is no extra
   binary and no flag beyond `--enable-helm`, and the tool versions are the ones Argo CD pins and tests
   together.

**Verified offline**, since quay.io (and so the argocd image) is not reachable from the sandbox this
was written in. The run simulated the repo-server environment:
- kustomize 5.8.1, from the release tarball whose sha256 matches Argo CD v3.5.3's
  `hack/installers/checksums/kustomize_5.8.1_linux_amd64.tar.gz.sha256`;
- Helm 4.2.1 at the same git commit as Argo CD's (`d591a19`);
- the ksops binary copied out of the pinned ksops image, on `PATH`;
- Argo CD's exact arguments: `build <path> --enable-alpha-plugins --enable-exec --enable-helm
  --helm-kube-version 1.35.8`.

Results:
- `cluster/infra/falco` pulls the chart from a chart repository, renders it, and every `/host` mount
  comes out read-only.
- A KSOPS kustomization shaped like `cluster/infra/cloudflared`, with a sops/age-encrypted test Secret,
  decrypts.
- The same falco build with the ksops image's kustomize v5.3.0 reproduces the production error.

**Re-apply:** `kubectl diff -k cluster/bootstrap/argocd` should show only the `argocd-repo-server`
Deployment: the `--with-kustomize` argument and the `/usr/local/bin/kustomize` subPath mount removed.
Then `kubectl apply -k cluster/bootstrap/argocd --server-side --force-conflicts`. The repo-server rolls,
and the falco Application renders on its next refresh.

**Open item:** `make validate` renders with the kustomize v5.7.1 image (and, with an age key, the ksops
image's v5.3.0). The helmCharts path is unaffected, because the Helm image renders the chart and
kustomize only applies the patch; the output was checked to be identical to a v5.8.1 `--enable-helm`
build. Bumping `KUSTOMIZE_IMAGE` to v5.8.1 needs its registry.k8s.io digest, which could not be
resolved from that sandbox.

### Correction 2026-10-01: Debian's `perf_event_paranoid=3` and the least-privileged probe

On the node (Debian 13, kernel 6.12.107+deb13), Falco crash-looped right after
`Opening 'syscall' source with modern BPF probe`:
`libbpf: tracepoint 'syscalls/sys_enter_connect' perf_event_open() failed: Permission denied`.

**Cause.**
- The modern probe attaches its TOCTOU-mitigation programs (`connect_e`, `creat_e`, `open_e`, ...)
  to classic syscall tracepoints. libbpf does that through `perf_event_open()`
  (`userspace/libpman/src/programs.c`, `attach_*_toctou_mitigation_progs`). They are attached
  whenever those syscalls are of interest, and Falco 0.45 has no setting to turn them off.
- Debian ships `kernel.perf_event_paranoid=3`, a Debian-only level. Its kernel patch refuses
  `perf_event_open()` to any caller without CAP_SYS_ADMIN when paranoid > 2, and returns EACCES.
  CAP_PERFMON, which upstream accepts for tracepoints, does not count. Nothing in this repository set
  the value, so the Debian default applied.
- What it is not:
  - Not seccomp. A seccomp denial is EPERM, and kubelet `seccompDefault` is not enabled, so a
    container without a profile runs unconfined.
  - Not AppArmor. The profile is `Unconfined`.
  - Not yama or `unprivileged_bpf_disabled`. Neither applies to a process with CAP_BPF and
    CAP_PERFMON.

**Options considered:**
- CAP_SYS_ADMIN for Falco (rejected). It would work, but it is the broadest capability there is
  (mounts, namespaces, most of the kernel's admin interfaces), and it would mean relaxing
  `restricted-falco` (ADR 0012).
- Privileged Falco (rejected). Worse than the above.
- seccomp `Unconfined` or a Localhost profile (rejected). Not the cause, so it would change nothing.
- (chosen) `kernel.perf_event_paranoid=2` through the existing sysctl role
  (`ansible/roles/sysctl/defaults/main.yml`). 2 is the upstream kernel default: unprivileged
  processes may only measure their own user-space activity, and tracepoints and kernel events still
  need CAP_PERFMON. It is a host-wide setting, but it widens nothing beyond what every non-Debian
  kernel allows, and it keeps the sensor at its four capabilities. Containers in the restricted
  namespaces additionally run under the RuntimeDefault seccomp profile.

**`disabled BPF iterators (not running in the root PID namespace ...)`** is informational. Without BPF
iterators, libscap scans `/host/proc` (read-only) for the processes that already exist at start-up.
`hostPID` is not needed, and Kyverno's `restricted-falco` does not relax Host Namespaces for it.

**Apply:**
```sh
cd ansible && ansible-playbook playbooks/hardening.yml --tags sysctl   # sets it live and in /etc/sysctl.d
```
Then restart the Falco pod (or wait for the next crash-loop back-off).
