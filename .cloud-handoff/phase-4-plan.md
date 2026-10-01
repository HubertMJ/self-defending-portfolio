# Phase 4 plan: runtime security (branch `phase-4-runtime`) — rev 2 (after critic REVISE)

Date: 2026-10-01 · Mode: plan only · Scope fixed by user; user decisions in §10.
DoD: a manual shell (`kubectl exec -it`) in a test pod produces a Falco alert and Falco Talon kills the pod,
proven by `tests/runtime/run.sh`.

Hard rules carried over (handoff): no AI attribution in commits/PRs/code (`git log --format=%B | grep -ci claude` = 0);
author Hubert Jabłoński; everything via Argo CD from `main` (exceptions pre-approved in §10: one-off bootstrap re-apply,
DoD test pods in `sandbox`, `kubectl exec` into them, `kubectl patch --dry-run=server`); every significant decision = ADR;
kubectl = `kubectl --kubeconfig /home/hubertmj/remoteControl/sdp-phase4/kubeconfig`.
Checks per commit: `DOCKER="sudo -n docker" make lint`, `make validate` (extended, see §4.2); add `tests/runtime/*.sh` to
the shellcheck list in `scripts/lint.sh`.

Legend: **[verified]** checked against chart source/cluster/image; **[assumed]** to be confirmed by the executor at the
named step.

---

## 1. Facts gathered (2026-10-01)

**Cluster now:** node `k3s01` allocatable 4 CPU / 7.70 GiB; used 205m / 4015 MiB (50 %); requests 620m / 918 Mi;
memory limits 3690 Mi. metrics-server present; `hubble` CLI not installed on docker01. Kernel 6.12.107 (BTF).
Argo CD pods (bootstrap-installed) have **no requests/limits**; kube-system Cilium pods neither.

**Versions from official indexes, digests via `docker buildx imagetools inspect`** [verified]:

| Component | Chart | App | Image (pin as `tag: "<v>@sha256:…"`) |
|---|---|---|---|
| Falco | `falco` 9.2.0 | 0.45.0 | `docker.io/falcosecurity/falco:0.45.0@sha256:788f1129c542171813083d4afc61b16730a47dde8c23d9c39370acef996349b6` |
| falcoctl (disabled) | – | 0.14.2 | `docker.io/falcosecurity/falcoctl:0.14.2@sha256:90ba9627886e8f26b746fa52465d755b28ee49b76eb1d047a0fefd8cadb21907` |
| Falcosidekick | `falcosidekick` 0.14.0 | 2.32.0 | `docker.io/falcosecurity/falcosidekick:2.32.0@sha256:1976da72151850aae4436f33a5ed94bdef469f42a9b61c182b4feeb5441fb081` |
| Falco Talon | `falco-talon` 0.5.0 (3 days old; fallback 0.4.2) | 0.3.0 | `docker.io/falcosecurity/falco-talon:0.3.0@sha256:333224a111a0722ff3f418ffe6bc5d8a3be0941f37c67520bc845e62f1234ad3` (override chart's `falco.docker.scarf.sh`) |
| Trivy Operator | `trivy-operator` 0.36.0 | 0.34.0 | `mirror.gcr.io/aquasec/trivy-operator:0.34.0@sha256:0e4f11e9632f34097f259f3a59d34bab4eea8cee9aef510d15cdfc7481d5e49c` |
| Trivy (server + scan jobs) | – | 0.74.0 | `mirror.gcr.io/aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969` |
| Policy Reporter | `policy-reporter` 3.10.0 | 3.10.0 | `ghcr.io/kyverno/policy-reporter:3.10.0@sha256:a77e93fe511772e105aae30274d205ed1377f231c6d1ec272604221dc04a3c2c` |
| Policy Reporter UI | same chart | 2.8.1 | `ghcr.io/kyverno/policy-reporter-ui:2.8.1@sha256:748d8c18851ba76ca8129a14b28f43bf9bee04ac9fc80926abd28f6fcba99a06` |
| PR trivy plugin | same chart | 0.5.1 | `ghcr.io/kyverno/policy-reporter/trivy-plugin:0.5.1` — digest **[assumed]**, resolve at commit 3 |
| kube-bench | own CronJob | v0.16.0 | `docker.io/aquasec/kube-bench:v0.16.0@sha256:75506f222d1eb6ce2a751a5533bdc0a3b54c898e2e49e7751d0ee22cfb862679` |
| kyverno CLI (validate only) | – | v1.19.1 | `ghcr.io/kyverno/kyverno-cli:v1.19.1` — digest resolve at commit 2 |

Executor re-checks digests at commit time and confirms each chart concatenates `repo:tag` (`helm template … | grep image:`).

Other verified facts:
- Falco 0.45.0 image bundles `/usr/share/falco/plugins/libcontainer.so` and `/etc/falco/falco_rules.yaml` (contains
  `Terminal shell in container`) -> falcoctl can be disabled; Falco needs no internet.
- Falco chart: `driver.modernEbpf.leastPrivileged` = caps {BPF, PERFMON, SYS_RESOURCE, SYS_PTRACE} instead of privileged.
- Talon actionners: `kubernetes:{terminate,label,annotation,networkpolicy,delete,exec,script,log,download,tcpdump,sysdig,
  cordon,drain}`, `cilium:networkpolicy`, `calico:networkpolicy`, `aws:lambda`, `gcp:function`. Both NP actionners are
  egress-only (cilium one denies the event's remote IP — meaningless for a shell event).
- Talon chart: `config.deduplication.leaderElection` and `config.watchRules` are rendered with
  `default true …`, so `false` renders as **true**; leader election is always on. Talon takes Lease `falco-talon` in the
  namespace from env `NAMESPACE` (default `falco`), renews every 2 s, and sets its publisher only in `OnNewLeader` -> without
  working lease RBAC it never processes events. Chart always renders a ClusterRole + ClusterRoleBinding (empty rules when
  every `rbac.*` list is `[]`).
- Talon `k8sevents` notifier calls `Namespaces().Get(<pod ns>)`.
- kube-bench v0.16.0 ships `k3s-cis-1.9` (39 master, 14 node, 1 controlplane checks); several audits shell out to
  `journalctl -u k3s` to read flags.
- Trivy Operator: node-collector (infra assessment / compliance) needs hostPath + root -> off; aquasec/trivy image runs as
  root by default; built-in trivy server defaults: 200m/512Mi + 5Gi PVC (local-path).
- cert-manager `startupapicheck` hook Job renders `resources: {}`.
- Root app OutOfSync: live `kyverno` Application carries `pre-delete-finalizer.argocd.argoproj.io` and
  `pre-delete-finalizer.argocd.argoproj.io/cleanup` (Argo 3.x adds them because the chart has a pre-delete hook); git
  only has `resources-finalizer`.

## 2. Argo CD drift fixes (commit 1)

**a) `kyverno` app, 11 `policies.kyverno.io` CRDs** [verified cause]: chart 3.9.1 renders exactly those 11 CRDs with
`metadata.labels: {}` / `annotations: {}`; the API server stores no map, Argo's client-side diff never matches.
Fix: `argocd.argoproj.io/compare-options: ServerSideDiff=true` on `cluster/apps/kyverno.yaml`. Fallback:
`ignoreDifferences` (`apiextensions.k8s.io/CustomResourceDefinition`, the 11 names, `jqPathExpressions:
[.metadata.labels, .metadata.annotations]`).

**b) `root` app** [verified cause]: runtime-added pre-delete finalizers on the `kyverno` Application. Fix in
`cluster/bootstrap/argocd/root-application.yaml`: `ignoreDifferences` for `argoproj.io/Application`
`jqPathExpressions: [.metadata.finalizers]` (alternative: ServerSideDiff on root, **[assumed]** to also normalise it — prefer
the explicit ignore). Root is bootstrap-owned, so apply once by hand (pre-approved):
`kubectl apply -f cluster/bootstrap/argocd/root-application.yaml`. Same commit adds `resource.exclusions` for
`aquasecurity.github.io` report kinds to `cluster/bootstrap/argocd/argocd-cm.yaml` (Argo must not track thousands of
Trivy reports) — that file is applied via the bootstrap kustomization: re-apply with
`kubectl apply -k cluster/bootstrap/argocd` (pre-approved one-off; confirm with user the -k form is covered).

AC: `kyverno` and `root` Synced; ADR 0005 amendment (ServerSideDiff for SSA co-owned charts; finalizer ignore; argocd-cm
exclusion; bootstrap re-apply is the documented exception).

## 3. Resource budget (single 8 GB node)

| Component | Replicas | Requests cpu/mem | Limits cpu/mem |
|---|---|---|---|
| Falco (DaemonSet, modern eBPF, `bufSizePreset: 4`) | 1 | 100m / 256Mi | 1000m / 768Mi |
| Falcosidekick (no UI, no Redis) | 1 | 10m / 32Mi | 200m / 64Mi |
| Falco Talon (leader election on, 1 replica) | 1 | 10m / 32Mi | 200m / 128Mi |
| Trivy Operator | 1 | 50m / 128Mi | 500m / 384Mi |
| Trivy server (built-in, 5Gi local-path PVC) | 1 | 200m / 512Mi | 1000m / 1Gi |
| Trivy scan job (client, `scanJobsConcurrentLimit: 1`) | transient | 50m / 64Mi | 500m / 512Mi |
| Policy Reporter core | 1 | 10m / 48Mi | 200m / 128Mi |
| Policy Reporter UI | 1 | 10m / 32Mi | 100m / 96Mi |
| Policy Reporter trivy plugin | 1 | 10m / 64Mi | 200m / 256Mi **[assumed sizing]** |
| kube-bench (CronJob, daily) | transient | 50m / 64Mi | 500m / 256Mi |

Steady state adds ~410m / ~1.1 GiB requests (node -> ~1.0 CPU / ~2.0 GiB) and ~2.8 GiB memory limits (node ~6.4 GiB;
+0.75 GiB transient ≈ 7.2 GiB < 7.7 GiB, i.e. still not overcommitted). Expected real usage +1.0–1.4 GiB -> ~5.3 GiB.
5Gi PVC on the 60 GB root disk. **Gate after every commit:** `kubectl top nodes` < 80 % (6.2 GiB); trim order: Trivy server
-> Standalone, PR UI/plugin off, Falco `bufSizePreset: 3`. Re-check Falco's real usage after commit 6 and tighten its
requests/limits to observed peak ×1.5. All new components have CPU limits (none is in the admission path).

## 4. Design

### 4.1 Namespaces, PSA, Argo layout
| Namespace | PSA enforce / audit | Content | Argo app |
|---|---|---|---|
| `policy-reporter` | restricted / restricted | core, UI, trivy plugin | `policy-reporter` |
| `trivy-system` | restricted / restricted | operator, trivy server, scan jobs | `trivy-operator` |
| `kube-bench` | **privileged** / restricted (no warn) | CronJob only | `kube-bench` |
| `falco` | **privileged** / restricted (no warn) | Falco DaemonSet only | `falco` |
| `falco-response` | restricted / restricted | Falcosidekick + Talon | `falco-response` |
| `sandbox` | restricted / restricted | DoD victim pods; phase 5 scenarios later | `sandbox` |

- Helm apps are **multi-source Applications** (chart + `cluster/infra/<name>/` for Namespace with PSS labels, default-deny
  NP, CNPs, RBAC); `CreateNamespace=false`. `ServerSideApply=true` for trivy-operator and policy-reporter. Sync-wave
  annotations are set for readability only: the root app has no Application health customisation, so **waves between
  child apps are cosmetic — do not rely on ordering**; every app must converge on its own (retry + selfHeal). Within an app,
  CNPs carry wave `-1` (that ordering is real).
- Privilege confined to two namespaces with one workload each; nothing that talks to the API server runs in `falco`.
- `sandbox` is created now (already in both image policies). Victim = our signed web image (busybox `sh`, `wget`,
  `nslookup`).

### 4.2 Kyverno policies (`cluster/infra/kyverno-policies/`)
- `pod-security-restricted.yaml` (ClusterPolicy, `failurePolicy: Ignore`, `background: true`):
  - rule `restricted`: `podSecurity {level: restricted, version: latest}`, match Pod, exclude namespaces
    `kube-system, falco, kube-bench`.
  - rule `restricted-falco` (match ns `falco`) — **verified accepted set** (scratchpad `crit/pss2.yaml`). `images:` is only
    valid on container-level controls; on pod-level controls (HostPath Volumes, Volume Types, Host Namespaces, AppArmor)
    it makes Kyverno reject the whole policy:
    - Capabilities — `images: [docker.io/falcosecurity/falco:*]`, `restrictedField:
      spec.containers[*].securityContext.capabilities.add`, `values: [BPF, PERFMON, SYS_RESOURCE, SYS_PTRACE]`
    - Capabilities — images only
    - HostPath Volumes — no images · Volume Types — no images · AppArmor — no images
    - Running as Non-root, Seccomp, Privilege Escalation — images only
  - rule `restricted-kube-bench` (match ns `kube-bench`): Host Namespaces, HostPath Volumes, Volume Types, Running as
    Non-root — pod level, no images (namespace match is the scope).
  - No PolicyException (`kyverno.io/v2` deprecated in 1.19; exclusions next to the rule are narrower and visible).
- `require-pod-resources.yaml`: every container/initContainer has `requests.cpu`, `requests.memory`, `limits.memory`;
  exclude `kube-system` and `argocd` (debt, ADR 0012). `failurePolicy: Ignore`.
- Both start **Audit**; validate rules, so no `mutateDigest` involvement (stays only on `verify-signature`).
- `restrict-image-registries` / `verify-portfolio-images` scope unchanged (`hello`, `sandbox`). New namespaces are covered by
  `disallow-latest-tag` (charts render tag@digest).
- **Offline policy check in `make validate`** (commit 2): `helm template` every chart Application (with its values, hooks
  included — `--no-hooks` NOT set) into the render dir, then
  `kyverno apply cluster/infra/kyverno-policies/ --resource <rendered>` in `ghcr.io/kyverno/kyverno-cli:v1.19.1@<digest>`.
  Policies must load (catches invalid `images:` usage) and Enforce-level rules must report 0 fail. Implement as
  `scripts/render-charts.sh` (reads `cluster/apps/*.yaml` chart/version/valuesObject via yq in `sdp-tooling`) — scope
  **[assumed]** feasible for multi-source apps; if not, a small explicit list of charts+values files.
- cert-manager: set `startupapicheck.resources` (10m/32Mi, limit 64Mi) in `cluster/apps/cert-manager.yaml` (commit 2) so
  its hook passes the resources policy before Enforce.
- Rejected: upstream `kyverno-policies` chart (noisy, 17 policies); CEL `ValidatingPolicy` (inconsistent with phase 3
  ClusterPolicies; migration = later ADR).

### 4.3 Network policies (K8s `default-deny` NP per namespace + CiliumNetworkPolicy per workload)
Every kube-dns egress rule uses the L7 `rules.dns: [{matchPattern: "*"}]` form from `cloudflared` (required for toFQDNs).

| Workload | Ingress | Egress |
|---|---|---|
| Falco | host -> 8765 (probes) | kube-dns ; Falcosidekick 2801 |
| Falcosidekick | Falco pods (ns `falco`) -> 2801 ; host | kube-dns ; Talon 2803 |
| Talon | Sidekick -> 2803 ; host -> 2803 | `toEntities: [kube-apiserver]` 6443 |
| Trivy operator | host | kube-apiserver 6443 ; kube-dns ; trivy server 4954 |
| Trivy server | operator + scan jobs -> 4954 ; host | kube-dns ; toFQDNs `mirror.gcr.io`, `ghcr.io`, `pkg-containers.githubusercontent.com` 443 |
| Trivy scan jobs | – | kube-dns ; server 4954 ; toFQDNs `ghcr.io`, `pkg-containers.githubusercontent.com`, `index.docker.io`, `registry-1.docker.io`, `auth.docker.io`, `production.cloudflare.docker.com`, `quay.io`, `*.quay.io`, `registry.k8s.io`, `*.pkg.dev`, `mirror.gcr.io`, `*.storage.googleapis.com` 443 |
| Policy Reporter core | UI, trivy plugin -> 8080 ; host | kube-apiserver ; kube-dns ; trivy plugin |
| PR trivy plugin | core ; host | kube-dns ; kube-apiserver ; external CVE source **[assumed — confirm from chart/docs at commit 3; if it needs the internet, toFQDNs list]** |
| Policy Reporter UI | none (port-forward enters pod netns) ; host probes | core 8080 ; kube-dns |
| kube-bench | none | none |
| `sandbox` victim | – | kube-dns only (needed to prove isolation) |
| Quarantine CCNP | `ingressDeny: fromEntities [all]` | `egressDeny: toEntities [all]` for `sdp.hubertjablon.ski/quarantine: "true"` |

Trivy: `trivy.offlineScan: true` (no Java DB / no online lookups from scan jobs; DB only via server).
Drop debugging without the hubble CLI: `kubectl -n kube-system exec ds/cilium -c cilium-agent -- hubble observe
--verdict DROPPED --namespace <ns> --last 50` (cilium-agent ships the hubble CLI **[assumed]**; exec into cilium is a
read operation but needs user OK); fallback `cilium-dbg monitor --type drop` in the same pod.

### 4.4 Falco -> Falcosidekick -> Talon
- **Falco values:** `driver.kind: modern_ebpf`, `driver.modernEbpf.leastPrivileged: true`; AppArmor via
  `podSecurityContext.appArmorProfile: {type: Unconfined}` (not `containerSecurityContext`, which would replace the
  chart's capability set); falcoctl install+follow off; `collectors.kubernetes.enabled: false`;
  `collectors.containerEngine.engines`: docker/podman/containerd/lxc/libvirt_lxc/bpm **off**, `cri` on with only
  `/run/k3s/containerd/containerd.sock`; mount host `/proc` read-only (no rw `/host/proc`) — verify in `helm template`;
  `json_output: true`, `http_output.url: http://falcosidekick.falco-response.svc:2801/`; `append_output` adds
  `k8s.ns.name`, `k8s.pod.name`; `customRules`: `SDP network tool in sandbox` (spawned_process, container,
  `k8s.ns.name=sandbox`, `proc.name in (wget, nc, curl)`, WARNING). Verify rendered `falco.yaml` loads
  `/usr/share/falco/plugins/libcontainer.so`.
- **Falcosidekick:** `replicaCount: 1`, `webui.enabled: false`, `config.talon.address:
  http://falco-talon.falco-response.svc:2803`, `minimumpriority: notice`, restricted securityContext.
- **Talon:** `replicaCount: 1`, docker.io image + digest, `pullPolicy: IfNotPresent`, restricted securityContext,
  `extraEnv` (a list — replaces the chart default, so restate both):
  `[{name: LOG_LEVEL, value: info}, {name: NAMESPACE, value: falco-response}]`; `defaultNotifiers: [k8sevents]`;
  all `rbac.*` verb lists `[]` (chart still renders an **empty** ClusterRole + ClusterRoleBinding — harmless, noted in ADR).
  `rulesOverride`:
  1. **DoD:** `match: {rules: ["Terminal shell in container"], output_fields: ["k8s.ns.name=sandbox"]}` ->
     `kubernetes:terminate` only (`grace_period_seconds: 0`, `ignore_standalone_pods: false`). No label first: a label
     patch is a Pod UPDATE through `verify-portfolio-images` (Fail, 30 s timeout) and would sit in front of the kill.
  2. **Isolate:** `match: {rules: ["SDP network tool in sandbox"]}` -> `kubernetes:label`
     `sdp.hubertjablon.ski/quarantine: "true"` (no kill).
- **Label-on-missing-key probe (before commit 7, pre-approved):** Talon's label actionner uses a JSON patch; whether
  `replace` on a missing key works is **[assumed]**. Probe: `kubectl -n sandbox patch pod <victim> --dry-run=server
  --type=json -p '[{"op":"replace","path":"/metadata/labels/sdp.hubertjablon.ski~1quarantine","value":"true"}]'` (and the
  `add` form). If `replace` fails, the victim manifest pre-sets `sdp.hubertjablon.ski/quarantine: "false"`. Also confirms
  Kyverno admits the UPDATE.
- **Isolation design:** label + standing CCNP (ingress + egress, only `pods patch` needed, lifted by removing the label)
  instead of Talon's egress-only NP actionners.
- **Talon RBAC (git):**
  - `Role` in `sandbox`: `pods: get, list, patch, delete`; `events: create, patch`; RoleBinding -> SA
    `falco-response/falco-talon`.
  - `Role` in `falco-response`: `coordination.k8s.io/leases: get, create, update` (leader election; Lease `falco-talon`);
    RoleBinding.
  - `ClusterRole` `falco-talon-namespace-read`: `namespaces: get`, `resourceNames: [sandbox]` (k8sevents notifier); binding.
  - Nothing else cluster-scoped; no secrets, exec, nodes, networkpolicies. Add `replicasets get` only if Talon logs a 403.
  - ADR 0013 records: leader election cannot be disabled in this chart version, 2 s lease renew = constant small API load.

### 4.5 Posture scanners
- **Trivy Operator:** `builtInTrivyServer: true` (5Gi PVC, 200m/512Mi), `scanJobsConcurrentLimit: 1`, `scanJobTimeout: 10m`,
  `vulnerabilityScannerScanOnlyCurrentRevisions: true`, `trivy.offlineScan: true`, `infraAssessmentScannerEnabled: false`,
  `clusterComplianceEnabled: false`, `sbomGenerationEnabled: false`, secrets/config/RBAC audit on. Restricted
  everywhere, set explicitly: `podSecurityContext`/`securityContext` (operator), `trivy.server.podSecurityContext`/
  `securityContext`, `trivyOperator.scanJobPodTemplatePodSecurityContext` + `scanJobPodTemplateContainerSecurityContext`:
  `runAsNonRoot: true`, `runAsUser: 65534`, `seccompProfile: RuntimeDefault`, `allowPrivilegeEscalation: false`,
  `capabilities.drop: [ALL]` (aquasec/trivy defaults to root). Exact value keys **[assumed]** per chart 0.36.0 —
  confirm with `helm template` + `kyverno apply`.
- **kube-bench:** `cluster/infra/kube-bench/` CronJob `17 3 * * *`, `concurrencyPolicy: Forbid`, history 3/3,
  `ttlSecondsAfterFinished: 86400`, `hostPID: true`, read-only hostPaths (`/var/lib/rancher`, `/etc/rancher`,
  `/var/lib/kubelet`, `/etc/systemd`), `automountServiceAccountToken: false`, resources set. A **ConfigMap with a custom
  k3s config** (copy of `cfg/k3s-cis-1.9` from the pinned image) where journalctl-based audits read flags from
  `/etc/rancher/k3s/config.yaml` instead; mounted over `/opt/kube-bench/cfg/k3s-cis-1.9`. Command
  `kube-bench run --benchmark k3s-cis-1.9 --json`. Results = Job logs (phase 6 reads them). Expected: 39 master / 14 node /
  1 controlplane checks; some FAIL/WARN are accepted findings, not gates.
- **Policy Reporter:** UI ClusterIP only (`kubectl -n policy-reporter port-forward svc/policy-reporter-ui 8082:8080`),
  `plugin.trivy.enabled: true` (user decision), `plugin.kyverno.enabled: false`, restricted securityContext. How Trivy
  results appear in PR (plugin vs. report source) **[assumed]** — confirm at commit 3/4.

## 5. Ordered commits (each: lint + validate green, push, ff-merge to main, wait Synced/Healthy, memory gate)

1. **`argocd: server-side diff for kyverno, ignore runtime finalizers on child apps, exclude Trivy reports`** — §2.
   One-off bootstrap re-apply. AC: `kyverno`, `root` Synced. ADR 0005 amendment.
2. **`kyverno: Pod Security restricted and pod resources policies in Audit`** — 2 ClusterPolicies, cert-manager
   `startupapicheck.resources`, `scripts/render-charts.sh` + `kyverno apply` in `make validate`; ADR 0012.
   AC: policies Ready (not rejected); PolicyReports appear; `tests/admission/run.sh` all PASS.
3. **`policy-reporter: reports UI and Trivy plugin, cluster-internal only`** — app + infra. AC: pods Ready (restricted),
   UI via port-forward shows Kyverno results.
4. **`trivy-operator: vulnerability and config audit reports`** — app + infra; ADR 0014. AC: VulnerabilityReports within
   ~30 min, no drops (§4.3), Argo not tracking reports, memory gate.
5. **`kube-bench: daily CIS benchmark CronJob with k3s config`** — infra + app. AC: first run (or user-approved
   `kubectl create job --from=cronjob/kube-bench`) prints JSON; PSS report for kube-bench shows only excluded controls.
6. **`falco: modern eBPF detection to Falcosidekick`** — `falco` + `falco-response` apps (sidekick only), CNPs.
   AC: log `Opening 'syscall' source with modern BPF probe`; an exec into a sandbox test pod shows up in sidekick logs;
   PSS report for Falco pod 0 fail; Falco resources re-checked.
   — *Before commit 7:* label probe (§4.4).
7. **`talon: kill and quarantine in sandbox`** — Talon in `falco-response`, `sandbox` app (ns, NP, victim CNP, Talon Role),
   lease Role, namespace ClusterRole, quarantine CCNP; ADR 0013. AC: Talon holds Lease `falco-response/falco-talon`
   (log `new leader`), rules loaded, `kubectl auth can-i delete pods -n hello --as=system:serviceaccount:falco-response:falco-talon` = no.
8. **`tests: runtime DoD (shell -> Falco alert -> Talon kill)`** — `tests/runtime/run.sh`, `victim-pod.yaml`,
   `make runtime-test`, shellcheck list, docs/bootstrap.md "Phase 4". AC: passes twice in a row.
9. **`kyverno: enforce Pod Security restricted and pod resources`** — flip to Enforce. Gate: `kubectl get polr,cpolr -A`
   0 fail for both policies **and** `make validate` (`kyverno apply` over all rendered charts incl. hooks) 0 fail. New
   admission manifests (privileged pod, pod without limits) carry explicit `metadata.namespace: default` (no PSA labels, so
   Kyverno is what rejects) and are added to `MANIFESTS` in `tests/admission/run.sh`. AC: admission + runtime tests PASS,
   all apps Healthy.

**Rollback:** `git revert` + push. Removing an Application file prunes it from root and its `resources-finalizer`
**deletes everything it rendered, CRDs included** (trivy-operator / policy-reporter CRDs and their reports go with it — fine,
reports are regenerable). Kyverno policies fail open (`Ignore`); flipping back to Audit is a one-line revert. Talon
misbehaving: revert commit 7 — its RBAC can only touch pods in `sandbox` anyway. Commit 1's bootstrap re-apply is reverted
by re-applying the previous file.

## 6. Scripted DoD test `tests/runtime/run.sh` (style of `tests/admission/run.sh`)
- `set -euo pipefail`, `KUBECTL` overridable, `step/pass/fail`, `trap` cleanup.
- Preflight: Falco DS, sidekick, Talon rolled out; Talon is leader (Lease holder set); `sandbox` + quarantine CCNP exist;
  `IMAGE` = signed digest read from `cluster/infra/hello/kustomization.yaml`.
- **Case 1 (DoD):** create `rt-shell-<rand>` (restricted, resources, `sleep 300`), wait Ready, record UID + T0, run
  `script -qec "kubectl exec -it -n sandbox <pod> -- sh -c 'id; sleep 60'" /dev/null` in background (pty ->
  `proc.tty != 0`). Assert within 30 s: Falco log since T0 has `Terminal shell in container` + pod name; sidekick log shows
  POST to Talon; Talon Event(s) on the pod in `sandbox` and Talon log line for `kubernetes:terminate`; pod UID gone
  (`kubectl wait --for=delete`); print time-to-kill.
- **Case 2 (isolate):** `rt-iso-<rand>`; poll until `nslookup kubernetes.default.svc.cluster.local.` succeeds; `kubectl exec`
  (no tty) `wget -T 2 …`; **poll** (≤20 s) for label `sdp.hubertjablon.ski/quarantine=true`, pod still Running; **poll**
  (≤20 s) until the same FQDN lookup fails.
- **Case 3 (least privilege):** `kubectl auth can-i --as=system:serviceaccount:falco-response:falco-talon`: `delete pods -n
  sandbox` yes; `delete pods -n hello`, `delete pods -n kube-system`, `get secrets -n sandbox`, `create pods/exec -n sandbox`,
  `get namespaces/hello` no; `get namespaces/sandbox` yes.
- Non-zero exit on any FAIL; output = phase evidence.

## 7. ADRs
- **0012** Pod Security and resource policy: PSA + Kyverno `podSecurity`, per-control exclusions (container-level scoped by
  image, pod-level by namespace — Kyverno limitation), Audit -> Enforce gate incl. offline `kyverno apply`, `Ignore`,
  `argocd` exclusion as debt.
- **0013** Runtime detection and response: Falco modern eBPF least-privileged, rules pinned in image (no falcoctl), Sidekick
  -> Talon, DoD rule terminate-only, isolate = label + Cilium quarantine, RBAC (sandbox Role, lease Role, namespace get on
  `sandbox` only, empty chart ClusterRole), forced leader election + 2 s renew load.
- **0014** Posture scanning: Trivy Operator client/server, offline scan, no node-collector, explicit non-root contexts;
  kube-bench CronJob + custom k3s config; Policy Reporter internal UI + trivy plugin; FQDN egress allow-lists.
- **0005 amendment:** ServerSideDiff, finalizer ignore on root, Trivy report exclusion, bootstrap re-apply exception.
- Update `docs/adr/README.md`.

## 8. Risks
| Risk | Mitigation |
|---|---|
| Talon 0.5.0 chart 3 days old | pin; fallback 0.4.2 (same app 0.3.0) |
| Talon never leads (lease RBAC/namespace wrong) -> no actions | preflight asserts Lease holder; `NAMESPACE` env set explicitly |
| `Terminal shell in container` does not fire | `script` pty; k8s output fields; fallback custom rule with `shell_procs` in `sandbox` |
| AppArmor/bpf blocked on Debian 13 | pod-level `appArmorProfile: Unconfined`; last resort `privileged: true` (ns already privileged; ADR) |
| Label patch rejected / slow via verify-portfolio-images | DoD path does not label; probe before commit 7; Case 2 catches it |
| Cilium deny may not cut established flows | test asserts new lookups fail; kill path covers DoD |
| Trivy FQDN list incomplete | drop inspection via cilium pod; extend list; fallback `world:443` for scan jobs only |
| Enforce blocks a hook/Job | offline `kyverno apply` over rendered charts incl. hooks + 0-fail report gate; `Ignore` |
| Memory pressure | per-commit gate (§3) |
| kube-bench profile older than 1.35 | documented limitation; posture info, not a gate |
| `render-charts.sh` complexity for multi-source apps | fallback to explicit chart+values list |

## 9. Remaining assumptions (confirm during execution)
- ServerSideDiff alone would not clear root's finalizer diff (hence explicit ignore).
- `kubectl apply -k cluster/bootstrap/argocd` counts as the pre-approved bootstrap re-apply (ask if unsure).
- Trivy chart 0.36.0 value keys for server/scan-job security contexts; PR trivy plugin egress and integration mode.
- Talon label actionner patch semantics (probe).
- hubble CLI inside the cilium-agent container.

## 10. User decisions (2026-10-01)
- Victim pod for the DoD test runs in namespace `sandbox`, created in this phase.
- kube-bench: results only in the Job logs (JSON); the posture page in phase 6 picks them up.
- Trivy -> Policy Reporter integration: now (trivy plugin in Policy Reporter).
- Argo CD: namespace `argocd` excluded from the resources policy, recorded as debt in the ADR.
- kube-bench: custom k3s config pointing journalctl-based audits at /etc/rancher/k3s/config.yaml (no own image).
- Talon: narrow ClusterRole get namespaces resourceNames [sandbox], recorded in ADR 0013; DoD asserts Events + logs + pod deletion.
- User pre-approved for the whole phase: one-off bootstrap re-apply of root Application, kubectl exec into test pods,
  test pods in sandbox, kubectl patch --dry-run=server.
- User approved: one-off `kubectl apply -k cluster/bootstrap/argocd` (after kubectl diff shows only root Application + argocd-cm change),
  and kubectl exec into cilium-agent for read-only hubble observe / cilium-dbg monitor.
- Commit 6 (from commit 2 review): Falco values must set `containerSecurityContext.capabilities.drop: [ALL]` alongside the
  four adds; leave `runAsUser` unset (same for kube-bench in commit 5).
