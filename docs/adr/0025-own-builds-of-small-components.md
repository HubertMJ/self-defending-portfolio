# ADR 0025: Falcosidekick, metrics-server, the Trivy Operator and kube-bench are built here

Date: 2026-10-02 · Status: accepted

## Context
After ADR 0023 and ADR 0024 the cluster's third-party CRITICAL+HIGH count is a handful of large
components (Argo CD, Cilium, CoreDNS - each its own decision, ADR 0026-0028) and four small ones.
Live, from the Trivy Operator's VulnerabilityReports on 2026-10-02:

| Image | Live C+H | Trivy 0.75.0, 2026-10-02 | Where the findings are |
|---|---:|---:|---|
| `falcosecurity/falcosidekick:2.35.0` | 3 + 9 | 3 + 12 | amqp091-go (3 C + 7 H), x/crypto, grpc (2), Alpine OpenSSL (libcrypto3, libssl3) |
| `rancher/mirrored-metrics-server:v0.9.0` (k3s-bundled) | 0 + 3 | 0 + 14 | Go 1.26.4 stdlib (9), x/crypto, x/text, grpc (3) |
| `aquasec/trivy-operator:0.34.0` | 0 + 2 | 0 + 4 | grpc (2), Alpine OpenSSL (libcrypto3, libssl3) |
| `aquasec/kube-bench:v0.16.0` | 0 + 1 | 0 + 13 | Go 1.26.5 stdlib (8), Alpine jq (2), Alpine OpenSSL (libcrypto3, libssl3, openssl) |

Every finding has a released fix; none of the four projects has released a version that takes them
(each is on its newest release). This is the situation ADR 0023 built Talon for and ADR 0024 KSOPS:
the same program, compiled by us with the fixed dependencies and a current Go, is the only honest way
to remove them (ignoring them is ruled out permanently, ADR 0023). These four are cheap to do: small
Go programs, upstream test suites that run offline, three of the four with no OS dependency at all.

kube-bench has a second problem, not a vulnerability: its k3s-cis-1.9 benchmark reads the flags of
each k3s component from the line k3s logs at start-up (`journalctl -m -u k3s | grep 'Running
kube-apiserver'`), upstream's Alpine image has no journalctl, and the stand-in this repository used
(ADR 0014: the same lines rebuilt from `/etc/rancher/k3s/config.yaml`) cannot see the flags k3s sets
itself. The 2026-10-02 run reported 27 FAIL / 35 PASS, and 23 of those FAILs were flags k3s does set
(`--anonymous-auth=false`, `--profiling=false`, `--authorization-mode=Node,RBAC`, the TLS and
service-account files, the cipher suites, `--read-only-port=0`, ...): the posture page showed a CIS
score of under half for a cluster that mostly passes.

metrics-server has one more problem: k3s deploys it from manifests compiled into its binary
(`manifests/metrics-server/` in the k3s source) and writes them to
`/var/lib/rancher/k3s/server/manifests/metrics-server/` on every start, so an edited image there is
overwritten, and k3s's own deploy controller owns the objects (`objectset.rio.cattle.io/*`).

## Decision
**1. Four images under `app/`, the app/talon / app/ksops pattern** - built, Trivy-gated (CRITICAL,
HIGH), SBOM'd and signed by `build-images.yml` like every image (ADR 0011, ADR 0016). Each Dockerfile
header carries the full reasoning; in short, for each one:
- source: the upstream release tag's commit, fetched by full hash and checked after checkout -
  falcosidekick `09883e3f55dade3c2ab2a471736ea5519aeac418` (2.35.0), metrics-server
  `2a7c4b2c7d46552ff47f4aeaa3a735c582587ecd` (v0.9.0), trivy-operator
  `7107830178ae50e96e9f09d98976e51e6152759f` (v0.34.0), kube-bench
  `5c6c22d51b926020e7414e1f1e051851d1a2feff` (v0.16.0). No Go source line is changed.
- dependencies: upstream's go.mod/go.sum with only the vulnerable modules raised, to the first fixed
  releases and the ones app/talon and app/ksops already use, then `go mod tidy`; minimal version
  selection moves what those require. Committed in `app/<name>/modules/`, `go mod verify` at build:
  - falcosidekick: amqp091-go v1.13.0, x/crypto v0.55.0, grpc v1.83.2;
  - metrics-server: x/crypto v0.55.0, grpc v1.83.2 (x/text v0.41.0 follows from x/crypto);
  - trivy-operator: grpc v1.83.2;
  - kube-bench: none - its findings are all in the Go standard library, so no `modules/`.
- toolchain: `golang:1.26.8`, the pin the other Go images use (upstream's metrics-server and
  kube-bench images were compiled with 1.26.4 and 1.26.5, whose standard library has the findings).
- tests: upstream's own target, in a stage the image depends on, with `--network=none` - falcosidekick
  `go vet` + `go test -race ./...`; metrics-server `go test --test.short -race ./pkg/... ./cmd/...`
  (`make test-unit`); trivy-operator `go test -short -timeout 60s ./...` with `CGO_ENABLED=0
  GOEXPERIMENT=jsonv2` (`mage test:unit`; envtest/integration suites skip themselves under -short);
  kube-bench `go test -vet all -short -race -timeout 30s ./...` (`make tests`). Nothing skipped by us.
- build: upstream's flags and version variables (falcosidekick `main.*`, metrics-server
  `k8s.io/client-go/pkg/version.*`, trivy-operator `main.*` plus `GOEXPERIMENT=jsonv2`, kube-bench
  `cmd.KubeBenchVersion`), CGO off, `-trimpath`, stripped, empty build id, the commit's date as build
  date - two builds are identical.
- runtime: distroless `static-debian13:nonroot` for the three static Go services, at upstream's paths
  (`/app/falcosidekick` with workdir `/app`, `/metrics-server`, `/usr/local/bin/trivy-operator`).
  kube-bench runs on Wolfi (`cgr.dev/chainguard/wolfi-base`, pinned by digest) instead of upstream's
  Alpine, because its checks need journalctl: Alpine has no systemd; Debian 13's systemd matches the
  node's version but `debian:13-slim` + systemd scans about 50 HIGH with no fix; Wolfi's systemd 261,
  procps, findutils and kubectl scan 0, and journalctl 261 reads the node's systemd 257 journal files.
  The checks are `/bin/sh` pipelines run by busybox, as in upstream's image; procps (`ps -C`),
  findutils (`xargs --no-run-if-empty`) and kubectl are kept; jq, openssl, bash and gcompat are dropped
  (no k3s-cis-1.9 audit uses them); apk-tools is removed at the end; package versions are pinned.
  kubectl stays on purpose: kube-bench asks for the Kubernetes version before every run, and without
  kubectl it falls back to executing the first file named `kubelet` that `find /` returns - which in
  the CronJob includes containerd's unpacked image layers under the mounted
  `/var/lib/rancher/k3s/agent`, as root.

**2. kube-bench reads the node's journal.** The CronJob runs upstream's `cfg/k3s-cis-1.9` as the image
ships it - the ConfigMap override and `k3s-config-args.sh` are deleted - and mounts `/var/log/journal`
read-only (`type: Directory`; journald is `Storage=persistent`, `ansible/roles/base`, so nothing is
in `/run/log/journal` after boot). Nothing else in the pod changes: hostPID only, every hostPath
read-only (`make validate` checks it), root without capabilities, no token, no network (ADR 0012,
amendment). The journal holds every unit's log, which the pod can now read; what leaves the pod is
kube-bench's JSON, i.e. the matched `Running ...` lines. The flag checks see the last k3s start that
is still in the journal; if journald has vacuumed it (500M cap), they FAIL with an empty actual
value, visibly rather than silently passing.

What is left after the switch, from replaying k3s v1.35.9+k3s1's start-up lines with this node's
configuration (Ansible's config.yaml, rendered) into a journal written by Debian 13's systemd 257 and
reading it with this image, and taking the file checks from the 2026-10-02 run on the node:
27 FAIL / 35 PASS become **4 FAIL / 58 PASS** (12 WARN and 14 INFO are manual checks, unchanged):
- 1.1.20 (server/tls/*.crt are 0644): genuine. Fixed in `ansible/roles/k3s/tasks/main.yml`, which now
  sets the top-level certificates in `/var/lib/rancher/k3s/server/tls` to 0600 after k3s is up (the
  check's own remediation); only the k3s process reads them. k3s writes renewed certificates 0644
  again; the next role run (or the next FAIL) catches that.
- 1.1.9 / 1.1.10 (files under `/var/lib/cni/networks`): the host-local IPAM state directory. With
  Cilium's own IPAM there is none, and the CronJob does not mount `/var/lib/cni`; kube-bench counts
  "no file found" as FAIL. Not a finding; nothing to fix (on the node, `ls /var/lib/cni/networks`
  confirms). Creating the directory or mounting a path that does not exist would only manufacture a
  PASS.
- 1.2.26 (`--etcd-cafile`): this k3s uses its SQLite datastore through kine on a unix socket
  (`--etcd-servers=unix://kine.sock`); there is no etcd and no etcd CA. Not fixable by a flag (an etcd
  CA on a plaintext unix socket would break the API server); only a move to embedded etcd
  (`cluster-init: true`) would make it applicable - a datastore migration and etcd's memory on an
  8 GB single node for one benchmark line. Not done; recorded here.
1.2.29 (cipher suites) and the `--profiling` checks (1.2.15, 1.3.2, 1.4.1) are among the 23 that pass:
k3s sets them itself, so no Ansible change is needed for them.

**3. metrics-server moves from k3s to Argo CD.** `k3s_disable_components` gains `metrics-server`
(`ansible/roles/k3s/defaults/main.yml`), and `cluster/apps/metrics-server.yaml` deploys
`cluster/infra/metrics-server/`: k3s v1.35.9+k3s1's own manifests object for object - same
ServiceAccount, ClusterRoles and bindings, auth-reader RoleBinding, Service, APIService
`v1beta1.metrics.k8s.io` and Deployment args (k3s's `%{PREFERRED_ADDRESS_TYPES}%` resolved to what it
substituted here) - with this image pinned by digest, a restricted security context (seccomp, all
capabilities dropped, pod-level runAsNonRoot) and limits added. Rejected alternatives:
- *keep k3s's copy and change its image*: not durable. k3s rewrites its bundled manifests on every
  start, and has no per-add-on image setting (`--system-default-registry` only changes the registry).
  A `.skip` file next to the manifest stops k3s applying it but leaves k3s's deploy controller as the
  owner of objects Argo CD would then also manage.
- *a namespace of its own* (restricted PSA, default-deny network policy, Kyverno signature check):
  more isolation, but it changes the Service the APIService points at, needs Cilium policies for the
  API server's aggregation calls and the kubelet scrapes that cannot be tested before rollout, and the
  auth-reader RoleBinding stays in kube-system anyway. Recorded as a possible follow-up.

The hand-over is ordered, because disabling an add-on makes k3s delete its objects - checked in the
source (`pkg/deploy/controller.go`, `delete`: an empty apply with the Addon as owner) and in a
throwaway k3s v1.35.9+k3s1 container: the Deployment, APIService and ClusterRoles were gone after the
restart; this repository's manifests applied afterwards survived a further k3s restart untouched.
Ansible first, then Argo CD (docs/bootstrap.md 8.10). The reverse order would have k3s delete the
objects Argo CD had just adopted (they keep k3s's labels), and Argo CD recreate them a little later.

**4. Admission.** Falcosidekick's namespace is already in `verify-portfolio-images`, so its signature
and SBOM attestation are required from the switch on. In a separate commit, applied once the switch
is live, the policies tighten further:
- `restrict-image-registries`: `falco-response` joins the main rule and the Falcosidekick exception
  rule (ADR 0023) is deleted - the namespace now runs only our images; `kube-bench` joins too.
- `verify-portfolio-images`: `kube-bench` (the root pod with the node's k3s keys mounted) and
  `trivy-system` (the operator reads every workload and RBAC object). Neither is on the repair path
  of a Kyverno outage (Argo CD, Kyverno, Cilium, CoreDNS), so failing closed there only pauses a
  benchmark run or a scan. `trivy-system` is not added to `restrict-image-registries`: the scan Jobs
  and the Trivy server run aquasec/trivy and the PolicyReport adapter its upstream image.
- `kube-system` stays out of both, as `argocd` does (ADR 0024): Cilium and CoreDNS run there, and a
  fail-closed check would make the CNI's restart depend on Kyverno. metrics-server's image is still
  signed, SBOM'd, Trivy-gated, pinned by digest and verifiable by hand (`scripts/verify-image.sh`).

**5. Pins.** falcosidekick and trivy-operator are pinned in chart values (`registry`/`repository`/
`tag: "main@sha256:..."`, the chart concatenates them); `scripts/bump-image-digest.sh` now rewrites
that form too (the `tag:` line of a mapping whose siblings are `registry: ghcr.io` and `repository:
hubertmj/self-defending-portfolio/<name>`). kube-bench and metrics-server use kustomize `images:`
entries. `scripts/check-image-digests.sh` already refuses a placeholder anywhere under `cluster/`.

**Verified locally** (2026-10-02), before anything deploys them - all four images scan **0**
CRITICAL/HIGH (`aquasec/trivy:0.75.0`), against upstream's 15, 14, 4 and 13 with the same DB:
- falcosidekick: run side by side with upstream's 2.35.0 under the pod's constraints (uid 1234,
  read-only root, no capabilities), configured with this cluster's two outputs (`talon`, `webhook`):
  `/ping` 200, a Falco event posted to `/` is forwarded to both, with the same body, by both images;
  a malformed event gets the same 400. `--version` reports 2.35.0, go1.26.8.
- metrics-server: in a throwaway k3s v1.35.9+k3s1 (`--disable=metrics-server`), `kubectl apply` of the
  rendered `cluster/infra/metrics-server` with this image: rollout complete, APIService Available,
  `kubectl top nodes` and `kubectl top pods -n kube-system` answer. `--version` prints v0.9.0.
- trivy-operator: upstream's unit suite (26 packages) passes against the raised dependencies; the
  binary is built with `GOEXPERIMENT=jsonv2` as upstream's (checked in the build). It is verified in
  the cluster after rollout (docs/bootstrap.md 8.10): VulnerabilityReports keep being written.
- kube-bench: the build behaves like upstream's: run side by side with identical arguments, mounts
  (the old config-override k3s-cis-1.9 over cfg/, which both can execute) and `--pid=host`, all 88
  results (master, controlplane, node) were identical, status, actual value and audit output alike.
  With the journal: a journal file written by `systemd-journal-remote` 257 (Debian 13, the node's
  version) from the captured start-up log of k3s v1.35.9+k3s1 run with this node's configuration,
  mounted read-only at `/var/log/journal`, read by this image under the CronJob's constraints (no
  network, read-only root, no capabilities, no-new-privileges): the 23 flag checks above turn from
  FAIL to PASS against the same run with the config override, and none turns the other way. (Two
  checks that also read k3s's files, 1.2.28 and 4.2.9, are not PASS in either replay, which had no
  k3s files; on the node they PASS.)

## Consequences
- The four images leave the third-party column of the posture page (`OwnImagePrefix`): live 3
  CRITICAL + 15 HIGH become 0 once the switch and a scan cycle have run. Falco-response becomes a
  namespace of only our images.
- Four more components whose release tracking this repository does by hand: on each upstream
  release, rebuild `modules/` from the new tag (each Dockerfile header says how) and drop every raise
  it has caught up with; when it has caught up with all of them, delete `app/<name>` and return to
  the upstream image. kube-bench's Wolfi package pins are bumped when the build's Trivy gate finds
  something in one of them.
- The phase 4 kube-bench decision (ADR 0014: a config override rather than an image of our own) is
  reversed: the image is our own, for its findings and for journalctl, and the override is gone
  (ADR 0014, amendment). The posture page's CIS numbers change from 35 PASS / 27 FAIL to about
  58 PASS / 4 FAIL after the switch, 3 after the Ansible change - a change in what is measured, not
  in the cluster; the ADR says so rather than the number alone.
- metrics-server's lifecycle is no longer tied to k3s: a k3s bump no longer moves it, and the
  manifests in `cluster/infra/metrics-server` must be compared with the new k3s release's
  `manifests/metrics-server/` on a k3s bump. A fresh cluster gets it from Argo CD after Ansible.
- Build cost in CI: four more matrix jobs on a push to their `app/` directory; the slowest locally
  (trivy-operator: module download, unit tests, build) took about 6 minutes, well under the runner
  limits.
- Staged like ADR 0023/0024: the images first, from `main`; then the switch commits with the real
  digests (metrics-server after the Ansible run); then the policy commit. The CIS file-mode change is
  a separate Ansible commit, applied with the k3s role run that disables metrics-server.

## Amendment 2026-10-10: the CIS benchmark - real paths, not applicable shown as such, the manual checks get real controls

**Context.** The posture page showed kube-bench at 59 PASS / 3 FAIL / 12 WARN / 14 INFO. Of the
three FAILs, 1.2.26 (`--etcd-cafile`) is the one this ADR already called "not a finding": there is
no etcd. 1.1.9 and 1.1.10 were called the same above ("no host-local IPAM directory"), and that was
wrong: they ask about the CNI files, and upstream's audit looks for them in
`/var/lib/cni/networks`, which Cilium's own IPAM never creates - the files exist elsewhere. The 14
INFO are upstream's own k3s skips ("Not Applicable.", e.g. no API server pod specification file),
which the page lumped into a bare "Info". The 12 WARN are manual or unscored checks. Owner
decisions, 2026-10-10: show what does not apply as not applicable, with the reason, honestly -
never a PASS, never hidden, the counts adding up; drive every WARN that has a real control to a
verified PASS; keep what has none as a visible, documented exception.

**1. Where the benchmark is changed: a patch applied at build time.** `app/kube-bench/k3s-cis-1.9.patch`,
applied by the Dockerfile with `git apply` to upstream's cfg/ at the pinned commit, before upstream's
tests run. The image stays the one versioned unit the CronJob runs; a bump whose upstream text
moved fails the build instead of running a stale copy; the change is one reviewable diff, and its
header lists every check it touches and what each now checks. Rejected: a ConfigMap copy of the
benchmark (what this ADR removed, for drift); kube-bench's `--skip` flag in the CronJob, which
carries no reason - the reason would have had to live in the API as a second copy.

**2. 1.1.9 and 1.1.10 check the real CNI files.** Measured on k3s01 (read-only, 2026-10-10):
containerd's config has no CNI section, so it uses its defaults, `/etc/cni/net.d` and
`/opt/cni/bin` (k3s sets its own CNI directories only for its bundled flannel); `/etc/cni/net.d` is
0700 root:root and holds Cilium's `05-cilium.conflist`, **0600 root:root**; `/var/lib/cni/networks`
does not exist (`/var/lib/cni` holds only containerd's `results`). The two audits now `find` in
`/etc/cni/net.d`, and the CronJob mounts it read-only (`type: Directory`; ADR 0012, amendment). They
pass on the node's real file - nothing is manufactured: an empty or unmounted directory, a 0644 file
or a non-root owner each FAIL (checked below). Durability: Cilium 1.19.8's agent writes the conflist
itself, atomically and with mode 0600 (`daemon/cmd/cni/config.go`, `renameio.WriteFile(dest,
contents, 0600)`), and only when its content changes, so an agent restart cannot widen it; no Helm
value or Ansible task is needed. The 0755 `/opt/cni/bin` binaries are not what these checks ask
about (the benchmark's own remediation names the configuration files).

**3. Not applicable.** 1.2.26 gets `type: skip`, with the reason as the remediation in upstream's
own form for its k3s skips ("Not Applicable." and why: SQLite through kine on a unix socket, no
etcd, no etcd CA). kube-bench reports any skipped check as INFO with `type: skip`. The posture API
counts a skipped check as not applicable only when its remediation opens with "Not Applicable." -
the configuration's statement that it does not apply; a check skipped another way (kube-bench's
`--skip` flag, a skipped group) keeps upstream's remediation and stays in INFO. Not-applicable
checks are counted in `kube_bench.not_applicable` - taken out of `info`, so pass + fail + warn +
info + not_applicable is every check that ran - and listed in `not_applicable_checks` (id, title,
reason: the remediation after the opener, scrubbed and capped like the failing list's; the list
never names more checks than the count). The reason has one source, the benchmark configuration;
upstream's 14 are shown the same way with upstream's reasons. The reason must stay true:
`make validate` runs `scripts/check-cis-na.sh`, which fails while the patch skips 1.2.26 and the k3s
role or its inventory configure etcd (`cluster-init`, `datastore-endpoint`, `etcd-*`). The page
draws not applicable as its own hatched segment and a folded "Not applicable (n)" list under the
CIS tile; the percentage stays pass / (pass + fail + warn), which never counted INFO. The API also
lists the WARN checks (`warning`, as `failing`) under a folded "Manual / warn (n)", and the tile's
status says "No failures · n manual / warn" when there are some. Older API responses (no
`not_applicable`) render as before.

**4. The manual checks, with real controls** (Ansible, `ansible/roles/k3s`; each value and its
reason is in the role's defaults). kube-bench reads each from the flags k3s logs at start-up, as the
journal checks above, so removing a setting makes its check WARN again:

| Check | Control | Note |
|---|---|---|
| 1.1.11 etcd data directory 700 | the check now stats `/var/lib/rancher/k3s/server/db` (kine's SQLite here, embedded etcd's `db/etcd` otherwise); the role keeps it 0700 | upstream stats the etcd default path, which does not exist on k3s. Rancher's k3s guide echoes `permissions=700` for a non-etcd cluster - a manufactured PASS, rejected. k3s creates the directory 0700 itself (checked) |
| 1.2.3 DenyServiceExternalIPs | admission plugin | no Service sets `externalIPs` (none on 2026-10-10) |
| 1.2.9 EventRateLimit | admission plugin + `/etc/rancher/k3s/admission-config.yaml` (0600): server 500 qps / burst 1000, per namespace 50 / 100 | the cluster records almost no events (none in the hour checked). The role refuses to run with EventRateLimit on and no limits (the API server would not start), or without NodeRestriction in the list |
| 1.2.11 AlwaysPullImages | admission plugin | see the trade-off below |
| 1.2.20 `--request-timeout` | `60s`, the default made explicit | |
| 1.3.1 `--terminated-pod-gc-threshold` | 100 (default 12500) | finished pods here: 2; the API reads the newest kube-bench pod's log, which the CronJob's history keeps far below 100 |
| 3.1.3 bootstrap tokens | `--enable-bootstrap-token-auth=false`; the check is automated: PASS only if the API server runs with it false | k3s enables it for `k3s token create` agent joins; this single node joins none and holds no bootstrap token Secret. Joining an agent with such a token needs `k3s_bootstrap_token_auth: true` first |
| 3.2.2 audit policy covers key concerns | policy gaps closed (below); the check is automated | |
| 4.2.12 kubelet cipher suites | `tls-cipher-suites` = the six ECDHE AEAD suites k3s already gives the API server | upstream's audit could never pass on k3s: k3s logs the kubelet's flags sorted inside `msg="..."`, `--tls-cipher-suites` comes last, and the closing quote was read as part of the last suite name. The patch drops that quote before the flags are read |
| 4.2.13 `--pod-max-pids` | 4096; the check now also requires a value of at least 1 (upstream accepted -1, no limit) | far above any workload here; bounds a fork bomb in a sandbox pod to one pod's share |

*AlwaysPullImages, the trade-off.* Every new pod's containers get `imagePullPolicy: Always`, so
the kubelet asks the registry each time a container starts, also when it already holds the image.
What runs does not change - every image is pinned by digest - but a pod start or a container restart
now needs its registry (ghcr.io for this repository's images, and the other registries the pins
name) to answer: during a registry outage a crashed container or a rebooted node does not come back
until it does, and each sandbox run's pod start makes one more registry round trip. The control's
purpose - a pod cannot use an image another tenant's credentials pulled - is about multi-tenancy,
which this cluster does not have; the owner chose it for the benchmark with this cost written down.
Pods created before the restart keep their policy until recreated, and pods created under the plugin
keep `Always` after it is removed, until recreated; a label or annotation change on an existing pod
(Talon's quarantine label) is still admitted (checked). Break-glass during a registry outage:
docs/bootstrap.md 8.11.

*3.2.2, the audit policy.* Against the CIS list: Secrets, `serviceaccounts/token` and the
`authentication.k8s.io` group (TokenReviews) move into one Metadata rule at the top, ahead of the
exclusions - so a node's or a controller's access to a Secret is now recorded (it was dropped), and
TokenReviews still never reach a body-logging rule (ADR 0034's guarantee, kept); ConfigMaps keep
their Metadata rule; `pods/proxy`, `services/proxy` and `nodes/proxy` get an explicit Metadata rule
(the proxied traffic is not logged). Pod and Deployment changes were and are covered by the
Metadata catch-all. More local audit log. More reaches siem01 too: its filter (ADR 0034, F2) ships
every refused request (code >= 400), so a refused Secret read by a node or controller (403, 404),
which the old policy dropped before the filter saw it, is now shipped - Metadata only, no body.
Successful reads are not shipped (F2 ships no reads). The automated check is a set of JSONPath tests
over the node's policy file; the patch header lists them exactly. In short: the first rule is an
unconditional Metadata rule naming Secrets and `authentication.k8s.io`; there are exactly three
None rules, at positions 1-3, each pinned (the three control-plane users' and the nodes' get/list/
watch; events, endpoints, endpointslices and leases); no Request or RequestResponse rule names
Secrets or ConfigMaps; `pods/exec` and `pods/portforward` are named by a RequestResponse rule,
`pods/proxy` and `services/proxy` by a Metadata rule; the last rule is an unconditional Metadata
catch-all. A JSONPath over a missing key yields nothing, so a general "every exclusion drops only
reads" cannot be expressed (a rule without `verbs` would slip past); the exclusions are therefore
pinned rule by rule and counted. What the tests do not evaluate is first-match order among the other
rules; `tests/golden/audit-policy.sh` evaluates the policy first-match against 18 requests and is
the review.

**5. What stays WARN - visible, with the reason:**
- **3.1.1 Client certificate authentication should not be used for users.** It is used: the owner
  (and the automation acting for the owner) authenticates with k3s's `system:admin` client
  certificate. The alternative the benchmark names, OIDC, needs an identity provider and the API
  server's OIDC flags, and would not remove k3s's own client-certificate authentication, which its
  components rely on. Not in reach in this change; a possible follow-up. Not N/A: the check applies.
- **3.1.2 Service account token authentication should not be used for users.** True today - no
  person uses a ServiceAccount token, and no long-lived token Secret exists (2026-10-10) - but
  nothing on the node can verify it, and kube-bench's pod has no API access by design (ADR 0014). A
  PASS here would be an attestation dressed as a measurement; it stays a manual check.

**Result** (verified, below): 71 PASS / 0 FAIL / 2 WARN / 0 INFO / 15 not applicable = 88 checks,
97% on the page.

**Verified locally (2026-10-10),** nothing deployed:
- the image builds with the patch (`git apply` clean, upstream's tests pass on the patched cfg/);
- a throwaway k3s v1.35.9+k3s1 (Docker, `--privileged`) with k3s01's files rendered by Ansible from
  this tree (config.yaml, admission-config.yaml, audit-policy.yaml; test-only: no node-ip,
  protect-kernel-defaults off) starts and answers /readyz; its start-up log written into a journal by
  systemd-journal-remote 257 (Debian 13, the node's systemd) and read by this image under the
  CronJob's constraints (shared PID namespace, no network, read-only root, no capabilities,
  no-new-privileges, every path read-only), with the role's 1.1.20 step applied and a copy of the
  node's `05-cilium.conflist` (0600 root:root, in a 0700 directory) at `/etc/cni/net.d`: the result
  above. The same with main's files: 1.2.3, 1.2.9, 1.2.11, 1.2.20, 1.3.1, 3.1.3, 3.2.2, 4.2.12 and
  4.2.13 each WARN without their setting;
- 1.1.9 / 1.1.10: the conflist 0600 root:root PASS / PASS; 0644 FAIL / PASS; owner 1000 PASS / FAIL;
  an empty directory FAIL / FAIL; nothing mounted FAIL / FAIL. 4.2.13 with `pod-max-pids=-1`: WARN;
- behaviour, new vs main's files: a Service with `externalIPs` is refused vs created; a pod asking
  for IfNotPresent gets Always vs IfNotPresent; a fresh bootstrap token gets 401 vs 200 on `/api`;
  400 events posted at once into one namespace: 120 created, 280 refused with 429 vs 400 created;
- 3.2.2 against seventeen mutations of the policy (Secrets behind the exclusions, or limited to a
  namespace; `authentication.k8s.io` out of the first rule; the first rule at RequestResponse;
  ConfigMaps with bodies; no `pods/exec`; no proxies; pods added to an exclusion; an exclusion
  dropping writes; a fourth None rule; the nodes' or the control-plane users' exclusion dropping every
  verb; a ServiceAccount or a group added to an exclusion; the catch-all limited to a namespace; no
  catch-all): each turns PASS into WARN;
- `scripts/check-cis-na.sh` fails on `cluster-init`, `datastore-endpoint` or an `etcd-*` argument
  added to the role's config template, and on an etcd variable in the inventory;
- the API's parser on that run's log (`testdata/kube-bench-cis.log`) and on the live log before the
  change; the page's parser and render; `tests/golden/audit-policy.sh` rebased onto this change, its
  two mutations killed.

**Consequences.** A kube-bench image rebuild (CI) and digest pin, and a k3s restart through the
role in a window (docs/bootstrap.md 8.11). The patch is re-read on each kube-bench bump. Bootstrap
token joins are off. Pod starts depend on the registries (above). The 3.1.1 and 3.1.2 WARNs stay on
the page until OIDC (3.1.1) or an API-side check (3.1.2) is decided. The 2026-10-02 text above
calling 1.1.9 and 1.1.10 "not a finding" is superseded by item 2.
