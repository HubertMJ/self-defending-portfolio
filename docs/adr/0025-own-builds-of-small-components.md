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
