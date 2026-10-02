# ADR 0026: CoreDNS is built here and deployed by the k3s role in place of k3s's bundled copy

Date: 2026-10-02 · Status: accepted

## Context
The cluster's DNS server is the CoreDNS k3s bundles: k3s v1.35.9+k3s1 writes
`/var/lib/rancher/k3s/server/manifests/coredns.yaml` from a manifest compiled into its binary on every
start, and its deploy controller applies it as the Addon `coredns` (Deployment `coredns`, Service
`kube-dns` at 10.43.0.10, ConfigMap, ServiceAccount, ClusterRole/Binding `system:coredns`). The
image is `rancher/mirrored-coredns-coredns:1.14.7`
(`sha256:7efd3c635b03efd68c4e8398fc45f0d993d0e9ab016f72c1cefb0fd6d01aa286`), a mirror of CoreDNS's
own 1.14.7 release image. ADR 0023 took it from 1.14.6 to 1.14.7 by bumping k3s (docs/bootstrap.md
8.2); nothing newer is released, so that route is exhausted.

`aquasec/trivy:0.75.0` on 2026-10-02: **16 HIGH**, 0 CRITICAL (13 HIGH in the cluster's older DB),
all in the binary, none in the Debian base:

| Module in the binary | Findings | Cause |
|---|---|---|
| github.com/coredns/coredns | 11 | The binary records its own module version as the pseudo-version `v0.0.0-20260819003913-427fc80ed9ca` (built from a checkout without tags), so every CoreDNS advisory is compared against "v0.0.0". All 11 are fixed in 1.14.7 or earlier: CVE-2023-28452 (1.11.0), CVE-2025-47950 (1.12.2), CVE-2026-26017/-26018 (1.14.2), CVE-2026-32934/-32936/-33190/-33489/-35579 (1.14.3), CVE-2026-82399/-86003 (1.14.7). |
| google.golang.org/grpc v1.83.0 | 2 | CVE-2026-84304 (fixed 1.83.1), CVE-2026-84445 (1.83.2) |
| golang.org/x/mod v0.37.0 | 2 | CVE-2026-56864, CVE-2026-56865 (0.40.0) |
| golang.org/x/crypto v0.54.0 | 1 | CVE-2026-56854 (0.55.0) |

Two things have to be decided: how to build a CoreDNS without the five real findings and with a
truthful version, and how to run it given that k3s owns these objects and re-creates them.

### How the image can reach the cluster (checked against k3s v1.35.9+k3s1, commit 58877f2)
- **Override k3s's image in place: not possible.** The image in `manifests/coredns.yaml` is
  `%{SYSTEM_DEFAULT_REGISTRY}%rancher/mirrored-coredns-coredns:1.14.7`; the only knob is
  `--system-default-registry`, which re-prefixes *every* system image (pause, local-path, metrics-server)
  and keeps the path and tag. A containerd mirror `rewrite` in registries.yaml could swap the bytes
  behind that name, invisibly to the API, Trivy Operator and anyone reading the manifest - rejected.
  `coredns-custom` only imports Corefile snippets; `HelmChartConfig` applies only to k3s's Helm-chart
  add-ons (Traefik), and CoreDNS is a plain manifest. Editing the live Deployment is reverted at the
  next k3s start (the manifest is re-staged and force-applied).
- **A `.skip` file** (`coredns.yaml.skip`) makes the deploy controller ignore the file, but k3s still
  re-stages it and keeps the Addon and its node controller (which rewrites `NodeHosts` in ConfigMap
  `coredns`): two writers on one object. Rejected.
- **`disable: [coredns]` plus our own objects** is the supported way. With `coredns` in `disable`,
  k3s neither stages the manifest nor runs the NodeHosts controller (`pkg/server/server.go`,
  `node.Register(..., !Skips["coredns"])`), and the deploy controller *deletes* a disabled manifest:
  it applies an empty set owned by Addon `coredns`, which deletes every object carrying that Addon's
  `objectset.rio.cattle.io/hash` label, then removes the file (`pkg/deploy/controller.go`, `delete`).
  Done naively, that deletes Service `kube-dns` and the Deployment - a DNS outage until something
  recreates them, and a recreated Service must get the same ClusterIP every pod's resolv.conf names.
- **Who then owns the objects.** An Argo CD Application was the first idea and is rejected: Argo CD's
  repo-server resolves github.com and helm.cilium.io through this very DNS. On a fresh bootstrap,
  with k3s's copy disabled, Argo CD could not fetch the repository that contains CoreDNS; on a live
  cluster, a bad CoreDNS commit would leave Argo CD unable to fetch the fix. DNS must come up with
  the node, below Argo CD - which is where k3s puts it today.

## Decision
**1. CoreDNS is built here** (`app/coredns`), the way app/talon and app/ksops are (ADR 0023, 0024),
and built, Trivy-gated, SBOM'd and signed by build-images.yml like every image under `app/`:
- source: `coredns/coredns` at `427fc80ed9ca47f354585eb30a3f1332950856c4`, the commit tag v1.14.7
  points at, fetched by full hash and checked after checkout. No Go source and no plugin is changed
  (upstream's plugin.cfg and generated plugin list).
- version: after the hash check, the checkout gets a local tag `v1.14.7` on that commit, so the Go
  toolchain stamps the main module as `v1.14.7+dirty` (dirty because the next step replaces
  go.mod/go.sum). The build fails unless `go version -m` shows that. Trivy then judges CoreDNS's own
  advisories against 1.14.7, which is what this is - an advisory fixed after 1.14.7 is still
  reported. This removes a scanner false positive by making the metadata true, not by ignoring
  anything.
- dependencies: upstream's go.mod/go.sum with grpc v1.83.2, x/crypto v0.55.0 and x/mod v0.40.0
  (grpc and x/crypto are the releases app/talon and app/ksops raised to), then `go mod tidy`; minimal
  version selection moved x/net (0.58.0), x/text (0.41.0) and x/tools (0.49.0) and nothing else.
  miekg/dns, client-go and every plugin's dependencies are upstream's. Committed in
  `app/coredns/modules/`, checked with `go mod verify` against go.sum and sum.golang.org.
- tests: upstream's `go vet` and `go test -race`, grouped per directory as upstream's CI does
  (request, core, coremain, plugin, test), with `--network=none` and as uid 65532, in a stage the
  image depends on. One test is skipped by name, `TestZoneExternalCNAMELookupWithProxy`: it forwards
  to 8.8.8.8 and needs the real answer. Non-root because `TestDefaultLoader` checks that an unreadable
  Corefile is refused, which root defeats. The same failures appear with upstream's own go.mod
  (checked side by side), so none is caused by the raised modules.
- build: upstream's Makefile flags - CGO off, `-tags grpcnotrace`, `-ldflags "-s -w -X
  coremain.GitCommit=427fc80"` - plus `-trimpath` and an empty build id. `coredns -version` prints
  `CoreDNS-1.14.7 / linux/amd64, go1.26.8, 427fc80` (upstream: go1.26.6).
- port 53 as non-root: like upstream's image, the binary carries the file capability
  `cap_net_bind_service=ep`. Upstream sets it with `setcap` from libcap2-bin installed off an
  unpinned Debian mirror; here `app/coredns/setcap.go` (standard library only) writes the identical
  `security.capability` xattr and reads it back, so a filesystem that dropped it fails the build.
- runtime: distroless `static-debian13:nonroot`, uid 65532, binary at `/coredns` with entrypoint
  `/coredns` - upstream's layout, so the Deployment's `args` do not change. Same Go and base pins as
  app/api, app/talon, app/ksops.

**2. The k3s role runs it, as a k3s auto-deploy manifest** - not Argo CD. With `k3s_coredns_own:
true` (default) the role adds `coredns` to k3s's `disable` list and renders
`templates/coredns-sdp.yaml.j2` to `/var/lib/rancher/k3s/server/manifests/coredns-sdp.yaml`. k3s's
deploy controller applies that file on every k3s start and whenever it changes, exactly as it did
its own: DNS still comes up with the node, before the CNI-dependent rest of the cluster, with no
dependency on Argo CD or Kyverno. The manifest mirrors k3s's object for object - same names, same
labels (`k8s-app: kube-dns` on the pods), same selector, ServiceAccount, RBAC, Service ports and
ClusterIP, same Corefile, probes, resources, tolerations and priority class. Every Cilium policy that
lets a namespace resolve names selects `k8s-app: kube-dns` in kube-system (cloudflared, falco,
falco-response, policy-reporter, portfolio-api, sandbox, trivy-operator), and Hubble's DNS
visibility and the L7 DNS rules ride on those policies; none needs to change. The differences, each
marked in the template:
- the image: `k3s_coredns_image`, pinned by digest in the role defaults;
- rolling update `maxUnavailable: 0, maxSurge: 1` (k3s: `maxUnavailable: 1`, which on one replica
  may stop the only DNS server before its replacement is ready);
- `health { lameduck 5s }` (kubeadm's default): a stopping pod keeps answering while its endpoint is
  withdrawn;
- a pod security context with the whole `restricted` profile stated (runAsNonRoot, uid/gid 65532,
  seccomp RuntimeDefault) on top of k3s's container context (no privilege escalation, read-only
  root, drop ALL, add only NET_BIND_SERVICE). kube-system stays exempt from the Kyverno pod-security
  rule and has no PSA labels (ADR 0012, unchanged), but the rendered pod passes that rule anyway
  (`kyverno apply` with the namespace changed to `default`: pass);
- `NodeHosts` rendered from the inventory (`<k3s_node_ip> <hostname>`, today `10.4.1.20 k3s01`):
  with k3s's copy disabled its NodeHosts controller is off, and on this single node the entry is
  static;
- `cluster-dns` is now set explicitly in k3s's config.yaml from `k3s_cluster_dns` (10.43.0.10, the
  value k3s derived by default), the same variable the Service's ClusterIP is rendered from.

**3. The cutover is a rolling update of the same Deployment, not a delete and re-create.** The k3s
deploy controller (wrangler apply) takes over an object that already exists: create returns
AlreadyExists, it patches the object and rewrites its owner labels/annotations to the new Addon
(`desiredset_process.go`, "Taking over an object that wasn't previously managed by us"). The role
orders the steps so DNS always has a ready server:
1. write `coredns-sdp.yaml` while k3s's copy is still enabled; within its 15 s poll k3s applies it and
   the six objects become Addon `coredns-sdp`'s; the Deployment rolls surge-first;
2. wait until the Deployment's `objectset.rio.cattle.io/owner-name` is `coredns-sdp` with our image,
   then `rollout status`;
3. only then render config.yaml with `disable: [coredns]` and restart k3s. The restart deletes the
   disabled coredns.yaml and "everything Addon `coredns` owns" - selected by its owner hash, which no
   object carries any more - so nothing is deleted.
The file name sorts before `coredns.yaml`, so even a start that does both at once (e.g. k3s stopped
when the role runs) applies the takeover before the removal. Service `kube-dns` and its ClusterIP are
never deleted; pods keep their resolv.conf; Cilium sees the same Service and, for a moment, two
labelled backends.

**4. Rollback is one variable.** `k3s_coredns_own: false` removes the file (which by itself deletes
nothing) and drops `coredns` from `disable`; the restart re-stages k3s's manifest and its force-apply
takes the same objects back to `rancher/mirrored-coredns-coredns:1.14.7`. That roll uses k3s's
strategy again (`maxUnavailable: 1`), so it can leave a gap of a few seconds; resolvers retry. For a
gap-free rollback of only the binary, keep the delivery and set `k3s_coredns_image` to upstream's
image by digest (docs/bootstrap.md 8.7).

**5. Not added to admission verification.** kube-system stays outside `verify-portfolio-images` and
`restrict-image-registries`. Those rules fail closed, and DNS is what everything else - Argo CD
included - needs to repair Kyverno; a DNS pod gated on Kyverno would make a Kyverno outage a DNS
outage at the next restart (the argocd reasoning of ADR 0024, more so). The image is still signed,
SBOM'd and Trivy-gated in CI, verifiable by hand (`scripts/verify-image.sh`), pinned by digest, and
changing the pin needs root on the node or cluster-admin.

**6. Pin handling.** The pin lives in `ansible/roles/k3s/defaults/main.yml`, the first image pin
outside `cluster/`. `scripts/check-image-digests.sh` now scans `ansible/` too (refusing the
placeholder there), and `scripts/bump-image-digest.sh coredns <digest>` rewrites it and says that the
role has to be run. The GHCR package `self-defending-portfolio/coredns` must be public: containerd
pulls it without credentials, through the node's own resolvers (not cluster DNS).

## Verified locally (2026-10-02)
Before anything deploys it:
- **Scan:** the image scans **0** CRITICAL/HIGH (`aquasec/trivy:0.75.0`; upstream's 16). Trivy lists
  the binary's modules as `github.com/coredns/coredns v1.14.7+dirty`, `grpc v1.83.2`, `x/crypto
  v0.55.0`, `x/mod v0.40.0`, `stdlib v1.26.8` - CoreDNS's own module is evaluated, not skipped. Two
  MEDIUM remain in x/crypto v0.55.0 (CVE-2026-56855, CVE-2026-78662), outside the gate.
- **Tests:** the build ran upstream's suite as described (every package ok) in 7 minutes on a loaded
  host, cold module cache included.
- **Same program:** `coredns -plugins` is identical to upstream's image (61 lines); `-version` prints
  `CoreDNS-1.14.7`, `linux/amd64, go1.26.8, 427fc80`.
- **Port 53 under the cluster's constraints** (`--read-only --cap-drop ALL --cap-add
  NET_BIND_SERVICE --security-opt no-new-privileges`, image user 65532): both images bind :53 and
  answer over UDP and TCP (hosts plugin, NodeHosts entry `k3s01`) and forward to the upstream
  resolver. Without NET_BIND_SERVICE both refuse to start identically (`exec /coredns: operation not
  permitted`): the file capability is present and behaves as upstream's.
- **Kubernetes answers:** with the template's Corefile and its `kubernetes` plugin pointed at the live
  API (read-only list/watch, as uid 1001), both images give the same answers -
  `kube-dns.kube-system.svc.cluster.local` A 10.43.0.10, its `_dns._udp` SRV, the PTR for
  10.43.0.10, `kubernetes.default` 10.43.0.1, NXDOMAIN for an unknown Service - pass `/health` and
  `/ready` within a second, log no errors and export the same 22 `coredns_*` metric families.
- **Manifest:** the role's template renders (Ansible, inventory values) to six objects that pass
  kubeconform (strict, Kubernetes 1.35), and the pod passes the repository's Kyverno
  pod-security-restricted, require-pod-resources and disallow-latest-tag policies. `make lint` passes
  the role.

The cutover itself can only be verified on the cluster; docs/bootstrap.md 8.7 gives the commands and
what each must show.

## Consequences
- CoreDNS leaves the third-party column of the posture page: 16 HIGH (13 in the cluster's DB) to
  the own image's count.
- CoreDNS no longer moves with k3s. A k3s bump must compare its `manifests/coredns.yaml` with
  `templates/coredns-sdp.yaml.j2` (objects, RBAC, Corefile, probes) and carry over what changed; a new
  CoreDNS release means rebuilding `app/coredns` (Dockerfile header). When k3s's bundled image scans
  clean, `k3s_coredns_own: false` returns to it.
- `NodeHosts` is no longer maintained by k3s: a second node or a new node address needs the template
  (or this decision) revisited.
- Applying a new digest is running the k3s role (`--tags k3s`); with only the manifest changed there
  is no k3s restart, just a surge-first roll.
- Staged like Talon and KSOPS: the image first, from `main`; then the switch commit with the real
  digest; then the role run. Until the role runs, the cluster keeps k3s's CoreDNS.
