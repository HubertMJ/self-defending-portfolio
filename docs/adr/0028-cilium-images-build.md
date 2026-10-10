# ADR 0028: Cilium's four images are upstream's release with the Go binaries rebuilt against fixed dependencies, rolled out one data-path component at a time

Date: 2026-10-02 · Status: accepted

## Context
Cilium 1.19.8 is the CNI, the kube-proxy replacement and the Gateway API data plane of a single-node
cluster (ADR 0004, ADR 0010). It is installed twice: by the Ansible `cilium` role on a fresh node, so
that anything else can run, and from then on by Argo CD (`cluster/apps/cilium.yaml`), which adopted
the release; both declare the same chart version and identical values (ADR 0005, ADR 0008,
`scripts/check-cilium-values.sh`). 1.19.8 is the newest 1.19 patch release (2026-09-15).

Its four images, `aquasec/trivy:0.75.0`, CRITICAL+HIGH, 2026-10-02:

| Image (chart 1.19.8 pin) | C+H | Findings |
|---|---:|---|
| `quay.io/cilium/cilium:v1.19.8` (agent) | 16 | grpc v1.79.3 (CVE-2026-84304, CVE-2026-84445, GHSA-hrxh-6v49-42gf) in cilium-agent, cilium-dbg, hubble, cilium-cni; x/crypto v0.53.0 (CVE-2026-56854) in cilium-agent, cilium-dbg; Ubuntu libssl3t64 + openssl 3.0.13-0ubuntu3.15 (CVE-2026-84782) |
| `quay.io/cilium/operator-generic:v1.19.8` | 3 | grpc v1.79.3 in cilium-operator-generic |
| `quay.io/cilium/hubble-relay:v1.19.8` | 3 | grpc v1.79.3 in hubble-relay |
| `quay.io/cilium/cilium-envoy:v1.37.6-1789133542-cbec91f6...` | 2 | Ubuntu libssl3t64 + openssl (CVE-2026-84782) |

Every finding has a fixed release. None is in Cilium's own code, in Envoy, or in the datapath
toolchain (clang/llc, bpftool, iproute2, iptables).

What upstream offers instead, checked the same day:
- **No 1.19 patch release carries the fixes yet.** The `v1.19` branch already has grpc v1.83.2 and
  x/crypto v0.57.0 in go.mod (upstream's dependency bot, 2026-09-18), so 1.19.9 will - but it is
  not released.
- **Cilium 1.20.2** still has grpc v1.83.1 (CVE-2026-84445 is fixed in 1.83.2) and x/crypto v0.53.0,
  and is a minor upgrade of the CNI on the only node.
- **cilium-envoy v1.37.7-1790879678-3aca86e6...** (2026-10-01), the newest build of the same Envoy
  minor, has the fixed OpenSSL but adds `/usr/bin/cilium-envoy-healthcheck` compiled with Go 1.24.6:
  **22** CRITICAL+HIGH. It is also not the Envoy 1.19.8 was released with (the agent checks
  `requiredEnvoyVersionSHA=cbec91f6...`, `pkg/envoy/versioncheck.go`).

ADR 0023's options, in order: nothing here is unused; no newer release fixes it; so build it here,
which is only worth it if the build is *the same software* - a CNI on a single node has no second node
to fail over to, and a broken agent means no pod networking for anything, including Argo CD.

## Decision
**1. Same release, same layers, only the Go binaries rebuilt.** Four directories, built, Trivy-gated,
SBOM'd and signed by build-images.yml like every image under `app/` (ADR 0011, ADR 0016):

- `app/cilium` - the agent DaemonSet's image (also all six of its init containers).
- `app/cilium-operator-generic` - the operator.
- `app/hubble-relay` - Hubble Relay.
- `app/cilium-envoy` - the Envoy DaemonSet's image.

For the first three:
- source: `cilium/cilium` at `5791d208dda456da8d08e9389c3d22514dc2db77`, the commit tag v1.19.8 points
  at, fetched by full hash and checked after checkout. No Go source is changed.
- dependencies: upstream's go.mod/go.sum with `go get google.golang.org/grpc@v1.83.2
  golang.org/x/crypto@v0.55.0` and `go mod tidy` - the grpc and x/crypto releases app/talon and
  app/ksops raised to, and the same grpc the `v1.19` branch is on. Minimal version selection moved
  what those two require (x/net, x/sys, x/text, x/oauth2, genproto, otel 1.41 -> 1.44,
  go-control-plane/envoy 1.36 -> 1.37 among others); nothing else was raised by hand. Upstream
  builds from `vendor/`, so `vendor/` is regenerated with `go mod vendor` after `go mod verify`.
  The three `modules/` copies are byte-identical; `scripts/check-cilium-values.sh` refuses a
  difference (an agent and operator on different dependency sets is a combination upstream never
  shipped).
- tests: upstream's unit tests for the packages the raised modules reach, unprivileged, with
  `--network=none`, in a stage the image depends on - agent: `./pkg/envoy/...` (the xDS server and
  the go-control-plane types that moved), `./pkg/hubble/...`, `./pkg/health/...`,
  `./plugins/cilium-cni/...`, `./cilium-dbg/...`, `./hubble/...` (59 packages pass); operator:
  `./operator/...` (30); relay: `./hubble-relay/...`, `./pkg/hubble/relay/...`, `./pkg/hubble/peer/...`
  (7). Not all of `./...`: upstream's full `make unit-tests` exceeds the CI budget, and its privileged
  half needs a kernel the build does not get.
- build: upstream's own make targets (`build-container install-container-binary` with `PKG_BUILD=1`,
  `install-bash-completion`, `licenses-all`; the operator and relay targets for those images), so
  ldflags, build tags and the installed file set are upstream's. Two additions, both visible in the
  Dockerfiles:
  - `GIT_VERSION` is passed in with the UTC offset spelled `+00:00`: the golang image's git 2.47
    prints the author date as `...Z`, upstream's builder printed `+00:00`; with it every version
    string (`cilium-dbg version`, `cilium-agent --version`, CNI, operator, relay, hubble) is
    byte-identical to upstream's.
  - `-X github.com/cilium/cilium/pkg/version.Version=v1.19.8`, for scanners. The Go build info
    records the main module as `v0.0.0-20260915215327-5791d208dda4+dirty` (the tree differs from the
    tag in go.mod, go.sum and vendor/), and Trivy matches Cilium's own advisories against that
    pseudo-version as if it predated every release: four phantom findings per binary, including
    fixes from 2022. Trivy reads a version from such an ldflag instead (upstream's hubble Makefile
    already stamps hubble this way, which is why hubble had none), so Cilium advisories are matched
    against 1.19.8 exactly as for upstream's binaries - they stay visible, they are not hidden.
    `pkg/version.init()` overwrites the variable before anything reads it, so nothing changes at run
    time (the version and `--help` outputs are identical, below).
- runtime, assembled as upstream's `release` stages at that commit, from upstream's own layers by
  digest:
  - agent: `quay.io/cilium/cilium-runtime:ccc1a8e2...@sha256:02a3f11f...` (upstream's
    `CILIUM_RUNTIME_IMAGE`; it is the single bottom layer of the upstream agent image), libcilium.so,
    cilium-envoy and cilium-envoy-starter from the pinned cilium-envoy image, then the build output
    (binaries, BPF C sources under /var/lib/cilium/bpf, bash completion, LICENSE.all, init scripts),
    the same ENV, WORKDIR and CMD;
  - operator: scratch, the CA bundle and gops copied out of the upstream operator image, the
    binary, LICENSE.all, /home/gops, GOPS_CONFIG_DIR;
  - relay: `distroless/static-debian13:nonroot` at the digest upstream pins (upstream calls it
    `distroless/static:nonroot`, same manifest), gops from the upstream relay image, the binary,
    LICENSE.all, /home/gops, uid 65532, `hubble-relay serve`.
- OpenSSL in the agent image: `libssl3t64` and `openssl` upgraded to 3.0.13-0ubuntu3.16 and nothing
  else, from the Ubuntu snapshot service at 2026-10-02T00:00Z, so the index cannot move under a
  rebuild (apt still verifies the archive signatures).

For cilium-envoy, Envoy is not rebuilt: it is statically linked against BoringSSL and does not load
the system OpenSSL (`ldd` lists no libssl/libcrypto; `--version` ends in `/BoringSSL`), which serves
only `/usr/bin/openssl` and coreutils' checksum tools in that image. `app/cilium-envoy` is upstream's
image at the chart's digest plus one layer that upgrades exactly the same two packages the same way.
A Bazel build of Envoy (hours, tens of GB of disk, beyond a GitHub-hosted runner) to change nothing
in Envoy was not worth it.

**Verified locally** (2026-10-02, before anything deploys it):
- Trivy 0.75.0 CRITICAL+HIGH, upstream -> here: agent 16 -> **0**, operator 3 -> **0**, relay
  3 -> **0**, envoy 2 -> **0** (also 0 with `--ignore-unfixed`, the CI gate's setting).
- File by file (exported root filesystems, sha256 of every regular file, mode/uid/gid, symlinks):
  agent 5329 entries each, the only differences are the 9 rebuilt binaries and the files of the two
  OpenSSL packages (with dpkg/apt bookkeeping); the BPF sources, init scripts, bash completion,
  LICENSE.all and every runtime tool are upstream's bytes. Operator 15 and relay 1399 entries: only
  the one binary differs. Envoy 3870: only the two packages' files and `ld.so.cache`. Env, cmd,
  entrypoint, working directory and user identical in all four.
- Behaviour against upstream's images, offline in Docker: the version strings and the full `--help`
  output of every agent binary, the operator and the relay are identical; `cilium-agent hive` and
  `cilium-operator-generic hive` (which construct every component without starting it) print the
  same cell graph; hubble-relay serves (uid 65532, read-only root, no capabilities) and both our
  `hubble` CLI and upstream's complete gRPC calls against it (health `NOT_SERVING` and an empty node
  list, as expected without an agent); `cilium-envoy --mode validate` accepts a bootstrap.
  `app/<name>/test/image-smoke.sh` repeats the version, hive, tool and package checks in CI, before
  signing.
- Build time on an 8-core machine, no cache: agent about 4 min, operator 3, relay 2 (tests
  included); expect about twice that on a 4-vCPU GitHub runner. The largest layer is vendor/ (0.4
  GB; the module cache is dropped after vendoring).

What this cannot show: attaching BPF programs, reconciling with an API server, serving real xDS to
Envoy or routing Gateway traffic. Those need the live cluster, which is why the rollout is staged.

**2. Pinned as chart image overrides in both declarations.** `image.override`,
`operator.image.override`, `hubble.relay.image.override` and `envoy.image.override` name
`ghcr.io/hubertmj/self-defending-portfolio/<name>:main@sha256:...`, in `cluster/apps/cilium.yaml` and
identically in `cilium_values` of the Ansible role, so a rebuild from zero installs the same images
(check-cilium-values enforces it). The chart's `override` is the whole reference and bypasses its
repository/tag/digest keys. Rendering the chart with the operator and relay overrides changes exactly
those two `image:` lines and nothing else (no config hash, no agent restart).
`scripts/bump-image-digest.sh` rewrites both files, and says that the role's copy only seeds a
rebuild: the role leaves a release Argo CD owns alone.

**3. One data-path component per commit, agent last.** Three switch commits, pushed one at a time with
the checks in between (`docs/bootstrap.md`, 8.8): operator + relay (nothing on the packet path),
then cilium-envoy (the Gateway's L7 path: the site), then the agent. Each image is pre-pulled on the
node first, so no rollout waits on a registry while its predecessor is already gone (both
DaemonSets roll `maxSurge: 0` on one node). Rollback is reverting the commit (Argo CD, about 3
minutes); if Argo CD cannot act - its own pods depend on the agent - the emergency path is
`kubectl set image` straight back to upstream's digests, which needs only the API server, a host
process reachable whatever state Cilium is in.

Not added to admission verification: `kube-system` stays outside `verify-portfolio-images` and
`restrict-image-registries`. Those rules fail closed, Kyverno needs pod networking, and pod
networking needs the agent: gating the agent's pods on Kyverno would make a Kyverno outage able to
keep the CNI from restarting - a cycle with no way out on one node (the same reasoning as `argocd`,
ADR 0024). The images are still signed, SBOM'd and Trivy-gated in CI, verifiable by hand
(`scripts/verify-image.sh`), and pinned by digest.

## Consequences
- Once rolled out, Cilium leaves the third-party column of the posture page: 24 CRITICAL+HIGH today
  (16 + 3 + 3 + 2) become 0 in four own images.
- Four more images to rebuild by hand on every Cilium patch release, and the riskiest component in
  the cluster to own. The exit is built in: 1.19.9 should carry grpc v1.83.2 and x/crypto v0.57.0;
  when a release's upstream images scan clean, delete the four directories, drop the overrides and
  return to the chart's images (a revert of the switch commits). Bumping before that: the Dockerfile
  headers (CILIUM_COMMIT, the runtime and envoy digests from upstream's Dockerfile at the new commit,
  modules/ regenerated, the expected version strings) and cilium_version/targetRevision together.
- The rebuilt binaries carry dependencies upstream did not release 1.19.8 with. The upstream tests
  above and the identical cell graph are the evidence that nothing moved; the v1.19 branch running
  the same grpc release in upstream's own CI is the strongest single reason to expect it holds.
  go-control-plane/envoy moved to 1.37.0 - the xDS API of the Envoy 1.37 the agent drives.
- A rebuild from zero pulls Cilium from GHCR before anything else runs: the four packages must be
  public (5.2) and GHCR reachable from the node. Upstream's images are no longer referenced except
  as build bases and in the emergency rollback.
- Rolled out in three steps, each a commit; until the agent step, the cluster runs a mix, which is
  a combination of the same release and compatible by construction.

## Amendment 2026-10-10: the MEDIUM and LOW findings with a fix, Go 1.26.9, gops and loopback rebuilt

The owner's decision of 2026-10-10: fix every MEDIUM and LOW finding with a fixed release in the
four images, as for the other own builds. Trivy Operator listed, for the running images: gopacket
v1.5.0 (CVE-2026-54332, CVE-2026-54345; agent, operator), mongo-driver v1.17.6 (CVE-2026-2303;
agent, operator, relay), cel-go v0.26.1 (GHSA-gcjh-h69q-9w9g; agent) and Ubuntu's perl-base
5.38.2-3.2ubuntu0.4 (CVE-2026-15534, CVE-2026-19487; agent and cilium-envoy). Trivy 0.75.0 with the
database of 2026-10-10 adds, in every Go binary of the three Cilium images: Go 1.26.8's standard
library (CVE-2026-78667, CVE-2026-78669, CVE-2026-97031 HIGH; five MEDIUM, one LOW; fixed in
1.26.9), x/net v0.58.0 (CVE-2026-78669 HIGH, two MEDIUM) and x/crypto v0.55.0 (two MEDIUM). The HIGH
ones would fail the CI gate on the next build of any of the three - including `gops` (agent,
operator, relay) and `/cni/loopback` (agent), which came byte-for-byte from upstream's layers and
were compiled by upstream with Go 1.26.8.

What changed, still with no line of Cilium's Go source touched:
- modules/ (all three copies, identical): `go get github.com/gopacket/gopacket@v1.6.1
  go.mongodb.org/mongo-driver@v1.17.7 github.com/google/cel-go@v0.29.0`, `go mod tidy` (moved only
  antlr4-go/antlr 4.13.0 -> 4.13.1 and dropped stoewer/go-strcase), then `go get
  golang.org/x/net@v0.60.0 golang.org/x/crypto@v0.57.0`, `go mod tidy` (the rest of golang.org/x
  moved, and the go directive to 1.26.0, which x/net 0.60 requires) - the same x/net and x/crypto
  releases as the talon change in this rebuild. The go directive alone would have changed the
  binaries' run-time behaviour: a main module at go 1.26 gets Go 1.26's GODEBUG defaults
  (`urlstrictcolons`, `tlssecpmlkem`, `cryptocustomrand` among them), where upstream's go.mod (go
  1.25.0) gives its build 1.25's. So go.mod also carries `godebug default=go1.25`, added by hand
  right below the go line (in all three copies; `go mod tidy` keeps it): the rebuilt binaries keep
  upstream's defaults, which `go version -m` shows as their `DefaultGODEBUG` build setting. cel-go
  0.29 is three minor releases on from what Cilium 1.19.8 and Kubernetes 0.35 were released with; it
  compiles against both unchanged, all of `./...` builds, and both Cilium's Hubble CEL filter tests
  (`pkg/hubble/filters`, its one direct user) and k8s.io/apiserver's own `pkg/cel/...` tests pass
  against it.
- golang:1.26.9 for the three builds (the same pin as the talon change in this rebuild). The version
  strings now end in `go1.26.9`; everything before the Go release is still byte-identical to
  upstream's.
- gops (v0.3.29) and the CNI loopback plugin (containernetworking/plugins v1.9.1): compiled in a
  `tools` stage exactly as upstream's `images/runtime/build-gops.sh` and `build-cni.sh` at
  CILIUM_COMMIT do it - same releases, same `go build` flags and version ldflag - with Go 1.26.9,
  fetched by the commit each tag points at, and copied over the runtime's copies. `-buildvcs=false`
  keeps the build info as upstream's (built from a tarball, no VCS stamp). The operator image now
  takes only the CA bundle from upstream's image; the relay image no longer references upstream's.
- perl-base 5.38.2-3.2ubuntu0.6 added to the in-place package upgrade in the agent and cilium-envoy,
  from the same Ubuntu snapshot (2026-10-02, which already carries it). The upgrade goes when the
  base upstream pins at a newer release carries the fixed versions.
- Tests: the agent's test stage also runs `./pkg/monitor/...` and `./pkg/datapath/linux/probes/...`
  (the gopacket users outside Hubble); 65 packages pass (agent), 30 (operator), 7 (relay). The
  monitor's decoding is exercised; the probes' tests compile but skip without privileges
  (`testutils.PrivilegedTest`), so they are no evidence for gopacket. What the probe uses - building
  an Ethernet/IPv4/UDP packet with `gopacket.SerializeLayers` - is unchanged between gopacket 1.5.0
  and 1.6.1: `writer.go`, `layers/ethernet.go`, `layers/ip4.go` and `layers/udp.go` have no diff;
  the one changed file on that path, `layers/ports.go`, only adds ports to the decoder's
  port-to-layer table. The smoke tests check perl-base, gops and the loopback plugin's version; the
  tools stages also assert that gops and loopback were built for amd64 with go1.26.9.

**Verified locally** (2026-10-10), Trivy 0.75.0, CRITICAL+HIGH+MEDIUM+LOW with `--ignore-unfixed`,
running image -> rebuilt image (findings, counted per binary): agent 39 HIGH, 88 MEDIUM, 11 LOW ->
**0**; operator 7 HIGH, 15 MEDIUM, 2 LOW -> **0**; relay 7 HIGH, 13 MEDIUM, 2 LOW -> **0**; envoy 2
MEDIUM -> **0**. File by file against the running agent image: the same 5336 entries, differing only
in the rebuilt Cilium binaries and LICENSE.all, gops, loopback, perl-base's files and the dpkg/apt
logs. Smoke tests pass for all four.

Rollout: as any rebuild, `scripts/bump-image-digest.sh` per image and the three switch steps of
`docs/bootstrap.md` 8.8 (operator + relay, then envoy, then the agent), each pre-pulled and checked;
the rollback is reverting that bump commit, back to the previous own digests. Before the agent step,
`sudo k3s crictl images --digests | grep cilium` on the node must still list the previous agent
digest, so that a rollback needs no pull.
