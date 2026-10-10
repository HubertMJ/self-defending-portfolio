# The Cilium agent image (DaemonSet `cilium` in kube-system, ADR 0004), built here from the pinned
# upstream release commit with fixed dependencies (ADR 0028). Built, Trivy-gated, SBOM'd and signed by
# .github/workflows/build-images.yml like every image under app/ (ADR 0016).
#
# Why not the upstream image: quay.io/cilium/cilium:v1.19.8 is the release the chart pins, and its Go
# binaries are compiled against google.golang.org/grpc v1.79.3 and golang.org/x/crypto v0.53.0, which
# have fixes since; its Ubuntu base carries an OpenSSL with a fixed CVE. 16 CRITICAL+HIGH with Trivy
# 0.75.0 on 2026-10-02: 3 grpc in each of cilium-agent, cilium-dbg, hubble and cilium-cni, x/crypto
# in cilium-agent and cilium-dbg, and libssl3t64 + openssl.
#
# The approach is "same image, rebuilt Go binaries": everything the agent runs that is not a Cilium
# Go binary - iproute2, iptables (with upstream's wrapper), clang/llc for compiling the datapath at
# runtime, bpftool, Envoy - comes from exactly the layers upstream ships, by digest, so the datapath
# toolchain is byte-for-byte upstream's. What changes:
#   * the nine Go binaries upstream's `make build-container install-container-binary` installs
#     (cilium-agent, cilium-dbg + its `cilium` symlink, cilium-health, cilium-health-responder,
#     cilium-bugtool, cilium-mount, cilium-sysctlfix, hubble, /opt/cni/bin/cilium-cni), compiled from
#     CILIUM_COMMIT with the raised dependencies; and LICENSE.all, regenerated from them;
#   * gops and the CNI loopback plugin, which upstream compiles from source in its runtime image
#     with Go 1.26.8: compiled again from the same releases with upstream's own commands and flags,
#     with the Go below (since 2026-10-10: 1.26.8's standard library has fixed findings);
#   * libssl3t64, openssl and perl-base, raised to the Ubuntu security updates that fix the findings.
# Everything else - the BPF C sources in /var/lib/cilium/bpf, the init scripts, the bash completion,
# the environment, the working directory and the command - is produced by the same make targets and
# the same Dockerfile lines as upstream's images/cilium/Dockerfile `release` stage at that commit.
# How identical it is was checked file by file against the upstream image (ADR 0028, "Verified").
#
# What is built:
#   * source: github.com/cilium/cilium at CILIUM_COMMIT, the commit tag v1.19.8 points at
#     (`git ls-remote https://github.com/cilium/cilium 'refs/tags/v1.19.8^{}'`). Fetched by full
#     commit hash and checked after the checkout, so a moved tag or branch cannot change what is
#     compiled. Not one line of upstream's Go source is changed. git stays in the source tree because
#     upstream's Makefile stamps the version (`cilium-dbg version`) from it.
#   * dependencies: upstream's go.mod/go.sum at that commit with the modules below raised to the
#     first releases that fix the findings, and nothing else changed by hand. modules/ holds the
#     result (identical in app/cilium, app/cilium-operator-generic and app/hubble-relay - the three
#     images are one source tree; scripts/check-cilium-values.sh refuses a difference). Produced
#     with, in a checkout of CILIUM_COMMIT:
#       go get google.golang.org/grpc@v1.83.2 golang.org/x/crypto@v0.55.0
#       go mod tidy
#       go get github.com/gopacket/gopacket@v1.6.1 go.mongodb.org/mongo-driver@v1.17.7 \
#              github.com/google/cel-go@v0.29.0
#       go mod tidy
#       go get golang.org/x/net@v0.60.0 golang.org/x/crypto@v0.57.0
#       go mod tidy
#     The same grpc and x/crypto releases app/talon and app/ksops raised to. Minimal version
#     selection moved what those two require (x/net, x/sys, x/text, genproto, the opentelemetry
#     family, go-control-plane/envoy 1.36 -> 1.37, among others). The second step (2026-10-10, the
#     MEDIUM findings with a fix: gopacket, mongo-driver, cel-go) moved nothing else but
#     antlr4-go/antlr 4.13.0 -> 4.13.1, and dropped stoewer/go-strcase, which cel-go 0.29 no longer
#     needs. The third (the same day, the same x/net and x/crypto as the talon change in this
#     rebuild) moved the rest of golang.org/x (mod, sync, sys, term, text, tools, telemetry) and the
#     go directive to 1.26.0, which x/net 0.60 requires. A go directive of 1.26 would also switch the
#     binaries to Go 1.26's GODEBUG defaults (urlstrictcolons, tlssecpmlkem, cryptocustomrand among
#     them) - behaviour upstream's go 1.25.0 build does not have - so go.mod carries
#     `godebug default=go1.25` by hand right below it: the defaults stay those of upstream's build
#     (`go version -m` on a binary shows DefaultGODEBUG). `go mod tidy` keeps the line.
#     `diff` against upstream's go.mod at CILIUM_COMMIT shows the whole set. Upstream builds from
#     vendor/ (-mod=vendor), so vendor/ is regenerated from the raised go.mod with `go mod vendor`
#     after `go mod download` has checked every module against the hashes in go.sum and
#     `go mod verify` has checked the extracted copies against them (the public checksum database is
#     consulted only for a module go.sum does not list, and go.sum lists them all).
#   * upstream's own unit tests for the packages the raised modules reach - the Envoy xDS server and
#     its go-control-plane types, Hubble (observer, peer, relay, parser, the CEL flow filters), the
#     monitor's packet decoding and the datapath probes (gopacket), cilium-health, the CNI
#     plugin, cilium-dbg and the Hubble CLI - run in the builder against the raised dependencies,
#     with --network=none: no tests, no image (as app/api, app/talon, app/ksops). Not the whole
#     suite: upstream's `make unit-tests` over all of ./... takes longer than this repository's CI
#     budget, and its privileged half needs a kernel this build does not get.
#   * the binaries with upstream's make targets (CGO off, -s -w, upstream's ldflags and build tags),
#     so `cilium-dbg version` reads "1.19.8 5791d208 <commit date> go1.26.9" - upstream's string but
#     for the Go release (upstream's says go1.26.8; the Go below is the one change of toolchain). One
#     ldflag is added, for scanners: the Go build info records the main module as the pseudo-version
#     "v0.0.0-<date>-5791d208dda4+dirty" (the tree differs from the tag by go.mod/go.sum/vendor), and
#     Trivy compares Cilium's own advisories against that as if it were older than every release -
#     four phantom findings per binary, among them fixes from 2022. `-X .../pkg/version.Version=v1.19.8`
#     is the version Trivy reads from ldflags instead (the way upstream's hubble Makefile already
#     stamps hubble), so Cilium advisories are matched against 1.19.8, as for upstream's binaries,
#     and stay visible. It changes nothing at run time: pkg/version's init() assigns that variable
#     before anything reads it, and `cilium-dbg version` is byte-for-byte the same with or without it.
#   * runtime: quay.io/cilium/cilium-runtime at the digest upstream's Dockerfile pins at
#     CILIUM_COMMIT, plus libcilium.so, cilium-envoy and cilium-envoy-starter from the cilium-envoy
#     image at the digest upstream pins, exactly as upstream assembles them.
#
# Bumping: set CILIUM_COMMIT (and the three bases below) to what upstream's images/cilium/Dockerfile
# pins at the newer release's commit, read the upstream diff, regenerate modules/ in all three
# directories with the commands above (drop any raise the release has caught up with - if it carries
# all of them, this image can go and the upstream one comes back), set GOPS_COMMIT and
# CNI_PLUGINS_COMMIT to the releases upstream's images/runtime/build-gops.sh and build-cni.sh name
# at that commit (or drop the tools stage once upstream's runtime has a Go without fixed findings),
# keep cilium_version / targetRevision in step (ADR 0008), push.
#
# Bases pinned by tag and digest (ADR 0008), resolved from the registries' index manifests:
#   golang:1.26.9                     docker.io  (the same pin as the talon change in this rebuild;
#                                                 1.26.8's standard library has fixed findings, HIGH
#                                                 among them)
#   cilium-runtime:ccc1a8e2...        quay.io    (upstream's CILIUM_RUNTIME_IMAGE at CILIUM_COMMIT)
#   cilium-envoy:v1.37.6-...          quay.io    (upstream's CILIUM_ENVOY_IMAGE at CILIUM_COMMIT, also
#                                                 the chart's envoy.image)
FROM quay.io/cilium/cilium-envoy:v1.37.6-1789133542-cbec91f666af0bf742da986d43832932dbb26b82@sha256:af7382699576b9e65e9184efa52eeca0b58aea70ad6e511bf260c91d9f740463 AS cilium-envoy

FROM docker.io/library/golang:1.26.9@sha256:d7722066f0b60ceccb6c0643cbed1f5f9e15506ac237146c95333504d7805d89 AS tools
# gops and the CNI loopback plugin as upstream's images/runtime/build-gops.sh and build-cni.sh at
# CILIUM_COMMIT build them - the same releases, `go build` with the same flags - but with this
# stage's Go instead of upstream's 1.26.8, fetched by the commit each tag points at instead of a tag
# tarball. -buildvcs=false: upstream builds from a tarball, so its build info carries no VCS
# stamp, and a stamp from a tagless shallow checkout would record a pseudo-version for scanners.
ARG GOPS_COMMIT=a2d8f7790eac63a6668583a060cb45903410a91b
ARG CNI_PLUGINS_COMMIT=adc3e6b5b581638afbd194cf2e9319ecbb0151a1
WORKDIR /go/src/github.com/google/gops
# google/gops tag v0.3.29.
RUN git init -q . \
 && git remote add origin https://github.com/google/gops.git \
 && git fetch -q --depth 1 origin "$GOPS_COMMIT" \
 && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$GOPS_COMMIT" \
 && CGO_ENABLED=0 go build -buildvcs=false -ldflags "-s -w" -o /out/usr/bin/gops github.com/google/gops \
 && go version -m /out/usr/bin/gops | grep -q 'GOARCH=amd64' \
 && go version /out/usr/bin/gops | grep -q ': go1\.26\.9$'
WORKDIR /go/src/github.com/containernetworking/cni
# containernetworking/plugins tag v1.9.1; built from its vendor/, as upstream's script does.
RUN git init -q . \
 && git remote add origin https://github.com/containernetworking/plugins.git \
 && git fetch -q --depth 1 origin "$CNI_PLUGINS_COMMIT" \
 && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$CNI_PLUGINS_COMMIT" \
 && CGO_ENABLED=0 go build -buildvcs=false -o /out/cni/loopback \
      -ldflags "-s -w -X github.com/containernetworking/plugins/pkg/utils/buildversion.BuildVersion=v1.9.1" \
      ./plugins/main/loopback \
 && go version -m /out/cni/loopback | grep -q 'GOARCH=amd64' \
 && go version /out/cni/loopback | grep -q ': go1\.26\.9$' \
 && /out/cni/loopback --version 2>&1 | grep -qx 'CNI loopback plugin v1\.9\.1'

FROM docker.io/library/golang:1.26.9@sha256:d7722066f0b60ceccb6c0643cbed1f5f9e15506ac237146c95333504d7805d89 AS deps
# cilium/cilium tag v1.19.8 (annotated tag 9f826a3d..., commit below).
ARG CILIUM_COMMIT=5791d208dda456da8d08e9389c3d22514dc2db77
# Upstream's path: the Makefiles and a few tests derive paths from it.
WORKDIR /go/src/github.com/cilium/cilium
# Fetch exactly one commit by its hash (GitHub serves any reachable commit by id), then refuse to go
# on unless that is what was checked out.
RUN git init -q . \
 && git remote add origin https://github.com/cilium/cilium.git \
 && git fetch -q --depth 1 origin "$CILIUM_COMMIT" \
 && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$CILIUM_COMMIT"
COPY modules/go.mod modules/go.sum ./
# The module cache is dropped once vendor/ is written: everything after this builds from vendor/
# (upstream's -mod=vendor, and Go's default when vendor/modules.txt is consistent), and the layer -
# which CI caches - shrinks from 1.2 GB to the 0.4 GB of vendor/.
RUN go mod download && go mod verify \
 && rm -rf vendor && go mod vendor \
 && go clean -modcache

FROM deps AS test
# --network=none: upstream's tests, run against dependencies we raised; every module is already in
# vendor/. Unprivileged tests only (PRIVILEGED_TESTS unset), as upstream's `make unit-tests`.
RUN --network=none go test -mod=vendor -count=1 -timeout 1200s \
      ./pkg/envoy/... ./pkg/hubble/... ./pkg/health/... ./plugins/cilium-cni/... \
      ./cilium-dbg/... ./hubble/... ./pkg/monitor/... ./pkg/datapath/linux/probes/... \
 && touch /tested

FROM deps AS build
# Depending on the test stage's marker is what makes BuildKit run it (see app/api/Dockerfile).
COPY --from=test /tested /tmp/tested
# Upstream's builder stage, without the debug-symbol split (upstream strips the result as well).
ARG SCANNER_VERSION_LDFLAG="-X github.com/cilium/cilium/pkg/version.Version=v1.19.8"
# GIT_VERSION as upstream's Makefile.defs computes it (`git show -s --format='%h %aI'`), but
# with the UTC offset spelled +00:00: the golang image's git 2.47 prints a UTC author date as "Z",
# the git upstream's builder ran printed "+00:00", and the version string should be upstream's.
RUN GIT_VERSION="$(git show -s --format='%h %aI' | sed 's/Z$/+00:00/')" \
 && make GIT_VERSION="$GIT_VERSION" GOARCH=amd64 DESTDIR=/out PKG_BUILD=1 EXTRA_GO_BUILD_LDFLAGS="$SCANNER_VERSION_LDFLAG" \
      build-container install-container-binary \
 && make GIT_VERSION="$GIT_VERSION" GOARCH=amd64 DESTDIR=/out PKG_BUILD=1 EXTRA_GO_BUILD_LDFLAGS="$SCANNER_VERSION_LDFLAG" \
      install-bash-completion licenses-all \
 && mv LICENSE.all /out/LICENSE.all \
 && cp images/cilium/init-container.sh plugins/cilium-cni/install-plugin.sh \
       plugins/cilium-cni/cni-uninstall.sh /out/ \
 && /out/usr/bin/cilium-dbg version 2>/dev/null | grep -qx 'Client: 1\.19\.8 5791d208 2026-09-15T18:23:52+00:00 go version go1\.26\.9 linux/amd64'

FROM quay.io/cilium/cilium-runtime:ccc1a8e2e299ac61182dcaddbf65cf324ec509b7@sha256:02a3f11fa19cfc9d990cf84ec3bba9f368c4644a1a7b1b6e6c21f29f95db45f6
# The OS findings: OpenSSL (CVE-2026-84782, HIGH) and perl-base 5.38.2-3.2ubuntu0.4 (CVE-2026-15534,
# CVE-2026-19487, MEDIUM; fixed in 5.38.2-3.2ubuntu0.6, already in the same snapshot). Only those
# packages, only the fixed versions, from the Ubuntu snapshot service at a fixed date, so the package
# index this resolves against cannot move under a rebuild (apt still checks the archive's
# signatures). Upstream's cilium-runtime runs `apt-get upgrade` when it is rebuilt; this is that,
# narrowed to the findings. The line goes when the cilium-runtime digest upstream pins at a newer
# CILIUM_COMMIT carries these versions (or newer).
RUN printf '%s\n' 'Types: deb' 'URIs: http://snapshot.ubuntu.com/ubuntu/20261002T000000Z/' \
      'Suites: noble-security' 'Components: main' \
      'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' > /tmp/snapshot.sources \
 && apt-get -q -o Dir::Etc::SourceList=/tmp/snapshot.sources -o Dir::Etc::SourceParts=/dev/null update \
 && apt-get -q -y -o Dir::Etc::SourceList=/tmp/snapshot.sources -o Dir::Etc::SourceParts=/dev/null \
      install --no-install-recommends --only-upgrade \
      libssl3t64=3.0.13-0ubuntu3.16 openssl=3.0.13-0ubuntu3.16 perl-base=5.38.2-3.2ubuntu0.6 \
 && rm -rf /tmp/snapshot.sources /var/lib/apt/lists/*
# gops and loopback over the runtime's copies (the same releases, the newer Go; see the tools stage).
COPY --from=tools /out/usr/bin/gops /usr/bin/gops
COPY --from=tools /out/cni/loopback /cni/loopback
# From here on, upstream's images/cilium/Dockerfile `release` stage at CILIUM_COMMIT, line for line.
LABEL maintainer="maintainer@cilium.io"
RUN echo ". /etc/profile.d/bash_completion.sh" >> /etc/bash.bashrc
COPY --from=cilium-envoy /usr/lib/libcilium.so /usr/lib/libcilium.so
COPY --from=cilium-envoy /usr/bin/cilium-envoy /usr/bin/cilium-envoy-starter /usr/bin/
# When used within the Cilium container, Hubble CLI should target the
# local unix domain socket instead of Hubble Relay.
ENV HUBBLE_SERVER=unix:///var/run/cilium/hubble.sock
COPY --from=build /out /
WORKDIR /home/cilium

ENV INITSYSTEM="SYSTEMD"
CMD ["/usr/bin/cilium-dbg"]
LABEL org.opencontainers.image.title="self-defending-portfolio cilium" \
      org.opencontainers.image.description="Cilium agent v1.19.8 built from the pinned upstream release with fixed dependencies" \
      org.opencontainers.image.source="https://github.com/HubertMJ/self-defending-portfolio" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="v1.19.8"
