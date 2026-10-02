# CoreDNS, the cluster DNS server (Service kube-system/kube-dns, 10.43.0.10), built here from the
# pinned upstream release commit with fixed dependencies (ADR 0026), instead of the copy k3s bundles.
# Built, Trivy-gated, SBOM'd and signed by .github/workflows/build-images.yml like every image under
# app/ (ADR 0016). Deployed by the k3s Ansible role as a k3s auto-deploy manifest, not by Argo CD
# (ADR 0026: Argo CD itself needs DNS).
#
# Why not the upstream image: k3s v1.35.9+k3s1 runs rancher/mirrored-coredns-coredns:1.14.7, a
# mirror of CoreDNS's own 1.14.7 release image. Its binary is compiled against
# google.golang.org/grpc v1.83.0, golang.org/x/crypto v0.54.0 and golang.org/x/mod v0.37.0, each
# with a fixed release since, and it records its own module version as the pseudo-version
# v0.0.0-20260819003913-427fc80ed9ca rather than v1.14.7 - so a scanner compares every CoreDNS
# advisory against "v0.0.0" and reports CVEs that 1.14.7 itself fixed (ADR 0026 lists them). 16 HIGH
# with Trivy 0.75.0 on 2026-10-02, 11 of them that version artefact.
#
# What is built:
#   * source: github.com/coredns/coredns at COREDNS_COMMIT, the commit tag v1.14.7 points at
#     (`git ls-remote https://github.com/coredns/coredns refs/tags/v1.14.7`). Fetched by full commit
#     hash and checked after the checkout, so a moved tag or branch cannot change what is compiled.
#     Not one line of upstream's Go source is changed; plugin.cfg (the plugin set) is upstream's.
#   * version: after that check, the checkout gets a local tag v1.14.7 on that same commit, so the Go
#     toolchain stamps the binary's main module as v1.14.7 (+dirty, because modules/ replaces two
#     files - the truth) and a scanner judges CoreDNS's own advisories against the release this
#     really is. Nothing is suppressed: an advisory fixed after 1.14.7 is still reported.
#   * dependencies: upstream's go.mod/go.sum at that commit with three modules raised to the first
#     releases that fix the findings in the binary, and nothing else changed by hand. modules/ holds
#     the result; it replaces upstream's two files before `go mod download`, and `go mod verify`
#     checks every module against go.sum (and go.sum against the public checksum database, which the
#     golang image enables by default). Produced with, in a checkout of COREDNS_COMMIT:
#       go get google.golang.org/grpc@v1.83.2 golang.org/x/crypto@v0.55.0 golang.org/x/mod@v0.40.0
#       go mod tidy
#     grpc and x/crypto are the releases app/talon and app/ksops raised to. Minimal version selection
#     then moved x/net, x/text and x/tools; `diff` against upstream's go.mod shows the whole set.
#     miekg/dns, the Kubernetes client and every plugin's own dependencies are upstream's, untouched.
#   * upstream's tests (`go vet` + `go test -race`, every package, grouped as upstream's CI does) run
#     in the builder against the raised dependencies, with --network=none and as a non-root user: no
#     tests, no image (as app/api, app/talon, app/ksops). One test needs 8.8.8.8 and is skipped.
#   * the binary as upstream's Makefile builds it: CGO off, -tags grpcnotrace, -ldflags "-s -w -X
#     coremain.GitCommit=<short commit>", plus -trimpath and an empty build id. `coredns -version`
#     and `coredns -plugins` print what upstream's do, Go version aside.
#   * port 53: as upstream's image, the binary carries the file capability cap_net_bind_service=ep,
#     so it binds :53 as uid 65532 when the pod adds exactly NET_BIND_SERVICE (k3s's manifest and
#     ours do; restricted Pod Security allows that one capability). Set by setcap.go - the same
#     xattr upstream's `setcap` writes - rather than by libcap2-bin from an unpinned Debian mirror.
#   * runtime: distroless `static` nonroot (uid 65532), the base and user app/api, app/talon and
#     app/ksops use; upstream's image is distroless static-debian12 with the same user. The binary sits
#     at /coredns, upstream's path and entrypoint, so the Deployment's args do not change.
#
# Bumping: set COREDNS_COMMIT and COREDNS_VERSION to a newer release tag, read the upstream diff,
# regenerate modules/ from that commit's go.mod/go.sum with the commands above (drop any raise the
# release has caught up with), push. If k3s's own bundled CoreDNS has caught up and scans clean, the
# k3s role can go back to it (ADR 0026, rollback).
#
# Bases pinned by tag and digest (ADR 0008), resolved from the registries' index manifests; both are
# the pins app/api, app/talon and app/ksops already use:
#   golang:1.26.8                          docker.io
#   distroless/static-debian13:nonroot     gcr.io
FROM docker.io/library/golang:1.26.8@sha256:0f063af2d465d8dcae54cce04278ada488b96f77b42449c8d071e47d016cc65a AS deps
# coredns/coredns tag v1.14.7.
ARG COREDNS_COMMIT=427fc80ed9ca47f354585eb30a3f1332950856c4
ARG COREDNS_VERSION=v1.14.7
WORKDIR /src
# Fetch exactly one commit by its hash (GitHub serves any reachable commit by id), refuse to go on
# unless that is what was checked out, and only then name it with the release tag (local only).
RUN git init -q . \
 && git remote add origin https://github.com/coredns/coredns.git \
 && git fetch -q --depth 1 origin "$COREDNS_COMMIT" \
 && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$COREDNS_COMMIT" \
 && git tag "$COREDNS_VERSION" "$COREDNS_COMMIT" \
 && grep -q "CoreVersion = \"${COREDNS_VERSION#v}\"" coremain/version.go
COPY modules/go.mod modules/go.sum ./
RUN go mod download && go mod verify

FROM deps AS test
# Upstream's tests the way upstream's CI runs them (.github/workflows/go.test.yml): `go test -race`
# per top-level directory in turn, which also keeps the timing-sensitive server tests from competing
# with every other package for the CPU. Plus `go vet` over everything.
#   * --network=none: run against dependencies we raised, a test that tried to reach the internet
#     must fail here rather than do so from the build. Loopback still works, which is all the
#     server/forward tests use - except TestZoneExternalCNAMELookupWithProxy, which forwards to
#     8.8.8.8 and needs its real answer; it is skipped by name, the only test skipped.
#   * as a non-root user, as on upstream's CI runners: TestDefaultLoader checks that an unreadable
#     Corefile is refused, and root can read anything.
# Every module is already in the cache from `go mod download`. -race needs cgo, which the golang
# image has; the shipped binary below does not use it.
RUN chown -R 65532:65532 /src
USER 65532:65532
ENV HOME=/tmp GOCACHE=/tmp/go-build
RUN --network=none CGO_ENABLED=1 go vet -tags grpcnotrace ./... \
 && for dir in request core coremain plugin test; do \
      (cd "$dir" && CGO_ENABLED=1 go test -race -count=1 -tags grpcnotrace \
        -skip '^TestZoneExternalCNAMELookupWithProxy$' ./...) || exit 1; \
    done \
 && touch /tmp/tested

FROM deps AS build
ARG COREDNS_VERSION=v1.14.7
# Depending on the test stage's marker is what makes BuildKit run it (see app/api/Dockerfile).
COPY --from=test /tmp/tested /tmp/tested
COPY setcap.go /tmp/setcap/main.go
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -tags grpcnotrace \
      -ldflags "-s -w -buildid= -X github.com/coredns/coredns/coremain.GitCommit=$(git rev-parse --short=7 HEAD)" \
      -o /out/coredns . \
 && go version -m /out/coredns | grep -E "^[[:space:]]+mod[[:space:]]+github.com/coredns/coredns[[:space:]]+${COREDNS_VERSION}(\+dirty)?[[:space:]]" \
 && (cd /tmp/setcap && CGO_ENABLED=0 go run main.go /out/coredns) \
 && /out/coredns -version | grep -qx "CoreDNS-${COREDNS_VERSION#v}"

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
# Upstream's path and entrypoint; COPY keeps the security.capability xattr set above.
COPY --from=build /out/coredns /coredns
USER 65532:65532
WORKDIR /
EXPOSE 53 53/udp
LABEL org.opencontainers.image.title="self-defending-portfolio coredns" \
      org.opencontainers.image.description="CoreDNS built from the pinned upstream release with fixed dependencies" \
      org.opencontainers.image.source="https://github.com/HubertMJ/self-defending-portfolio" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="v1.14.7"
ENTRYPOINT ["/coredns"]
