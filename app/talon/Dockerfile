# Falco Talon, built here from a pinned upstream commit (ADR 0023). Built, Trivy-gated, SBOM'd and
# signed by .github/workflows/build-images.yml like every image under app/ (ADR 0016), so Kyverno can
# demand our signature on the one workload in falco-response that holds Kubernetes API permissions.
#
# Why not the upstream image: 0.3.0 (2025-02-05) is still Talon's latest release, and its image
# carries 24 CRITICAL+HIGH findings in the live cluster (4/51 with today's Trivy DB), every one of
# them in a Go dependency or the Go standard library it was compiled with, every one fixed upstream.
# No release will bring those fixes until upstream tags one, so the only honest way to remove them
# is to compile the same program with fixed dependencies - not to ignore them in the scanner.
#
# What is built:
#   * source: github.com/falcosecurity/falco-talon at TALON_COMMIT, the head of `main` on 2026-09-05
#     (v0.3.0 + 132 commits: bug fixes and dependency bumps, no configuration key renamed or removed;
#     it also carries the k8sevents namespace fix, 87dd820, which ADR 0013 waits for - the notifier
#     stays off here until that is decided separately). Fetched by full commit hash and checked
#     after the checkout, so a moved branch or tag cannot change what is compiled.
#   * dependencies: upstream's go.mod/go.sum at that commit, with three modules raised to the first
#     release that fixes the findings in the binary, and nothing else changed by hand. modules/ holds
#     the result; it replaces upstream's two files before `go mod download`, and `go mod verify`
#     checks every module against go.sum (and go.sum against the public checksum database, which the
#     golang image enables by default). Produced with, in a checkout of TALON_COMMIT:
#       go get google.golang.org/grpc@v1.83.2 golang.org/x/crypto@v0.55.0 \
#              github.com/cilium/cilium@v1.17.15
#       go get google.golang.org/grpc/stats/opentelemetry@none   # the old split-out module; grpc
#       go mod tidy                                               # now ships that package itself
#     cilium v1.17.15 rather than 1.19: the smallest jump that fixes both Cilium advisories, so the
#     cilium networkpolicy actionner compiles against an API closest to the one upstream tested.
#     Minimal version selection and `go mod tidy` then raised further transitive modules (the
#     cloud.google.com and opentelemetry families, k8s.io/kubectl, among others) to what those
#     three require; `diff` against upstream's go.mod at TALON_COMMIT shows the whole set.
#   * upstream's own test suite runs in the builder (`go vet` + `go test`) against the raised
#     dependencies: no tests, no image (as app/api).
#   * the binary as upstream builds it (.ko.yaml): CGO off, -trimpath, stripped, the same
#     configuration.Git* version variables mageFile.go sets, so `falco-talon version` names the
#     commit. Static, so the runtime needs no libc.
#   * runtime: distroless `static` nonroot (uid 65532), the same base and user as app/api, and the
#     same uid the upstream ko/chainguard image runs as, so talon-deployment.yaml's pod context does
#     not change. ENTRYPOINT is the binary, as in the upstream image: the Deployment passes `server
#     ...` and tests/scenarios/offline.sh passes `rules check ...`.
#
# Bases pinned by tag and digest (ADR 0008), resolved from the registries' index manifests; both are
# the pins app/api already uses:
#   golang:1.26.8                          docker.io
#   distroless/static-debian13:nonroot     gcr.io
FROM docker.io/library/golang:1.26.8@sha256:0f063af2d465d8dcae54cce04278ada488b96f77b42449c8d071e47d016cc65a AS deps
ARG TALON_COMMIT=d273e352f80e114954f40c9843fd0a1b71a30d57
WORKDIR /src
# Fetch exactly one commit by its hash (GitHub serves any reachable commit by id), then refuse to go
# on unless that is what was checked out.
RUN git init -q . \
 && git remote add origin https://github.com/falcosecurity/falco-talon.git \
 && git fetch -q --depth 1 origin "$TALON_COMMIT" \
 && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$TALON_COMMIT"
COPY modules/go.mod modules/go.sum ./
RUN go mod download && go mod verify

FROM deps AS test
# -race needs cgo, which the golang image has; the shipped binary below does not use it.
# --network=none: these are upstream's tests, run against dependencies we raised, and a test that
# reaches out (a notifier or an output dialling a real endpoint) must fail here rather than talk to
# the internet from the build. Every module is already in the cache from `go mod download` above.
RUN --network=none CGO_ENABLED=1 go vet ./... && CGO_ENABLED=1 go test -race -count=1 ./... && touch /tested

FROM deps AS build
ARG TALON_COMMIT=d273e352f80e114954f40c9843fd0a1b71a30d57
# `git describe` of TALON_COMMIT. Stated, not computed: the depth-1 fetch has no tags to describe.
ARG TALON_VERSION=v0.3.0-132-gd273e35
# Depending on the test stage's marker is what makes BuildKit run it (see app/api/Dockerfile).
COPY --from=test /tested /tmp/tested
# BuildDate is the commit's own date, not the build's, so two builds of this file stay identical.
# GitTreeState is "dirty" on purpose: go.mod/go.sum are not upstream's at this commit.
RUN pkg=github.com/falcosecurity/falco-talon/configuration \
 && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFLAGS=-buildvcs=false \
    go build -trimpath -o /out/falco-talon \
      -ldflags="-s -w -buildid= \
        -X ${pkg}.GitVersion=${TALON_VERSION} \
        -X ${pkg}.GitCommit=${TALON_COMMIT} \
        -X ${pkg}.GitTreeState=dirty \
        -X ${pkg}.BuildDate=2026-09-05T00:00:00Z" \
      . \
 && /out/falco-talon version

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/falco-talon /usr/bin/falco-talon
USER 65532:65532
# 2803: the HTTP endpoint Falcosidekick posts alerts to (/) and the probes read (/healthz).
EXPOSE 2803
LABEL org.opencontainers.image.title="self-defending-portfolio talon" \
      org.opencontainers.image.description="Falco Talon built from a pinned upstream commit with fixed dependencies" \
      org.opencontainers.image.source="https://github.com/HubertMJ/self-defending-portfolio" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="v0.3.0-132-gd273e35"
ENTRYPOINT ["/usr/bin/falco-talon"]
