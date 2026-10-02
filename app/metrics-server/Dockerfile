# metrics-server, the resource metrics API behind `kubectl top` (docs/bootstrap.md 6), built here from
# the pinned upstream release commit with fixed dependencies (ADR 0025). Built, Trivy-gated, SBOM'd
# and signed by .github/workflows/build-images.yml like every image under app/ (ADR 0016).
#
# Why not the upstream image: v0.9.0 (2026-07-13) is metrics-server's newest release and the one k3s
# v1.35.9+k3s1 bundles (rancher/mirrored-metrics-server:v0.9.0). It is compiled with Go 1.26.4 against
# dependencies that have fixes since: 14 HIGH with Trivy 0.75.0 on 2026-10-02 (9 in the Go standard
# library, fixed in 1.26.6; x/crypto, x/text and three in grpc), 3 in the cluster's last scan. k3s
# pins the image inside its binary, so the only way to run a fixed build is to stop k3s deploying it
# (`disable: [metrics-server]`, ansible/roles/k3s) and deploy this one from cluster/infra/metrics-server.
#
# What is built:
#   * source: github.com/kubernetes-sigs/metrics-server at METRICS_SERVER_COMMIT, the commit tag v0.9.0
#     points at (`git ls-remote https://github.com/kubernetes-sigs/metrics-server refs/tags/v0.9.0`).
#     Fetched by full commit hash and checked after the checkout, so a moved tag cannot change what is
#     compiled. Not one line of upstream's Go source is changed.
#   * dependencies: upstream's go.mod/go.sum at that commit with two modules raised to the first
#     releases that fix the findings, and nothing else changed by hand. modules/ holds the result; it
#     replaces upstream's two files before `go mod download`, and `go mod verify` checks every module
#     against go.sum (and go.sum against the public checksum database, which the golang image enables
#     by default). Produced with, in a checkout of METRICS_SERVER_COMMIT:
#       go get golang.org/x/crypto@v0.55.0 google.golang.org/grpc@v1.83.2
#       go mod tidy
#     The same releases app/talon and app/ksops raised to. Minimal version selection then moved what
#     those two require - x/text to v0.41.0 (which fixes its finding), x/net, x/sys, x/term, x/sync,
#     x/mod, x/tools; `diff` against upstream's go.mod at METRICS_SERVER_COMMIT shows the whole set.
#     The Kubernetes libraries (apiserver, client-go, component-base, metrics) are upstream's.
#   * upstream's own unit tests (`make test-unit`: `go test --test.short -race ./pkg/... ./cmd/...`)
#     run in the builder against the raised dependencies, with --network=none: no tests, no image.
#   * the binary as upstream's Makefile builds it: CGO off, -mod=readonly, -trimpath, the same
#     k8s.io/client-go/pkg/version variables (what `--version` prints), plus -s and an empty build id.
#     The Go standard library is the toolchain's: 1.26.8 instead of 1.26.4.
#   * runtime: distroless `static` nonroot, the base app/api, app/talon and app/ksops use. Upstream's
#     image is distroless `static` too, with the binary at /metrics-server and USER 65534; both are
#     kept, so the Deployment's args and its runAsUser are what k3s's manifest used.
#
# Bumping: set METRICS_SERVER_COMMIT to the commit of a newer release tag, regenerate modules/ from
# that commit's go.mod/go.sum with the commands above (drop any raise the release has caught up with),
# compare upstream's manifests/ with cluster/infra/metrics-server, push.
#
# Bases pinned by tag and digest (ADR 0008); both are the pins app/api, app/talon and app/ksops use:
#   golang:1.26.8                          docker.io
#   distroless/static-debian13:nonroot     gcr.io
FROM docker.io/library/golang:1.26.8@sha256:0f063af2d465d8dcae54cce04278ada488b96f77b42449c8d071e47d016cc65a AS deps
# kubernetes-sigs/metrics-server tag v0.9.0.
ARG METRICS_SERVER_COMMIT=2a7c4b2c7d46552ff47f4aeaa3a735c582587ecd
WORKDIR /src
# Fetch exactly one commit by its hash (GitHub serves any reachable commit by id), then refuse to go
# on unless that is what was checked out.
RUN git init -q . \
 && git remote add origin https://github.com/kubernetes-sigs/metrics-server.git \
 && git fetch -q --depth 1 origin "$METRICS_SERVER_COMMIT" \
 && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$METRICS_SERVER_COMMIT"
COPY modules/go.mod modules/go.sum ./
RUN go mod download && go mod verify

FROM deps AS test
# --network=none: upstream's tests against dependencies we raised; nothing in them needs the network.
# -race needs cgo, which the golang image has; the shipped binary below does not use it.
RUN --network=none CGO_ENABLED=1 go test --test.short -race -count=1 ./pkg/... ./cmd/... \
 && touch /tested

FROM deps AS build
ARG METRICS_SERVER_COMMIT=2a7c4b2c7d46552ff47f4aeaa3a735c582587ecd
# Depending on the test stage's marker is what makes BuildKit run it (see app/api/Dockerfile).
COPY --from=test /tested /tmp/tested
# buildDate is the commit's own date, not the build's, so two builds of this file stay identical.
RUN pkg=k8s.io/client-go/pkg/version \
 && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFLAGS=-buildvcs=false \
    go build -mod=readonly -trimpath -o /out/metrics-server \
      -ldflags="-s -w -buildid= \
        -X ${pkg}.gitVersion=v0.9.0 \
        -X ${pkg}.gitCommit=${METRICS_SERVER_COMMIT} \
        -X ${pkg}.buildDate=2026-07-13T10:38:03Z" \
      sigs.k8s.io/metrics-server/cmd/metrics-server \
 && test "$(/out/metrics-server --version)" = v0.9.0

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/metrics-server /metrics-server
# Upstream's user. The Deployment sets its own (cluster/infra/metrics-server/deployment.yaml).
USER 65534:65534
# 10250: the HTTPS port the API server's aggregation layer calls (--secure-port).
EXPOSE 10250
LABEL org.opencontainers.image.title="self-defending-portfolio metrics-server" \
      org.opencontainers.image.description="metrics-server built from the pinned upstream release with fixed dependencies" \
      org.opencontainers.image.source="https://github.com/HubertMJ/self-defending-portfolio" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="v0.9.0"
ENTRYPOINT ["/metrics-server"]
