# The Trivy Operator (ADR 0014), built here from the pinned upstream release commit with fixed
# dependencies (ADR 0025). Built, Trivy-gated, SBOM'd and signed by .github/workflows/build-images.yml
# like every image under app/ (ADR 0016).
#
# Only the operator. The scan Jobs and the built-in Trivy server run aquasec/trivy itself (0.75.0,
# clean, cluster/apps/trivy-operator.yaml), which this image does not replace.
#
# Why not the upstream image: aquasec/trivy-operator:0.34.0 (chart 0.36.0) is the newest release. It
# carries 4 HIGH with Trivy 0.75.0 on 2026-10-02: two in grpc (fixed in 1.83.2) and two in Alpine's
# OpenSSL (libcrypto3, libssl3), which the operator does not use - it is a static Go binary on an
# Alpine base.
#
# What is built:
#   * source: github.com/aquasecurity/trivy-operator at TRIVY_OPERATOR_COMMIT, the commit tag v0.34.0
#     points at (`git ls-remote https://github.com/aquasecurity/trivy-operator refs/tags/v0.34.0`).
#     Fetched by full commit hash and checked after the checkout, so a moved tag cannot change what is
#     compiled. Not one line of upstream's Go source is changed.
#   * dependencies: upstream's go.mod/go.sum at that commit with the modules raised that carry findings
#     in the binary, and nothing else changed by hand. modules/ holds the result; it replaces upstream's two files before `go mod
#     download`, and `go mod verify` checks every module against go.sum (and go.sum against the public
#     checksum database, which the golang image enables by default). Produced with, in a checkout of
#     TRIVY_OPERATOR_COMMIT:
#       go get google.golang.org/grpc@v1.83.2
#       go mod tidy
#     The grpc release app/talon and app/ksops raised to. Minimal version selection then moved three
#     modules grpc requires (two gcp detectors, go-spiffe). Then, for the MEDIUM and LOW findings with
#     a fix (2026-10-10), on top of that result:
#       go get github.com/containerd/containerd/v2@v2.3.6 golang.org/x/net@v0.60.0 \
#              go.opentelemetry.io/otel/sdk@v1.45.0 \
#              go.opentelemetry.io/otel/exporters/otlp/otlptrace@v1.45.0 \
#              go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc@v1.45.0
#       go mod tidy
#     containerd v2.3.6, the patch release of upstream's 2.3 line that fixes both advisories; x/net
#     v0.60.0 requires x/crypto v0.57.0, which also fixes x/crypto's two MEDIUM findings. `diff`
#     against upstream's go.mod at TRIVY_OPERATOR_COMMIT shows the whole set. Trivy itself (the library the operator embeds for
#     config audits and report types) and the Kubernetes libraries are upstream's versions.
#   * upstream's own unit tests (`mage test:unit`: `go test -short -timeout 60s ./...`, with
#     magefile.go's CGO_ENABLED=0 and GOEXPERIMENT=jsonv2) run in the builder against the raised
#     dependencies, with --network=none: no tests, no image. The envtest and integration suites skip
#     themselves under -short, as upstream's unit target intends.
#   * the binary as upstream's release builds it (.goreleaser.yaml): CGO off, GOEXPERIMENT=jsonv2 (the
#     Trivy library needs encoding/json/v2), goreleaser's default -s -w and main.* version variables,
#     plus -trimpath and an empty build id.
#   * runtime: distroless `static` nonroot, the base app/api, app/talon and app/ksops use, with the
#     binary at /usr/local/bin/trivy-operator as in upstream's image. The chart sets no command, so
#     ENTRYPOINT is the binary, as upstream's. The chart pins the pod to uid 65534
#     (cluster/apps/trivy-operator.yaml); upstream's image user (10000) is not used here either.
#
# Bumping: set TRIVY_OPERATOR_COMMIT to the commit of a newer release tag (and the chart to the matching
# chart release), regenerate modules/ with the commands above (drop any raise the release has caught up
# with - if it carries all of them, this image can go and the upstream one comes back), push.
#
# Bases pinned by tag and digest (ADR 0008):
#   golang:1.26.9                          docker.io   (as app/talon; 1.26.8's standard library has
#                                                       fixed findings)
#   distroless/static-debian13:nonroot     gcr.io      (as app/api, app/talon and app/ksops)
FROM docker.io/library/golang:1.26.9@sha256:d7722066f0b60ceccb6c0643cbed1f5f9e15506ac237146c95333504d7805d89 AS deps
# aquasecurity/trivy-operator tag v0.34.0.
ARG TRIVY_OPERATOR_COMMIT=7107830178ae50e96e9f09d98976e51e6152759f
WORKDIR /src
# Fetch exactly one commit by its hash (GitHub serves any reachable commit by id), then refuse to go
# on unless that is what was checked out.
RUN git init -q . \
 && git remote add origin https://github.com/aquasecurity/trivy-operator.git \
 && git fetch -q --depth 1 origin "$TRIVY_OPERATOR_COMMIT" \
 && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$TRIVY_OPERATOR_COMMIT"
COPY modules/go.mod modules/go.sum ./
RUN go mod download && go mod verify

FROM deps AS test
# --network=none: upstream's tests against dependencies we raised; a test that tried to pull an image
# or a DB must fail here rather than talk to the internet from the build.
RUN --network=none CGO_ENABLED=0 GOEXPERIMENT=jsonv2 go test -short -timeout 60s -count=1 ./... \
 && touch /tested

FROM deps AS build
ARG TRIVY_OPERATOR_COMMIT=7107830178ae50e96e9f09d98976e51e6152759f
# Depending on the test stage's marker is what makes BuildKit run it (see app/api/Dockerfile).
COPY --from=test /tested /tmp/tested
# date is the commit's own date, not the build's, so two builds of this file stay identical.
RUN CGO_ENABLED=0 GOEXPERIMENT=jsonv2 GOOS=linux GOARCH=amd64 GOFLAGS=-buildvcs=false \
    go build -trimpath -o /out/trivy-operator \
      -ldflags="-s -w -buildid= \
        -X main.version=0.34.0 \
        -X main.commit=${TRIVY_OPERATOR_COMMIT} \
        -X main.date=2026-08-24T10:33:31Z" \
      ./cmd/trivy-operator \
 && go version -m /out/trivy-operator | grep -q 'GOEXPERIMENT=jsonv2'

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/trivy-operator /usr/local/bin/trivy-operator
USER 65532:65532
LABEL org.opencontainers.image.title="self-defending-portfolio trivy-operator" \
      org.opencontainers.image.description="Trivy Operator built from the pinned upstream release with fixed dependencies" \
      org.opencontainers.image.source="https://github.com/HubertMJ/self-defending-portfolio" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="0.34.0"
ENTRYPOINT ["/usr/local/bin/trivy-operator"]
