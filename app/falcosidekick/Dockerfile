# Falcosidekick, the alert fan-out between Falco and Falco Talon / the portfolio API (ADR 0013),
# built here from the pinned upstream release commit with fixed dependencies (ADR 0025). Built,
# Trivy-gated, SBOM'd and signed by .github/workflows/build-images.yml like every image under app/
# (ADR 0016).
#
# Why not the upstream image: falcosecurity/falcosidekick:2.35.0 (2026-08-31) is the newest release,
# and the Falcosidekick chart 0.14.0 runs it (cluster/apps/falco-response.yaml). It carries 3 CRITICAL
# + 12 HIGH with Trivy 0.75.0 on 2026-10-02: amqp091-go (3 CRITICAL + 7 HIGH, fixed in 1.13.0),
# x/crypto, grpc (two), and Alpine's OpenSSL (libcrypto3, libssl3) - every one with a released fix
# that 2.35.0 has not taken. No release will bring those fixes until upstream tags one.
#
# What is built:
#   * source: github.com/falcosecurity/falcosidekick at FALCOSIDEKICK_COMMIT, the commit tag 2.35.0
#     points at (`git ls-remote https://github.com/falcosecurity/falcosidekick refs/tags/2.35.0`).
#     Fetched by full commit hash and checked after the checkout, so a moved tag cannot change what is
#     compiled. Not one line of upstream's Go source is changed.
#   * dependencies: upstream's go.mod/go.sum at that commit with the modules raised to the first
#     releases that fix the findings, and nothing else changed by hand. modules/ holds the result; it
#     replaces upstream's two files before `go mod download`, and `go mod verify` checks every module
#     against go.sum (and go.sum against the public checksum database, which the golang image enables
#     by default). Produced with, in a checkout of FALCOSIDEKICK_COMMIT:
#       go get github.com/rabbitmq/amqp091-go@v1.13.0 golang.org/x/crypto@v0.55.0 \
#              google.golang.org/grpc@v1.83.2
#       go mod tidy
#     grpc and x/crypto are the releases app/talon and app/ksops raised to. Minimal version selection
#     then moved what those three require (x/net, x/sys, x/text, x/term, x/sync and a few gcp/spiffe
#     modules). Then, for the MEDIUM and LOW findings with a fix (2026-10-10), on top of that result:
#       go get github.com/rabbitmq/amqp091-go@v1.14.0 golang.org/x/net@v0.60.0 \
#              go.opentelemetry.io/otel/sdk@v1.45.0 \
#              go.opentelemetry.io/otel/exporters/otlp/otlptrace@v1.45.0 \
#              go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc@v1.45.0 \
#              go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp@v1.45.0 \
#              go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc@v0.21.0 \
#              go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp@v0.21.0 \
#              go.opentelemetry.io/otel/sdk/log@v0.21.0 \
#              go.opentelemetry.io/contrib/bridges/otelslog@v0.20.0
#       go mod tidy
#     otlploghttp and otelslog carry no finding: they are raised with the log exporter because the
#     otel/log API they compile against changed between v0.19.0 and v0.21.0 (otelslog v0.20.0 is the
#     release built on otel v1.45.0 and log v0.21.0). x/net v0.60.0 requires x/crypto v0.57.0, which
#     also fixes x/crypto's two MEDIUM findings. `diff` against upstream's go.mod at
#     FALCOSIDEKICK_COMMIT shows the whole set.
#   * upstream's own test suite (`make test`: `go vet` + `go test -race`) runs in the builder against
#     the raised dependencies, with --network=none: no tests, no image (as app/talon, app/ksops).
#   * the binary as upstream's release builds it (.goreleaser.yml + Makefile LDFLAGS): CGO off,
#     -trimpath, the same main.* version variables, plus -s -w and an empty build id (stripped,
#     reproducible). Static, so the runtime needs no libc - upstream's Alpine base and its gcompat
#     are what the binary does not use.
#   * runtime: distroless `static` nonroot, the base app/api, app/talon and app/ksops use. It has the
#     CA bundle the HTTPS outputs need (the ones used here are plain HTTP inside the cluster, see
#     cluster/apps/falco-response.yaml) and nothing else. The binary sits at /app/falcosidekick and the
#     working directory is /app, as in upstream's image (WORKDIR ${HOME}/app with HOME unset); the
#     chart sets no command, so ENTRYPOINT is the binary, as upstream's. The chart pins the pod to uid
#     1234 (upstream's user); distroless does not need the user to exist in /etc/passwd.
#
# Bumping: set FALCOSIDEKICK_COMMIT to the commit of a newer release tag, regenerate modules/ from that
# commit's go.mod/go.sum with the commands above (drop any raise the release has caught up with - if it
# carries all of them, this image can go and the upstream one comes back), push.
#
# Bases pinned by tag and digest (ADR 0008):
#   golang:1.26.9                          docker.io   (as app/talon; 1.26.8's standard library has
#                                                       fixed findings)
#   distroless/static-debian13:nonroot     gcr.io      (as app/api, app/talon and app/ksops)
FROM docker.io/library/golang:1.26.9@sha256:d7722066f0b60ceccb6c0643cbed1f5f9e15506ac237146c95333504d7805d89 AS deps
# falcosecurity/falcosidekick tag 2.35.0.
ARG FALCOSIDEKICK_COMMIT=09883e3f55dade3c2ab2a471736ea5519aeac418
WORKDIR /src
# Fetch exactly one commit by its hash (GitHub serves any reachable commit by id), then refuse to go
# on unless that is what was checked out.
RUN git init -q . \
 && git remote add origin https://github.com/falcosecurity/falcosidekick.git \
 && git fetch -q --depth 1 origin "$FALCOSIDEKICK_COMMIT" \
 && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$FALCOSIDEKICK_COMMIT"
COPY modules/go.mod modules/go.sum ./
RUN go mod download && go mod verify

FROM deps AS test
# --network=none: upstream's tests against dependencies we raised; an output test that tried to dial
# a real endpoint must fail here rather than talk to the internet from the build. Every module is
# already in the cache from `go mod download`. -race needs cgo, which the golang image has; the
# shipped binary below does not use it.
RUN --network=none CGO_ENABLED=1 go vet ./... \
 && CGO_ENABLED=1 go test -race -count=1 ./... \
 && touch /tested

FROM deps AS build
ARG FALCOSIDEKICK_COMMIT=09883e3f55dade3c2ab2a471736ea5519aeac418
# Depending on the test stage's marker is what makes BuildKit run it (see app/api/Dockerfile).
COPY --from=test /tested /tmp/tested
# buildDate is the commit's own date, not the build's, so two builds of this file stay identical.
# gitTreeState is "dirty" on purpose: go.mod/go.sum are not upstream's at this commit.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFLAGS=-buildvcs=false \
    go build -trimpath -o /out/falcosidekick \
      -ldflags="-s -w -buildid= \
        -X main.GitVersion=2.35.0 \
        -X main.gitCommit=${FALCOSIDEKICK_COMMIT} \
        -X main.gitTreeState=dirty \
        -X main.buildDate=2026-08-31T08:44:54Z" \
      . \
 && /out/falcosidekick --version

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
WORKDIR /app
COPY --from=deps /src/LICENSE /app/LICENSE
COPY --from=build /out/falcosidekick /app/falcosidekick
USER 65532:65532
# 2801: the HTTP endpoint Falco posts alerts to (/) and the probes read (/ping).
EXPOSE 2801
LABEL org.opencontainers.image.title="self-defending-portfolio falcosidekick" \
      org.opencontainers.image.description="Falcosidekick built from the pinned upstream release with fixed dependencies" \
      org.opencontainers.image.source="https://github.com/HubertMJ/self-defending-portfolio" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="2.35.0"
ENTRYPOINT ["/app/falcosidekick"]
