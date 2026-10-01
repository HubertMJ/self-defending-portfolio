# Falco Talon, built by this repository from a pinned upstream commit (ADR 0020). Built, Trivy-gated,
# SBOM'd and signed by .github/workflows/build-images.yml like every image under app/ (ADR 0016), so
# Kyverno can require our signature in falco-response too.
#
# Why not the upstream image: 0.3.0 (2025-02-05) is still the latest release, and its image carries
# the Go toolchain and modules of that day - 57 CRITICAL/HIGH findings with a fix available (Trivy
# 0.75.0, 2026-10-01), all in stdlib, x/crypto, x/net and nats-server. Upstream `main` has bumped
# every one of those modules and carries the k8sevents namespace fix that 0.3.0 lacks; it has no
# changelog entry since 0.3.0, i.e. no feature or configuration change, only fixes and dependency
# bumps. So: upstream's own code at one reviewed commit, compiled with a current Go, no source
# patched.
#
# Upstream builds with ko (.ko.yaml): CGO off, -trimpath, -s -w, static, onto chainguard/static as
# nonroot. Same here, with distroless static:nonroot (uid 65532, which talon-deployment.yaml already
# asserts) as the base this repository already uses for the API.
#
# Bumping: set TALON_COMMIT to a newer upstream commit (git ls-remote https://github.com/falcosecurity/
# falco-talon refs/heads/main), read the diff, push. The checkout below refuses any other commit.
#
# Bases pinned by tag and digest (ADR 0008):
#   golang:1.26.8                          docker.io
#   distroless/static-debian13:nonroot     gcr.io
FROM docker.io/library/golang:1.26.8@sha256:0f063af2d465d8dcae54cce04278ada488b96f77b42449c8d071e47d016cc65a AS src
# falcosecurity/falco-talon main, 2026-09-05 ("chore(deps): bump github.com/cilium/ebpf ...").
ARG TALON_COMMIT=d273e352f80e114954f40c9843fd0a1b71a30d57
ARG TALON_VERSION=0.3.0-g${TALON_COMMIT}
WORKDIR /src
# A commit id, not a tag or a branch: fetched by id and checked, so the build cannot drift to
# whatever main points at later.
RUN git init -q . \
 && git fetch -q --depth 1 https://github.com/falcosecurity/falco-talon "${TALON_COMMIT}" \
 && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "${TALON_COMMIT}" \
 && go mod download && go mod verify
# The one deviation from upstream's module graph: minimum versions for the Go team's own
# golang.org/x modules, which keep Go's compatibility promise, where upstream still pins a release
# with a fixed CVE. Nothing else is bumped - a third-party module (grpc, cilium, nats) moves only
# when upstream moves it (ADR 0020). `go get` checks every new module against sum.golang.org.
ARG X_FLOORS="golang.org/x/crypto@v0.55.0 golang.org/x/net@v0.58.0 golang.org/x/text@v0.41.0"
RUN go get ${X_FLOORS} && go mod verify

FROM src AS test
# Upstream's own unit tests; the image does not exist if they fail.
RUN CGO_ENABLED=1 go vet ./... && CGO_ENABLED=1 go test -count=1 ./... && touch /tested

FROM src AS build
COPY --from=test /tested /tmp/tested
# The ldflags upstream's mageFile sets, so `falco-talon version` says what this is.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
      -ldflags "-s -w -extldflags '-static' \
        -X github.com/falcosecurity/falco-talon/configuration.GitVersion=${TALON_VERSION} \
        -X github.com/falcosecurity/falco-talon/configuration.GitCommit=${TALON_COMMIT} \
        -X github.com/falcosecurity/falco-talon/configuration.GitTreeState=clean \
        -X github.com/falcosecurity/falco-talon/configuration.BuildDate=1970-01-01T00:00:00Z" \
      -o /out/falco-talon .

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/falco-talon /usr/bin/falco-talon
USER 65532:65532
EXPOSE 2803
LABEL org.opencontainers.image.title="self-defending-portfolio talon" \
      org.opencontainers.image.description="Falco Talon built from a pinned upstream commit with a current Go toolchain" \
      org.opencontainers.image.source="https://github.com/HubertMJ/self-defending-portfolio" \
      org.opencontainers.image.licenses="Apache-2.0"
ENTRYPOINT ["/usr/bin/falco-talon"]
