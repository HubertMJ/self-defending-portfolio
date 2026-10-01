# KSOPS, the kustomize exec plugin Argo CD's repo-server decrypts SOPS secrets with (ADR 0006), built
# by this repository from the pinned upstream release commit (ADR 0020). Built, Trivy-gated, SBOM'd
# and signed by .github/workflows/build-images.yml like every image under app/ (ADR 0016).
#
# Why not viaductoss/ksops:v4.5.1: it is the latest release (and upstream master), but its image is
# built with Go 1.25.0 and also ships kustomize, git and glibc (distroless/base) - 109 CRITICAL/HIGH
# findings with a fix available (Trivy 0.75.0, 2026-10-01), mostly the Go standard library. The
# repo-server only ever takes the `ksops` binary out of the image (`ksops install`, see
# cluster/bootstrap/argocd/argocd-repo-server-ksops.yaml) and keeps Argo CD's own kustomize, so this
# image contains that one static binary and nothing else.
#
# Same source and the same build as upstream's Makefile (`-trimpath -ldflags "-w -s"`, CGO off,
# static), with a current Go and the golang.org/x floors below. No source patched.
#
# Bumping: set KSOPS_COMMIT to the commit of a newer release tag (git ls-remote
# https://github.com/viaduct-ai/kustomize-sops refs/tags/vX.Y.Z), read the diff, push.
#
# Bases pinned by tag and digest (ADR 0008):
#   golang:1.26.8                          docker.io
#   distroless/static-debian13:nonroot     gcr.io
FROM docker.io/library/golang:1.26.8@sha256:0f063af2d465d8dcae54cce04278ada488b96f77b42449c8d071e47d016cc65a AS src
# viaduct-ai/kustomize-sops tag v4.5.1 (also master as of 2026-10-01).
ARG KSOPS_COMMIT=d9442dc3153d9c16e517a68ce8926c9507386429
WORKDIR /src
RUN git init -q . \
 && git fetch -q --depth 1 https://github.com/viaduct-ai/kustomize-sops "${KSOPS_COMMIT}" \
 && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "${KSOPS_COMMIT}" \
 && go mod download && go mod verify
# The one deviation from upstream's module graph: minimum versions for the Go team's own
# golang.org/x modules, which keep Go's compatibility promise, where upstream still pins a release
# with a fixed CVE. Nothing else is bumped - a third-party module (grpc, cilium, nats) moves only
# when upstream moves it (ADR 0020). `go get` checks every new module against sum.golang.org.
ARG X_FLOORS="golang.org/x/crypto@v0.55.0 golang.org/x/net@v0.58.0 golang.org/x/text@v0.41.0"
RUN go get ${X_FLOORS} && go mod verify

FROM src AS test
# Upstream's unit tests. TestKSOPSPluginInstallation is skipped: it is an integration test that
# shells out to a `kustomize` binary, which is exactly what this image deliberately does not carry.
# (`make validate` still renders this repository's KSOPS kustomizations with the pinned ksops image.)
RUN CGO_ENABLED=0 go vet ./... \
 && CGO_ENABLED=0 go test -count=1 -skip TestKSOPSPluginInstallation ./... \
 && touch /tested

FROM src AS build
COPY --from=test /tested /tmp/tested
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-w -s" -o /out/ksops .

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
# Where the repo-server's init container calls it (/usr/local/bin/ksops install /custom-tools).
COPY --from=build /out/ksops /usr/local/bin/ksops
USER 65532:65532
LABEL org.opencontainers.image.title="self-defending-portfolio ksops" \
      org.opencontainers.image.description="KSOPS kustomize plugin built from the pinned upstream release with a current Go toolchain" \
      org.opencontainers.image.source="https://github.com/HubertMJ/self-defending-portfolio" \
      org.opencontainers.image.licenses="Apache-2.0"
ENTRYPOINT ["/usr/local/bin/ksops"]
