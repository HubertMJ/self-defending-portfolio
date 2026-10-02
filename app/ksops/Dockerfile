# KSOPS, the kustomize exec plugin Argo CD's repo-server decrypts SOPS secrets with (ADR 0006), built
# here from the pinned upstream release commit with fixed dependencies (ADR 0024). Built, Trivy-gated,
# SBOM'd and signed by .github/workflows/build-images.yml like every image under app/ (ADR 0016).
#
# Why not the upstream image: viaductoss/ksops:v4.5.1 (2026-04-13) is still KSOPS's newest release and
# the head of upstream master, but it is compiled with Go 1.25.0 against dependencies that have fixes
# since, and it also ships kustomize, kustomize-sops (a second copy of ksops), git and glibc
# (distroless/base): 109 CRITICAL+HIGH findings with Trivy 0.75.0 on 2026-10-02. The repo-server only
# ever takes the `ksops` binary out of that image (`ksops install`, see
# cluster/bootstrap/argocd/argocd-repo-server-ksops.yaml) and keeps Argo CD's own kustomize (ADR 0013,
# correction), so this image is that one static binary on distroless `static` and nothing else.
#
# What is built:
#   * source: github.com/viaduct-ai/kustomize-sops at KSOPS_COMMIT, the commit tag v4.5.1 points at
#     (`git ls-remote https://github.com/viaduct-ai/kustomize-sops refs/tags/v4.5.1`). Fetched by full
#     commit hash and checked after the checkout, so a moved tag or branch cannot change what is
#     compiled. Not one line of upstream's Go source is changed.
#   * dependencies: upstream's go.mod/go.sum at that commit with four modules raised to the first
#     releases that fix the findings in the binary, and nothing else changed by hand. modules/ holds
#     the result; it replaces upstream's two files before `go mod download`, and `go mod verify`
#     checks every module against go.sum (and go.sum against the public checksum database, which the
#     golang image enables by default). Produced with, in a checkout of KSOPS_COMMIT:
#       go get google.golang.org/grpc@v1.83.2 golang.org/x/crypto@v0.55.0 \
#              golang.org/x/net@v0.58.0 golang.org/x/text@v0.41.0
#       go mod tidy
#     The same grpc and x/crypto releases app/talon raised to. Minimal version selection then moved
#     what those four require (x/sys, x/oauth2, x/sync, genproto, the opentelemetry and envoy
#     families, among others); `diff` against upstream's go.mod at KSOPS_COMMIT shows the whole set.
#     sops, age and kustomize/api - the modules that actually do the decryption and the KRM I/O - are
#     upstream's versions, untouched.
#   * upstream's own test suite (`go vet` + `go test -race`, as upstream's `make test`) runs in the
#     builder against the raised dependencies, with --network=none: no tests, no image (as app/api,
#     app/talon). One test is skipped, TestKSOPSPluginInstallation: it shells out to a `kustomize`
#     binary, which this build deliberately does not have. What it would check - kustomize running
#     this ksops as an exec KRM function and getting the Secret decrypted - is checked against the
#     built image instead, with the kustomize release Argo CD ships (ADR 0024, "Verified").
#   * the binary as upstream's Makefile builds it: CGO off, -trimpath, -ldflags "-w -s" (plus an
#     empty build id, so two builds of this file are byte-identical). Static, so the runtime needs no
#     libc - and none of the CA bundle, git or kustomize the upstream image carries: ksops decrypts
#     with a local age key and opens no network connection here.
#   * runtime: distroless `static` nonroot (uid 65532), the same base and user as app/api and
#     app/talon. The binary sits at /usr/local/bin/ksops, the path the upstream image uses and the
#     repo-server's init container calls, so the init container's command does not change: `ksops
#     install /custom-tools` is a subcommand of the binary itself (it copies os.Executable() to the
#     directory, mode 0755) and needs no shell, cp or other tool in the image.
#
# Bumping: set KSOPS_COMMIT to the commit of a newer release tag, read the upstream diff, regenerate
# modules/ from that commit's go.mod/go.sum with the commands above (drop any raise the release has
# caught up with - if it carries all of them, this image can go and the upstream one comes back), push.
#
# Bases pinned by tag and digest (ADR 0008), resolved from the registries' index manifests; both are
# the pins app/api and app/talon already use:
#   golang:1.26.8                          docker.io
#   distroless/static-debian13:nonroot     gcr.io
FROM docker.io/library/golang:1.26.8@sha256:0f063af2d465d8dcae54cce04278ada488b96f77b42449c8d071e47d016cc65a AS deps
# viaduct-ai/kustomize-sops tag v4.5.1 (also master as of 2026-10-02).
ARG KSOPS_COMMIT=d9442dc3153d9c16e517a68ce8926c9507386429
WORKDIR /src
# Fetch exactly one commit by its hash (GitHub serves any reachable commit by id), then refuse to go
# on unless that is what was checked out.
RUN git init -q . \
 && git remote add origin https://github.com/viaduct-ai/kustomize-sops.git \
 && git fetch -q --depth 1 origin "$KSOPS_COMMIT" \
 && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$KSOPS_COMMIT"
COPY modules/go.mod modules/go.sum ./
RUN go mod download && go mod verify

FROM deps AS test
# --network=none: these are upstream's tests, run against dependencies we raised; nothing in them
# needs the network, and a test that tried to reach a KMS or a key server must fail here rather than
# talk to the internet from the build. Every module is already in the cache from `go mod download`.
# The gpg import is upstream's `make import-test-keys` (the PGP cases decrypt fixtures encrypted to
# test/key.asc); gpg is in the golang image. -race needs cgo, which the golang image has; the shipped
# binary below does not use it.
RUN --network=none gpg --batch --quiet --import test/key.asc \
 && CGO_ENABLED=1 go vet ./... \
 && CGO_ENABLED=1 go test -race -count=1 -skip '^TestKSOPSPluginInstallation$' ./... \
 && touch /tested

FROM deps AS build
# Depending on the test stage's marker is what makes BuildKit run it (see app/api/Dockerfile).
COPY --from=test /tested /tmp/tested
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFLAGS=-buildvcs=false \
    go build -trimpath -ldflags "-w -s -buildid=" -o /out/ksops . \
 && mkdir /out/probe \
 && /out/ksops install /out/probe \
 && cmp /out/ksops /out/probe/ksops

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
# Where the repo-server's init container calls it: /usr/local/bin/ksops install /custom-tools.
COPY --from=build /out/ksops /usr/local/bin/ksops
USER 65532:65532
LABEL org.opencontainers.image.title="self-defending-portfolio ksops" \
      org.opencontainers.image.description="KSOPS kustomize exec plugin built from the pinned upstream release with fixed dependencies" \
      org.opencontainers.image.source="https://github.com/HubertMJ/self-defending-portfolio" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="v4.5.1"
ENTRYPOINT ["/usr/local/bin/ksops"]
