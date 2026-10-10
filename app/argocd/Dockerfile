# Argo CD v3.5.4 - argocd-server, argocd-repo-server and argocd-application-controller - built here
# from the pinned upstream release commit with fixed dependencies, together with the Helm, kustomize
# and Git LFS releases that release ships (ADR 0027). Built, Trivy-gated, SBOM'd and signed by
# .github/workflows/build-images.yml like every image under app/ (ADR 0016).
#
# Why not the upstream image: when this image was introduced (ADR 0027), quay.io/argoproj/argocd
# v3.5.3 (2026-09-14) was the newest Argo CD 3.5 release, but its argocd binary is compiled with Go
# 1.26.4 against grpc, oras-go, go-git, x/crypto and x/text releases with fixes since, and the tools
# it carries are older still: kustomize v5.8.1 is compiled with Go 1.24.0, git-lfs v3.7.1 with Go
# 1.25.3, helm v4.2.1 with Go 1.26.4 and an oras-go with fixes since. 118 CRITICAL+HIGH (2 CRITICAL)
# with Trivy 0.75.0 on 2026-10-02 (ADR 0027 has the breakdown) - all of them in those four Go
# binaries, an OpenSSL already fixed in Ubuntu 26.04, and a /usr/bin/pebble that came with the
# Ubuntu base image. v3.5.4 (2026-10-06, which fixes CVE-2026-55797 in Argo CD itself) changes none
# of that: its go.mod, go.sum, hack/tool-versions.sh and Dockerfile are v3.5.3's.
#
# What is built - the same thing upstream's Dockerfile at ARGOCD_COMMIT builds, stage by stage:
#   * argocd: github.com/argoproj/argo-cd at ARGOCD_COMMIT, the commit tag v3.5.4 points at
#     (`git ls-remote https://github.com/argoproj/argo-cd refs/tags/v3.5.4`). Fetched by full commit
#     hash and checked after the checkout, so a moved tag or branch cannot change what is compiled.
#     Not one line of upstream's Go or TypeScript source is changed. The binary is built by upstream's
#     own `make argocd-all` (CGO off, static, the version variables upstream's release workflow
#     passes), one multi-call binary that every component runs as a symlink, as upstream ships it.
#   * the UI: upstream's ui/ at the same commit, built exactly as upstream's argocd-ui stage does -
#     the same node image (tag and digest), corepack, `pnpm install --frozen-lockfile` against
#     upstream's pnpm-lock.yaml, `pnpm build` - and embedded into the binary by the same go:embed
#     (ui/embed.go) from ui/dist/app.
#   * helm, kustomize and git-lfs: upstream installs the vendors' release binaries at the versions
#     hack/tool-versions.sh pins (helm4_version=4.2.1, kustomize5_version=5.8.1,
#     git_lfs_version=3.7.1). Here each is compiled from the commit its release tag points at, with
#     the linker flags its own release build uses, so `helm version`, `kustomize version` and
#     `git-lfs version` report the same release (Argo CD parses `kustomize version` to decide which
#     flags kustomize gets - it must say v5.8.1, not the unknown-version fallback v99.99.99).
#   * dependencies: each project's go.mod/go.sum at its commit with only the modules raised that carry
#     findings in the shipped binary, then `go mod tidy`, nothing else changed by hand. modules/<name>
#     holds the result; it replaces upstream's two files before `go mod download`, and `go mod verify`
#     checks every module against go.sum (and go.sum against the public checksum database, which the
#     golang image enables by default). Produced with, in a checkout of each commit:
#       argocd:    go get google.golang.org/grpc@v1.83.2 golang.org/x/crypto@v0.55.0 \
#                         golang.org/x/net@v0.58.0 golang.org/x/text@v0.41.0 \
#                         github.com/go-git/go-git/v5@v5.19.2 oras.land/oras-go/v2@v2.6.2
#       helm:      go get golang.org/x/crypto@v0.55.0 golang.org/x/net@v0.58.0 \
#                         golang.org/x/text@v0.41.0 oras.land/oras-go/v2@v2.6.2 \
#                         google.golang.org/grpc@v1.83.2
#       kustomize: (in kustomize/) GOWORK=off go get golang.org/x/text@v0.41.0
#       git-lfs:   go get golang.org/x/crypto@v0.55.0 golang.org/x/net@v0.58.0 golang.org/x/text@v0.41.0
#       then       go mod tidy   (GOWORK=off for kustomize)
#     The grpc, x/crypto, x/net and x/text releases app/talon and app/ksops raised to. Minimal version
#     selection then moved what those require (x/sys, x/sync, genproto, the opentelemetry and
#     cloud.google.com families, among others). Then, for the MEDIUM and LOW findings with a fix
#     (2026-10-10), on top of that result:
#       argocd:    go get github.com/slack-go/slack@v0.23.1 golang.org/x/net@v0.60.0 \
#                         go.opentelemetry.io/otel/sdk@v1.45.0 \
#                         go.opentelemetry.io/otel/exporters/otlp/otlptrace@v1.45.0 \
#                         go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc@v1.45.0
#       helm:      go get golang.org/x/net@v0.60.0
#       git-lfs:   go get golang.org/x/net@v0.60.0
#       then       go mod tidy
#     x/net v0.60.0 requires x/crypto v0.57.0, which also fixes x/crypto's two MEDIUM findings.
#     It also needs `go 1.26.0`, which in git-lfs's go.mod (1.25.0 before) would switch git-lfs to
#     Go 1.26's GODEBUG defaults; its go.mod carries `godebug default=go1.25` by hand below the go
#     line, so they stay those of the git-lfs this image shipped before (`go mod tidy` keeps the
#     line; `go version -m` shows DefaultGODEBUG).
#     slack-go is notifications-engine's; v0.23.1 is the release Argo CD 3.6 (v3.6.0-rc2) requires.
#     Argo CD's notification packages pass their tests against it; notifications-engine's own slack
#     tests pass but for two that expect an empty `blocks=[]` form field, which slack-go v0.23.1
#     leaves out when there are no blocks. No notifications controller runs here (ADR 0024).
#     `diff` against upstream's go.mod at each commit shows the whole set. The Kubernetes libraries,
#     gitops-engine (in-tree, `replace`d) and every replace directive upstream has are untouched.
#   * Go 1.26.9 for all four, the golang image app/talon and app/ksops use (upstream: 1.26.4 for
#     argocd and helm; the vendors' 1.24.0 and 1.25.3 for kustomize and git-lfs).
#   * upstream's own unit tests run in the builder against the raised dependencies, with
#     --network=none and as an unprivileged user (as upstream's CI; several argocd tests check that a
#     file mode is enforced, which root bypasses): no tests, no image (as app/api, app/talon,
#     app/ksops). For argocd, the packages that use the raised modules directly or drive helm,
#     kustomize, git and gpg - with this image's own helm, kustomize and git-lfs on PATH, so Argo CD's
#     helm and kustomize wrappers are tested against the binaries that ship; the full argo-cd suite
#     needs a Kubernetes API server, Redis and the network. For helm, kustomize and git-lfs, each
#     project's `go test ./...` (kustomize: its kustomize/ module), with the few cases that need
#     the network skipped by name.
#   * runtime: upstream's argocd-base stage - Ubuntu 26.04 by digest, the same package list
#     (git, tini, ca-certificates, gpg, gpg-agent, tzdata, connect-proxy, openssh-client), the same
#     user (argocd, uid/gid 999), the same paths (/usr/local/bin/argocd and its symlinks,
#     /app/config/{ssh,tls,gpg}, /home/argocd), the same ENV and wrapper scripts, `git lfs install
#     --system` - so install.yaml's Deployments, their volume mounts and this repository's KSOPS
#     init container and plugin mount (cluster/bootstrap/argocd/argocd-repo-server-ksops.yaml) work
#     unchanged. `apt-get dist-upgrade` as upstream, so a rebuild picks up Ubuntu's security fixes;
#     the base digest is newer than upstream's, which is what removes upstream's OpenSSL findings.
#     One difference: /usr/bin/pebble is deleted. The Ubuntu image ships Canonical's service manager
#     there, outside any package (`dpkg -S` finds no owner, so dist-upgrade cannot fix it); nothing
#     here runs it (the entrypoint is tini), and it is compiled with a Go whose standard library has
#     fixed findings (Go 1.26.7 in the 26.04 image of 2026-10-10).
#
# Version strings: argocd reports v3.5.4+d6d5b24.dirty, not v3.5.4, because its build variables say
# what was compiled - upstream's tree at the release commit with two files (go.mod, go.sum)
# different - and Argo CD prints a bare tag only for a clean tree (common/version.go). helm reports
# GitTreeState "dirty" for the same reason. Nothing in Argo CD parses its own version.
#
# Bumping: set the *_COMMIT args to the commits of the new release tags (argocd's hack/tool-versions.sh
# names the helm, kustomize and git-lfs releases it ships - follow it), read the upstream diffs,
# regenerate modules/ from those commits' go.mod/go.sum with the commands above (drop any raise the
# release has caught up with - if all are caught up, this image can go and the upstream one comes
# back), and take the node image pin from upstream's Dockerfile at that commit.
#
# Bases pinned by tag and digest (ADR 0008), resolved from the registries' index manifests:
#   golang:1.26.9      docker.io   (as app/talon, app/ksops)
#   node:24.14.1       docker.io   (upstream's argocd-ui stage, same tag and digest)
#   ubuntu:26.04       docker.io   (upstream's BASE_IMAGE, a newer digest of the same tag)
ARG GOLANG_IMAGE=docker.io/library/golang:1.26.9@sha256:d7722066f0b60ceccb6c0643cbed1f5f9e15506ac237146c95333504d7805d89

####################################################################################################
# Sources: each fetched by one full commit hash, checked, then its dependencies swapped and verified.
####################################################################################################
FROM ${GOLANG_IMAGE} AS argocd-src
# argoproj/argo-cd tag v3.5.4.
ARG ARGOCD_COMMIT=d6d5b248ce00e1a2c512068002a93d3319767087
WORKDIR /src
RUN git init -q . \
 && git remote add origin https://github.com/argoproj/argo-cd.git \
 && git fetch -q --depth 1 origin "$ARGOCD_COMMIT" \
 && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$ARGOCD_COMMIT"
COPY modules/argocd/go.mod modules/argocd/go.sum ./
RUN go mod download && go mod verify

FROM ${GOLANG_IMAGE} AS helm-src
# helm/helm tag v4.2.1 (hack/tool-versions.sh: helm4_version=4.2.1).
ARG HELM_COMMIT=d591a19b953bd9cfdf7d9ddd83c2f4ffdaeafb29
WORKDIR /src
RUN git init -q . \
 && git remote add origin https://github.com/helm/helm.git \
 && git fetch -q --depth 1 origin "$HELM_COMMIT" \
 && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$HELM_COMMIT"
COPY modules/helm/go.mod modules/helm/go.sum ./
# The second module is a test fixture: TestRuntimeExtismV1InvokePlugin compiles it to WebAssembly, so
# its one dependency is fetched here, before the tests lose the network.
RUN go mod download && go mod verify \
 && cd internal/plugin/testdata/src/extismv1-test && go mod download && go mod verify

FROM ${GOLANG_IMAGE} AS kustomize-src
# kubernetes-sigs/kustomize tag kustomize/v5.8.1 (hack/tool-versions.sh: kustomize5_version=5.8.1).
ARG KUSTOMIZE_COMMIT=9790a1c3efd2fd35f1b768d495112834176581c1
WORKDIR /src
RUN git init -q . \
 && git remote add origin https://github.com/kubernetes-sigs/kustomize.git \
 && git fetch -q --depth 1 origin "$KUSTOMIZE_COMMIT" \
 && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$KUSTOMIZE_COMMIT"
WORKDIR /src/kustomize
# GOWORK=off: the kustomize/ module is built against the api, kyaml and cmd/config releases its
# go.mod requires (as the release binaries are), not the in-repo copies the go.work points at.
ENV GOWORK=off
COPY modules/kustomize/go.mod modules/kustomize/go.sum ./
RUN go mod download && go mod verify

FROM ${GOLANG_IMAGE} AS git-lfs-src
# git-lfs/git-lfs tag v3.7.1 (hack/tool-versions.sh: git_lfs_version=3.7.1).
ARG GIT_LFS_COMMIT=b84b33847fe6458f36ef521534dc0eac953cb379
WORKDIR /src
RUN git init -q . \
 && git remote add origin https://github.com/git-lfs/git-lfs.git \
 && git fetch -q --depth 1 origin "$GIT_LFS_COMMIT" \
 && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$GIT_LFS_COMMIT"
COPY modules/git-lfs/go.mod modules/git-lfs/go.sum ./
RUN go mod download && go mod verify

####################################################################################################
# The tools: upstream tests (offline, unprivileged), then the binary with the release's linker flags.
# Every test stage runs as uid 1000 with HOME and the build cache under /tmp; the module cache from
# `go mod download` is root's and only read.
####################################################################################################
FROM helm-src AS helm
ARG HELM_COMMIT=d591a19b953bd9cfdf7d9ddd83c2f4ffdaeafb29
RUN chown -R 1000:1000 /src
USER 1000:1000
ENV HOME=/tmp/home GOCACHE=/tmp/gocache GOFLAGS=-buildvcs=false
# helm's `make test-unit`: go test ./... (shuffled), CGO off as the binary. Two tests reach the
# internet and are skipped by name: TestPullRun_ChartNotFound downloads from charts.helm.sh and
# TestRenderWithDNS resolves helm.sh.
# The two lint/rules packages run after the rest, not alongside it: their
# TestTemplateIntegrationHappyPath renames a file in rules/testdata/albatross for its duration, and
# the lint packages' TestInvalidYaml lints that same chart expecting the file - an upstream race
# between packages that `go test ./...` runs in parallel, which fails TestInvalidYaml on a loaded
# host. Every test still runs.
RUN --network=none \
    rules='helm.sh/helm/v4/pkg/chart/v2/lint/rules helm.sh/helm/v4/internal/chart/v3/lint/rules' \
 && CGO_ENABLED=0 go test -shuffle=on -count=1 \
      -skip '^(TestPullRun_ChartNotFound|TestRenderWithDNS)$' \
      $(go list ./... | grep -vxF -e "${rules% *}" -e "${rules#* }") \
 && CGO_ENABLED=0 go test -shuffle=on -count=1 $rules
# helm's Makefile `build` for a release tag: -trimpath, CGO off, -w -s and the version variables.
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-w -s \
      -X helm.sh/helm/v4/internal/version.version=v4.2.1 \
      -X helm.sh/helm/v4/internal/version.metadata= \
      -X helm.sh/helm/v4/internal/version.gitCommit=$HELM_COMMIT \
      -X helm.sh/helm/v4/internal/version.gitTreeState=dirty" \
      -o /tmp/out/helm ./cmd/helm \
 && /tmp/out/helm version | grep -F 'Version:"v4.2.1"'

FROM kustomize-src AS kustomize
ARG KUSTOMIZE_COMMIT=9790a1c3efd2fd35f1b768d495112834176581c1
RUN chown -R 1000:1000 /src
USER 1000:1000
ENV HOME=/tmp/home GOCACHE=/tmp/gocache GOFLAGS=-buildvcs=false
RUN --network=none go test -count=1 ./...
# releasing/create-release.sh: CGO off, -s -w and the provenance variables; the build date is the
# release commit's, so two builds of this file agree.
RUN CGO_ENABLED=0 go build -ldflags "-s -w \
      -X sigs.k8s.io/kustomize/api/provenance.version=v5.8.1 \
      -X sigs.k8s.io/kustomize/api/provenance.gitCommit=$KUSTOMIZE_COMMIT \
      -X sigs.k8s.io/kustomize/api/provenance.buildDate=2026-02-09T16:11:22Z" \
      -o /tmp/out/kustomize . \
 && test "$(/tmp/out/kustomize version)" = v5.8.1

FROM git-lfs-src AS git-lfs
ARG GIT_LFS_COMMIT=b84b33847fe6458f36ef521534dc0eac953cb379
RUN chown -R 1000:1000 /src
USER 1000:1000
ENV HOME=/tmp/home GOCACHE=/tmp/gocache GOFLAGS=-buildvcs=false
# go test's own vet checks less printf, then printf alone on every package but `commands`: x/net
# v0.60.0 needs `go 1.26.0` in go.mod (upstream: 1.23.0), and at that language version vet's printf
# check flags a line upstream has always had (commands/lockverifier.go passes a *git.Ref to %q in a
# translated message). Every check of go test's default list (cmd/go/internal/test, Go 1.26.9) still
# runs on every package; only printf on that one package is left out.
RUN --network=none go test -count=1 \
      -vet=atomic,bool,buildtags,directive,errorsas,ifaceassert,nilfunc,slog,stringintconv,tests ./... \
 && go vet -printf $(go list ./... | grep -vxF github.com/git-lfs/git-lfs/v3/commands)
# git-lfs's Makefile: -trimpath, -s -w, Vendor "GitHub" and the short commit (as its release build).
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w \
      -X 'github.com/git-lfs/git-lfs/v3/config.Vendor=GitHub' \
      -X github.com/git-lfs/git-lfs/v3/config.GitCommit=$(printf %.8s "$GIT_LFS_COMMIT")" \
      -o /tmp/out/git-lfs ./git-lfs.go \
 && /tmp/out/git-lfs version | grep -F 'git-lfs/3.7.1 (GitHub; linux amd64;'

####################################################################################################
# The UI, exactly as upstream's argocd-ui stage (ARGO_VERSION unset there too, so the bundle says
# "latest").
####################################################################################################
FROM docker.io/library/node:24.14.1@sha256:80fc934952c8f1b2b4d39907af7211f8a9fff1a4c2cf673fb49099292c251cec AS argocd-ui
WORKDIR /src
COPY --from=argocd-src /src/ui/package.json /src/ui/pnpm-lock.yaml ./
RUN npm install -g corepack@0.34.6 && corepack enable && pnpm install --frozen-lockfile
COPY --from=argocd-src /src/ui/ .
RUN NODE_ENV='production' NODE_ONLINE_ENV='online' NODE_OPTIONS=--max_old_space_size=8192 pnpm build

####################################################################################################
# argocd: upstream tests against the raised dependencies and this image's tools, then the binary.
####################################################################################################
FROM argocd-src AS argocd-test
COPY --from=helm /tmp/out/helm /usr/local/bin/helm
COPY --from=kustomize /tmp/out/kustomize /usr/local/bin/kustomize
COPY --from=git-lfs /tmp/out/git-lfs /usr/local/bin/git-lfs
RUN chown -R 1000:1000 /src
USER 1000:1000
ENV HOME=/tmp/home GOCACHE=/tmp/gocache GOFLAGS=-buildvcs=false
# The packages that import the raised modules (oras-go: util/helm, util/oci; go-git and x/crypto:
# util/git, util/cert, util/crypto, util/password; x/net: util/grpc, util/proxy; grpc: the
# repo-server, CMP and commit-server clients and servers, util/askpass; slack-go, through
# notifications-engine: util/notification, server/notification) plus the wrappers around
# helm, kustomize, git and gpg the repo-server renders and verifies with (util/kustomize,
# util/sourceintegrity). As upstream's Makefile: hack/ on PATH for gpg-wrapper.sh and
# git-verify-wrapper.sh, and a git identity for the tests that commit. gpg is in the golang image.
# Skipped by name, because they need the internet: TestIndex, Test_nativeHelmChart_ExtractChart and
# Test_nativeHelmChart_ExtractChart_insecure (argoproj.github.io), TestLsRemote, TestNewFactory,
# TestListRevisions, TestAnnotatedTagHandling and TestVerifyCommitSignature (github.com), and
# TestGitHubAppGetAccessToken_DialerDefaultTimeout (expects a connect *timeout* to a TEST-NET
# address; without a network the dial fails at once with "unreachable"). And one that is timing:
# TestNewConnection_ErrorWhenRotatedCertIsInvalid rewrites a file and expects its mtime to differ,
# which a filesystem with jiffy-granular timestamps does not guarantee for two writes in the same
# few milliseconds (it passes and fails on the same tree between runs here).
RUN --network=none export PATH="$PATH:/src/hack" \
 && mkdir -p "$HOME" \
 && git config --global user.name "Argo CD test" \
 && git config --global user.email test@example.com \
 && go test -count=1 \
      -skip '^(TestIndex|Test_nativeHelmChart_ExtractChart|Test_nativeHelmChart_ExtractChart_insecure|TestLsRemote|TestNewFactory|TestListRevisions|TestAnnotatedTagHandling|TestVerifyCommitSignature|TestGitHubAppGetAccessToken_DialerDefaultTimeout|TestNewConnection_ErrorWhenRotatedCertIsInvalid)$' \
      ./util/helm/... ./util/oci/... ./util/kustomize/... ./util/git/... ./util/sourceintegrity/... \
      ./util/cert/... ./util/crypto/... ./util/password/... ./util/grpc/... ./util/proxy/... \
      ./util/askpass/... ./reposerver/apiclient/... ./cmpserver/... ./commitserver/... \
      ./util/notification/... ./server/notification/... \
 && touch /tmp/tested

FROM argocd-src AS argocd-build
# Depending on the test stage's marker is what makes BuildKit run it (see app/api/Dockerfile).
COPY --from=argocd-test /tmp/tested /tmp/tested
COPY --from=argocd-ui /src/dist/app /src/ui/dist/app
ARG ARGOCD_COMMIT=d6d5b248ce00e1a2c512068002a93d3319767087
# The variables upstream's release workflow passes (image-reuse.yaml), with the commit's own date
# for BUILD_DATE so two builds of this file agree, and the tree state as it is: go.mod and go.sum
# differ from the commit.
RUN GIT_COMMIT=$ARGOCD_COMMIT \
    GIT_TREE_STATE=dirty \
    GIT_TAG=v3.5.4 \
    BUILD_DATE=2026-10-06T19:58:31Z \
    EXTRA_BUILD_INFO="self-defending-portfolio app/argocd: dependencies raised, see ADR 0027" \
    GOOS=linux GOARCH=amd64 \
    make argocd-all \
 && dist/argocd version --client | grep -F 'argocd: v3.5.4+d6d5b24.dirty'

####################################################################################################
# Runtime: upstream's argocd-base and final stages.
####################################################################################################
FROM docker.io/library/ubuntu:26.04@sha256:3595d7fc4286a33fad0fd853a4063e654287a9c3787437d7937c94ca3f7a804e

USER root

ENV ARGOCD_USER_ID=999 \
    DEBIAN_FRONTEND=noninteractive

RUN groupadd -g $ARGOCD_USER_ID argocd && \
    useradd -r -u $ARGOCD_USER_ID -g argocd argocd && \
    mkdir -p /home/argocd && \
    chown argocd:0 /home/argocd && \
    chmod g=u /home/argocd && \
    apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get install --no-install-recommends -y \
    git tini ca-certificates gpg gpg-agent tzdata connect-proxy openssh-client && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/share/doc/* && \
    rm -f /usr/bin/pebble

COPY --from=argocd-src \
    /src/hack/gpg-wrapper.sh \
    /src/hack/git-verify-wrapper.sh \
    /src/entrypoint.sh \
    /usr/local/bin/
# root-owned like upstream's (the test stages built them as uid 1000, which BuildKit would carry over).
COPY --from=helm --chown=0:0 /tmp/out/helm /usr/local/bin/helm
COPY --from=kustomize --chown=0:0 /tmp/out/kustomize /usr/local/bin/kustomize
COPY --from=git-lfs --chown=0:0 /tmp/out/git-lfs /usr/local/bin/git-lfs

# Initialize git-lfs system configuration (/etc/gitconfig) so LFS filters are active
RUN git lfs install --system

# keep uid_entrypoint.sh for backward compatibility
RUN ln -s /usr/local/bin/entrypoint.sh /usr/local/bin/uid_entrypoint.sh

# support for mounting configuration from a configmap
WORKDIR /app/config/ssh
RUN touch ssh_known_hosts && \
    ln -s /app/config/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts

WORKDIR /app/config
RUN mkdir -p tls && \
    mkdir -p gpg/source && \
    mkdir -p gpg/keys && \
    chown argocd gpg/keys && \
    chmod 0700 gpg/keys

ENV USER=argocd

# Disable gRPC service config lookups via DNS TXT records (upstream, argoproj/argo-cd#24991).
ENV GRPC_ENABLE_TXT_SERVICE_CONFIG=false

COPY --from=argocd-build /src/dist/argocd /usr/local/bin/argocd

RUN ln -s /usr/local/bin/argocd /usr/local/bin/argocd-server && \
    ln -s /usr/local/bin/argocd /usr/local/bin/argocd-repo-server && \
    ln -s /usr/local/bin/argocd /usr/local/bin/argocd-cmp-server && \
    ln -s /usr/local/bin/argocd /usr/local/bin/argocd-application-controller && \
    ln -s /usr/local/bin/argocd /usr/local/bin/argocd-dex && \
    ln -s /usr/local/bin/argocd /usr/local/bin/argocd-notifications && \
    ln -s /usr/local/bin/argocd /usr/local/bin/argocd-applicationset-controller && \
    ln -s /usr/local/bin/argocd /usr/local/bin/argocd-k8s-auth && \
    ln -s /usr/local/bin/argocd /usr/local/bin/argocd-commit-server

USER $ARGOCD_USER_ID
WORKDIR /home/argocd
LABEL org.opencontainers.image.title="self-defending-portfolio argocd" \
      org.opencontainers.image.description="Argo CD v3.5.4 built from the pinned upstream release with fixed dependencies, helm, kustomize and git-lfs likewise" \
      org.opencontainers.image.source="https://github.com/HubertMJ/self-defending-portfolio" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="v3.5.4"
ENTRYPOINT ["/usr/bin/tini", "--"]
