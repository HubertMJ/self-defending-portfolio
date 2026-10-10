# kube-bench, the CIS benchmark the daily CronJob in cluster/infra/kube-bench runs (ADR 0014), built
# here from the pinned upstream release commit (ADR 0025). Built, Trivy-gated, SBOM'd and signed by
# .github/workflows/build-images.yml like every image under app/ (ADR 0016).
#
# Why not the upstream image: aquasec/kube-bench:v0.16.0 (2026-08-05) is the newest release. It
# carries 13 HIGH with Trivy 0.75.0 on 2026-10-02: 8 in the Go standard library the binary was
# compiled with (1.26.5; fixed in 1.26.6), 2 in jq and 3 in OpenSSL (libcrypto3, libssl3, openssl;
# Alpine packages), and none in kube-bench's own dependencies. So this build changes no module at
# all: the same go.mod/go.sum, compiled with Go 1.26.8, on an Alpine base that carries only what the
# k3s checks run.
#
# What is built:
#   * source: github.com/aquasecurity/kube-bench at KUBE_BENCH_COMMIT, the commit tag v0.16.0 points at
#     (`git ls-remote https://github.com/aquasecurity/kube-bench refs/tags/v0.16.0`). Fetched by full
#     commit hash and checked after the checkout, so a moved tag cannot change what is compiled.
#     Upstream's Go source, go.mod and go.sum are not changed (`go mod verify`).
#   * upstream's own tests (`make tests`: `go test -vet all -short -race -timeout 30s ./...`) run in
#     the builder with --network=none: no tests, no image.
#   * the binary as upstream's makefile builds it: CGO off, the same cmd.KubeBenchVersion variable,
#     plus -trimpath, -s -w and an empty build id.
#   * cfg/ is upstream's at the same commit, at /opt/kube-bench/cfg as in upstream's image (kube-bench
#     looks for ./cfg in its working directory), with one change: k3s-cis-1.9.patch, applied with
#     `git apply` before upstream's tests run (ADR 0025, amendment 2026-10-10). It marks the three
#     checks that do not apply to this cluster as skipped, with the reason, points 1.1.11 at k3s's
#     datastore directory, makes 4.2.12 read the kubelet's flags without k3s's closing quote, and
#     turns the manual 3.1.3 and 3.2.2 into automated checks; the patch's header lists them. Every
#     other check, journalctl audits included, runs as upstream ships it. A bump whose upstream text
#     moved fails at `git apply`, rather than running a stale copy.
#   * runtime: Wolfi (Chainguard's glibc distribution), not upstream's Alpine, because the checks need
#     a journal reader. kube-bench's k3s-cis-1.9 reads the flags each k3s component really runs with
#     from the line k3s logs at start-up (`journalctl -m -u k3s | grep 'Running kube-apiserver'`);
#     k3s sets most of them itself, so /etc/rancher/k3s/config.yaml alone (the stand-in this
#     repository used before, ADR 0014) cannot show them and those checks failed falsely. Alpine has
#     no systemd and so no journalctl; Debian 13's has the right version but its base and systemd
#     bring ~50 HIGH findings with no fix (Trivy 0.75.0, 2026-10-02); Wolfi's systemd, procps,
#     findutils and kubectl scan 0. journalctl 261 reads the node's journal files (Debian 13,
#     systemd 257): newer readers read older journal files. The checks are /bin/sh pipelines, run by
#     busybox (sh, grep, sed, stat, tail) as in upstream's image. What upstream installs, and what is
#     kept:
#       - procps: kept. kube-bench finds the k3s components with `/bin/ps -C <name> -o cmd
#         --no-headers` (cmd/util.go), which busybox ps does not support.
#       - findutils: kept. The master checks use `xargs --no-run-if-empty` (GNU only).
#       - kubectl: kept. kube-bench always asks for the Kubernetes version before running, even with
#         --benchmark given (cmd/run.go: getPlatformInfo). With kubectl present, `kubectl version`
#         fails harmlessly here (no credentials, no network). Without it, kube-bench falls back to
#         running the first executable named `kubelet` that `find /` turns up - and / in the CronJob
#         includes the node's /var/lib/rancher/k3s/agent, i.e. containerd's unpacked image layers, as
#         root. Keeping kubectl keeps upstream's path.
#       - jq, openssl, bash, gcompat: dropped. They serve other benchmarks (EKS/GKE helper scripts,
#         OpenShift's `oc`); no audit in k3s-cis-1.9 calls them. jq and openssl were three of the
#         findings.
#       - helper_scripts/check_files_owner_in_dir.sh (bash, used by other benchmarks): dropped.
#     Added: systemd, for journalctl only. Its package brings libraries and tools nothing here runs
#     (curl, dbus, cryptsetup and others); they are installed as packages, so Trivy sees and counts
#     them, rather than copied in as loose files it could not see. apk-tools goes at the end: no
#     package manager in a root pod. The package versions are pinned, so a rebuild cannot pick up a
#     different journalctl or kubectl silently; Wolfi keeps old package versions, and a finding in a
#     pinned one shows up in the build's Trivy gate and is bumped here.
#     Wolfi's base is pinned by digest; cgr.dev serves it publicly only as `latest`.
#   * ENTRYPOINT is the binary. Upstream's is a shell wrapper whose only other mode copies the binary
#     to the host (`install`); the CronJob called the binary directly already.
#
# Bumping: set KUBE_BENCH_COMMIT to the commit of a newer release tag, read its cfg/k3s-cis-1.9 diff
# (the CronJob runs these audits as shipped, apart from k3s-cis-1.9.patch), regenerate the patch if it
# no longer applies (its header says how) and read the new Dockerfile's package list against the one
# below; push.
#
# Bases pinned by tag and digest (ADR 0008):
#   golang:1.26.8      docker.io, the pin app/api, app/talon and app/ksops use
#   wolfi-base:latest  cgr.dev/chainguard
FROM docker.io/library/golang:1.26.8@sha256:0f063af2d465d8dcae54cce04278ada488b96f77b42449c8d071e47d016cc65a AS deps
# aquasecurity/kube-bench tag v0.16.0.
ARG KUBE_BENCH_COMMIT=5c6c22d51b926020e7414e1f1e051851d1a2feff
WORKDIR /src
# Fetch exactly one commit by its hash (GitHub serves any reachable commit by id), then refuse to go
# on unless that is what was checked out.
RUN git init -q . \
 && git remote add origin https://github.com/aquasecurity/kube-bench.git \
 && git fetch -q --depth 1 origin "$KUBE_BENCH_COMMIT" \
 && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$KUBE_BENCH_COMMIT"
RUN go mod download && go mod verify
# This repository's change to the benchmark (see the header). After the module download, so a patch
# change does not download again; before the test stage, so upstream's tests run on the patched cfg/.
COPY k3s-cis-1.9.patch /tmp/k3s-cis-1.9.patch
RUN git apply --verbose /tmp/k3s-cis-1.9.patch && git diff --stat

FROM deps AS test
# --network=none: nothing in upstream's tests needs the network. -race needs cgo, which the golang
# image has; the shipped binary below does not use it.
RUN --network=none CGO_ENABLED=1 go test -vet all -short -race -timeout 30s -count=1 ./... \
 && touch /tested

FROM deps AS build
# Depending on the test stage's marker is what makes BuildKit run it (see app/api/Dockerfile).
COPY --from=test /tested /tmp/tested
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFLAGS=-buildvcs=false \
    go build -trimpath -o /out/kube-bench \
      -ldflags="-s -w -buildid= -X github.com/aquasecurity/kube-bench/cmd.KubeBenchVersion=v0.16.0" \
      . \
 && /out/kube-bench version | grep -qx v0.16.0

FROM cgr.dev/chainguard/wolfi-base:latest@sha256:824f77df45397eb954dfb963db255907ee8842e3446353ce93d688e5e862f51d
# busybox is named so that it stays in the world file when wolfi-base (the meta package that pulls in
# apk-tools) is removed: it is /bin/sh and the text tools of every audit.
RUN apk add --no-cache \
      busybox=1.38.0-r2 \
      systemd=261.3-r2 \
      procps=4.0.7-r1 \
      findutils=4.11.0-r2 \
      kubectl-1.36=1.36.4-r8 \
      kubectl-1.36-default=1.36.4-r8 \
 && apk del --no-network --purge wolfi-base apk-tools \
 && rm -rf /var/cache/apk /etc/apk/cache \
 && journalctl --version | head -n1 \
 && ps --version && xargs --version | head -n1 && kubectl version --client >/dev/null
WORKDIR /opt/kube-bench
COPY --from=deps /src/cfg/ /opt/kube-bench/cfg/
COPY --from=build /out/kube-bench /usr/local/bin/kube-bench
# Root, as upstream's image: the CronJob reads root-owned 0600 files under /var/lib/rancher as their
# owner, with every capability dropped (cluster/infra/kube-bench/cronjob.yaml).
LABEL org.opencontainers.image.title="self-defending-portfolio kube-bench" \
      org.opencontainers.image.description="kube-bench built from the pinned upstream release with a current Go toolchain, with journalctl for the k3s checks" \
      org.opencontainers.image.source="https://github.com/HubertMJ/self-defending-portfolio" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="v0.16.0"
ENTRYPOINT ["/usr/local/bin/kube-bench"]
