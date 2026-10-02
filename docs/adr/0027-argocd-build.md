# ADR 0027: Argo CD is built here from the pinned release, with its tools

Date: 2026-10-02 · Status: accepted

## Context
After ADR 0023 (Dex removed, Redis one patch on) and ADR 0024 (ApplicationSet and notifications
controllers removed, KSOPS built here), every Argo CD process left runs one image,
`quay.io/argoproj/argocd:v3.5.3`: argocd-server, the repo-server and its `copyutil` init container,
the application controller and the Redis `secret-init` init container. v3.5.3 (2026-09-14) is still
the newest Argo CD 3.5 release. Trivy Operator reports that image at **2 CRITICAL + 29 HIGH** in
each of those five containers (2026-10-02); `aquasec/trivy:0.75.0` against today's database finds
**118** (2 CRITICAL, 116 HIGH):

| Where | C+H | What |
|-------|-----|------|
| `/usr/local/bin/git-lfs` v3.7.1 | 39 (1 C) | Go 1.25.3 stdlib; x/crypto 0.36.0, x/net 0.38.0, x/text 0.23.0 |
| `/usr/local/bin/kustomize` v5.8.1 | 24 (1 C) | Go 1.24.0 stdlib; x/text 0.28.0 |
| `/usr/bin/pebble` (Ubuntu base image) | 21 | Go 1.26.2 stdlib, x/net 0.40.0 |
| `/usr/local/bin/argocd` v3.5.3 | 17 | Go 1.26.4 stdlib; grpc 1.81.1, oras-go 2.6.1, go-git 5.19.1, x/crypto 0.53.0, x/text 0.38.0 |
| `/usr/local/bin/helm` v4.2.1 | 14 | Go 1.26.4 stdlib; oras-go 2.6.1, x/crypto 0.53.0, x/net 0.55.0, x/text 0.38.0 |
| Ubuntu 26.04 packages | 3 | OpenSSL 3.5.5-1ubuntu3.5 (`libssl3t64`, `openssl`, `openssl-provider-legacy`) |

Every one has a fixed release. Argo CD does not compile the tools: its Dockerfile downloads the
vendors' release binaries at the versions `hack/tool-versions.sh` pins (helm 4.2.1, kustomize 5.8.1,
git-lfs 3.7.1), so 77 of the 118 are in binaries Argo CD's next release would still ship unless the
vendors re-release. The Ubuntu findings and pebble are an older base digest: Ubuntu 26.04's current
digest plus `apt-get dist-upgrade` (upstream's own build step) scans clean. Waiting for upstream fixes
nothing here; Talon (ADR 0023) and KSOPS (ADR 0024) set the pattern for this.

## Decision
**1. `app/argocd` builds the image** from upstream's own Dockerfile at the release commit, stage by
stage, and build-images.yml builds, Trivy-gates, SBOMs and signs it like every image under `app/`
(ADR 0011, ADR 0016):
- **argocd:** `argoproj/argo-cd` at `c9c369efcc5b2a0bd720803f8d14a1c3eaddf579` (tag v3.5.3), fetched by
  full hash and checked after checkout. No Go or TypeScript source is changed. The binary is built by
  upstream's `make argocd-all` (CGO off, static, the version variables upstream's release workflow
  passes); every component is the same multi-call binary behind a symlink, as upstream ships it.
- **the UI:** upstream's `argocd-ui` stage unchanged - the same `node:24.14.1` image by digest,
  corepack 0.34.6, `pnpm install --frozen-lockfile` against upstream's `pnpm-lock.yaml`, `pnpm build` -
  embedded through upstream's `go:embed` (`ui/embed.go`).
- **helm, kustomize, git-lfs:** compiled from the commits their release tags point at
  (helm v4.2.1 `d591a19b`, kustomize/v5.8.1 `9790a1c3`, git-lfs v3.7.1 `b84b3384`) with the linker
  flags their own release builds use, so `helm version`, `kustomize version` and `git-lfs version`
  report the releases Argo CD expects. This matters beyond cosmetics: Argo CD runs `kustomize version`
  and parses the semver to decide which flags kustomize gets; an unset version would make it assume
  v99.99.99.
- **dependencies:** each project's go.mod/go.sum with only the modules raised that carry findings, then
  `go mod tidy`; committed under `app/argocd/modules/<project>/`, `go mod verify`d in the build. argocd:
  grpc v1.83.2, x/crypto v0.55.0, x/net v0.58.0, x/text v0.41.0, go-git v5.19.2, oras-go v2.6.2. helm:
  the same x/ modules, oras-go v2.6.2 and grpc v1.83.2. kustomize: x/text v0.41.0. git-lfs: x/crypto,
  x/net, x/text as above. grpc, x/crypto, x/net and x/text are the releases app/talon and app/ksops
  raised to. Minimal version selection moved what those require (x/sys, x/sync, genproto,
  opentelemetry, cloud.google.com among others); the Kubernetes libraries, the in-tree gitops-engine
  and every `replace` directive of upstream's are untouched. The commands are in the Dockerfile
  header.
- **Go 1.26.8** for all four (the golang image app/api, app/talon and app/ksops pin).
- **tests:** upstream's unit tests run in the builder against the raised dependencies, offline
  (`--network=none`) and as uid 1000 (as upstream's CI; several tests check file modes root would
  bypass); no tests, no image. helm: its whole `go test ./...` (the WebAssembly test plugin's one
  dependency is fetched before the network goes); kustomize: its `kustomize/` module; git-lfs: its
  `go test ./...`. argocd: the packages that import the raised modules or drive the tools -
  `util/helm`, `util/oci`, `util/kustomize`, `util/git`, `util/sourceintegrity`, `util/cert`,
  `util/crypto`, `util/password`, `util/grpc`, `util/proxy`, `util/askpass`, `reposerver/apiclient`,
  `cmpserver/...`, `commitserver/...` - **with this image's own helm, kustomize and git-lfs on PATH**,
  so Argo CD's wrappers are tested against the binaries that ship. The full argo-cd suite needs a
  Kubernetes API server, Redis and the network, and is not run. Skipped by name, each because it
  needs the internet: helm's TestPullRun_ChartNotFound and TestRenderWithDNS; Argo CD's TestIndex,
  Test_nativeHelmChart_ExtractChart(_insecure), TestLsRemote, TestNewFactory, TestListRevisions,
  TestAnnotatedTagHandling, TestVerifyCommitSignature and
  TestGitHubAppGetAccessToken_DialerDefaultTimeout (expects a connect timeout, gets "unreachable"
  offline); and TestNewConnection_ErrorWhenRotatedCertIsInvalid, which assumes two writes a few
  milliseconds apart get different mtimes - not guaranteed with jiffy-granular timestamps, and seen
  to pass and fail on the same tree.
- **runtime:** upstream's `argocd-base` and final stages line for line: Ubuntu 26.04 (a newer digest
  of upstream's tag), `apt-get dist-upgrade`, the same eight packages (git, tini, ca-certificates,
  gpg, gpg-agent, tzdata, connect-proxy, openssh-client), user `argocd` uid/gid 999, the same paths
  (`/usr/local/bin/argocd` and its nine symlinks, `/app/config/{ssh,tls,gpg/source,gpg/keys}`,
  `/home/argocd`, `/etc/ssh/ssh_known_hosts` -> `/app/config/ssh/ssh_known_hosts`), the wrapper
  scripts, `git lfs install --system`, `GRPC_ENABLE_TXT_SERVICE_CONFIG=false`, `tini --` as the
  entrypoint. A distroless or slimmer base was considered and rejected: the repo-server execs git,
  gpg, ssh and the wrappers (`/bin/sh` scripts), install.yaml's Deployments mount into those paths,
  and Debian 13 slim with the same packages scans at 61 CRITICAL+HIGH (OpenSSH, GnuPG, util-linux,
  expat, most unfixed) against Ubuntu's 0.
- **version strings:** argocd reports `v3.5.3+c9c369e.dirty` (and `ExtraBuildInfo` names this ADR),
  helm `GitTreeState:"dirty"`: the build variables say what was compiled - the release tree with
  go.mod and go.sum changed - and Argo CD prints a bare tag only for a clean tree. Nothing in Argo CD
  parses its own version.

**Verified locally** (2026-10-02):
- `aquasec/trivy:0.75.0 image --severity CRITICAL,HIGH`: **0** (upstream: 118). 775 MB vs 828 MB.
- the image as upstream's: `argocd version`, `argocd-server --help`, `argocd-repo-server --help`,
  `argocd-application-controller --help`; uid 999, the same entrypoint, working directory, ENV,
  `/etc/gitconfig` LFS filter and paths; git 2.53.0, gpg 2.4.8, OpenSSH 10.2p1, tini 0.19.0 (the same
  package versions as upstream's image); helm `v4.2.1`, kustomize `v5.8.1`, git-lfs `3.7.1`.
- **the repo-server renders like upstream's:** both images started side by side as
  `argocd-repo-server` (read-only root, uid 999, no capabilities, Redis 8.2.10), and asked over gRPC -
  `GenerateManifest`, as the application controller asks - to render `cluster/infra/falco` from a git
  checkout with this repository's `kustomize.buildOptions` (`--enable-alpha-plugins --enable-exec
  --enable-helm`): both pulled falco chart 9.2.0 and returned the same 7 manifests, byte for byte,
  with the read-only hostPath patch applied.
- **KSOPS through the repo-server:** the same, with app/ksops' binary at `/usr/local/bin/ksops` and a
  throwaway age key at `SOPS_AGE_KEY_FILE` (never this repository's): a SOPS-encrypted Secret behind
  a `viaduct.ai/v1 ksops` generator comes back decrypted, from both images alike.
- **the whole bootstrap:** `cluster/bootstrap/argocd` rendered with this image (and app/ksops') in place
  of upstream's and applied to a throwaway k3s v1.35.9 in Docker: server, repo-server (KSOPS init
  container included), application controller and Redis Ready; the UI and `/api/version` served by
  argocd-server; `argocd login`, `argocd version` (server: Kustomize v5.8.1, Helm v4.2.1), `argocd app
  list`, `argocd app diff` and a partial `argocd app sync` of an Application for
  `cluster/infra/falco` from GitHub `main` - git over HTTPS through go-git, chart pull, render,
  compare and apply all through the new binaries. No error in any component's log.

**2. `argocd` stays outside admission verification.** Not added to `verify-portfolio-images` or
`restrict-image-registries`, for the reason ADR 0024 gave for KSOPS, which is stronger here: these
are all of Argo CD's pods, and Kyverno is an Argo CD Application. With `failurePolicy: Fail`, a
Kyverno outage would stop Argo CD's pods from starting, and so stop the redeploy of Kyverno. With
`Ignore` the outage case is fail-open, but signature verification is still a network round trip to
GHCR and the Sigstore TUF root on every pod admission: an outage of either would block Argo CD -
the cluster's repair path - on an external service. No variant was found that adds a guarantee
without adding that coupling. The image is signed, SBOM'd and Trivy-gated in CI, verifiable by hand
(`scripts/verify-image.sh`, done in the runbook before the switch), pinned by digest in git, and only
cluster-admin can change the pin. An `Audit`-mode verification for `argocd` (reports, never blocks)
would add visibility without coupling; it is not part of this decision.

**3. Argo CD runs it.** The bootstrap kustomization maps `quay.io/argoproj/argocd` to
`ghcr.io/hubertmj/self-defending-portfolio/argocd`, pinned by digest, in its `images:` list - one
entry that rewrites all five references install.yaml v3.5.3 makes (server, repo-server and
`copyutil`, application controller, Redis `secret-init`), without patching any Deployment.
`scripts/bump-image-digest.sh argocd <digest>` rewrites it (the script now also recognises an entry
whose `newName:` is ours), `scripts/check-image-digests.sh` refuses its placeholder like every other,
and it reaches the cluster only through `kubectl apply -k cluster/bootstrap/argocd`
(`docs/bootstrap.md`, 8.9).

## Consequences
- Once applied, Argo CD leaves the third-party column of the posture page: five containers at 2
  CRITICAL + 29 HIGH each in the cluster today become an own image at 0. The whole `argocd` namespace
  then runs this repository's images, except Redis (0 already, ADR 0023).
- Argo CD's release tracking is by hand, like Talon's and KSOPS's, and heavier: on each Argo CD
  release, take the new commit, re-read upstream's Dockerfile and `hack/tool-versions.sh` (base image,
  node pin, tool versions), regenerate the four `modules/` directories from the new commits and drop
  every raise the release has caught up with. When upstream's image scans clean, delete app/argocd and
  the `images:` entry. The bootstrap's install.yaml URL and `ARGOCD_COMMIT` must name the same
  release; a newer install.yaml with this older image is not a supported combination.
- The build is the heaviest under `app/`: under 6 minutes here without layer cache (8 cores, base
  images present; the UI's webpack build and the argocd binary are most of it, the four test runs
  about 3 minutes in parallel). Expect roughly 15-25 minutes on a 4-core GitHub-hosted runner without
  cache - inside the ~45 minute budget - and a few GB of disk for four projects' Go module and build
  caches and node_modules, well under the runner's 14 GB. BuildKit's GHA cache makes a rebuild with
  only `modules/` changed shorter.
- `apt-get dist-upgrade` is not pinned (as upstream's): a rebuild picks up Ubuntu's security fixes, and
  two builds of the same commit can differ in OS packages. The digest that runs is the one in git.
- Pulled from GHCR: a fresh bootstrap needs the `self-defending-portfolio/argocd` package public, as
  every other package here, before `bootstrap.sh` runs - otherwise Argo CD itself cannot start.
- Rollback is the switch commit reverted and the bootstrap re-applied: upstream's image comes back
  with nothing else changed, because the paths, user and configuration are upstream's.
