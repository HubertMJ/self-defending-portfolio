# ADR 0024: Argo CD runs only the controllers this installation uses, and KSOPS is built here

Date: 2026-10-02 · Status: accepted

## Context
ADR 0023 removed Dex from Argo CD's `install.yaml` because nothing used it, and recorded that nothing
else was found unused. That search looked at images, i.e. at what moves the posture number. Two
more upstream components are unused, but they run the same `quay.io/argoproj/argocd:v3.5.3` image as
the rest of Argo CD, so removing them was not visible in a per-image count and was not looked at:

- **The ApplicationSet controller.** `cluster/apps` is an app-of-apps of plain `Application` objects,
  one file each, each reviewed on its own; there is no `ApplicationSet` in this repository
  (`git grep -i applicationset`) or in the cluster (`kubectl get applicationsets -A`: none). The
  controller still ran, with a ClusterRole of its own, a Service, a NetworkPolicy and about 40 MiB.
- **The notifications controller.** Argo CD notifications need triggers, templates and services in
  `argocd-notifications-cm` and `notifications.argoproj.io/subscribe*` annotations on Applications or
  AppProjects. This repository sets none (the live ConfigMap and Secret have no data; no
  Application or AppProject carries the annotation). Alerting here is Falco -> Falcosidekick
  (ADR 0013). The controller still ran, with its Role, a metrics Service and about 37 MiB.

Each unused controller is a process with API credentials that can be wrong, a deployment to keep
patched and memory on an 8 GB node; none of that buys anything.

The repo-server's KSOPS init container runs `viaductoss/ksops:v4.5.1`, the newest KSOPS release
(2026-04-13; also upstream master on 2026-10-02, `git ls-remote
https://github.com/viaduct-ai/kustomize-sops`). ADR 0023 left it as "a candidate for the Talon
treatment". Its image is built with Go 1.25.0 and ships, besides `ksops`, a second copy of it
(`kustomize-sops`), kustomize v5.3.0, git and glibc (distroless/base): **109** CRITICAL+HIGH
(`aquasec/trivy:0.75.0`, 2026-10-02: 41 in each ksops copy, 23 in kustomize, 4 in Debian's OpenSSL).
The repo-server uses exactly one file of it: `ksops install /custom-tools` copies the binary into an
emptyDir that is mounted at `/usr/local/bin/ksops`, and Argo CD's own kustomize stays (ADR 0013,
correction). Compiling upstream's v4.5.1 source unchanged with Go 1.26.8 leaves 19 HIGH, all in four
modules with fixed releases: golang.org/x/crypto, x/net, x/text and google.golang.org/grpc.

## Decision
**1. Both controllers are removed from the bootstrap kustomization**, by kustomize `$patch: delete`
on every object install.yaml v3.5.3 creates for them, matched by kind and name - the pattern
`argocd-dex-server-delete.yaml` set (ADR 0023):
`cluster/bootstrap/argocd/argocd-applicationset-controller-delete.yaml` (Deployment, Service,
ServiceAccount, Role, RoleBinding, ClusterRole, ClusterRoleBinding, NetworkPolicy) and
`cluster/bootstrap/argocd/argocd-notifications-controller-delete.yaml` (Deployment, metrics
Service, ServiceAccount, Role, RoleBinding, NetworkPolicy, ConfigMap `argocd-notifications-cm`).
The rendered bootstrap goes from 55 objects to 40.

**2. What stays, and why** (checked against the v3.5.3 sources, not assumed):
- The CRD `applicationsets.argoproj.io`. argocd-server v3.5.3 builds an ApplicationSet informer
  unconditionally (`server/server.go`, `NewServer`: `appFactory.Argoproj().V1alpha1()
  .ApplicationSets().Informer()`, started in `Run`) and serves the ApplicationSet API and UI from
  it. It is not in the server's cache-sync wait, so the server would start without the CRD - but the
  informer would then fail its list/watch for the life of the process, and the UI's ApplicationSet
  view would error. With the CRD and no controller it is an empty list. The CRD also keeps an
  accidental `ApplicationSet` visible as a known, inert kind instead of an unknown one.
- Secret `argocd-notifications-secret`, empty. argocd-server reads it (and the ConfigMap) for its
  notifications API through notifications-engine, which treats either object being absent as empty
  (`pkg/api/factory.go`, `getConfigMapAndSecretWithListers`), so deleting both would be safe. The
  ConfigMap is deleted. The Secret is not, because a `$patch: delete` for it is a plaintext
  `kind: Secret` document in git, which `scripts/check-secrets-encrypted.sh` refuses (ADR 0006). The
  guard is right and is not weakened to remove an empty object.
- argocd-server's own RBAC on applicationsets, the `applicationsetcontroller.*` keys of
  argocd-cmd-params-cm, and upstream's `argocd-repo-server-network-policy`, which still names both
  controllers' pod labels as allowed clients on 8081. All inert without the controllers; patching
  them would widen the diff against install.yaml for no change in behaviour. A pod claiming either
  label needs create rights in `argocd`, which is already full control of Argo CD.

**3. Live objects are deleted explicitly, once, by name.** `kubectl apply -k` never prunes, and the
bootstrap is not an Argo CD Application (ADR 0005, amendment), so nothing would ever remove the
running controllers. `cluster/bootstrap/prune-removed-argocd-components.sh` lists every object the
three delete patches remove (Dex included, a no-op where 8.1 already ran), by kind and name, no label
selectors. It re-checks the preconditions against the cluster (no ApplicationSets, an empty
notifications ConfigMap), refuses to run while the checked-out kustomization still declares any of
the components, and is a server-side dry run unless given `--delete`. Runbook: `docs/bootstrap.md`,
8.5.

**4. KSOPS is built here** (`app/ksops`), the way `app/talon` is (ADR 0023), and built, Trivy-gated,
SBOM'd and signed by build-images.yml like every image under `app/` (ADR 0011, ADR 0016):
- source: `viaduct-ai/kustomize-sops` at `d9442dc3153d9c16e517a68ce8926c9507386429`, the commit tag
  v4.5.1 points at, fetched by full hash and checked after checkout. No Go source is changed.
- dependencies: upstream's go.mod/go.sum with grpc v1.83.2, x/crypto v0.55.0, x/net v0.58.0 and
  x/text v0.41.0 (grpc and x/crypto are the releases app/talon raised to), then `go mod tidy`;
  minimal version selection moved what those four require and nothing else was raised by hand.
  sops v3.12.2, age v1.3.1 and kustomize/api v0.19.0 - decryption and KRM I/O - are upstream's.
  Committed in `app/ksops/modules/`, checked with `go mod verify` against go.sum and sum.golang.org.
  The grpc raise is clean here: unlike app/talon, nothing in KSOPS's graph imports the split-out
  `grpc/stats/opentelemetry` module, so no ambiguous import had to be removed.
- tests: upstream's `make test` (`go vet`, `go test -race`, the PGP fixtures imported first) with
  `--network=none`, in a stage the image depends on: 15 tests pass, 0 skipped by upstream's own
  guards. TestKSOPSPluginInstallation is skipped explicitly: it shells out to a `kustomize` binary
  this build does not have; the same property is checked against the built image instead (below).
- build: upstream's flags (CGO off, `-trimpath`, `-ldflags "-w -s"`, plus an empty build id); the
  build stage runs `ksops install` on the result and compares the copy byte for byte.
- runtime: distroless `static-debian13:nonroot`, uid 65532, the binary at `/usr/local/bin/ksops` -
  the path upstream's image uses, so the init container's command is unchanged. `ksops install` is
  a subcommand of the binary (it copies `os.Executable()`), so the image needs no shell, `cp` or
  busybox. No CA bundle, git or kustomize: KSOPS here decrypts with a local age key and never
  dials out.
- `golang:1.26.8` and the distroless base are the digests app/api and app/talon pin.

**Verified locally** (2026-10-02), before anything deploys it: the image scans **0** CRITICAL/HIGH
(`aquasec/trivy:0.75.0`; upstream's 109). Run like the init container (read-only root filesystem,
uid 65532, all capabilities dropped, no-new-privileges, no network), `ksops install /custom-tools`
writes a 46 MB static ELF. With that file mounted at `/usr/local/bin/ksops` in
`registry.k8s.io/kustomize/kustomize:v5.8.1` - the kustomize Argo CD v3.5.3 ships - `kustomize build
--enable-alpha-plugins --enable-exec`, as uid 999 like the repo-server, decrypts a SOPS/age-encrypted
Secret through a `viaduct.ai/v1 ksops` exec generator; with a different age key it fails with
sops' "0 successful groups required". The age key was a throwaway generated for the check, never
this repository's.

## Consequences
- Two fewer Deployments, one fewer ClusterRole/ClusterRoleBinding pair, two fewer Roles, Services,
  ServiceAccounts and NetworkPolicies in `argocd`; about 77 MiB of memory back. No change to the
  posture number: the image they ran is still running as argocd-server, repo-server and the
  application controller.
- Using either feature later is deleting its patch entry from `kustomization.yaml` (and, for
  notifications, adding the configuration as a patch) and re-applying the bootstrap.
- An Argo CD bump must re-check the delete patches against the new install.yaml: a renamed or new
  object for either controller would otherwise come back silently. `kubectl kustomize
  cluster/bootstrap/argocd | grep -i 'applicationset-controller\|notifications-controller'` must
  stay empty.
- KSOPS joins Talon as a component whose release tracking this repository does by hand: on each
  KSOPS release, rebuild `app/ksops/modules/` from the new tag's go.mod (Dockerfile header) and drop
  every raise the release has caught up with; when it has caught up with all of them and its image is
  clean, delete app/ksops and return to the upstream image.
