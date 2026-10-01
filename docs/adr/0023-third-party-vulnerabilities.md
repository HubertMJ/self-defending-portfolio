# ADR 0023: Third-party vulnerabilities go down only by removing or replacing images, never by hiding them

Date: 2026-10-01 · Status: accepted

## Context
The posture page (ADR 0015, ADR 0019) shows the CRITICAL and HIGH findings Trivy Operator reports
across every distinct running image (ADR 0014). On 2026-10-01 that number was **236**. Recomputed from
the cluster (`kubectl get vulnerabilityreports -A -o json`, one entry per digest, as
`app/api/internal/posture` counts):

| Image | CRITICAL+HIGH | Where it comes from |
|---|---:|---|
| `ghcr.io/dexidp/dex:v2.45.1` | 52 | Argo CD's `install.yaml` (SSO broker) |
| `falcosecurity/falcosidekick:2.32.0` | 43 | the falcosidekick chart's default |
| `quay.io/argoproj/argocd:v3.5.3` | 31 | Argo CD (every component, one image) |
| `viaductoss/ksops:v4.5.1` | 29 | the repo-server's KSOPS init container |
| `falcosecurity/falco-talon:0.3.0` | 24 | Falco Talon |
| Cilium agent, operator, hubble-relay, envoy (1.19.8) | 22 | Cilium |
| k3s-bundled CoreDNS 1.14.6 + metrics-server v0.9.0 | 17 | k3s v1.35.8+k3s1 |
| `redis:8.2.3-alpine` | 11 | Argo CD's `install.yaml` |
| Trivy 0.74.0 + trivy-operator 0.34.0 | 6 | Trivy Operator, Policy Reporter's Trivy plugin |
| `aquasec/kube-bench:v0.16.0` | 1 | kube-bench |

This project's own images (web, api, scenario) had 0. Every one of the 236 had a fixed version
upstream. A visitor reading "236" next to "self-defending" draws a conclusion; the conclusion should be
the true one, and the number should go down for a true reason.

What could make the number smaller, and what each would mean:
- **Ignore, filter or suppress findings** (`ignoreUnfixed`, a `.trivyignore`, a severity cut, counting
  only our own images, hiding a namespace). Each makes the number smaller without making the cluster
  safer, on a page whose whole claim is that it reports what the tools see. Rejected, permanently: not
  an option for any future change either.
- **Remove what nothing uses.** Honest, and the cheapest fix there is.
- **Run the newest release of each component** that is not on it. Honest; bounded by what upstream
  has released.
- **Build a component ourselves** when its newest release is old and its findings are all in
  dependencies with fixes. Honest, but it moves maintenance to this repository, so it is done where it
  pays (one image, many findings, a workload that holds API permissions) and not by reflex.
- **Explain the rest.** A visitor should be able to see that the remaining findings sit in third-party
  cluster components, not in the code this project writes, without the total being reduced to say it.

## Decision
**1. The total stays the true count.** `GET /api/posture` keeps its five Trivy totals exactly as
before: every distinct running image, every finding. It adds `trivy.own`, `trivy.third_party` (each
`{images, critical, high, fixable}`) and `trivy.by_image` (`[{image, own, critical, high, fixable}]`,
worst first). They partition the same reports - own is "published by build-images.yml", i.e.
`ghcr.io/hubertmj/self-defending-portfolio/*` - so the parts always add up to the total, and the tests
assert that. `fixable` counts findings with a `fixedVersion`. The page shows the split in the image
tile and the five worst images in a table, as text; an API without the fields renders the page it
always rendered. Nothing in this repository filters what Trivy reports.

**2. Removed: Argo CD's Dex.** There is no SSO (no `dex.config`, no `oidc.config`; the only login is
the local `admin`, behind a port-forward, ADR 0003). The bootstrap kustomization deletes every Dex
object `install.yaml` creates (`$patch: delete`, `cluster/bootstrap/argocd/argocd-dex-server-delete.yaml`).
SSO later means `oidc.config` against an external IdP, which needs no Dex, or dropping that patch.
Nothing else was found unused: metrics-server serves `kubectl top`, which the memory budget relies on
(ADR 0014), and local-path backs the Trivy server's volume.

**3. Moved to the newest release** (checked against the projects' release pages, Helm indexes and
registries on 2026-10-01; images pinned by tag and digest, ADR 0008):

| Component | From | To | Note |
|---|---|---|---|
| Argo CD's Redis | 8.2.3-alpine | 8.2.10-alpine | kustomize `images:` over install.yaml; same 8.2 line |
| Falcosidekick | 2.32.0 | 2.35.0 | past chart 0.14.0's default; chart unchanged (newest) |
| Trivy (server, scan Jobs, Policy Reporter plugin) | 0.74.0 | 0.75.0 | ahead of the operator's chart default; every CLI flag operator 0.34.0 passes is unchanged |
| k3s (CoreDNS) | v1.35.8+k3s1 (1.14.6) | v1.35.9+k3s1 (1.14.7) | Ansible, run by hand (docs/bootstrap.md 8.2) |

Already the newest in their line, so unchanged: Argo CD v3.5.3 (3.6.0 is a release candidate),
KSOPS v4.5.1, Cilium 1.19.8 (Argo CD's chart and the Ansible seed stay identical, ADR 0004),
trivy-operator 0.34.0 (chart 0.36.0), kube-bench v0.16.0, metrics-server v0.9.0.

**4. Built here: Falco Talon** (`app/talon`). 0.3.0 (2025-02-05) is still the newest release; its 24
findings are all in Go dependencies and the Go standard library. The image is built by
build-images.yml like every image under `app/` (Trivy gate, SPDX SBOM, cosign keyless, ADR 0011,
ADR 0016) from:
- upstream `main` at `d273e352f80e114954f40c9843fd0a1b71a30d57` (2026-09-05): v0.3.0 plus 132
  commits, bug fixes and dependency bumps; the configuration keys are identical to 0.3.0's, so
  `cluster/infra/falco-response/talon/` (log_format json, deduplication, the webhook notifier) is used
  unchanged. Fetched by full hash and checked after checkout;
- upstream's go.mod/go.sum with grpc v1.83.2, x/crypto v0.55.0 and cilium v1.17.15 - the first
  releases that fix the findings in the binary, nothing else raised by hand - committed in
  `app/talon/modules/` and verified with `go mod verify`;
- upstream's tests (`go vet`, `go test -race`) in the build; `golang:1.26.8` and distroless
  `static-debian13:nonroot` (uid 65532, as upstream's image), both the pins app/api uses.
Built locally: 0 CRITICAL/HIGH; `rules check` accepts `talon/rules.yaml`; `server` starts identically
to the upstream image.

Being ours, Talon is now checked at admission: `falco-response` joins both rules of
`verify-portfolio-images` (Falcosidekick's docker.io image is outside its imageReferences, so it is out
of scope, not exempted), and `restrict-image-registries` gains `validate-registries-talon`, which pins
the origin of Talon's pods in that namespace. It selects them by the Deployment's label through a
precondition, not `match.selector`: a label selector in any rule switches off Kyverno's autogen for
the whole policy, which would drop the Deployment-level rules - and the offline gate in `make
validate`, which only sees Deployments - for the other namespaces too. Checked both ways with `make
validate`: upstream's image in falco-response fails, a signed image of ours passes.

The k8sevents notifier fix ADR 0013 waits for (87dd820, title-cased Namespace/Pod keys; 5d5808c, the
involved object's uid) is in the built commit. The notifier stays off: enabling it needs a
namespace-read ClusterRole and an events grant, and that is its own decision, not a side effect of
replacing an image.

## Consequences
- Expected after the changes are deployed, at the cluster's 2026-10-01 vulnerability DB: Dex 52 -> 0
  (gone), Talon 24 -> 0, Redis 11 -> 0, Trivy 4 -> 0, Falcosidekick 43 -> about 8, CoreDNS 14 -> about
  9; unchanged: Argo CD 31, KSOPS 29, Cilium 22, metrics-server 3, trivy-operator 2, kube-bench 1.
  About 105 in total, down from 236, all third-party; own images 0. Measured with today's DB
  (`aquasec/trivy:0.74.0`, CRITICAL,HIGH, findings as Trivy Operator counts them): Falcosidekick 82
  -> 15, CoreDNS 26 -> 16, Talon 57 -> 0, Redis 23 -> 0, Trivy 13 -> 0, Dex 133 -> gone. The DB moves
  daily, so the live number will drift up as new CVEs are published against unchanged images; that
  drift is real and is shown.
- Two components now have one release-tracking job each that upstream used to do: Talon's pinned
  commit and its raised dependencies (re-check on every upstream release; drop app/talon and return
  to the upstream image if a release carries the fixes), and Falcosidekick's image tag above its
  chart's default.
- Several changes reach the cluster outside a plain Argo CD sync, because Argo CD does not manage what
  they touch: the bootstrap re-apply plus a one-off delete of the Dex objects (docs/bootstrap.md 8.1),
  the k3s role (8.2), and the Talon image, which is pinned only once CI has built it from `main` (8.3).
- The posture API exposes image names and versions. They are already public in `cluster/` in this
  repository; no CVE identifiers or report bodies are returned (threat model, AB11).
- Remaining, with a fix upstream in each case: Argo CD (until a 3.5 patch or 3.6 GA), KSOPS (its
  newest release is built with an old Go and dependencies - a candidate for the Talon treatment),
  Falcosidekick (amqp091-go, grpc, x/crypto, OpenSSL; a candidate as well, and building it would also
  let falco-response be a full namespace in `restrict-image-registries`), Cilium (newer only in 1.20,
  a minor upgrade of the CNI that is a decision of its own), metrics-server.
