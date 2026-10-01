# ADR 0020: Third-party image vulnerabilities: remove what is unused, bump what has a newer release, rebuild what upstream will not, and say which is which

Date: 2026-10-01 · Status: accepted

## Context
With phases 5 and 6 live, the posture page showed "236 critical + high" (Trivy Operator, 33 distinct
running images). None of them were in this project's own images (web, api, scenario: 0). All were in
third-party images, and every one had a fixed version upstream. The largest contributors were Argo
CD's Dex (52), Falcosidekick 2.32.0 (43), Argo CD 3.5.3 (31), KSOPS 4.5.1 (29), Falco Talon 0.3.0
(24), Cilium 1.19.8 (22), k3s's CoreDNS and metrics-server (17) and Argo CD's Redis (11).

A page whose purpose is to show a security posture should not lead with a number that is mostly
somebody else's backlog. Hiding the number would be worse. The task was to make it smaller where we
can, and to make it say what it is.

The numbers below come from a local Trivy 0.75.0 with the vulnerability DB of 2026-10-01, run on the
Docker Hub images. They are higher than the live operator's (newer DB, a different count per
finding), so they are comparable with each other, not with the page. Argo CD, Dex and Cilium are on
quay.io and ghcr.io, which the build environment could not pull; their counts are the live ones.

## Decision

**1. Remove what is not used: Dex, the ApplicationSet controller, the notifications controller.**
`argocd-cm` has neither `dex.config` nor `oidc.config`; the only login is the local admin through a
port-forward (ADR 0003). Nothing in `cluster/` is an ApplicationSet, and no notification is
configured. `cluster/bootstrap/argocd/argocd-unused-components.yaml` deletes the three Deployments
from upstream's `install.yaml`, together with their ServiceAccounts, Roles, RoleBindings, Services,
NetworkPolicies, the ApplicationSet ClusterRole and ClusterRoleBinding, and the notifications
ConfigMap: 21 objects, 61 -> 40 rendered. The CRDs stay, and so does the empty notifications Secret:
deleting it would need an exception in the plaintext-Secret guard (ADR 0006). `argocd-server`'s Dex TLS volume
is `optional`, and upstream's repo-server NetworkPolicy still names the removed pods as peers, which
selects nothing and is left alone rather than patched. Dex goes from 52 to nothing.

**2. Bump where a newer release exists, pinned tag@digest (ADR 0008).** The releases checked on
2026-10-01:

| Component | Was | Newest | Done | CRITICAL/HIGH with a fix (local) |
|---|---|---|---|---|
| Argo CD | v3.5.3 | v3.5.3 | nothing to bump | live 31, unchanged |
| Argo CD's Redis | 8.2.3-alpine | 8.2.10-alpine (same minor) | bumped, via the bootstrap `images:` | 23 -> 0 |
| KSOPS | v4.5.1 | v4.5.1 (= master) | rebuilt, see 3 | 109 -> 3 |
| Falcosidekick | 2.32.0 | 2.35.0 (chart 0.14.0 is newest) | bumped, image newer than the chart default | 82 -> 15 |
| Falco Talon | 0.3.0 | 0.3.0 | rebuilt from main, see 3 | 57 -> 6 |
| Cilium | 1.19.8 | 1.19.8 | nothing to bump (Ansible and Argo CD stay identical) | live 22, unchanged |
| Trivy (server, scan jobs) | 0.74.0 | 0.75.0 | bumped | 9 -> 0 |
| Trivy Operator | 0.34.0 | 0.34.0 | nothing to bump | 4, unchanged |
| kube-bench | v0.16.0 | v0.16.0 | nothing to bump | 13, unchanged |
| k3s (CoreDNS, metrics-server) | v1.35.8+k3s1 | v1.35.9+k3s1 | pin bumped; the operator runs Ansible | CoreDNS 1.14.6 -> 1.14.7: 26 -> 16; metrics-server v0.9.0 in both: 14 |

Redis comes from Docker Hub by digest rather than the `public.ecr.aws` mirror `install.yaml` names,
because that is where the digest could be resolved and checked. Argo CD uses Redis as a cache, and
a patch release changes no protocol. An Argo CD bump re-checks the line and drops it once upstream
ships a newer Redis. Falcosidekick 2.33.0-2.34.1 changed no output or environment key (the webhook
and Talon outputs used here included). Ten of its fifteen remaining findings are in the RabbitMQ
client, an output that is not enabled.

The k3s bump is a pin in git (`group_vars`, the role default, and the Kubernetes version
`validate-cluster.sh`, `render-charts.sh` and Falco's `helmCharts` render against). Argo CD does not
apply it. The operator does, with `make cluster` (docs/bootstrap.md section 8). Until then git says
1.35.9 and the node runs 1.35.8, which is harmless for rendering between two patches of one minor.

**3. Rebuild what upstream will not: Talon and KSOPS, through our own pipeline.** Both are the latest
release, and both images carry an old Go toolchain and old modules. Both are Go programs with no cgo.
Building them through `build-images.yml` gives them the same Trivy gate, SBOM and keyless signature
as our own images (ADR 0011, 0016):

- `app/talon`: falcosecurity/falco-talon `main` at `d273e352` (2026-09-05). There is no changelog
  entry since 0.3.0, so it carries fixes and dependency bumps only, including the k8sevents
  namespace fix 0.3.0 lacks. Our `talon/rules.yaml` passes `falco-talon rules check` with it.
  `verify-portfolio-images` now also covers `falco-response`, so the component that deletes and
  quarantines pods has to carry our signature. Falcosidekick's upstream image is not under our
  registry path, so it is not in scope, and `restrict-image-registries` does not list the namespace.
- `app/ksops`: viaduct-ai/kustomize-sops `v4.5.1` (= master), the static `ksops` binary only. The
  repo-server never uses the kustomize, git and glibc that upstream's image also ships. Checked:
  `ksops install` drops a static binary, and kustomize 5.7.1 with it decrypts a SOPS/age-encrypted
  Secret.

Both fetch their source by commit id and check it, run upstream's unit tests in a stage the image
depends on, build with Go 1.26.8, CGO off, `-trimpath -s -w`, and run on distroless
`static:nonroot` (65532). No source is patched. **The one deviation from upstream's module graph** is
a set of minimum versions for `golang.org/x/{crypto,net,text}`. These are the Go team's own modules,
under Go's compatibility promise, and upstream's tests pass with them. A third-party module moves
only when upstream moves it. Raising grpc in Talon cascaded into an ambiguous-import split
(`grpc/stats/opentelemetry`) and missing transitive modules, so it was not taken. What remains (Talon:
grpc 1.68.1 and the Cilium library 1.16.8; KSOPS: grpc 1.79.3) is for upstream to fix.

Rejected: building Argo CD, Cilium or kube-bench the same way. Argo CD and Cilium are large,
multi-binary, partly cgo builds whose release process (UI assets, Envoy) we would be taking over.
kube-bench's remaining findings are mostly in its Alpine base and `jq`. Each is a component we would
then own, and the cost is out of proportion to the gain. They are recorded as accepted until
upstream releases.

**4. Say which is which.** `/api/posture` keeps the original `trivy` totals (every distinct running
image) and adds `fixable_critical`/`fixable_high`, plus `ours` and `third_party` groups with the same
fields. "Ours" means `ghcr.io/hubertmj/self-defending-portfolio/`, with the trailing slash, so a
look-alike repository of another owner does not count. The page's tile now leads with critical +
high in our images. Underneath it shows third-party critical + high, with how many are fixable
upstream, and the total. The split is optional in the page's contract, so a page newer than the API
still renders.

## Consequences
- Expected after deployment (live operator terms): Dex and Redis disappear from the count, KSOPS,
  Talon and Falcosidekick drop to their few remaining module findings, Trivy goes to 0, CoreDNS
  improves after the k3s run, and Argo CD, Cilium, metrics-server, Trivy Operator and kube-bench are
  unchanged. Our own images stay at 0 and are now the headline.
- Two more images of ours, built from upstream source. A Talon or KSOPS bump is now a commit id in a
  Dockerfile plus a digest pin, not a tag in a manifest, and the diff between commits has to be read.
  The `golang.org/x` floors drop out when upstream catches up.
- The Argo CD changes are bootstrap-owned. They reach the cluster only through a re-apply of
  `cluster/bootstrap/argocd` and the explicit deletes in `argocd-unused-components.yaml`, because
  `kubectl apply -k` does not prune. SSO later means bringing Dex back: delete its block there and
  re-apply.
- KSOPS runs in `argocd`, which no image policy covers (ADR 0012: a Kyverno outage must not block
  Argo CD's own pods). Its provenance is the digest in git and `scripts/verify-image.sh`, as for
  every other image there.
- Same rollout as phases 5 and 6 (docs/bootstrap.md section 7): the image sources merge first and
  CI builds them. A second commit pins Talon and KSOPS (and the rebuilt api and web) by digest,
  because `scripts/check-image-digests.sh` refuses placeholder digests on main.
