# Architecture Decision Records

Short, dated records of decisions that shaped this project. Format: context, decision, consequences.
Superseded ADRs stay in place with a note pointing at the replacement; later changes to an accepted
decision are appended as dated amendments in the same file.

| # | Decision | Phase | Status |
|---|----------|-------|--------|
| [0001](0001-dedicated-vm-for-the-cluster.md) | Dedicated VM for the cluster, not the shared Docker host | 0 | accepted |
| [0002](0002-github-for-repo-and-ci.md) | GitHub + GitHub Actions + GHCR | 0 | accepted |
| [0003](0003-cloudflare-tunnel-exposure.md) | Expose the site via Cloudflare Tunnel, no inbound ports | 0 | accepted |
| [0004](0004-cilium-as-cni.md) | Cilium as CNI, kube-proxy replacement, no flannel | 0 | accepted |
| [0005](0005-argocd-for-gitops.md) | Argo CD for GitOps | 0 | accepted, amended 2026-10-01 (drift-free diffs, bootstrap re-apply exception) |
| [0006](0006-sops-age-for-secrets.md) | SOPS + age for secrets in git | 0 | accepted |
| [0007](0007-cloud-init-and-ansible-bootstrap.md) | VM from cloud image via Proxmox API, everything else Ansible | 0 | accepted |
| [0008](0008-pinned-versions.md) | Pin every version, bump deliberately | 0 | accepted |
| [0009](0009-nftables-host-firewall.md) | nftables host firewall with default-deny input | 0 | accepted |
| [0010](0010-cilium-gateway-api.md) | Cilium's built-in Gateway API instead of ingress-nginx | 2 | accepted, amended 2026-10-01 (internal LoadBalancer address for the Gateway) |
| [0011](0011-supply-chain.md) | Build, scan, describe and sign our own image; verify it at admission | 3 | accepted, amended 2026-10-01 (Kyverno verifies cosign v3 Sigstore bundles) |
| [0012](0012-pod-security-and-resource-policy.md) | Pod Security `restricted` and pod resources as Kyverno policies, Audit before Enforce | 4 | accepted, amended 2026-10-01 (both policies Enforce) |
| [0013](0013-runtime-detection-and-response.md) | Runtime detection and response: Falco modern eBPF least-privileged, Falcosidekick, Falco Talon scoped to `sandbox` | 4 | accepted, amended 2026-10-01 (read-only host mounts via a kustomize post-render; corrections: Argo CD's own kustomize, `perf_event_paranoid=2`, no Talon Events, Talon JSON log) |
| [0014](0014-posture-scanning.md) | Posture scanning: Trivy Operator client/server with offline scan Jobs, kube-bench CronJob with a k3s config override, Policy Reporter internal only | 4 | accepted |
| [0015](0015-portfolio-api.md) | The portfolio API: one Go process runs visitor-triggered attacks in `sandbox`, streams detection and response over SSE, and rations itself | 5 | accepted |
| [0016](0016-one-image-workflow.md) | One matrix workflow builds and signs every image; the admission identity stays one file on main | 5 | accepted |
| [0017](0017-attack-scenario-safety-model.md) | Attack scenarios: a safety model for letting anonymous visitors attack the cluster | 5 | accepted |
| [0018](0018-scenario-detection-and-response-mapping.md) | Attack scenarios: which Falco rule detects each one, and what Talon does about it | 5 | accepted |
| [0019](0019-frontend-stack-and-csp.md) | Frontend stack and Content Security Policy: vanilla TypeScript + esbuild, no third-party origins, Trusted Types | 6 | accepted, amended 2026-10-01 (errors never cacheable; rollout skew accepted) |
| [0021](0021-evidence-events-and-victim-poller.md) | Evidence events (pod, enriched falco/talon, victim) and a hardened reader for the attacked pod's victim app | 7 | accepted |
| [0023](0023-third-party-vulnerabilities.md) | Third-party vulnerabilities go down only by removing or replacing images (Dex removed, newest releases, Talon built here), never by hiding them; posture shows own vs third-party | 7 | accepted |
| [0024](0024-argocd-trim-and-ksops-build.md) | Argo CD runs only the controllers it uses (no ApplicationSet, no notifications controller); KSOPS built here from the pinned release with fixed dependencies | 7 | accepted |

Phases 5 and 6 were built on parallel branches and merged together; the numbers they had reserved
are all in use except 0020 (phase 6 documentation needed no decision of its own), which is released.
0020 stays unused; the next ADR is 0025.

## Open items carried by accepted ADRs

Decisions are accepted with their known costs written down. The ones still open:

| Item | ADR |
|------|-----|
| `make validate` renders with kustomize v5.7.1; Argo CD's repo-server runs its own v5.8.1 | [0013](0013-runtime-detection-and-response.md) |
| Talon 0.3.0's k8sevents notifier cannot work (object keys title-cased); the fix is in the commit app/talon builds, the notifier stays off until enabling it is decided | [0013](0013-runtime-detection-and-response.md), [0023](0023-third-party-vulnerabilities.md) |
| Third-party images with fixed but unreleased or unadopted findings: Argo CD, Falcosidekick, Cilium 1.19, metrics-server; Talon's and KSOPS's raised dependencies need re-checking on each upstream release | [0023](0023-third-party-vulnerabilities.md), [0024](0024-argocd-trim-and-ksops-build.md) |
| The KSOPS image pin is in the bootstrap: a digest bump reaches the cluster only through a manual `kubectl apply -k cluster/bootstrap/argocd`; `argocd` is outside Kyverno's signature check by design | [0024](0024-argocd-trim-and-ksops-build.md) |
| Argo CD has no requests/limits and is excluded from the resources policy | [0012](0012-pod-security-and-resource-policy.md) |
| `ClusterPolicy` is deprecated in Kyverno 1.19; migration to ImageValidatingPolicy / CEL policies deferred | [0011](0011-supply-chain.md), [0012](0012-pod-security-and-resource-policy.md) |
| The signer identity still accepts the phase 3 `build-web.yml` (transition); dropped once hello runs a `build-images.yml` digest | [0016](0016-one-image-workflow.md) |
| Digest bumps are manual commits (`scripts/bump-image-digest.sh`) until Renovate is enabled | [0008](0008-pinned-versions.md), [0011](0011-supply-chain.md), [0016](0016-one-image-workflow.md) |
| The API's 24 h counters and run history are in memory only; one replica by design | [0015](0015-portfolio-api.md) |
| No Hubble flow events: a Relay client is too heavy for the API today | [0021](0021-evidence-events-and-victim-poller.md) |

The full list of gaps and residual risks, including ones no ADR records yet, is in the
[threat model](../threat-model.md#7-known-gaps-and-residual-risk).
