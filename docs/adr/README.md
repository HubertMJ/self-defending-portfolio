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
| [0006](0006-sops-age-for-secrets.md) | SOPS + age for secrets in git | 0 | accepted, amended 2026-10-04 (second KSOPS Secret: the API's SIEM certificate, ADR 0034) |
| [0007](0007-cloud-init-and-ansible-bootstrap.md) | VM from cloud image via Proxmox API, everything else Ansible | 0 | accepted, amended 2026-10-04 (second inventory group `siem_nodes`, Ansible from the tooling container; ingest.yml for the SIEM shipper) |
| [0008](0008-pinned-versions.md) | Pin every version, bump deliberately | 0 | accepted, amended 2026-10-04 (third-party debs pinned by key fingerprint, indexed SHA256, preference and hold; Fluent Bit too) |
| [0009](0009-nftables-host-firewall.md) | nftables host firewall with default-deny input | 0 | accepted |
| [0010](0010-cilium-gateway-api.md) | Cilium's built-in Gateway API instead of ingress-nginx | 2 | accepted, amended 2026-10-01 (internal LoadBalancer address for the Gateway) |
| [0011](0011-supply-chain.md) | Build, scan, describe and sign our own image; verify it at admission | 3 | accepted, amended 2026-10-01 (Kyverno verifies cosign v3 Sigstore bundles) |
| [0012](0012-pod-security-and-resource-policy.md) | Pod Security `restricted` and pod resources as Kyverno policies, Audit before Enforce | 4 | accepted, amended 2026-10-01 (both policies Enforce) |
| [0013](0013-runtime-detection-and-response.md) | Runtime detection and response: Falco modern eBPF least-privileged, Falcosidekick, Falco Talon scoped to `sandbox` | 4 | accepted, amended 2026-10-01 (read-only host mounts via a kustomize post-render; corrections: Argo CD's own kustomize, `perf_event_paranoid=2`, no Talon Events, Talon JSON log), 2026-10-02 (isolation under 3 s, ADR 0032), 2026-10-04 (Falco's metrics snapshot as the SIEM heartbeat, priority Informational) |
| [0014](0014-posture-scanning.md) | Posture scanning: Trivy Operator client/server with offline scan Jobs, kube-bench CronJob with a k3s config override, Policy Reporter internal only | 4 | accepted |
| [0015](0015-portfolio-api.md) | The portfolio API: one Go process runs visitor-triggered attacks in `sandbox`, streams detection and response over SSE, and rations itself | 5 | accepted, amended 2026-10-02 (Trivy counts only images a pod runs; cluster-wide pods list), 2026-10-03 (the 24 h counters persist, ADR 0035), 2026-10-04 (one egress to siem01:9200 and one SIEM credential, ADR 0034) |
| [0016](0016-one-image-workflow.md) | One matrix workflow builds and signs every image; the admission identity stays one file on main | 5 | accepted, amended 2026-10-03 (commit and run id to the web image too; run-id label on every image, ADR 0035) |
| [0017](0017-attack-scenario-safety-model.md) | Attack scenarios: a safety model for letting anonymous visitors attack the cluster | 5 | accepted, amended 2026-10-02 (interactive terminal, unguarded twin), 2026-10-03 (`dns-exfil` resolves a name inside the cluster only, ADR 0034) |
| [0018](0018-scenario-detection-and-response-mapping.md) | Attack scenarios: which Falco rule detects each one, and what Talon does about it | 5 | accepted, amended 2026-10-01 (execs mark the victim first), 2026-10-02 (terminal detections; execution-from-shop-volume rule) |
| [0019](0019-frontend-stack-and-csp.md) | Frontend stack and Content Security Policy: vanilla TypeScript + esbuild, no third-party origins, Trusted Types | 6 | accepted, amended 2026-10-01 (errors never cacheable; rollout skew accepted) |
| [0021](0021-evidence-events-and-victim-poller.md) | Evidence events (pod, enriched falco/talon, victim) and a hardened reader for the attacked pod's victim app | 7 | accepted, amended 2026-10-03 (provenance, posture detail and run-list fields, ADR 0035), 2026-10-04 (Hubble flows reach the SIEM, not the API) |
| [0023](0023-third-party-vulnerabilities.md) | Third-party vulnerabilities go down only by removing or replacing images (Dex removed, newest releases, Talon built here), never by hiding them; posture shows own vs third-party | 7 | accepted |
| [0024](0024-argocd-trim-and-ksops-build.md) | Argo CD runs only the controllers it uses (no ApplicationSet, no notifications controller); KSOPS built here from the pinned release with fixed dependencies | 7 | accepted |
| [0025](0025-own-builds-of-small-components.md) | Falcosidekick, metrics-server, the Trivy Operator and kube-bench built here from their pinned releases with fixed dependencies; metrics-server moves from k3s to Argo CD | 7 | accepted |
| [0026](0026-coredns-build-and-delivery.md) | CoreDNS built here from the pinned release with fixed dependencies, deployed by the k3s role as a k3s auto-deploy manifest in place of k3s's bundled copy (same objects and ClusterIP, taken over by a rolling update) | 7 | accepted, amended 2026-10-04 (`coredns-custom`: the `exfil.sdp.test` sinkhole, NXDOMAIN, never forwarded, ADR 0034) |
| [0027](0027-argocd-build.md) | Argo CD built here from the pinned release commit, with the helm, kustomize and git-lfs releases it ships, all with fixed dependencies; `argocd` stays outside admission verification | 7 | accepted |
| [0028](0028-cilium-images-build.md) | Cilium's four images (agent, operator, Hubble Relay, Envoy) are upstream's 1.19.8 release with the Go binaries rebuilt against fixed dependencies and the base OS's OpenSSL updated, on upstream's own layers; rolled out operator/relay, then Envoy, then the agent | 7 | accepted |
| [0029](0029-terminal-runs-and-command-output.md) | The attacker's terminal: interactive runs where the visitor types command ids and reads the real, scrubbed, capped output; quarantine lingers until the cut is visible (FIX 1) | 5 | accepted |
| [0030](0030-stats-and-persistence.md) | Cross-visitor stats from a hub tap, persisted in one `portfolio-stats` ConfigMap (get/update only) that survives a rollout | 5 | accepted, amended 2026-10-03 (hourly buckets for the 24 h window, last run time, ADR 0035) |
| [0031](0031-unguarded-twin-namespace.md) | The unguarded twin namespace (`sandbox-unguarded`): every preventive layer of `sandbox`, no automatic response, so the response's worth is visible by contrast | 5 | accepted, amended 2026-10-03 (`dns-exfil` resolves a name; dropped in the twin) |
| [0032](0032-terminal-scenario-and-quarantine-latency.md) | The attacker's terminal (a fifth, interactive scenario run by command id) and bringing quarantine isolation under 3 s (per-run labels out of the Cilium identity, 500 ms grace period) | 5 | accepted, amended 2026-10-03 (fifteenth command `dns-exfil`, ADR 0034) |
| [0033](0033-interactive-terminal-defence-map-twin.md) | The front end becomes interactive: an attacker's terminal, a defence map, an unguarded twin and live stats; real-time-first playback, probe-based quarantine proof, placeholder copy stripped from production | 8 | accepted, amended 2026-10-03 (the mock is not shipped, ADR 0035) |
| [0034](0034-siem-opensearch-security-analytics.md) | A ready-made SIEM: OpenSearch 3.9 with Security Analytics on its own VM `siem01`, Sigma rules and Alerting monitors synced from git, write-only, certificate-authenticated ingest into daily data streams whose rolled indices are write-blocked, host identities HMAC-pseudonymised, order/periodicity/intervals in the API; a DNS-exfiltration scenario Falco cannot see and correlation catches | 9 | accepted, amended 2026-10-04 (siem01 as built and the S0 results, P1; ingest as built, P2: shipper sandbox, sdp.lua, N5-N7 closed) |
| [0035](0035-credibility-provenance-evidence-persisted-window.md) | Credibility: provenance on the page (commit, CI run, digests, one checked cosign identity), evidence by default, the 24 h Falco/Talon counters in the persisted stats as hourly buckets, no MockBackend in production, stale Talon/Falcosidekick ReplicaSets pruned | 8 | accepted, amended 2026-10-04 (verify panel at the bottom of the page, linked from the footer) |

Phases 5 and 6 were built on parallel branches and merged together; the numbers they had reserved
are all in use except 0020 (phase 6 documentation needed no decision of its own), which is released.
0020 stays unused. 0025-0033 are in use: the interactive demo was built on three parallel branches (0029 terminal
runs and command output, 0030 stats and persistence - API; 0031 unguarded twin, 0032 terminal catalogue and
quarantine latency - cluster; 0033 terminal, defence map, twin view - web). 0034 is the SIEM decision (phase 9);
0035 makes the existing page verifiable (provenance, evidence, the persisted 24 h window, no mock in production).
The next free ADR is 0036.

## Open items carried by accepted ADRs

Decisions are accepted with their known costs written down. The ones still open:

| Item | ADR |
|------|-----|
| `make validate` renders with kustomize v5.7.1; Argo CD's repo-server runs its own v5.8.1 | [0013](0013-runtime-detection-and-response.md) |
| Talon 0.3.0's k8sevents notifier cannot work (object keys title-cased); the fix is in the commit app/talon builds, the notifier stays off until enabling it is decided | [0013](0013-runtime-detection-and-response.md), [0023](0023-third-party-vulnerabilities.md) |
| Third-party images with fixed but unreleased or unadopted findings: the raised dependencies of Talon, KSOPS, Argo CD (with helm, kustomize, git-lfs), Falcosidekick, metrics-server and the Trivy Operator (and kube-bench's Go and Wolfi pins) need re-checking on each upstream release | [0023](0023-third-party-vulnerabilities.md), [0024](0024-argocd-trim-and-ksops-build.md), [0025](0025-own-builds-of-small-components.md), [0027](0027-argocd-build.md) |
| metrics-server is deployed by Argo CD in `kube-system`, outside Kyverno's signature check by design, and its manifests must be compared with k3s's bundled copy on each k3s bump | [0025](0025-own-builds-of-small-components.md) |
| Cilium is four images built here until a 1.19 patch release ships clean (1.19.9 should): each release means rebuilding `app/cilium*` and `app/hubble-relay` (new commit, runtime and Envoy digests, modules/, expected version strings) or, once upstream is clean, reverting to the chart's images; the pins are in both `cluster/apps/cilium.yaml` and the cilium role; `kube-system` is outside Kyverno's signature check by design | [0028](0028-cilium-images-build.md) |
| The KSOPS image pin is in the bootstrap: a digest bump reaches the cluster only through a manual `kubectl apply -k cluster/bootstrap/argocd`; `argocd` is outside Kyverno's signature check by design | [0024](0024-argocd-trim-and-ksops-build.md) |
| CoreDNS no longer moves with k3s: each k3s bump must diff its bundled `coredns.yaml` against the role's template; the image pin is in the k3s role and reaches the cluster only when the role runs; `kube-system` is outside Kyverno's signature check by design; NodeHosts is static (single node) | [0026](0026-coredns-build-and-delivery.md) |
| Argo CD has no requests/limits and is excluded from the resources policy | [0012](0012-pod-security-and-resource-policy.md) |
| `ClusterPolicy` is deprecated in Kyverno 1.19; migration to ImageValidatingPolicy / CEL policies deferred | [0011](0011-supply-chain.md), [0012](0012-pod-security-and-resource-policy.md) |
| The signer identity still accepts the phase 3 `build-web.yml` (transition); dropped once hello runs a `build-images.yml` digest | [0016](0016-one-image-workflow.md) |
| Digest bumps are manual commits (`scripts/bump-image-digest.sh`) until Renovate is enabled | [0008](0008-pinned-versions.md), [0011](0011-supply-chain.md), [0016](0016-one-image-workflow.md) |
| The API's rate-limit windows and per-run history are in memory only; one replica by design (the 24 h counters persist since ADR 0035) | [0015](0015-portfolio-api.md), [0035](0035-credibility-provenance-evidence-persisted-window.md) |
| No Hubble flow events in the API's own feed: a Relay client is too heavy for the API today (the SIEM gets them from the static exporter, ADR 0034) | [0021](0021-evidence-events-and-victim-poller.md) |
| Fluent Bit 5.1.3 crashes with a heartbeat input set to `Flush_On_Startup`; heartbeats start a minute after a restart until a fixed release is pinned | [0034](0034-siem-opensearch-security-analytics.md) |

The full list of gaps and residual risks, including ones no ADR records yet, is in the
[threat model](../threat-model.md#7-known-gaps-and-residual-risk).
