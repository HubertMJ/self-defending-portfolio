# Threat model

Scope: everything this repository deploys or depends on to put `https://hubertjablon.ski` on the
internet, plus the phase 5 feature that lets an anonymous visitor trigger a controlled attack in the
cluster. Method: STRIDE per trust boundary, with each control linked to the file that implements it.
Where a control is only planned (phase 5/6 work in progress), it says so; a planned control is not
counted as mitigation.

Last reviewed against the repository at phase 4 (Falco, Talon, Kyverno, Trivy Operator, kube-bench,
Policy Reporter committed; phase 4 not yet accepted on the live cluster).

Contents: [system](#1-system-in-one-paragraph) · [assets](#2-assets) · [attackers and goals](#3-attackers-and-their-goals) ·
[trust boundaries](#4-trust-boundaries) · [STRIDE per boundary](#5-stride-per-boundary) ·
[abuse cases for the attack button](#6-abuse-cases-for-the-attack-button-planned) ·
[known gaps](#7-known-gaps-and-residual-risk) · [what an attacker would try next](#8-what-an-attacker-would-try-next) ·
[review triggers](#9-when-to-revisit-this-document)

## 1. System in one paragraph

A single Debian 13 VM (`k3s01`) on a home Proxmox host runs k3s with Cilium. The only public path in
is a Cloudflare Tunnel that `cloudflared` dials outbound; it forwards to a Cilium Gateway API listener
with a Let's Encrypt certificate, which routes to a static site built, scanned, signed and SBOM-attested
in GitHub Actions and verified by Kyverno at admission. Argo CD reconciles everything from the public
GitHub repository; secrets are SOPS/age-encrypted in git. Falco watches syscalls, Falcosidekick
forwards alerts, Falco Talon kills or quarantines pods in the `sandbox` namespace. Trivy Operator,
kube-bench and Kyverno background scans produce posture reports. Diagrams:
[docs/architecture/](architecture/README.md).

## 2. Assets

| # | Asset | Why it matters | Where it lives |
|---|-------|----------------|----------------|
| A1 | Integrity of the public site | Defacement is the visible failure of a security portfolio | `hello` pods, image in GHCR |
| A2 | Cluster control (API server, `cluster-admin`, Argo CD's service account) | Whoever holds it owns every other asset | k3s on `k3s01`; kubeconfig on the operator machine |
| A3 | The age private key | Decrypts every secret in git | operator machine; Secret `argocd/sops-age` |
| A4 | Cloudflare DNS-01 token, tunnel credentials | Certificate issuance for the zone; impersonating the origin | SOPS files in `cluster/infra/`, Secrets in `cert-manager` and `cloudflared` |
| A5 | The signing identity (`build-web.yml` on `refs/heads/main`) | Anything it signs is admitted | GitHub repository + Actions |
| A6 | Write access to `main` | Argo CD deploys whatever `main` says | GitHub account(s) with push rights |
| A7 | The node and the homelab behind it | Pivot to other VLANs (`docker01`, Proxmox, trusted LAN) | Proxmox host, DMZ VLAN 41 |
| A8 | Integrity of detection and response | A blinded or forged alert pipeline makes the demo lie, or kills the wrong pod | `falco`, `falco-response` |
| A9 | Honesty of the posture data shown to visitors | Reports that can be forged or are silently stale undermine the project's claim | PolicyReports, Trivy reports, kube-bench Job logs |
| A10 | Availability of the demo | The attack button is the product | single node, 8 GB RAM |
| A11 | Visitor data | Client IPs reach the planned API via `CF-Connecting-IP` | planned `portfolio-api` |

## 3. Attackers and their goals

| Attacker | Capability assumed | Likely goals |
|----------|--------------------|--------------|
| Anonymous internet visitor | HTTPS requests through Cloudflare; may automate and rotate IPs | Deface (A1), exhaust the demo (A10), find a bug in the planned API, use the attack button as a foothold |
| Visitor using the attack button (planned) | Can make the API start one of four fixed scenarios in `sandbox` | Turn a "controlled" attack into an uncontrolled one: escape the pod, reach other namespaces, the node or the LAN; mine; forge events shown to others |
| Code execution in any pod | A compromised workload (nginx bug, scenario escape, malicious upstream image) | Lateral movement, read Secrets, reach the API server, disable Falco/Talon, exfiltrate |
| Supply-chain attacker | Compromised GitHub account, action, base image or registry | Get an image admitted (A5), get a manifest synced (A6) |
| Insider-equivalent on the LAN | Reach to the DMZ VLAN or the Proxmox host | Node access (A7), steal kubeconfig or age key |

Out of scope: Cloudflare, GitHub, Sigstore and Let's Encrypt being malicious themselves (they are
trusted third parties; see residual risks), physical access to the homelab, and denial of service
against Cloudflare.

## 4. Trust boundaries

| ID | Boundary | Crossed by |
|----|----------|------------|
| TB1 | Internet → Cloudflare edge | visitor HTTPS |
| TB2 | Cloudflare → tunnel → cluster | requests forwarded over the outbound tunnel to cloudflared, then to the Gateway and backends |
| TB3 | Visitor → attack scenarios in `sandbox` (planned) | API call that creates a pod and execs into it |
| TB4 | CI / GHCR / Sigstore → cluster admission | images, signatures, SBOM attestations |
| TB5 | Git repository → Argo CD → cluster | manifests, chart versions, encrypted secrets |
| TB6 | Workloads → node / host / LAN | syscalls, host mounts, node network, Proxmox |
| TB7 | Inside the cluster: detection → response | Falco → Falcosidekick → Talon → API server (unauthenticated HTTP hops) |

## 5. STRIDE per boundary

Format per row: threat, existing control (linked), residual risk. "Planned" means the control is part
of the phase 5/6 design and is not in the repository yet.

### TB1 · Internet → Cloudflare

| STRIDE | Threat | Control | Residual |
|--------|--------|---------|----------|
| S | Phishing look-alike or DNS hijack of the zone | Zone on Cloudflare; the only record the site needs is the tunnel CNAME ([`docs/bootstrap.md`](bootstrap.md) §4.2) | Cloudflare account takeover is out of the repo's reach; account MFA is an owner responsibility (TODO-CONTENT: confirm) |
| T | TLS interception between visitor and edge | Cloudflare terminates TLS; HSTS 2 years at the origin ([`cluster/infra/hello/httproute.yaml`](../cluster/infra/hello/httproute.yaml)) | Cloudflare itself sees plaintext (accepted, [ADR 0003](adr/0003-cloudflare-tunnel-exposure.md)) |
| R | No record of who hit what | Cloudflare logs; nginx access log to stdout ([`app/web/nginx.conf`](../app/web/nginx.conf)) | Pod logs are not shipped anywhere durable; Cloudflare-side logging is not configured from this repository |
| I | Origin IP discovery, then direct attack | No inbound port anywhere; host firewall input policy drop ([`nftables.conf.j2`](../ansible/roles/firewall/templates/nftables.conf.j2), [ADR 0009](adr/0009-nftables-host-firewall.md)) | Low: there is nothing listening to find |
| D | Volumetric or L7 flood | Cloudflare's edge in front; the site is static | WAF and rate-limit rules are dashboard settings, not in git (gap G9) |
| E | — | — | — |

### TB2 · Cloudflare → tunnel → cluster

| STRIDE | Threat | Control | Residual |
|--------|--------|---------|----------|
| S | A rogue connector registers for the tunnel | Tunnel credential is SOPS-encrypted ([`cloudflared-credentials.sops.yaml`](../cluster/infra/cloudflared/cloudflared-credentials.sops.yaml), [ADR 0006](adr/0006-sops-age-for-secrets.md)) | Anyone with the age key or a decrypted copy can run a competing connector |
| S | Forged `X-Forwarded-*` / client IP headers | Envoy trusts exactly one XFF hop ([`cluster/apps/cilium.yaml`](../cluster/apps/cilium.yaml)); the only path to the Gateway is cloudflared ([`cloudflared/ciliumnetworkpolicy.yaml`](../cluster/infra/cloudflared/ciliumnetworkpolicy.yaml)) | Any in-cluster pod that can reach the Gateway Service could forge headers; today only cloudflared's egress is written to allow it, but nothing in this repository stops pods in namespaces without a policy (kyverno, argocd, cert-manager) from reaching the Gateway Service |
| T | Plaintext hop inside the cluster | cloudflared → Gateway is HTTPS with SNI and certificate verification ([`config.yaml`](../cluster/infra/cloudflared/config.yaml)) | Gateway → backend is plain HTTP on the node (Envoy in the host netns), accepted |
| R | — | Hubble records flows and DNS lookups (L7 DNS rules) | Hubble keeps a ring buffer, not an archive |
| I | Routing to an internal service by Host header | Tunnel ingress has one hostname and a `http_status:404` catch-all; Gateway listeners are bound to `hubertjablon.ski`; only labelled namespaces may attach routes ([`gateway.yaml`](../cluster/infra/gateway/gateway.yaml)) | A new namespace given the `gateway-routes` label is both routable and reachable by cloudflared on 8080 - one label, one review |
| D | Tunnel or Gateway saturation | Two cloudflared replicas, rolling update with `maxUnavailable: 0` ([`deployment.yaml`](../cluster/infra/cloudflared/deployment.yaml)) | Single node: a node outage is a site outage |
| E | Compromised cloudflared pivots inward | cloudflared: restricted PSA, non-root, read-only rootfs, no SA token, egress allow-list (DNS, Cloudflare on 7844/443, Gateway 443, route backends 8080) | Egress to `world:443` is an exfiltration channel for a compromised cloudflared |

### TB3 · Visitor → attack scenarios in `sandbox` (planned)

The `sandbox` namespace and its controls exist today; the API and scenario images do not. Planned
design (phase 5): the API accepts `POST /api/attack/{id}` for one of four fixed scenario IDs, creates a
pod from a template held in a ConfigMap, optionally execs a fixed command, correlates Falco/Talon events
by pod name and streams them over SSE.

| STRIDE | Threat | Control | Residual |
|--------|--------|---------|----------|
| S | Spoof another visitor's run or inject events into their stream | Planned: run IDs generated server-side; events are a broadcast of what Falco/Talon reported, not visitor input; webhooks on an internal port reachable only from `falco-response` | Until built, unverified |
| T | Choose the image, command or pod spec | Planned: fixed scenario IDs (404 otherwise), templates from git; today, any pod in `sandbox` must pass [`verify-portfolio-images`](../cluster/infra/kyverno-policies/verify-portfolio-images.yaml) and [`restrict-image-registries`](../cluster/infra/kyverno-policies/restrict-image-registries.yaml) (Enforce, `failurePolicy: Fail`) and PSA `restricted` ([`sandbox/namespace.yaml`](../cluster/infra/sandbox/namespace.yaml)) | The scenario image is ours and signed, so a bug in it is admitted |
| R | Abuse without trace | k3s audit policy logs pods, `pods/exec` at RequestResponse and full bodies in `sandbox` ([`audit-policy.yaml.j2`](../ansible/roles/k3s/templates/audit-policy.yaml.j2)); Talon writes an Event per action | Audit log stays on the node (no shipping) |
| I | Scenario pod reads cluster data | No SA token in victims ([`tests/runtime/victim-pod.yaml`](../tests/runtime/victim-pod.yaml)); `sandbox` is default-deny with DNS only ([`sandbox/ciliumnetworkpolicy.yaml`](../cluster/infra/sandbox/ciliumnetworkpolicy.yaml)) | DNS is a covert channel (names are logged by Hubble) |
| D | Exhaust the node through the button | Planned: 3 attacks / 10 min / IP, 30 / hour global, one concurrent run, pod deadline ≤ 120 s, `sandbox` ResourceQuota (3 pods, 500m CPU, 512 Mi) | A distributed requester can consume the global budget and deny the demo to others (accepted: the budget protects the node, not fairness) |
| E | Escape from scenario pod to node or to other namespaces | PSA `restricted` (no privilege, no host namespaces, no capabilities); Falco + Talon kill a shell and quarantine a network tool ([`talon/rules.yaml`](../cluster/infra/falco-response/talon/rules.yaml)); quarantine policy denies all traffic ([`quarantine-ccnp.yaml`](../cluster/infra/sandbox/quarantine-ccnp.yaml)) | A kernel exploit from a restricted pod is not prevented, only (possibly) detected; the API's own RBAC (pods create/exec in `sandbox`) becomes the prize, see §6 |

### TB4 · CI / GHCR / Sigstore → admission

| STRIDE | Threat | Control | Residual |
|--------|--------|---------|----------|
| S | Image signed by someone else (fork, PR run, other workflow) | Keyless identity pinned and anchored: `build-web.yml@refs/heads/main`, issuer GitHub OIDC ([`verify-portfolio-images.yaml`](../cluster/infra/kyverno-policies/verify-portfolio-images.yaml), [ADR 0011](adr/0011-supply-chain.md)) | Anyone who can push to `main` (A6) or alter that workflow on `main` gets a valid signature |
| T | Tag repointed after verification | Manifests pin digests; `mutateDigest: true` rewrites the pod to the verified digest; `disallow-latest-tag` Enforce ([`disallow-latest-tag.yaml`](../cluster/infra/kyverno-policies/disallow-latest-tag.yaml)) | — |
| T | Malicious or vulnerable dependency | Trivy gate on fixable CRITICAL/HIGH, SARIF for the rest ([`build-web.yml`](../.github/workflows/build-web.yml)); actions pinned by commit SHA; base image pinned by digest ([`app/web/Dockerfile`](../app/web/Dockerfile)) | Unfixed CVEs pass by design; a compromised upstream at a pinned digest is not detected by signature checks |
| R | "What was running in March?" | SBOM as a signed SPDX attestation, Rekor entry for every signature | — |
| I | — | Public repo and public package by design | — |
| D | Sigstore/GHCR outage blocks deploys | `failurePolicy: Fail` only on `hello` and `sandbox`; `webhookTimeoutSeconds: 30` | A Kyverno outage or GHCR outage stops new pods in those two namespaces (accepted, fail closed) |
| E | Third-party images run unverified | Third-party charts/images pinned by tag+digest ([ADR 0008](adr/0008-pinned-versions.md)); signature verification covers only our registry path | Upstream images (Cilium, Kyverno, Falco, Argo CD, ...) are trusted by digest, not by signature |

Also: in `SigstoreBundle` mode the signature rule has no predicate filter, so the SBOM attestation
bundle alone satisfies it; accepted because both come from the same pinned identity (ADR 0011,
amendment).

### TB5 · Git → Argo CD → cluster

| STRIDE | Threat | Control | Residual |
|--------|--------|---------|----------|
| S | Push to `main` by an attacker | GitHub account security | Branch protection, required reviews and signed commits are not visible from the repository (TODO-CONTENT: owner to state what is configured) |
| T | Malicious manifest synced | CI: kubeconform, `kyverno apply` over every rendered object, gitleaks ([`lint.yml`](../.github/workflows/lint.yml), [`validate-cluster.sh`](../scripts/validate-cluster.sh)) | Argo CD polls `main` and does not wait for CI to pass; every Application uses `project: default`, so any file in `cluster/apps/` can deploy anything anywhere (gap G6) |
| R | Who changed the cluster | Every change is a commit; manual exceptions are listed (bootstrap re-apply, [ADR 0005](adr/0005-argocd-for-gitops.md) amendment) | — |
| I | Secret disclosure from the public repo | SOPS/age with only `data`/`stringData` encrypted ([`.sops.yaml`](../.sops.yaml)); CI refuses plaintext Secrets ([`check-secrets-encrypted.sh`](../scripts/check-secrets-encrypted.sh)); gitleaks over history | The age key sits in one Secret readable by `argocd-repo-server`; its compromise decrypts all of git's secrets |
| D | Bad commit wedges the cluster | Prune off for `cilium`, `kyverno`, `gateway-api-crds`; cluster-wide policies use `failurePolicy: Ignore` | Single Argo CD replica, no resource limits (gap G2) |
| E | Argo CD UI or API reached | No route, tunnel entry or LoadBalancer for Argo CD; port-forward only ([`argocd-cmd-params-cm.yaml`](../cluster/bootstrap/argocd/argocd-cmd-params-cm.yaml)) | Local admin account; no NetworkPolicy in `argocd` (gap G5) |

### TB6 · Workloads → node / host / LAN

| STRIDE | Threat | Control | Residual |
|--------|--------|---------|----------|
| S | SSH as someone else | Key-only, no root, `AllowUsers ansible`, modern crypto ([`00-hardening.conf.j2`](../ansible/roles/ssh_hardening/templates/00-hardening.conf.j2)); SSH and API reachable only from two admin VLANs ([`group_vars/all.yml`](../ansible/inventory/group_vars/all.yml)) | — |
| T | Host tampering after compromise | auditd rules ([`ansible/roles/auditd/`](../ansible/roles/auditd/)), unattended upgrades | Logs are local; a root attacker can erase them |
| R | — | k3s API audit log, auditd, `nft-drop:` log prefix | Not shipped off the node |
| I | Secrets at rest on the node | k3s `secrets-encryption: true`, kubeconfig mode 0600 ([`config.yaml.j2`](../ansible/roles/k3s/templates/config.yaml.j2)) | kube-bench mounts k3s's server/agent dirs read-only and runs as root (no network, no token: [`kube-bench/cronjob.yaml`](../cluster/infra/kube-bench/cronjob.yaml)) |
| D | One workload starves the node | `require-pod-resources` (Audit), quotas planned for `sandbox` | `argocd` and `kube-system` excluded; policy not yet Enforce (gap G3) |
| E | Privileged sensor compromised → host | Falco runs with 4 capabilities, not `privileged`; read-only `/proc` (`driver.loader.enabled: false`); no API token; egress only to Falcosidekick ([`cluster/apps/falco.yaml`](../cluster/apps/falco.yaml)) | Writable `/host/lib/modules` mount (gap G1); BPF + PERFMON + SYS_PTRACE are close to host-equivalent ([ADR 0013](adr/0013-runtime-detection-and-response.md)) |
| E | Pod → node → LAN pivot | Node in a DMZ VLAN; host firewall default-deny input; forward chain left to Cilium | Egress from the node to the LAN is not restricted by this repository (host `output` chain accepts) |

### TB7 · Detection → response (inside the cluster)

| STRIDE | Threat | Control | Residual |
|--------|--------|---------|----------|
| S | Forged alert makes Talon kill or quarantine a pod | Falcosidekick accepts only Falco pods, Talon only Falcosidekick ([`falco-response/ciliumnetworkpolicy.yaml`](../cluster/infra/falco-response/ciliumnetworkpolicy.yaml)) | Both HTTP APIs are unauthenticated; integrity rests entirely on Cilium policy (ADR 0013) |
| T | Rules changed at run time | No falcoctl; rules from the image plus git ([`cluster/apps/falco.yaml`](../cluster/apps/falco.yaml)); Talon rules from a hashed ConfigMap | — |
| R | Silent response | Talon's `k8sevents` notifier writes an Event on every acted-on pod ([`talon/config.yaml`](../cluster/infra/falco-response/talon/config.yaml)) | Events expire (1 h default) |
| I | — | Alerts contain command lines; Falco output stays in-cluster | Planned SSE stream will show truncated Falco output to visitors (§6) |
| D | Blind the sensor (kill Falco, flood events, evade rules) | DaemonSet + Argo CD self-heal; Falco runs with requests/limits | Rule evasion (renamed binaries, non-TTY shells, interpreters) is possible; detection coverage is the stock ruleset plus one custom rule |
| E | Talon abused as a cluster-wide killer | Talon RBAC: pods get/patch/delete and events create in `sandbox` only, `get` on Namespace `sandbox`, its own Lease; proven by `kubectl auth can-i` in [`tests/runtime/run.sh`](../tests/runtime/run.sh) | — |

## 6. Abuse cases for the attack button (planned)

These are the requirements the phase 5 API is built against; they are listed here so the
implementation can be checked against them. None of them is enforced by the repository yet.

| # | Abuse case | Expected behaviour | Mechanism (planned unless noted) |
|---|------------|--------------------|----------------------------------|
| AB1 | Hammer `POST /api/attack/{id}` | `429` with `Retry-After` | per-IP limit 3 / 10 min, global 30 / hour |
| AB2 | Two runs at once | `409` | global concurrency 1 |
| AB3 | Unknown or crafted scenario id (`../`, long strings, other namespaces) | `404`, no pod created | IDs looked up in the scenario ConfigMap; nothing from the request reaches the pod spec |
| AB4 | Spoof `CF-Connecting-IP` to dodge the per-IP limit | header ignored unless the request came via cloudflared | Cloudflare overwrites the header at the edge; the API is reachable only through the Gateway, which only cloudflared can reach |
| AB5 | Rotate IPs to drain the global budget | demo unavailable to others until the window passes | accepted; Cloudflare rate limiting is the outer layer (not in git, G9) |
| AB6 | Hold thousands of SSE connections to `/api/events` | bounded memory, connections shed | needs an explicit connection cap and idle timeout in the API; not yet specified in the design |
| AB7 | Inject markup through Falco output shown in the browser | rendered as text | output truncated to 300 chars server-side; frontend must not use HTML insertion; CSP without `unsafe-inline` scripts |
| AB8 | Reach the internal webhook port from outside | not routed | port 8081 has no HTTPRoute; network policy admits only `falco-response` |
| AB9 | Use a scenario pod to mine or to scan | killed or capped | `activeDeadlineSeconds` ≤ 120 s, `sandbox` ResourceQuota, default-deny egress (exists), quarantine on network tools (exists) |
| AB10 | Compromise the API itself, then use its RBAC | blast radius = `sandbox` | API RBAC limited to pods create/get/list/watch/delete and pods/exec in `sandbox` plus report reads; anything it creates still passes Kyverno + PSA (exists) |
| AB11 | Read sensitive data through `/api/posture` | aggregate counts only | posture endpoint returns numbers, not report bodies |
| AB12 | Make the timeline lie (forge "detected"/"responded") | impossible without reaching port 8081 from `falco-response` | event source is the webhook, not the visitor |

## 7. Known gaps and residual risk

Found while writing this document or recorded in the ADRs. Each is a fact about the repository today.

| ID | Gap | Impact | Where recorded / next step |
|----|-----|--------|----------------------------|
| G1 | Falco chart 9.2.0 mounts `/host/lib/modules` **read-write** in least-privileged mode; no value changes it | A compromised sensor plus module autoload is a host-root path | [ADR 0013](adr/0013-runtime-detection-and-response.md), [`cluster/apps/falco.yaml`](../cluster/apps/falco.yaml); fix upstream or post-render |
| G2 | Argo CD runs with no requests or limits and is excluded from `require-pod-resources` | OOM on the 8 GB node can take out the reconciler | [ADR 0012](adr/0012-pod-security-and-resource-policy.md) (recorded debt); bootstrap patch |
| G3 | `pod-security-restricted` and `require-pod-resources` are still **Audit** with `failurePolicy: Ignore` | Violations are reported, not blocked; PSA labels remain the floor | [ADR 0012](adr/0012-pod-security-and-resource-policy.md); flip after zero failures (plan commit 9) |
| G4 | All five policies are `kyverno.io/v1` ClusterPolicies, deprecated in Kyverno 1.19 | Future Kyverno bump may force a rushed migration | [ADR 0011](adr/0011-supply-chain.md) amendment, [ADR 0012](adr/0012-pod-security-and-resource-policy.md); migrate to ImageValidatingPolicy / CEL policies and rewrite `tests/admission/` |
| G5 | No NetworkPolicy in `kyverno`, `argocd`, `cert-manager` | Their egress is open; a compromised controller can reach anything, including the Gateway Service | `docs/bootstrap.md` §5.6 says a Kyverno egress policy comes "in phase 4"; it is not in the repository |
| G6 | All Applications use `project: default`; Argo CD syncs `main` without waiting for CI | A merged mistake in `cluster/apps/` can target any namespace with cluster-wide effect | add an AppProject with namespace/kind allow-lists; branch protection requiring the `validate` job |
| G7 | Falcosidekick and Talon are unauthenticated HTTP | A Cilium policy outage lets any pod forge alerts against `sandbox` | ADR 0013 consequences |
| G8 | Quarantine applies to new flows only | An already-open connection survives the label until it closes | [`quarantine-ccnp.yaml`](../cluster/infra/sandbox/quarantine-ccnp.yaml) header |
| G9 | Cloudflare WAF, rate limiting, "Always Use HTTPS" and account settings are not in git | The outer layer is unreviewed and not restored by a rebuild | TODO-CONTENT: document the settings or codify them |
| G10 | Logs (k3s audit, auditd, Falco, pod logs) stay on the node | A root attacker can erase evidence; nothing alerts a human outside the cluster | ADR 0009 mentions shipping to Loki "later" |
| G11 | Deploying a new image digest is a manual commit; Renovate not enabled | Patched images can lag | [ADR 0011](adr/0011-supply-chain.md) known gap |
| G12 | The web image is Alpine-based and ships busybox `sh` and `wget` | A code-execution bug in nginx gets a shell and a downloader for free (the runtime test relies on them) | consider a distroless/static image for `hello` and a separate victim image (phase 5 scenario image) |
| G13 | Single node, single replica for most controllers | Any node incident is a full outage; Kyverno down = no new pods in `hello`/`sandbox` | accepted for a homelab demo |
| G14 | Signature verification covers only `ghcr.io/hubertmj/self-defending-portfolio/*` | Upstream images are trusted by digest pin alone | [ADR 0008](adr/0008-pinned-versions.md) |
| G15 | Host `output` chain accepts everything | A node compromise can reach the rest of the DMZ / LAN as far as the UniFi gateway allows | [`nftables.conf.j2`](../ansible/roles/firewall/templates/nftables.conf.j2); gateway rules are outside this repo |
| G16 | No backup of cluster state is described | Recovery is a rebuild from git plus the age key; anything not in git (reports, Leases, PVC of the Trivy server) is lost | rebuild path in [`docs/bootstrap.md`](bootstrap.md) |

## 8. What an attacker would try next

Assuming the obvious doors are shut (no inbound port, signed images only, restricted pods), a
patient attacker's order of play would likely be:

1. **Go around the cluster, not through it.** Phish or token-steal a GitHub account with push to
   `main` (A6): one commit is both a signed image (the workflow signs whatever `main` builds) and a
   synced manifest. Mitigation lives outside the repo: MFA, branch protection, required CI, review.
2. **Attack the planned API, not the static site.** It is the only component that parses visitor
   input and holds create/exec rights. Look for request smuggling through the Gateway, SSE resource
   exhaustion (AB6) and any path where request data reaches a pod spec (AB3).
3. **From a scenario pod, test the edges of `restricted`.** Kernel bugs reachable without capabilities,
   DNS as a covert channel, timing before Talon reacts (the runtime test measures time-to-kill), and
   evasion of Falco's stock rules (no TTY, renamed binaries, interpreters instead of `sh`).
4. **Target the privileged corners.** Falco (four capabilities, writable `/host/lib/modules`, G1) and
   kube-bench (root with k3s's keys mounted read-only) are the only pods close to host-level. A
   malicious upstream release at the next digest bump is the realistic way in, which is why bumps are
   reviewed commits (ADR 0008).
5. **Turn the defences into the weapon.** Forge alerts to Talon if Cilium policy ever lapses (G7),
   or try to make Talon act outside `sandbox` (RBAC returns 403, proven in `tests/runtime/run.sh`).
6. **Pivot east-west.** From any compromised controller in a namespace without network policy (G5),
   reach the API server, the Gateway with forged headers, or the LAN via the node (G15).
7. **Cover tracks.** Logs are local (G10); deleting them after a node compromise is easy.

## 9. When to revisit this document

- The phase 5 API, scenario images or new HTTPRoutes land (TB3 and §6 move from planned to existing).
- Any policy flips between Audit and Enforce, or migrates away from ClusterPolicy.
- A new namespace gets the `portfolio.hubertjablon.ski/gateway-routes` label.
- A new outbound FQDN is added to any CiliumNetworkPolicy.
- Falco or its chart is bumped (re-check G1).
