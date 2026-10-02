# Threat model

Scope: everything this repository deploys or depends on to put `https://hubertjablon.ski` on the
internet, including the feature that lets an anonymous visitor trigger a controlled attack in the
cluster. Method: STRIDE per trust boundary, with each control linked to the file that implements it.
Every control listed exists in the repository; where a case is not covered, the row says so.

Last reviewed against the repository after the phase 5/6 integration (portfolio API, attack scenarios
and the new site, on top of phase 4's Falco, Talon, Kyverno, Trivy Operator, kube-bench and Policy
Reporter). Phase 5/6 is not yet accepted on the live cluster: its images reach `main` in two merges,
and the digest pins come in the second ([`docs/bootstrap.md`](bootstrap.md) §7).

Contents: [system](#1-system-in-one-paragraph) · [assets](#2-assets) · [attackers and goals](#3-attackers-and-their-goals) ·
[trust boundaries](#4-trust-boundaries) · [STRIDE per boundary](#5-stride-per-boundary) ·
[abuse cases for the attack button](#6-abuse-cases-for-the-attack-button) ·
[known gaps](#7-known-gaps-and-residual-risk) · [what an attacker would try next](#8-what-an-attacker-would-try-next) ·
[review triggers](#9-when-to-revisit-this-document)

## 1. System in one paragraph

A single Debian 13 VM (`k3s01`) on a home Proxmox host runs k3s with Cilium. The only public path in
is a Cloudflare Tunnel that `cloudflared` dials outbound; it forwards to a Cilium Gateway API listener
with a Let's Encrypt certificate, which routes `/` to the site (a TypeScript page served by nginx) and
`/api` to the portfolio API (Go); every image of ours is built, scanned, signed and SBOM-attested in
one GitHub Actions workflow and verified by Kyverno at admission. Argo CD reconciles everything from
the public GitHub repository; secrets are SOPS/age-encrypted in git. Falco watches syscalls,
Falcosidekick forwards alerts, Falco Talon kills or quarantines pods in the `sandbox` namespace. A
visitor can make the API start one of four fixed attack scenarios in `sandbox` and watch Falco's
alert and Talon's action arrive over SSE; both reach the API as webhooks. Trivy Operator, kube-bench
and Kyverno background scans produce the posture numbers the API serves. Diagrams:
[docs/architecture/](architecture/README.md).

## 2. Assets

| # | Asset | Why it matters | Where it lives |
|---|-------|----------------|----------------|
| A1 | Integrity of the public site | Defacement is the visible failure of a security portfolio | `hello` pods, image in GHCR |
| A2 | Cluster control (API server, `cluster-admin`, Argo CD's service account) | Whoever holds it owns every other asset | k3s on `k3s01`; kubeconfig on the operator machine |
| A3 | The age private key | Decrypts every secret in git | operator machine; Secret `argocd/sops-age` |
| A4 | Cloudflare DNS-01 token, tunnel credentials | Certificate issuance for the zone; impersonating the origin | SOPS files in `cluster/infra/`, Secrets in `cert-manager` and `cloudflared` |
| A5 | The signing identity (`build-images.yml` on `refs/heads/main`; `build-web.yml` still accepted during a transition, G17) | Anything it signs is admitted | GitHub repository + Actions |
| A6 | Write access to `main` | Argo CD deploys whatever `main` says | GitHub account(s) with push rights |
| A7 | The node and the homelab behind it | Pivot to other VLANs (`docker01`, Proxmox, trusted LAN) | Proxmox host, DMZ VLAN 41 |
| A8 | Integrity of detection and response | A blinded or forged alert pipeline makes the demo lie, or kills the wrong pod | `falco`, `falco-response` |
| A9 | Honesty of the posture data shown to visitors | Reports that can be forged or are silently stale undermine the project's claim | PolicyReports, Trivy reports, kube-bench Job logs |
| A10 | Availability of the demo | The attack button is the product | single node, 8 GB RAM; one API replica |
| A11 | Visitor data | Client IPs reach the API via `CF-Connecting-IP` | `portfolio-api` memory only, as rate-limit keys (IPv6 by /64); the API does not log them |

## 3. Attackers and their goals

| Attacker | Capability assumed | Likely goals |
|----------|--------------------|--------------|
| Anonymous internet visitor | HTTPS requests through Cloudflare; may automate and rotate IPs | Deface (A1), exhaust the demo (A10), find a bug in the API, use the attack button as a foothold |
| Visitor using the attack button | Can make the API start one of four fixed scenarios in `sandbox` | Turn a "controlled" attack into an uncontrolled one: escape the pod, reach other namespaces, the node or the LAN; mine; forge events shown to others |
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
| TB3 | Visitor → attack scenarios in `sandbox` | API call that creates a pod and execs into it |
| TB4 | CI / GHCR / Sigstore → cluster admission | images, signatures, SBOM attestations |
| TB5 | Git repository → Argo CD → cluster | manifests, chart versions, encrypted secrets |
| TB6 | Workloads → node / host / LAN | syscalls, host mounts, node network, Proxmox |
| TB7 | Inside the cluster: detection → response | Falco → Falcosidekick → Talon → API server, and Falcosidekick/Talon → portfolio API webhooks (unauthenticated HTTP hops) |

## 5. STRIDE per boundary

Format per row: threat, existing control (linked), residual risk.

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
| S | Forged `X-Forwarded-*` / client IP headers | Envoy trusts exactly one XFF hop ([`cluster/apps/cilium.yaml`](../cluster/apps/cilium.yaml)); the only path to the Gateway is cloudflared ([`cloudflared/ciliumnetworkpolicy.yaml`](../cluster/infra/cloudflared/ciliumnetworkpolicy.yaml)) | Any in-cluster pod that can reach the Gateway Service could forge headers, including the `CF-Connecting-IP` the API's per-visitor limits are keyed on (AB4); today only cloudflared's egress is written to allow it, but nothing in this repository stops pods in namespaces without a policy (kyverno, argocd, cert-manager) from reaching the Gateway Service |
| T | Plaintext hop inside the cluster | cloudflared → Gateway is HTTPS with SNI and certificate verification ([`config.yaml`](../cluster/infra/cloudflared/config.yaml)) | Gateway → backend is plain HTTP on the node (Envoy in the host netns), accepted |
| R | — | Hubble records flows and DNS lookups (L7 DNS rules) | Hubble keeps a ring buffer, not an archive |
| I | Routing to an internal service by Host header | Tunnel ingress has one hostname and a `http_status:404` catch-all; Gateway listeners are bound to `hubertjablon.ski`; only labelled namespaces (`gateway`, `hello`, `portfolio-api`) may attach routes ([`gateway.yaml`](../cluster/infra/gateway/gateway.yaml)) | A new namespace given the `gateway-routes` label is both routable and reachable by cloudflared on 8080 - one label, one review; the Gateway's LB address 10.4.1.30 is not announced, but a host on the DMZ segment with a static route via the node could probably reach Envoy without Cloudflare in front ([ADR 0010](adr/0010-cilium-gateway-api.md) amendment, unverified) |
| D | Tunnel or Gateway saturation | Two cloudflared replicas, rolling update with `maxUnavailable: 0` ([`deployment.yaml`](../cluster/infra/cloudflared/deployment.yaml)) | Single node: a node outage is a site outage |
| E | Compromised cloudflared pivots inward | cloudflared: restricted PSA, non-root, read-only rootfs, no SA token, egress allow-list (DNS, Cloudflare on 7844/443, Gateway 443, route backends 8080) | Egress to `world:443` is an exfiltration channel for a compromised cloudflared |

### TB3 · Visitor → attack scenarios in `sandbox`

The API ([`app/api`](../app/api), [ADR 0015](adr/0015-portfolio-api.md)) accepts `POST /api/attack/{id}`
for one of the scenario IDs in [`scenarios.yaml`](../cluster/infra/sandbox/scenarios/scenarios.yaml)
(a ConfigMap mounted into the API), creates the pod in `sandbox` from that template plus the runner's
own fields (run-id and quarantine labels, `restartPolicy: Never`, `activeDeadlineSeconds` = the
scenario timeout ≤ 120 s, no ServiceAccount token, no service links), execs the scenario's fixed
command, correlates the Falcosidekick and Talon webhooks by pod name and streams the run over SSE.
Every path ends with the pod deleted. The four scenarios run the busybox-only image
[`app/scenario/Dockerfile`](../app/scenario/Dockerfile) (Alpine without apk-tools or TLS libraries,
uid 10001); safety model [ADR 0017](adr/0017-attack-scenario-safety-model.md), rule-to-response
mapping [ADR 0018](adr/0018-scenario-detection-and-response-mapping.md), Talon side
[`talon/rules.yaml`](../cluster/infra/falco-response/talon/rules.yaml):

| Scenario | MITRE | Falco rule | Talon | Relaxation inside `restricted` |
|----------|-------|------------|-------|--------------------------------|
| `shell-in-container` | T1059.004 | Terminal shell in container | terminate | — |
| `network-tool` | T1071.001 | SDP network tool in sandbox (custom) | quarantine | — (targets `127.0.0.1:9`, nothing leaves the pod) |
| `sensitive-file-read` | T1003.008 | Read sensitive file untrusted | terminate | `supplementalGroups: [42]` (Alpine's `shadow` group; every account in the image is locked) |
| `drop-and-execute` | T1105 | Drop and execute new binary in container | terminate | `readOnlyRootFilesystem: false`, bounded by an 8 Mi ephemeral-storage limit |

| STRIDE | Threat | Control | Residual |
|--------|--------|---------|----------|
| S | Spoof another visitor's run or inject events into their stream | Run IDs generated server-side; the feed is a broadcast of what Falcosidekick and Talon posted, never visitor input; the webhooks listen on `:8081`, which has no HTTPRoute and admits only the `falcosidekick` and `falco-talon` pods ([`portfolio-api/ciliumnetworkpolicy.yaml`](../cluster/infra/portfolio-api/ciliumnetworkpolicy.yaml)) | The webhooks are unauthenticated; the policy is the authentication (AB12, G7) |
| T | Choose the image, command or pod spec | Only the `{id}` path segment comes from the request (unknown → 404); the API validates each catalogue entry before it can run (strict PodSpec decode, our registry with a digest, no ephemeral containers); `make validate` renders every scenario as the Pod the API creates and runs the Kyverno gate over it ([`scripts/lib/scenario_pods.py`](../scripts/lib/scenario_pods.py)); at admission every pod in `sandbox` must pass [`verify-portfolio-images`](../cluster/infra/kyverno-policies/verify-portfolio-images.yaml) and [`restrict-image-registries`](../cluster/infra/kyverno-policies/restrict-image-registries.yaml) (Enforce, `failurePolicy: Fail`) and PSA `restricted` ([`sandbox/namespace.yaml`](../cluster/infra/sandbox/namespace.yaml)) | The scenario image is ours and signed, so a bug in it is admitted; changing what visitors can run is one reviewed commit to `scenarios.yaml` |
| R | Abuse without trace | k3s audit policy logs pods, `pods/exec` at RequestResponse and full bodies in `sandbox` ([`audit-policy.yaml.j2`](../ansible/roles/k3s/templates/audit-policy.yaml.j2)); the API logs each accepted run (run id, scenario) and its end state; Talon logs one JSON line per action | Audit and pod logs stay on the node (G10); the API does not log client addresses, so a run is attributable to a time window, not to a visitor |
| I | Scenario pod reads cluster data | No SA token in scenario pods ([`scenarios.yaml`](../cluster/infra/sandbox/scenarios/scenarios.yaml)) or runtime-test victims ([`tests/runtime/victim-pod.yaml`](../tests/runtime/victim-pod.yaml)); `sandbox` is default-deny with DNS only ([`sandbox/ciliumnetworkpolicy.yaml`](../cluster/infra/sandbox/ciliumnetworkpolicy.yaml)) | DNS is a covert channel (names are logged by Hubble) |
| D | Exhaust the node through the button | API: 3 attacks / 10 min per visitor, 30 / hour global, one run at a time (ADR 0015, [`limits.go`](../app/api/internal/limits/limits.go)); `activeDeadlineSeconds` ≤ 120 s; `sandbox` [ResourceQuota](../cluster/infra/sandbox/resourcequota.yaml) (3 pods, 500m CPU and 512 Mi requests and limits, 128 Mi ephemeral storage, zero Services/PVCs) and [LimitRange](../cluster/infra/sandbox/limitrange.yaml) (≤ 200m / 128 Mi / 16 Mi per container) | A distributed requester can consume the global budget and deny the demo to others (accepted: the budget protects the node, not fairness); an API restart resets the windows, the quota still bounds a burst |
| E | Escape from scenario pod to node or to other namespaces | PSA `restricted` (no privilege, no host namespaces, no capabilities, uid 10001); no attack tooling in the image ([ADR 0017](adr/0017-attack-scenario-safety-model.md)); Falco + Talon terminate three scenarios and quarantine `network-tool` ([`talon/rules.yaml`](../cluster/infra/falco-response/talon/rules.yaml)); quarantine policy denies all traffic ([`quarantine-ccnp.yaml`](../cluster/infra/sandbox/quarantine-ccnp.yaml)); the chain is checked offline and live ([`tests/scenarios/offline.sh`](../tests/scenarios/offline.sh), [`run.sh`](../tests/scenarios/run.sh)) | A kernel exploit from a restricted pod is not prevented, only (possibly) detected; the API's own RBAC (pods create/exec in `sandbox`) becomes the prize, see §6 |

### TB4 · CI / GHCR / Sigstore → admission

| STRIDE | Threat | Control | Residual |
|--------|--------|---------|----------|
| S | Image signed by someone else (fork, PR run, other workflow) | Keyless identity pinned and anchored: one matrix workflow, [`build-images.yml`](../.github/workflows/build-images.yml), on `refs/heads/main`, issuer GitHub OIDC; subject regexp `^https://github\.com/HubertMJ/self-defending-portfolio/\.github/workflows/(build-images\|build-web)\.yml@refs/heads/main$` in both rules of [`verify-portfolio-images.yaml`](../cluster/infra/kyverno-policies/verify-portfolio-images.yaml) ([ADR 0011](adr/0011-supply-chain.md), [ADR 0016](adr/0016-one-image-workflow.md)) | Anyone who can push to `main` (A6) or alter that workflow on `main` gets a valid signature; `build-web` is a transition alternative (the file no longer exists on main, G17); one identity signs every image, so a digest pinned to the wrong image of ours is a review error the policy cannot catch |
| T | Tag repointed after verification | Manifests pin digests; `mutateDigest: true` rewrites the pod to the verified digest; `disallow-latest-tag` Enforce ([`disallow-latest-tag.yaml`](../cluster/infra/kyverno-policies/disallow-latest-tag.yaml)) | — |
| T | Malicious or vulnerable dependency | Trivy gate on fixable CRITICAL/HIGH, SARIF for the rest, per image ([`build-images.yml`](../.github/workflows/build-images.yml)); actions pinned by commit SHA; base images pinned by digest ([`app/web/Dockerfile`](../app/web/Dockerfile), [`app/api/Dockerfile`](../app/api/Dockerfile), [`app/scenario/Dockerfile`](../app/scenario/Dockerfile)); the API image's build runs `go vet` and `go test -race` | Unfixed CVEs pass by design; a compromised upstream at a pinned digest is not detected by signature checks |
| R | "What was running in March?" | SBOM as a signed SPDX attestation, Rekor entry for every signature | — |
| I | — | Public repo and public packages by design | — |
| D | Sigstore/GHCR outage blocks deploys | `failurePolicy: Fail` only on `hello`, `sandbox`, `portfolio-api`, `falco-response` (ADR 0023), `kube-bench` and `trivy-system` (ADR 0025); `webhookTimeoutSeconds: 30` | A Kyverno outage or GHCR outage stops new pods in those six namespaces, Talon's, the daily kube-bench Job and the Trivy scans included (accepted, fail closed; none of them is on the path that repairs Kyverno) |
| E | Third-party images run unverified | Third-party charts/images pinned by tag+digest ([ADR 0008](adr/0008-pinned-versions.md)); signature verification covers only our registry path | Upstream images (Cilium, Kyverno, Falco, Argo CD, ...) are trusted by digest, not by signature |

Also: in `SigstoreBundle` mode the signature rule has no predicate filter, so the SBOM attestation
bundle alone satisfies it; accepted because both come from the same pinned identity (ADR 0011,
amendment).

### TB5 · Git → Argo CD → cluster

| STRIDE | Threat | Control | Residual |
|--------|--------|---------|----------|
| S | Push to `main` by an attacker | GitHub account security | Branch protection, required reviews and signed commits are not visible from the repository (TODO-CONTENT: owner to state what is configured) |
| T | Malicious manifest synced | CI: kubeconform, `kyverno apply` over every rendered object and every scenario pod spec, read-only hostPath assertion, site CSP parity, no placeholder digests, gitleaks ([`lint.yml`](../.github/workflows/lint.yml), [`validate-cluster.sh`](../scripts/validate-cluster.sh), [`check-image-digests.sh`](../scripts/check-image-digests.sh)) | Argo CD polls `main` and does not wait for CI to pass; every Application uses `project: default`, so any file in `cluster/apps/` can deploy anything anywhere (gap G6) |
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
| I | Secrets at rest on the node | k3s `secrets-encryption: true`, kubeconfig mode 0600 ([`config.yaml.j2`](../ansible/roles/k3s/templates/config.yaml.j2)) | kube-bench mounts k3s's server/agent dirs and the node's journal (`/var/log/journal`, every unit's log, ADR 0025) read-only and runs as root (no network, no token: [`kube-bench/cronjob.yaml`](../cluster/infra/kube-bench/cronjob.yaml)) |
| D | One workload starves the node | [`require-pod-resources`](../cluster/infra/kyverno-policies/require-pod-resources.yaml) Enforce; `sandbox` [ResourceQuota](../cluster/infra/sandbox/resourcequota.yaml) and [LimitRange](../cluster/infra/sandbox/limitrange.yaml); the API runs with `GOMEMLIMIT` under its limit | `argocd` and `kube-system` excluded (G2); `failurePolicy: Ignore`, so an unsized pod admitted during a Kyverno outage is only reported afterwards by the background scan ([ADR 0012](adr/0012-pod-security-and-resource-policy.md) amendment) |
| E | Privileged sensor compromised → host | Falco runs with 4 capabilities, not `privileged`; every host mount read-only, `/host/lib/modules` included, via a kustomize post-render patch on chart 9.2.0 ([`cluster/infra/falco/kustomization.yaml`](../cluster/infra/falco/kustomization.yaml), ADR 0013 amendment), asserted on the render by `make validate` ([`check_hostpath_readonly.py`](../scripts/lib/check_hostpath_readonly.py)); no API token; egress only to Falcosidekick | BPF + PERFMON + SYS_PTRACE are close to host-equivalent ([ADR 0013](adr/0013-runtime-detection-and-response.md)) |
| E | Pod → node → LAN pivot | Node in a DMZ VLAN; host firewall default-deny input; forward chain left to Cilium | Egress from the node to the LAN is not restricted by this repository (host `output` chain accepts) |

### TB7 · Detection → response (inside the cluster)

| STRIDE | Threat | Control | Residual |
|--------|--------|---------|----------|
| S | Forged alert makes Talon kill or quarantine a pod | Falcosidekick accepts only Falco pods, Talon only Falcosidekick ([`falco-response/ciliumnetworkpolicy.yaml`](../cluster/infra/falco-response/ciliumnetworkpolicy.yaml)) | Both HTTP APIs are unauthenticated; integrity rests entirely on Cilium policy (ADR 0013) |
| S | Forged alert or action on the live feed | Falcosidekick's `webhook` output ([`cluster/apps/falco-response.yaml`](../cluster/apps/falco-response.yaml)) and Talon's only notifier post to the API's `:8081`, which admits only those two pods ([`portfolio-api/ciliumnetworkpolicy.yaml`](../cluster/infra/portfolio-api/ciliumnetworkpolicy.yaml)) | Unauthenticated as well: the policy is the authentication; a forged entry changes the feed, not the cluster (the API acts only on its own runs, and only by deleting their pods) |
| T | Rules changed at run time | No falcoctl; rules from the image plus git ([`cluster/infra/falco/kustomization.yaml`](../cluster/infra/falco/kustomization.yaml)); Talon rules from a hashed ConfigMap | — |
| R | Silent response | Talon logs one JSON line per action (`log_format: json`, status, actionner, pod, namespace) and posts each action to the API, which shows it on the live feed ([`talon/config.yaml`](../cluster/infra/falco-response/talon/config.yaml)); `tests/runtime/run.sh` asserts on the log line | No Kubernetes Events: Talon 0.3.0's `k8sevents` notifier cannot work and is off (ADR 0013 correction; the fix is in the commit app/talon builds, enabling it is a separate decision, ADR 0023); the log stays on the node (G10) and the feed keeps the last 50 events in memory |
| I | — | Alerts contain command lines; Falco output stays in-cluster except on the live feed | The SSE stream shows Falco output, truncated to 300 characters, to every visitor (§6, AB7) |
| D | Blind the sensor (kill Falco, flood events, evade rules) | DaemonSet + Argo CD self-heal; Falco runs with requests/limits; `make scenario-offline` fails if a rule a scenario or Talon depends on is renamed, disabled or below the forwarded priority ([`tests/scenarios/offline.sh`](../tests/scenarios/offline.sh)) | Rule evasion (renamed binaries, non-TTY shells, interpreters) is possible; detection coverage is the stock ruleset plus one custom rule |
| E | Talon abused as a cluster-wide killer | Talon RBAC: pods get/patch/delete in `sandbox` only ([`sandbox/talon-rbac.yaml`](../cluster/infra/sandbox/talon-rbac.yaml)), its own Lease in `falco-response` ([`falco-response/talon-rbac.yaml`](../cluster/infra/falco-response/talon-rbac.yaml)); no events, no Namespace reads, nothing cluster-scoped; proven by `kubectl auth can-i` in [`tests/runtime/run.sh`](../tests/runtime/run.sh) | — |

## 6. Abuse cases for the attack button

The requirements the API is built against, each with the mechanism that implements it. Limits are
those of [ADR 0015](adr/0015-portfolio-api.md); [`tests/abuse/run.sh`](../tests/abuse/run.sh) asserts
404/403/409/429, the per-visitor attack limit, the stream cap and the request budget over HTTP, and
the Go tests ([`app/api/internal`](../app/api/internal), run with `-race` in the image build) cover the
same arithmetic, the global limit included.

| # | Abuse case | Expected behaviour | Mechanism |
|---|------------|--------------------|-----------|
| AB1 | Hammer `POST /api/attack/{id}` | `429` with `Retry-After` | 3 per 10 min per visitor, 30 per hour in total, sliding windows; refused attempts are not counted ([`limits.go`](../app/api/internal/limits/limits.go)); every endpoint also has a budget of 120 requests per minute per visitor, with the tracked-key table capped |
| AB2 | Two runs at once | `409` | one run at a time; rate limits are checked before the slot, so a visitor over quota gets 429, not a 409 that invites a retry loop |
| AB3 | Unknown or crafted scenario id (`../`, long strings, other namespaces) | `404`, no pod created | the id is looked up in the validated catalogue (DNS-1123 ids); nothing else from the request reaches the pod spec; the trigger's body must be empty (bounded to 1 KiB, `413` above) ([`server.go`](../app/api/internal/server/server.go)) |
| AB4 | Spoof `CF-Connecting-IP` to dodge the per-IP limit | header trusted only because of the path | Cloudflare's edge overwrites it; `:8080` admits only the Gateway (`ingress`) and the kubelet (`host`) ([`portfolio-api/ciliumnetworkpolicy.yaml`](../cluster/infra/portfolio-api/ciliumnetworkpolicy.yaml)); IPv6 keyed by its /64; a request without the header shares one stricter `direct:` bucket ([`clientip.go`](../app/api/internal/clientip/clientip.go)). Residual: an in-cluster pod that can reach the Gateway Service could forge it (TB2); the global limit still holds |
| AB5 | Rotate IPs to drain the global budget | demo unavailable to others until the window passes | accepted; Cloudflare rate limiting is the outer layer (not in git, G9) |
| AB6 | Hold thousands of SSE connections to `/api/events` | bounded memory, connections shed | 4 streams per visitor, 200 in total (`429` above); every stream closed after 30 min; a client that stops reading is dropped; 15 s heartbeat; the HTTPRoute switches Envoy's request timeout off for `/api/events` only ([`portfolio-api/httproute.yaml`](../cluster/infra/portfolio-api/httproute.yaml)) |
| AB7 | Inject markup through Falco output shown in the browser | rendered as text | output truncated to 300 chars server-side ([`webhook.go`](../app/api/internal/webhook/webhook.go)); the site's CSP has `script-src 'self'`, no inline script, and Trusted Types with no policy allowed (`require-trusted-types-for 'script'; trusted-types 'none'`), sent by nginx ([`security-headers.conf`](../app/web/security-headers.conf)) and set identically by the hello HTTPRoute ([`hello/httproute.yaml`](../cluster/infra/hello/httproute.yaml)); [`check-web-csp.sh`](../scripts/check-web-csp.sh) fails `make validate` and CI if they differ ([ADR 0019](adr/0019-frontend-stack-and-csp.md)); `/api` responses carry `default-src 'none'` |
| AB8 | Reach the internal webhook port from outside | not routed | the HTTPRoute's backend is the Service's port 80 (→ 8080) only; `:8081` admits only the `falcosidekick` and `falco-talon` pods in `falco-response` |
| AB9 | Use a scenario pod to mine or to scan | killed or capped | `activeDeadlineSeconds` ≤ 120 s, pod deleted at the end of every run and orphans deleted at API start-up, `sandbox` ResourceQuota and LimitRange, default-deny egress, no tooling in the scenario image, quarantine on network tools |
| AB10 | Compromise the API itself, then use its RBAC | blast radius = `sandbox` | [`rbac.yaml`](../cluster/infra/portfolio-api/rbac.yaml): Role in `sandbox` pods create/get/list/delete and `pods/exec` create; Role in `kube-bench` pods list and `pods/log` get; ClusterRole list on `policyreports`, `clusterpolicyreports`, `vulnerabilityreports` and `pods` (pod specs cluster-wide are readable, ADR 0015 amendment 2026-10-02); no Secrets, ConfigMaps or Jobs. Its egress is the API server on 6443 and DNS for `*.cluster.local` only; the pod is distroless non-root with a read-only root in a PSA `restricted` namespace; anything it creates still passes Kyverno + PSA + the quota (zero Services/PVCs). Residual: `pods/exec` create in `sandbox` reaches any pod there, the runtime-test victims included |
| AB11 | Read sensitive data through `/api/posture` | aggregate counts only | posture returns per-policy pass/fail/warn, Trivy severity totals per distinct image plus a per-image CRITICAL/HIGH/fixable breakdown by image name (names and versions that are already public in `cluster/`; no CVE lists, no report bodies, ADR 0023), kube-bench totals and 24 h Falco/Talon counts, not report bodies ([`posture.go`](../app/api/internal/posture/posture.go)); cached 60 s, one refresh at a time |
| AB12 | Make the timeline lie (forge "detected"/"responded") | impossible without reaching port 8081 from the `falcosidekick` or `falco-talon` pod | event source is the webhook, not the visitor; the webhooks are unauthenticated and the CiliumNetworkPolicy is the authentication; webhook bodies capped at 256 KiB |
| AB13 | Make a visitor's browser spend the quota from another site (CSRF) | `403` | no CORS headers are ever sent; a POST with a foreign `Origin` or `Sec-Fetch-Site: cross-site\|same-site` is refused; requests with neither header are judged by the limits alone |

## 7. Known gaps and residual risk

Found while writing this document or recorded in the ADRs. Each is a fact about the repository today;
the open items carried by accepted ADRs are also listed in [`docs/adr/README.md`](adr/README.md).
Resolved gaps keep their ID so that references stay valid.

| ID | Gap | Impact | Where recorded / next step |
|----|-----|--------|----------------------------|
| G1 | **Resolved.** Falco chart 9.2.0 mounts `/host/lib/modules` read-write in least-privileged mode, and no value changes it; a kustomize post-render patch now makes every Falco host mount read-only | — (was: a compromised sensor plus module autoload is a host-root path) | [ADR 0013](adr/0013-runtime-detection-and-response.md) amendment, [`cluster/infra/falco/kustomization.yaml`](../cluster/infra/falco/kustomization.yaml); `make validate` fails if a Falco or kube-bench hostPath mount is writable ([`check_hostpath_readonly.py`](../scripts/lib/check_hostpath_readonly.py)); re-check on every chart bump |
| G2 | Argo CD runs with no requests or limits and is excluded from `require-pod-resources` | OOM on the 8 GB node can take out the reconciler | [ADR 0012](adr/0012-pod-security-and-resource-policy.md) (recorded debt); bootstrap patch |
| G3 | **Resolved** (Enforce). `pod-security-restricted` and `require-pod-resources` are Enforce; both keep `failurePolicy: Ignore` | During a Kyverno outage pods are not judged at admission: PSA `restricted` labels remain the floor where set; `falco`, `kube-bench` (PSA `privileged`) and `default` (no label) are only reported afterwards by the background scan | [ADR 0012](adr/0012-pod-security-and-resource-policy.md) amendment (accepted: `Fail` would let an outage block the pods needed to end it) |
| G4 | All five policies are `kyverno.io/v1` ClusterPolicies, deprecated in Kyverno 1.19 | Future Kyverno bump may force a rushed migration | [ADR 0011](adr/0011-supply-chain.md) amendment, [ADR 0012](adr/0012-pod-security-and-resource-policy.md); migrate to ImageValidatingPolicy / CEL policies and rewrite `tests/admission/` |
| G5 | No NetworkPolicy in `kyverno`, `argocd`, `cert-manager` | Their egress is open; a compromised controller can reach anything, including the Gateway Service | `docs/bootstrap.md` §5.6 says a Kyverno egress policy comes "in phase 4"; it is not in the repository |
| G6 | All Applications use `project: default`; Argo CD syncs `main` without waiting for CI | A merged mistake in `cluster/apps/` can target any namespace with cluster-wide effect | add an AppProject with namespace/kind allow-lists; branch protection requiring the `validate` job |
| G7 | Falcosidekick, Talon and the API's webhook port (`:8081`) are unauthenticated HTTP | A Cilium policy outage lets any pod forge alerts against `sandbox` and forge entries on the visitors' live feed | ADR 0013 consequences, [ADR 0015](adr/0015-portfolio-api.md) consequences |
| G8 | Quarantine applies to new flows only | An already-open connection survives the label until it closes | [`quarantine-ccnp.yaml`](../cluster/infra/sandbox/quarantine-ccnp.yaml) header |
| G9 | Cloudflare WAF, rate limiting, "Always Use HTTPS" and account settings are not in git | The outer layer is unreviewed and not restored by a rebuild | TODO-CONTENT: document the settings or codify them |
| G10 | Logs (k3s audit, auditd, Falco, pod logs) stay on the node | A root attacker can erase evidence; nothing alerts a human outside the cluster | ADR 0009 mentions shipping to Loki "later" |
| G11 | Deploying a new image digest is a manual commit ([`bump-image-digest.sh`](../scripts/bump-image-digest.sh)); Renovate not enabled; a new image reaches `main` in two merges ([`docs/bootstrap.md`](bootstrap.md) §7) | Patched images can lag; a placeholder digest cannot reach `main` ([`check-image-digests.sh`](../scripts/check-image-digests.sh) fails `make validate` and CI) | [ADR 0011](adr/0011-supply-chain.md) known gap, [ADR 0016](adr/0016-one-image-workflow.md) |
| G12 | The web image is Alpine-based and ships busybox `sh` and `wget` | A code-execution bug in nginx gets a shell and a downloader for free (`tests/runtime` still uses hello's digest as its victim and relies on them) | consider a distroless/static image for `hello` and moving `tests/runtime` to the scenario image ([`app/scenario/Dockerfile`](../app/scenario/Dockerfile)), which the scenarios already use |
| G13 | Single node, single replica for most controllers; the API is one replica with in-process state by design | Any node incident is a full outage; Kyverno down = no new pods in `hello`/`sandbox`/`portfolio-api`; an API restart resets the rate-limit windows and the 24 h Falco/Talon counters | accepted for a homelab demo; [ADR 0015](adr/0015-portfolio-api.md) |
| G14 | Signature verification covers only `ghcr.io/hubertmj/self-defending-portfolio/*` | Upstream images are trusted by digest pin alone | [ADR 0008](adr/0008-pinned-versions.md) |
| G15 | Host `output` chain accepts everything | A node compromise can reach the rest of the DMZ / LAN as far as the UniFi gateway allows | [`nftables.conf.j2`](../ansible/roles/firewall/templates/nftables.conf.j2); gateway rules are outside this repo |
| G16 | No backup of cluster state is described | Recovery is a rebuild from git plus the age key; anything not in git (reports, Leases, PVC of the Trivy server) is lost | rebuild path in [`docs/bootstrap.md`](bootstrap.md) |
| G17 | The signer identity still accepts the phase 3 `build-web.yml` alongside `build-images.yml` (transition) | Grants nothing new while it lasts (the file no longer exists on `main`, and restoring it takes the same write access as editing `build-images.yml`), but it is one more identity to reason about | [ADR 0016](adr/0016-one-image-workflow.md); drop `\|build-web` from both policy rules, `scripts/verify-image.sh` and `docs/bootstrap.md` in one commit once hello runs a `build-images.yml` digest |
| G18 | `make validate` renders with kustomize v5.7.1; Argo CD's repo-server runs its own v5.8.1 | What CI checks is not rendered by exactly the binary that deploys it; a behaviour difference between the two versions would go unnoticed until sync | [ADR 0013](adr/0013-runtime-detection-and-response.md) correction |

## 8. What an attacker would try next

Assuming the obvious doors are shut (no inbound port, signed images only, restricted pods), a
patient attacker's order of play would likely be:

1. **Go around the cluster, not through it.** Phish or token-steal a GitHub account with push to
   `main` (A6): one commit is both a signed image (the workflow signs whatever `main` builds) and a
   synced manifest. Mitigation lives outside the repo: MFA, branch protection, required CI, review.
2. **Attack the API, not the site.** It is the only component that parses visitor input and holds
   create/exec rights. Look for request smuggling through the Gateway, a way to reach the Gateway
   from inside the cluster with a forged `CF-Connecting-IP` (AB4), SSE resource exhaustion below the
   caps (AB6), any path where request data reaches a pod spec (AB3), and a bug in client-go or the
   API that turns its `pods/exec` grant in `sandbox` into more (AB10).
3. **From a scenario pod, test the edges of `restricted`.** Kernel bugs reachable without capabilities,
   DNS as a covert channel, timing before Talon reacts (the runtime test measures time-to-kill), and
   evasion of Falco's stock rules (no TTY, renamed binaries, interpreters instead of `sh`).
4. **Target the privileged corners.** Falco (four capabilities, host mounts read-only since G1 was
   fixed) and kube-bench (root with k3s's keys mounted read-only) are the only pods close to
   host-level. A
   malicious upstream release at the next digest bump is the realistic way in, which is why bumps are
   reviewed commits (ADR 0008).
5. **Turn the defences into the weapon.** Forge alerts to Talon, or entries on the live feed, if
   Cilium policy ever lapses (G7), or try to make Talon act outside `sandbox` (RBAC returns 403,
   proven in `tests/runtime/run.sh`).
6. **Pivot east-west.** From any compromised controller in a namespace without network policy (G5),
   reach the API server, the Gateway with forged headers, or the LAN via the node (G15).
7. **Cover tracks.** Logs are local (G10); deleting them after a node compromise is easy.

## 9. When to revisit this document

- A scenario is added to or changed in `scenarios.yaml`, or a Talon rule or response changes (TB3, §6).
- The API's RBAC, network policy, endpoints or abuse limits change, or a new HTTPRoute lands (§6).
- The site's CSP changes, or the frontend starts rendering HTML from data (AB7).
- The `build-web` transition is dropped from the signer identity (G17, A5).
- Any policy flips between Audit and Enforce or changes `failurePolicy`, or migrates away from ClusterPolicy.
- A new namespace gets the `portfolio.hubertjablon.ski/gateway-routes` label.
- A new outbound FQDN is added to any CiliumNetworkPolicy.
- Falco, Talon or their charts are bumped (re-check G1's patch, and whether Talon's `k8sevents` notifier works again).
