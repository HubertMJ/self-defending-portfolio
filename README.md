# Self-defending portfolio

A DevOps/security portfolio that is also the thing it describes: a single-node Kubernetes cluster
in a homelab that serves its own website, refuses software it did not build and sign, watches every
process it runs, and kills or isolates a compromised pod on its own. The planned finale lets a
visitor press a button, launch a controlled attack in a sandbox, and watch detection and response
happen live.

**Live:** [hubertjablon.ski](https://hubertjablon.ski)
<!-- TODO-CONTENT: confirm what the live site serves today and update this line when the phase 5/6 demo goes live. -->

**Status:** phases 0-3 are built and running (hardened host, GitOps, public site behind a tunnel,
signed images enforced at admission). Phase 4 (runtime detection and response, posture scanning) is
committed and awaiting deployment on the live cluster. Phases 5-6 (the attack button and the new
site) are in progress. See [phases](#phases-and-definition-of-done) and
[limitations](#limitations-and-not-done-yet).

---

## The 30-second tour

1. **Nothing listens on the internet.** The site reaches visitors through a Cloudflare Tunnel that the
   cluster dials *outbound*. The router and the host firewall have no open inbound port.
2. **The cluster is a git repository.** Apart from one bootstrap command, every object in the cluster
   is applied by Argo CD from this repo. Secrets are committed encrypted.
3. **Only signed software runs where it matters.** The site image is built, vulnerability-gated,
   given an SBOM and signed in GitHub Actions without any stored key. The cluster checks that
   signature at admission and rejects anything else.
4. **Running containers are watched.** Falco sees every process start in the cluster. A shell in a
   sandbox pod gets that pod deleted within seconds; a network tool gets it cut off from the network.
   No human in the loop.
5. **Every claim has a test.** Each control below links to the code that implements it and to the
   command that proves it.

![Architecture overview](docs/architecture/overview.svg)

## Key security controls

| Control | What it does | Code | Why (ADR) |
|---------|--------------|------|-----------|
| Outbound-only exposure | Cloudflare Tunnel, no port-forward, host firewall default-deny input | [`cluster/infra/cloudflared/`](cluster/infra/cloudflared/), [`nftables.conf.j2`](ansible/roles/firewall/templates/nftables.conf.j2) | [0003](docs/adr/0003-cloudflare-tunnel-exposure.md), [0009](docs/adr/0009-nftables-host-firewall.md) |
| TLS end to end | Let's Encrypt via DNS-01 on the Gateway; the tunnel verifies the origin certificate | [`cluster/infra/gateway/`](cluster/infra/gateway/), [`cluster/infra/cert-manager-issuers/`](cluster/infra/cert-manager-issuers/) | [0010](docs/adr/0010-cilium-gateway-api.md) |
| Security headers at the edge of the cluster | HSTS, strict CSP, nosniff, Referrer/Permissions policy, COOP | [`cluster/infra/hello/httproute.yaml`](cluster/infra/hello/httproute.yaml) | [0010](docs/adr/0010-cilium-gateway-api.md) |
| Default-deny networking | Per-namespace default-deny plus explicit Cilium allow-lists, FQDN-scoped egress | `cluster/infra/*/networkpolicy.yaml`, `ciliumnetworkpolicy.yaml` | [0004](docs/adr/0004-cilium-as-cni.md), [0014](docs/adr/0014-posture-scanning.md) |
| GitOps | Argo CD app-of-apps, pinned charts, self-heal | [`cluster/apps/`](cluster/apps/), [`cluster/bootstrap/`](cluster/bootstrap/) | [0005](docs/adr/0005-argocd-for-gitops.md), [0008](docs/adr/0008-pinned-versions.md) |
| Secrets in a public repo | SOPS + age, decrypted only inside Argo CD; CI rejects plaintext Secrets | [`.sops.yaml`](.sops.yaml), [`scripts/check-secrets-encrypted.sh`](scripts/check-secrets-encrypted.sh) | [0006](docs/adr/0006-sops-age-for-secrets.md) |
| Signed, scanned, described images | Trivy gate, SPDX SBOM attestation, cosign keyless signing bound to one workflow on `main` | [`.github/workflows/build-web.yml`](.github/workflows/build-web.yml) | [0011](docs/adr/0011-supply-chain.md) |
| Admission control | Kyverno: signature + SBOM required, own registry only, no `:latest`, Pod Security `restricted`, resource limits | [`cluster/infra/kyverno-policies/`](cluster/infra/kyverno-policies/) | [0011](docs/adr/0011-supply-chain.md), [0012](docs/adr/0012-pod-security-and-resource-policy.md) |
| Runtime detection and response | Falco (eBPF, 4 capabilities, no API token) → Falcosidekick → Falco Talon (kill / quarantine, `sandbox` only) | [`cluster/apps/falco.yaml`](cluster/apps/falco.yaml), [`cluster/infra/falco-response/`](cluster/infra/falco-response/), [`cluster/infra/sandbox/`](cluster/infra/sandbox/) | [0013](docs/adr/0013-runtime-detection-and-response.md) |
| Posture scanning | Trivy Operator (images, config, RBAC, secrets), daily CIS benchmark (kube-bench), Policy Reporter | [`cluster/apps/trivy-operator.yaml`](cluster/apps/trivy-operator.yaml), [`cluster/infra/kube-bench/`](cluster/infra/kube-bench/) | [0014](docs/adr/0014-posture-scanning.md) |
| Host hardening | SSH key-only from admin VLANs, sysctl, auditd, unattended upgrades, k3s audit log and secrets encryption | [`ansible/roles/`](ansible/roles/) | [0001](docs/adr/0001-dedicated-vm-for-the-cluster.md), [0007](docs/adr/0007-cloud-init-and-ansible-bootstrap.md) |

The threat model ([`docs/threat-model.md`](docs/threat-model.md)) lists what these controls do
*not* cover.

<!-- TODO-CONTENT: optional short "about me" paragraph (role, what I am looking for, contact link). Only facts you want public. -->

---

## For engineers

### Architecture

Detailed diagrams, one per flow, each with a table of the files behind every arrow:
[`docs/architecture/`](docs/architecture/README.md).

```
visitor ─HTTPS─> Cloudflare edge <─tunnel, dialled outbound─ cloudflared x2 (ns cloudflared)
                                                                  │ HTTPS :443, SNI + cert verified
                                         Cilium Gateway API (Envoy), Gateway "portfolio" (ns gateway)
                                                                  │ HTTPRoute + security headers
                                                    hello x2, signed web image :8080 (ns hello)

k3s01: Proxmox VM, Debian 13, hardened by Ansible
├─ k3s v1.35 (no flannel, no kube-proxy, audit policy, secrets encryption)
├─ Cilium 1.19 (CNI, kube-proxy replacement, NetworkPolicy, Hubble, Gateway API)
├─ Argo CD v3.5 + KSOPS ── everything below is synced from git
├─ cert-manager ── Let's Encrypt DNS-01 certificate for the Gateway
├─ Kyverno ── 5 ClusterPolicies: signature + SBOM, registry allow-list, no :latest, PSS restricted, resources
├─ Trivy Operator + PolicyReport adapter, kube-bench CronJob, Policy Reporter (cluster-internal)
├─ Falco (modern eBPF) ──> Falcosidekick ──> Falco Talon ──> delete / label pods in ns sandbox
└─ sandbox: restricted, default-deny (DNS only), quarantine policy, Talon's only RBAC
```

Planned for phase 5 (not in the repository yet): a Go API in its own namespace behind `/api`,
four fixed attack scenarios run as pods in `sandbox`, and a live event stream (SSE) from Falco and
Talon to the browser. Phase 6 replaces the placeholder page with the posture and demo site.

### Repository map

| Path | Purpose |
|------|---------|
| [`ansible/`](ansible/) | host hardening (base, SSH, nftables, sysctl, auditd, unattended upgrades) and the k3s + Cilium seed install |
| [`scripts/pve-create-vm.sh`](scripts/pve-create-vm.sh) | creates the VM on Proxmox from the Debian cloud image (API token from the environment) |
| [`cluster/bootstrap/`](cluster/bootstrap/) | the one manual step: Argo CD + KSOPS + the app-of-apps root |
| [`cluster/apps/`](cluster/apps/) | one Argo CD `Application` per component, ordered by sync wave |
| [`cluster/infra/`](cluster/infra/) | what those Applications deploy: namespaces, policies, network policies, workloads |
| [`app/web/`](app/web/) | the site image (nginx-unprivileged, static files) |
| [`.github/workflows/`](.github/workflows/) | `lint.yml` (lint, validate, gitleaks, smoke) and `build-web.yml` (build, scan, SBOM, sign) |
| [`scripts/`](scripts/) | validation and verification helpers used by `make` and CI |
| [`tests/`](tests/) | host idempotency smoke test, admission tests, runtime detection/response test |
| [`docs/bootstrap.md`](docs/bootstrap.md) | zero-to-cluster-to-GitOps runbook, phase by phase |
| [`docs/adr/`](docs/adr/README.md) | architecture decision records: why, not just what |
| [`docs/architecture/`](docs/architecture/README.md) | diagrams |
| [`docs/threat-model.md`](docs/threat-model.md) | STRIDE per trust boundary, abuse cases, known gaps |

### Reproduce from zero

The full runbook, with the prerequisites (Proxmox API token, Cloudflare token and tunnel, age key)
and troubleshooting tables, is [`docs/bootstrap.md`](docs/bootstrap.md). The short version:

```sh
make lint          # yamllint, ansible-lint, shellcheck, playbook syntax (in a container)
make validate      # render cluster/, validate against Kubernetes + CRD schemas, run the Kyverno policies over it
make smoke         # hardening playbook twice in a throwaway container; second run must be changed=0

make vm            # Proxmox VM from the Debian 13 cloud image (needs PVE_HOST, PVE_TOKEN_ID, PVE_TOKEN)
make hardening     # phase 1; run twice, the second run must report changed=0
make cluster       # k3s (no flannel, no kube-proxy) + Cilium
make bootstrap     # installs Argo CD once (needs KUBECONFIG and SOPS_AGE_KEY_FILE); from here on, git push
```

The deployment-specific values (GitHub owner, hostname, ACME contact, tunnel UUID, age recipient,
the two encrypted secrets) are committed for this cluster; a fork replaces them first. Where each one
lives: [`cluster/bootstrap/README.md`](cluster/bootstrap/README.md) and
[`docs/bootstrap.md`](docs/bootstrap.md) §4.0.

<!-- TODO-CONTENT: measured time for a full rebuild from zero (docs/bootstrap.md, "Rebuild from zero"). -->

### Verify each claim yourself

| Claim | How to check | Needs |
|-------|--------------|-------|
| The site image was signed by this repo's workflow on `main` and has an SPDX SBOM attestation | `scripts/verify-image.sh ghcr.io/hubertmj/self-defending-portfolio/web@sha256:<digest>` with the digest from [`cluster/infra/hello/kustomization.yaml`](cluster/infra/hello/kustomization.yaml) ([script](scripts/verify-image.sh)) | docker or cosign; no cluster |
| Manifests are valid, every chart renders, and the cluster's own policies pass over everything | `make validate` ([`scripts/validate-cluster.sh`](scripts/validate-cluster.sh)) | docker, python3, network |
| No plaintext Secret is committed; no secret in history | `scripts/check-secrets-encrypted.sh`, `make gitleaks` | docker |
| Host hardening is idempotent | `make smoke` ([`tests/smoke.sh`](tests/smoke.sh)) | docker |
| An unsigned image, a foreign registry and a `:latest` tag are all rejected at admission | `tests/admission/run.sh` ([script](tests/admission/run.sh)); with `SIGNED_IMAGE=...@sha256:...` it also proves a signed digest is admitted | cluster credentials |
| A shell in a sandbox pod raises a Falco alert and Talon deletes the pod; a network tool gets the pod quarantined; Talon cannot act outside `sandbox` | `make runtime-test` ([`tests/runtime/run.sh`](tests/runtime/run.sh)) | cluster credentials, `script` (util-linux) |
| Security headers and HTTPS redirect are served | `curl -sI https://hubertjablon.ski`, `curl -sI http://hubertjablon.ski` | nothing |
| Talon's permissions are limited to `sandbox` | `kubectl auth can-i delete pods -n hello --as=system:serviceaccount:falco-response:falco-talon` → `no` | cluster credentials |

CI runs the first four on every push ([`.github/workflows/lint.yml`](.github/workflows/lint.yml)).

### Phases and Definition of Done

| # | Phase | Definition of Done | State |
|---|-------|--------------------|-------|
| 0 | Reconnaissance | report, decisions, plan (ADR 0001-0009) | done |
| 1 | Repo + Ansible | second playbook run = 0 changes | done |
| 2 | Cluster + GitOps | the page over HTTPS, deployed only by `git push` | done |
| 3 | Supply chain | an unsigned image fails admission | done |
| 4 | Policies + runtime | a manual shell in a test pod = alert + kill | committed, awaiting deployment and acceptance |
| 5 | Demo app | four scenarios end to end, abuse test documented | in progress |
| 6 | Site + docs | a stranger understands the project in two minutes | in progress |
| 7 | Optional | Event-Driven Ansible, Hubble UI read-only, timed rebuild from zero | not started |

<!-- TODO-CONTENT: confirm the "done" states for phases 1-3 against the live cluster before publishing. -->

### Limitations and not done yet

Honest list; details and the rest are in the [threat model](docs/threat-model.md#7-known-gaps-and-residual-risk)
and the [ADR open items](docs/adr/README.md#open-items-carried-by-accepted-adrs).

- **Single node, single replica.** A node incident is a full outage; there is no HA and no described
  backup beyond "rebuild from git plus the age key".
- **The interactive demo does not exist yet.** The API, the attack scenarios and their abuse limits
  (rate limits, quota, timeouts) are phase 5 work; nothing in this README claims them as done.
- **Two Kyverno policies are still Audit.** Pod Security `restricted` and required resources report
  but do not block until the Audit → Enforce gate passes (ADR 0012). The image policies do enforce.
- **Kyverno `ClusterPolicy` is deprecated** in 1.19; migration to the new policy types is deferred.
- **Falco's chart mounts `/host/lib/modules` read-write** in the least-privileged mode used here;
  recorded in ADR 0013 as an open item.
- **Argo CD runs without resource limits** and is excluded from the resources policy (recorded debt).
- **Some namespaces have no network policy** (`kyverno`, `argocd`, `cert-manager`), so their egress
  is open.
- **Only this project's images are signature-verified.** Upstream images (Cilium, Kyverno, Falco,
  Argo CD, ...) are pinned by digest but trusted, not verified.
- **Image updates are manual commits** until Renovate is enabled.
- **Cloudflare-side settings** (WAF, rate limiting) are not in git.
- **Logs stay on the node**; nothing is shipped off-host yet.

### Decisions

Every non-obvious choice is an ADR: [`docs/adr/`](docs/adr/README.md). Good entry points:
[why a Cloudflare Tunnel](docs/adr/0003-cloudflare-tunnel-exposure.md),
[why Cilium's Gateway API instead of ingress-nginx](docs/adr/0010-cilium-gateway-api.md),
[how keyless signing is verified](docs/adr/0011-supply-chain.md),
[how Falco runs without `privileged`](docs/adr/0013-runtime-detection-and-response.md).

## License

[MIT](LICENSE)
