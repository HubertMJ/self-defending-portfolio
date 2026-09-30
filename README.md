# Self-defending portfolio

A DevOps/Security portfolio that is also the thing it describes: a single-node k3s cluster that shows
its own security posture live and lets a visitor trigger a controlled attack, then watch detection
and automatic response happen.

**Status: phase 1 (host + Ansible).** See [Phases](#phases). Site: `https://hubertjablon.ski` (not yet live).

## What a visitor will see

1. A posture page: Kyverno policy reports, Trivy vulnerability reports, last kube-bench result.
2. Four buttons. Each one runs a predefined scenario as a Job in an isolated `sandbox` namespace:
   shell in a container, read of a sensitive file, blocked egress, rejected privileged/unsigned pod.
3. A timeline: attack → Falco detection → Falco Talon response (kill + quarantine), with timestamps.

## Architecture

```
  visitor ──HTTPS──> Cloudflare (WAF, tunnel) ──> cloudflared (in-cluster) ──> ingress ──> web + api
                                                                                            │
      Proxmox VM k3s01 (Debian 13, hardened by Ansible: ssh, nftables, sysctl, auditd)      │
      ├─ k3s (no flannel, no kube-proxy, audit log, secrets encryption)                     │
      ├─ Cilium (CNI, NetworkPolicy, Hubble)                                                │
      ├─ Argo CD (everything below is a git commit)                                         │
      ├─ cert-manager (Let's Encrypt DNS-01)                                                │
      ├─ Kyverno (cosign signature, PSS restricted, no :latest, limits) + Policy Reporter   │
      ├─ Trivy Operator, kube-bench CronJob                                                 │
      ├─ Falco (eBPF) ──> Falcosidekick ──> api (SSE to the browser)                        │
      │                └──> Falco Talon ──> kill pod / label + isolate (NetworkPolicy)      │
      └─ sandbox ns: default-deny, quotas, no SA token, 30 s deadline ◄── api creates Jobs ─┘
```

Supply chain (GitHub Actions): lint → tests → Trivy → SBOM (syft) → cosign keyless → Kyverno verifies at admission.

## Repository layout

| Path | Purpose |
|------|---------|
| `ansible/` | host hardening, k3s and Cilium bootstrap (roles + playbooks) |
| `scripts/pve-create-vm.sh` | creates the VM on Proxmox from the Debian cloud image (API token from env) |
| `docs/bootstrap.md` | zero-to-cluster runbook |
| `docs/adr/` | architecture decision records (why, not just what) |
| `tests/smoke.sh` | applies the hardening playbook twice to a systemd container; second run must be `changed=0` |
| `.github/workflows/` | CI: yamllint, ansible-lint, shellcheck, gitleaks, container smoke test |
| `.sops.yaml` | SOPS/age recipients (public keys only) |

Later phases add `cluster/` (Argo CD apps, Kustomize), `app/` (Go backend, static frontend), `docs/threat-model.md`.

## Quick start

```sh
make lint                      # same checks as CI, in a container
make smoke                     # hardening playbook x2 in a throwaway container, asserts idempotency
make vm hardening cluster      # see docs/bootstrap.md for the tokens you need first
```

## Phases and Definition of Done

| # | Phase | DoD |
|---|-------|-----|
| 0 | Reconnaissance | report, decisions, plan (done: ADR 0001-0009) |
| 1 | Repo + Ansible | second playbook run = 0 changes |
| 2 | Cluster + GitOps | "hello" page over HTTPS deployed only by git push |
| 3 | Supply chain | unsigned image fails admission |
| 4 | Policies + runtime | manual shell in a test pod = alert + kill |
| 5 | Demo app | 4 scenarios end-to-end, abuse test documented |
| 6 | Site + docs | a stranger understands the project in 2 minutes |
| 7 | Optional | Event-Driven Ansible, Hubble UI read-only, timed rebuild-from-zero |

## Decisions

Every non-obvious choice is an ADR in [`docs/adr/`](docs/adr/README.md): dedicated VM, GitHub, Cloudflare Tunnel,
Cilium, Argo CD, SOPS+age, cloud-init + Ansible, pinned versions, nftables.

## License

MIT
