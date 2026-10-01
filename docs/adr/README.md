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
| [0010](0010-cilium-gateway-api.md) | Cilium's built-in Gateway API instead of ingress-nginx | 2 | accepted |
| [0011](0011-supply-chain.md) | Build, scan, describe and sign our own image; verify it at admission | 3 | accepted, amended 2026-10-01 (Kyverno verifies cosign v3 Sigstore bundles) |
| [0012](0012-pod-security-and-resource-policy.md) | Pod Security `restricted` and pod resources as Kyverno policies, Audit before Enforce | 4 | accepted |
| [0013](0013-runtime-detection-and-response.md) | Runtime detection and response: Falco modern eBPF least-privileged, Falcosidekick, Falco Talon scoped to `sandbox` | 4 | accepted |
| [0014](0014-posture-scanning.md) | Posture scanning: Trivy Operator client/server with offline scan Jobs, kube-bench CronJob with a k3s config override, Policy Reporter internal only | 4 | accepted |
| 0015 | *reserved: phase 5 API* | 5 | reserved |
| 0016 | *reserved: phase 5 API* | 5 | reserved |
| 0017 | *reserved: phase 5 attack scenarios* | 5 | reserved |
| 0018 | *reserved: phase 5 attack scenarios* | 5 | reserved |
| 0019 | *reserved: phase 6 site* | 6 | reserved |
| 0020 | *reserved: phase 6 documentation* | 6 | reserved |

Reserved numbers are held for work in progress on parallel branches. A reserved number that ends up
unused is released, and later ADRs are renumbered when those branches merge, so the table never
links to a file that does not exist.

## Open items carried by accepted ADRs

Decisions are accepted with their known costs written down. The ones still open:

| Item | ADR |
|------|-----|
| Falco chart mounts `/host/lib/modules` read-write in least-privileged mode | [0013](0013-runtime-detection-and-response.md) |
| Argo CD has no requests/limits and is excluded from the resources policy | [0012](0012-pod-security-and-resource-policy.md) |
| `pod-security-restricted` and `require-pod-resources` still in Audit | [0012](0012-pod-security-and-resource-policy.md) |
| `ClusterPolicy` is deprecated in Kyverno 1.19; migration to ImageValidatingPolicy / CEL policies deferred | [0011](0011-supply-chain.md), [0012](0012-pod-security-and-resource-policy.md) |
| Digest bumps are manual commits until Renovate is enabled | [0008](0008-pinned-versions.md), [0011](0011-supply-chain.md) |

The full list of gaps and residual risks, including ones no ADR records yet, is in the
[threat model](../threat-model.md#7-known-gaps-and-residual-risk).
