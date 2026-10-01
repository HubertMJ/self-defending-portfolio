# Architecture Decision Records

Short, dated records of decisions that shaped this project. Format: context, decision, consequences.
Superseded ADRs stay in place with a note pointing at the replacement.

| # | Decision | Status |
|---|----------|--------|
| [0001](0001-dedicated-vm-for-the-cluster.md) | Dedicated VM for the cluster, not the shared Docker host | accepted |
| [0002](0002-github-for-repo-and-ci.md) | GitHub + GitHub Actions + GHCR | accepted |
| [0003](0003-cloudflare-tunnel-exposure.md) | Expose the site via Cloudflare Tunnel, no inbound ports | accepted |
| [0004](0004-cilium-as-cni.md) | Cilium as CNI, kube-proxy replacement, no flannel | accepted |
| [0005](0005-argocd-for-gitops.md) | Argo CD for GitOps | accepted |
| [0006](0006-sops-age-for-secrets.md) | SOPS + age for secrets in git | accepted |
| [0007](0007-cloud-init-and-ansible-bootstrap.md) | VM from cloud image via Proxmox API, everything else Ansible | accepted |
| [0008](0008-pinned-versions.md) | Pin every version, bump deliberately | accepted |
| [0009](0009-nftables-host-firewall.md) | nftables host firewall with default-deny input | accepted |
| [0010](0010-cilium-gateway-api.md) | Cilium's built-in Gateway API instead of ingress-nginx | accepted |
| [0011](0011-supply-chain.md) | Build, scan, describe and sign our own image; verify it at admission | accepted |
