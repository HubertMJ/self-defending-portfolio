# ADR 0001: Dedicated VM for the cluster, not the shared Docker host

Date: 2026-09-30 · Status: accepted

## Context
The homelab already has a Debian VM (`docker01`) running 19 Docker containers: monitoring
(Grafana, Loki, VictoriaMetrics, Alloy), Immich, Komodo. Reconnaissance showed no host
firewall (INPUT ACCEPT, only Docker chains), five Docker bridges, iptables-nft managed by Docker,
and plaintext credentials in home directories.

## Decision
Create a new VM (`k3s01`, 4 vCPU / 8 GB / 60 GB, Debian 13 cloud image) on the same Proxmox host
and put k3s there. `docker01` is not touched.

## Consequences
- Cilium (eBPF, own datapath) does not fight Docker's iptables-nft rules.
- Ansible hardening (default-deny nftables, sysctl, auditd) cannot break Immich or Grafana.
- Falco/Trivy/kube-bench see only the portfolio, so the public posture page reflects
  only what the repo describes.
- Cost: ~8 GB RAM on the Proxmox host; "rebuild from zero" becomes a clean, measurable path.
