# ADR 0009: nftables host firewall with default-deny input

Date: 2026-09-30 · Status: accepted

## Context
The host is on a LAN VLAN behind a UniFi gateway, but "the router protects it" is not a story
a security portfolio should tell. Cilium provides pod-level policy, not host-level.

## Decision
nftables (native on Debian 13) with `input` policy drop. Allowed: loopback, established/related,
rate-limited ICMP, SSH and the k3s API only from the LAN CIDR, traffic from the pod and service CIDRs
to the host (kubelet, host-network components). Dropped packets are logged with a rate limit and a
`nft-drop:` prefix so they are visible in journald and can be shipped to Loki later.
`forward` policy is accept and left to Cilium, which enforces policy in eBPF before iptables.

## Consequences
- Nothing on the host is reachable from the internet; the only public path is the outbound tunnel.
- ufw/firewalld are not installed, so there is a single source of truth for host rules.
- A mistake in the ruleset can lock out SSH: the role validates with `nft -c` before applying and
  Proxmox console access is the documented escape hatch.
