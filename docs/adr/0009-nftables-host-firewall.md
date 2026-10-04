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
  the QEMU guest agent (`qm guest exec` from the Proxmox node) is the documented escape hatch, see docs/bootstrap.md.

## Amendment 2026-10-04: a second host, siem01; the k3s rules become group-conditional

**Context.** The SIEM host siem01 (ADR 0034) uses the same hardening roles as k3s01, but nearly
everything k3s-shaped in them is wrong for it: the kube-apiserver port, the pod and service CIDRs, the
Cilium interfaces and proxy marks, an accepting forward chain, rp_filter off and forwarding on, the
kubelet's kernel values and the k3s audit watches.

**Decision.** Each role gets one switch defaulting to membership of the `k3s_nodes` group
(`firewall_k3s_enabled`, `sysctl_k3s_enabled`, `auditd_k3s_enabled`), so k3s01 keeps exactly what it
had and every other host gets none of it. The firewall gains a per-service allow-list
(`firewall_services: [{name, port, proto, sources}]`, one accept rule each); siem01's ruleset is SSH
from the admin networks, 9200/tcp from 10.4.1.20/32 only, rate-limited ICMP, drop logging - and a
forward chain with policy drop, since a host without a cluster routes nothing. sysctl is split into
common hardening keys, the k3s/Cilium keys and host extras (siem01: `vm.max_map_count`,
`vm.swappiness`); auditd renders host-specific watches into `60-extra.rules` (siem01: OpenSearch's
configuration and plugins, `/etc/sdp-siem`, the rules sync) and removes `50-k3s.rules` where the switch
is off. `tests/golden/render.sh` evaluates the roles with each host's real inventory - the templates
and, through a plan generated from each role's own task file, every file task's real loop and
condition: k3s01's files and plans must equal, byte for byte, those rendered the same way from the
commit before the split (b374c0e), except for removals of files k3s01 never had; siem01's must have
the siem01 shape (and verify.yml checks the live host). siem01's 9200 rule carries a byte-rate cap
(`rate_limit`), rendered ahead of the established/related accept so it binds whole connections.

**Consequences.** The split cannot change k3s01 unnoticed: dropping the default of any switch, or a
condition or loop entry in the role tasks, fails the golden test, and `hardening.yml --check --diff --limit k3s01` stays the live gate. The gateway's
zone policy and the host firewall still express the same allow-list for siem01, twice on purpose.
