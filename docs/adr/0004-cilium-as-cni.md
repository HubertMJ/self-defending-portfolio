# ADR 0004: Cilium as CNI with kube-proxy replacement, no flannel

Date: 2026-09-30 · Status: accepted

## Context
k3s ships flannel (no NetworkPolicy enforcement) and kube-proxy. The demo needs
NetworkPolicy to block egress from the sandbox and to isolate quarantined pods, plus visibility of
what was blocked (Hubble). The kernel (6.12, BTF available) supports eBPF fully.

## Decision
k3s is started with `flannel-backend: none`, `disable-network-policy: true`, `disable-kube-proxy: true`.
Cilium 1.19 is installed by Ansible during bootstrap (native routing, IPAM kubernetes,
kube-proxy replacement, Hubble relay enabled, UI off). After bootstrap Argo CD takes over the Helm release.

## Consequences
- NetworkPolicy (and CiliumNetworkPolicy for DNS/L7 rules) is enforced; Hubble shows dropped flows.
- `rp_filter` must be 0 and `bpf_jit_harden` must not be 2: recorded in the sysctl role.
- One more thing to bootstrap before Argo CD can run (Argo needs a working CNI).
- Multus/flannel-style simplicity is lost; acceptable on a single node.
