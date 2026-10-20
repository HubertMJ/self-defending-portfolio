# ADR 0010: Cilium's built-in Gateway API instead of ingress-nginx

Date: 2026-09-30 · Status: accepted

## Context
Phase 2 needs an HTTP entry point inside the cluster: something that terminates TLS for
`hubertjablon.ski`, that `cloudflared` can point at, and that can carry L7 rules (redirects,
response headers) declaratively from git.

Three candidates:

1. **ingress-nginx.** The default reflex. Retirement was announced for March 2026, after which the
   project is in maintenance-only mode; standing up new infrastructure on a component with a
   published end date is a liability in a project whose whole claim is "reproducible and current".
   It also means a second data plane (nginx) next to the one already running (Cilium's Envoy).
2. **Cilium Ingress.** Reuses Cilium's Envoy, but the `Ingress` API cannot express a redirect or a
   response-header filter without vendor annotations, and annotations are exactly the thing
   Gateway API was created to remove.
3. **Cilium Gateway API.** Cilium 1.19.8 ships a Gateway API v1.4.1 implementation backed by the
   same Envoy DaemonSet that Cilium already runs for L7 policy and Hubble L7 visibility.

The project has a standing rule from the brief: no tool earns a place without a role in the story.
Cilium is already load-bearing (ADR 0004: CNI, NetworkPolicy, kube-proxy replacement, Hubble).

## Decision
Use **Cilium's built-in Gateway API implementation**. `gatewayAPI.enabled: true` in the Cilium Helm
values; `gatewayAPI.hostNetwork.enabled: false` (nothing listens on the host — exposure is the
tunnel, ADR 0003). The Gateway API CRDs are installed as their own Argo CD Application in sync
wave -2, pinned to the v1.4.1 standard channel, because Cilium's operator only creates the `cilium`
GatewayClass once those CRDs exist.

Install them *before* Cilium, from the Ansible `cilium` role, not from Argo CD: the operator only
starts its Gateway controller when the CRDs exist at its own startup, and `gatewayAPI.enabled` is a
`cilium-config` field, so enabling it on a running cluster drifts the agents' config and costs a
manual restart of the DaemonSet, `cilium-envoy` and the operator. Ansible therefore installs Cilium
with the Gateway values already set, and the two Argo CD Applications (`gateway-api-crds` wave -2,
`cilium` wave -1) only adopt what is already there.

TLS: cert-manager (chart v1.21.2) with `config.gatewayAPI.enabled: true` watches Gateways carrying
the `cert-manager.io/cluster-issuer` annotation and issues into the listener's `certificateRefs`
Secret. Validation is **DNS-01** against Cloudflare (zone-scoped API token), not HTTP-01: there is no
inbound port to answer an HTTP-01 challenge on, which is the whole point of ADR 0003.

`cloudflared` connects to the Gateway's Service over **HTTPS** (`originServerName: hubertjablon.ski`,
`noTLSVerify: false`), so the certificate is actually exercised end to end instead of being
decoration in front of a plaintext hop.

## Consequences
- One data plane instead of two. Envoy is already in the cluster; no nginx image, no nginx CVE feed,
  no second set of timeouts and buffer sizes to reason about.
- Redirects and security headers are first-class API fields (`HTTPRoute` filters), not annotations.
  They are reviewable in a diff.
- Cilium's Gateway API tracks upstream Gateway API versions, so the CRD Application and the Cilium
  chart version are now a coupled pair: bumping Cilium may require bumping the CRDs. Recorded in
  `cluster/apps/gateway-api-crds.yaml`.
- Cilium creates a `LoadBalancer` Service named `cilium-gateway-<gateway-name>` in the Gateway's
  namespace. On a single node with no LB IP provider its `EXTERNAL-IP` stays `<pending>` forever.
  That is accepted: `cloudflared` reaches it by ClusterIP, and no LB IPAM is configured on purpose —
  an external IP would be an exposure surface that ADR 0003 explicitly does not want.
- Cilium's Envoy runs in the host network namespace, so traffic from the Gateway to a backend pod
  carries the `reserved:host` Cilium identity. Ingress policies for backends must allow `host`
  rather than a pod selector. Recorded in `cluster/infra/hello/`.
- The Gateway API spec is younger than Ingress; some ecosystem tools (older cert-manager, some
  dashboards) still assume `Ingress`. Fallback if this becomes painful is ingress-nginx for the
  remaining months of its life, which is a mechanical change: one Gateway + HTTPRoute becomes one
  Ingress, and `cloudflared` points at a different Service name.

## Amendment 2026-10-01: an internal LoadBalancer address for the Gateway

**Context.** The consequence above ("`EXTERNAL-IP` stays `<pending>` forever ... no LB IPAM is
configured on purpose") did not survive bring-up. With the Service pending, the Gateway never reported
`Programmed=True`, so the `gateway` Application never reported Healthy and the Gateway's status could
not be used as a readiness signal.

**Decision.** `cluster/infra/gateway/lb-ip-pool.yaml` adds a `CiliumLoadBalancerIPPool` with exactly
one address, `10.4.1.30/32`, selected only by the Service of Gateway `portfolio`
(`io.cilium.gateway/owning-gateway: portfolio`). The address is reserved outside the DMZ's DHCP pool
and recorded in `docs/bootstrap.md` (section 0). Nothing announces it: Cilium's L2 announcements and
BGP are not enabled (neither in `cluster/apps/cilium.yaml` nor in the Ansible role), k3s's
`servicelb` is disabled, and `gatewayAPI.hostNetwork.enabled` stays `false`. cloudflared still
reaches the Gateway by its ClusterIP Service name; the public path is unchanged.

**Consequences.**
- The Gateway reports `Programmed=True`, the `gateway` Application can be Healthy, and
  `kubectl -n gateway get svc cilium-gateway-portfolio` shows `EXTERNAL-IP 10.4.1.30` - that is now
  the expected output.
- The no-exposure argument of ADR 0003 now rests on "not announced" instead of "no address". Nothing
  answers ARP for 10.4.1.30, so no LAN host learns a path to it; a host on the same segment that
  installs a static route to it via the node could probably reach Envoy, because Cilium's eBPF load
  balancer handles the address before the host's nftables input chain sees the packet (not verified).
  It would get the same routes, certificate and headers the tunnel gets, without Cloudflare in front.
- Turning on L2 announcements or BGP later would publish the Gateway on the LAN; that is a decision
  for a new ADR, not a values change.

## Amendment 2026-10-20: the Gateway's Service exposes its ClusterIP only

**Context.** The amendment above guarded the LoadBalancer address and missed the NodePorts a
LoadBalancer Service also gets (`allocateLoadBalancerNodePorts` defaults to true; here 30525 for
:80 and 30572 for :443). With kube-proxy replacement, Cilium's eBPF load balancer answers a NodePort
on every node address before the nftables input chain sees the packet, so the host firewall's
default-deny did not apply: `curl -sk --resolve hubertjablon.ski:30572:10.4.1.20
https://hubertjablon.ski:30572/cluster/api/healthz` answered 200 from docker01. A request that way
skips Cloudflare's WAF, and since the API keys its per-visitor limits on `CF-Connecting-IP`, a LAN
client could set that header itself.

**Decision.** The Gateway carries `spec.infrastructure.annotations: service.cilium.io/type:
ClusterIP`. Cilium copies infrastructure annotations onto the Service it generates, and with that
annotation its load balancer installs the ClusterIP frontend only: no NodePort and no LoadBalancer
address in the datapath. cloudflared already reaches the Gateway by its ClusterIP Service name, so
the public path is unchanged. The Service stays type LoadBalancer, so LB IPAM still assigns
10.4.1.30 and the Gateway still reports `Programmed=True` (the reason for the amendment above).
`scripts/check-gateway-exposure.sh` (in `make validate`) fails when a Gateway lacks the annotation
or a Service in `cluster/` is of type NodePort or LoadBalancer.

Not chosen: a `CiliumGatewayClassConfig` (Cilium 1.19) can set `allocateLoadBalancerNodePorts:
false`, but the chart-made `cilium` GatewayClass has no `parametersRef`, so it would need a
GatewayClass of our own, and the LoadBalancer address would still be served. A Cilium host firewall
policy would cover every NodePort on the node, at the price of enabling the host firewall in the
agent, a CNI-wide change on a single node.

**Consequences.**
- The NodePort numbers stay allocated in the Service object (Kubernetes still assigns them); nothing
  answers them. The same holds for 10.4.1.30.
- Cilium merges annotations into the existing Service, it does not remove them: reverting means
  deleting the annotation from the Gateway *and* from `gateway/cilium-gateway-portfolio`.
- The `host` entity in the backends' ingress rules (hello, site, lab, portfolio-api) is not what
  admits the kubelet's probes: with Kubernetes, Cilium's `allow-localhost` resolves to `always`, so
  the node always reaches its local endpoints whatever the policy says. Removing `host` would not
  close anything in the datapath; whether Envoy's check of the original client still matches it
  after this change needs Hubble on the live node, so the entries stay until that is looked at.
