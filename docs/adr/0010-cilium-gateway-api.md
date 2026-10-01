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
