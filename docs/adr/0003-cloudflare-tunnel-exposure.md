# ADR 0003: Expose the site via Cloudflare Tunnel, no inbound ports

Date: 2026-09-30 · Status: accepted

## Context
The cluster lives behind a home connection (UniFi UCG, dynamic-ish public IP).
`hubertjablon.ski` is already on Cloudflare. Options: port-forward 443 to the ingress
with cert-manager HTTP-01, or an outbound-only Cloudflare Tunnel (`cloudflared` in the cluster).

## Decision
Cloudflare Tunnel. `cloudflared` runs as a Deployment in the cluster and connects outbound to
Cloudflare; the tunnel routes `hubertjablon.ski` to the in-cluster ingress. No inbound port is opened
on the router or the host firewall. Origin TLS: cert-manager with Let's Encrypt DNS-01 (Cloudflare API
token, scoped to the zone) so the ingress still serves a real certificate and the tunnel connects over HTTPS.

## Consequences
- Home IP stays hidden; Cloudflare WAF/rate limiting is a first layer before the demo backend.
- The visitor-triggered "attack" endpoint gets DDoS protection for free.
- Cloudflare terminates TLS from the visitor: it is a trusted intermediary. This is stated in the threat model.
- Dependency on one vendor for exposure; fallback is a port-forward, which the ingress already supports.
- Argo CD and Hubble are never routed through the tunnel; they stay LAN-only.
