// Package clientip derives the key the abuse limits are counted against.
//
// The visitor's address comes from CF-Connecting-IP. That header is trustworthy here only because of
// the path a request has to take (ADR 0015): Cloudflare's edge sets it, overwriting whatever the
// client sent; cloudflared carries it through the tunnel; the Gateway's Envoy passes it on; and the
// API's public port accepts connections from the Gateway alone (CiliumNetworkPolicy
// cluster/infra/portfolio-api/ciliumnetworkpolicy.yaml). Nothing else in the cluster can reach the
// port to forge it.
//
// IPv6 addresses are keyed by their /64: a single subscriber line is routinely handed a whole /64,
// so keying by the full address would give one visitor 2^64 independent quotas.
package clientip

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Header is the request header set by Cloudflare's edge.
const Header = "CF-Connecting-IP"

// Key returns the rate-limit key for r: the CF-Connecting-IP address (IPv4, or the IPv6 /64), or,
// when the header is missing or not an address, one shared "direct:<peer>" key. Requests without
// the header did not come through Cloudflare; in production the only peer that can send them is the
// Gateway, so they all share one budget - which is stricter, not looser.
func Key(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get(Header)); v != "" {
		if addr, err := netip.ParseAddr(v); err == nil {
			addr = addr.Unmap()
			if addr.Is4() {
				return addr.String()
			}
			if p, err := addr.WithZone("").Prefix(64); err == nil {
				return p.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return "direct:" + host
}
