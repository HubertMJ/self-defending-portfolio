package clientip

import (
	"net/http/httptest"
	"testing"
)

func TestKey(t *testing.T) {
	cases := []struct{ header, remote, want string }{
		{"203.0.113.7", "10.0.0.1:5555", "203.0.113.7"},
		{" 203.0.113.7 ", "10.0.0.1:5555", "203.0.113.7"},
		{"::ffff:203.0.113.7", "10.0.0.1:5555", "203.0.113.7"},
		{"2001:db8:1:2:3:4:5:6", "10.0.0.1:5555", "2001:db8:1:2::/64"},
		{"2001:db8:1:2:ffff::1", "10.0.0.1:5555", "2001:db8:1:2::/64"},
		{"", "10.0.0.1:5555", "direct:10.0.0.1"},
		{"not-an-ip", "10.0.0.1:5555", "direct:10.0.0.1"},
		{"1.2.3.4, 5.6.7.8", "10.0.0.1:5555", "direct:10.0.0.1"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/api/healthz", nil)
		r.RemoteAddr = c.remote
		if c.header != "" {
			r.Header.Set(Header, c.header)
		}
		if got := Key(r); got != c.want {
			t.Errorf("Key(%q, %q) = %q, want %q", c.header, c.remote, got, c.want)
		}
	}
}
