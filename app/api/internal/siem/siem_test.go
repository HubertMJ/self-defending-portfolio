package siem

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pki writes a CA, a client certificate signed by it (tls.crt, tls.key, ca.crt into a temp dir) and
// returns the dir and a server TLS config with a 127.0.0.1 certificate that requires the client cert.
func pki(t *testing.T) (string, *tls.Config) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	issue := func(serial int64, cn string, server bool) ([]byte, *ecdsa.PrivateKey) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if server {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		} else {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der, k
	}
	pemCert := func(der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}) }
	pemKey := func(k *ecdsa.PrivateKey) []byte {
		b, _ := x509.MarshalECPrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	}
	dir := t.TempDir()
	cDER, cKey := issue(2, "portfolio-api-g1", false)
	for name, b := range map[string][]byte{"ca.crt": pemCert(caDER), "tls.crt": pemCert(cDER), "tls.key": pemKey(cKey)} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sDER, sKey := issue(3, "siem01", true)
	sCert, err := tls.X509KeyPair(pemCert(sDER), pemKey(sKey))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return dir, &tls.Config{Certificates: []tls.Certificate{sCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
}

type seen struct {
	method, path, query string
	body                []byte
	clientCN            string
}

// siemServer is a TLS server requiring the test client certificate; it records every request and
// answers with answer(r).
func siemServer(t *testing.T, answer func(r *http.Request) (int, string)) (*Client, *[]seen, *sync.Mutex) {
	t.Helper()
	dir, srvTLS := pki(t)
	var mu sync.Mutex
	var reqs []seen
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		cn := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			cn = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		mu.Lock()
		reqs = append(reqs, seen{r.Method, r.URL.Path, r.URL.RawQuery, b, cn})
		mu.Unlock()
		code, body := answer(r)
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}))
	ts.TLS = srvTLS
	ts.StartTLS()
	t.Cleanup(ts.Close)
	c, err := New(Config{URL: ts.URL, CertDir: dir, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c, &reqs, &mu
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The allow-list: exactly three GET paths and POST _search on the named indices; everything else is
// refused before a request is sent (siem contract P4: "anything else is a programming error").
func TestAllowList(t *testing.T) {
	c, reqs, mu := siemServer(t, func(*http.Request) (int, string) { return 200, `{}` })
	ok := []struct{ method, path string }{
		{"GET", PathFindings}, {"GET", PathCorrelations}, {"GET", PathMonitorAlerts},
		{"POST", "/sdp-falco/_search"}, {"POST", "/sdp-api/_search"}, {"POST", "/siem-sync/_search"},
		{"POST", "/sdp-falco,sdp-talon,sdp-hubble,sdp-k8s-audit,sdp-api,sdp-host/_search"},
	}
	refused := []struct{ method, path string }{
		{"PUT", "/sdp-falco/_doc/x"}, {"PUT", PathFindings}, {"POST", PathFindings}, {"DELETE", "/sdp-falco"},
		{"DELETE", PathMonitorAlerts}, {"PATCH", "/sdp-api/_search"}, {"HEAD", PathFindings},
		{"POST", "/sdp-falco/_doc"}, {"POST", "/sdp-falco/_bulk"}, {"POST", "/_bulk"}, {"POST", "/sdp-falco/_update/x"},
		{"POST", "/sdp-falco/_delete_by_query"}, {"POST", "/sdp-*/_search"}, {"POST", "/sdp-siem01/_search"},
		{"POST", "/sdp-api,sdp-siem01/_search"}, {"POST", "/_search"}, {"POST", "//_search"}, {"POST", "/sdp-api/../_bulk/_search"},
		{"POST", "/.opendistro_security/_search"}, {"POST", "/sdp-api/_search/x"}, {"POST", "sdp-api/_search"},
		{"GET", "/_plugins/_security_analytics/alerts"}, {"GET", "/_cluster/settings"}, {"GET", "/sdp-falco/_doc/x"},
		{"GET", "/_plugins/_security/authinfo"}, {"POST", "/_plugins/_security_analytics/rules"},
		{"POST", "/_plugins/_security_analytics/mappings"}, {"POST", "/_plugins/_alerting/monitors"},
		{"GET", PathFindings + "/"}, {"GET", "/_plugins/_alerting/monitors/alerts/x/_acknowledge"},
	}
	for _, r := range ok {
		if !allowed(r.method, r.path) {
			t.Errorf("allowed(%s %s) = false", r.method, r.path)
		}
	}
	for _, r := range refused {
		if allowed(r.method, r.path) {
			t.Errorf("allowed(%s %s) = true", r.method, r.path)
		}
		var out any
		err := c.do(context.Background(), r.method, r.path, nil, map[string]any{"x": 1}, &out)
		if !errors.Is(err, ErrNotAllowed) {
			t.Errorf("do(%s %s) = %v, want ErrNotAllowed", r.method, r.path, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*reqs) != 0 {
		t.Fatalf("refused requests reached the server: %+v", *reqs)
	}
}

func TestFindingsRequestAndDecode(t *testing.T) {
	c, reqs, mu := siemServer(t, func(*http.Request) (int, string) { return 200, readFile(t, "findings-s0.json") })
	from := time.UnixMilli(1791094000000)
	to := from.Add(15 * time.Minute)
	fs, err := c.Findings(context.Background(), "sdp_falco", from, to, 9999)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 3 || fs[0].ID != "936d24a3-9570-41ea-8879-fd4e23438258" || fs[0].Timestamp != 1791094982951 {
		t.Fatalf("findings: %+v", fs)
	}
	q := fs[0].Queries[0]
	if q.Name != "S0 r4 dotted field k8s.pod.ref" || q.ID != "hNKTBaEBGESM_NsHYoqy" || len(q.Tags) != 3 {
		t.Fatalf("query: %+v", q)
	}
	if d := fs[0].Documents[0]; d.ID != "ndKUBaEBGESM_NsHAYpC" || !strings.Contains(d.Document, `"ref":"sandbox/b-nested"`) {
		t.Fatalf("document: %+v", d)
	}
	mu.Lock()
	defer mu.Unlock()
	r := (*reqs)[0]
	if r.method != "GET" || r.path != PathFindings || r.clientCN != "portfolio-api-g1" {
		t.Fatalf("request: %+v", r)
	}
	for _, want := range []string{"detectorType=sdp_falco", "startTime=1791094000000", "endTime=1791094900000", "size=500", "sortOrder=desc"} {
		if !strings.Contains(r.query, want) {
			t.Errorf("query %q lacks %q", r.query, want)
		}
	}
	if _, err := c.Findings(context.Background(), "sdp-falco&x=1", from, to, 1); err == nil {
		t.Error("a malformed log type was sent")
	}
	if _, err := c.Findings(context.Background(), "sdp_falco", time.Time{}, to, 1); err == nil {
		t.Error("an unbounded range was sent")
	}
}

func TestCorrelationsAndAlertsDecode(t *testing.T) {
	c, reqs, mu := siemServer(t, func(r *http.Request) (int, string) {
		if r.URL.Path == PathCorrelations {
			return 200, readFile(t, "correlations-s0.json")
		}
		return 200, readFile(t, "alerts.json")
	})
	now := time.Now()
	cs, err := c.Correlations(context.Background(), now.Add(-time.Hour), now)
	if err != nil || len(cs) != 3 || cs[0].Finding1 != "a3a0d8f7-e7d3-46bc-a698-c543a27df248" || cs[0].Rules[0] != "P9KbBaEBGESM_NsHz4uZ" {
		t.Fatalf("correlations: %v %+v", err, cs)
	}
	as, err := c.MonitorAlerts(context.Background(), 500)
	if err != nil || len(as) != 1 {
		t.Fatalf("alerts: %v %+v", err, as)
	}
	a := as[0]
	if a.MonitorName != "sdp-git: prevented-not-detected (S0)" || a.State != "ACTIVE" || a.StartTime == nil ||
		*a.StartTime != 1791097352733 || a.EndTime != nil || a.Agg == nil || a.Agg.BucketKeys[0] != "sandbox_g2-silent" {
		t.Fatalf("alert: %+v", a)
	}
	mu.Lock()
	defer mu.Unlock()
	if q := (*reqs)[1].query; !strings.Contains(q, "alertState=ALL") || !strings.Contains(q, "sortString=start_time") {
		t.Fatalf("alerts query %q", q)
	}
}

func TestSearchBodyBuiltInCode(t *testing.T) {
	c, reqs, mu := siemServer(t, func(*http.Request) (int, string) {
		return 200, `{"hits":{"total":{"value":2,"relation":"eq"},"hits":[{"_id":"a","_index":".ds-sdp-api-000001","_source":{"api":{"run_id":"r"}}}]}}`
	})
	now := time.UnixMilli(1791100000000)
	res, err := c.Search(context.Background(), []string{"sdp-api"}, Query{TimeField: "event.ingested", Since: now.Add(-time.Hour), Until: now,
		Filters: []map[string]any{{"term": map[string]any{"event.action": "siem.command"}}}, Size: 500, SortField: "@timestamp",
		Source: []string{"api.run_id", "k8s.pod.ref"}})
	if err != nil || res.Total != 2 || len(res.Hits) != 1 || res.Hits[0].ID != "a" {
		t.Fatalf("search: %v %+v", err, res)
	}
	mu.Lock()
	r := (*reqs)[0]
	mu.Unlock()
	if r.method != "POST" || r.path != "/sdp-api/_search" {
		t.Fatalf("request %+v", r)
	}
	var body map[string]any
	if err := json.Unmarshal(r.body, &body); err != nil {
		t.Fatal(err)
	}
	if body["size"].(float64) != 500 || body["track_total_hits"] != true {
		t.Fatalf("body %s", r.body)
	}
	if !strings.Contains(string(r.body), `"range":{"event.ingested":{"format":"epoch_millis","gte":1791096400000,"lte":1791100000000}}`) {
		t.Fatalf("no bounded range in %s", r.body)
	}
	if !strings.Contains(string(r.body), `"_source":["api.run_id","k8s.pod.ref"]`) {
		t.Fatalf("no field list in %s", r.body)
	}

	bad := []Query{
		{TimeField: "event.ingested", Since: now.Add(-time.Hour), Until: now, Size: 501},
		{TimeField: "event.ingested", Since: now.Add(-time.Hour), Until: now, Size: -1},
		{TimeField: "event.ingested", Until: now, Size: 1},
		{TimeField: "event.ingested", Since: now, Until: now.Add(-time.Hour), Size: 1},
		{TimeField: "event.ingested", Since: now.Add(-32 * 24 * time.Hour), Until: now, Size: 1},
		{Since: now.Add(-time.Hour), Until: now, Size: 1},
	}
	for i, q := range bad {
		if _, err := c.Search(context.Background(), []string{"sdp-api"}, q); err == nil {
			t.Errorf("bad query %d was sent", i)
		}
	}
	if _, err := c.Search(context.Background(), []string{"sdp-siem01"}, Query{TimeField: "x", Since: now.Add(-time.Hour), Until: now}); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("search on sdp-siem01: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*reqs) != 1 {
		t.Fatalf("%d requests sent, want 1", len(*reqs))
	}
}

func TestCountQueryHasNoSource(t *testing.T) {
	q := Query{TimeField: "event.ingested", Since: time.Now().Add(-time.Hour), Until: time.Now(), Size: 0, Source: []string{"x"}}
	b, err := q.body()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b["_source"]; ok {
		t.Fatalf("count query asks for documents: %v", b)
	}
}

func TestErrorsAndRedirects(t *testing.T) {
	var n atomic.Int32
	c, _, _ := siemServer(t, func(r *http.Request) (int, string) {
		if n.Add(1) == 1 {
			return 403, `{"error":"no permissions"}`
		}
		return 302, ``
	})
	now := time.Now()
	if _, err := c.Correlations(context.Background(), now.Add(-time.Minute), now); err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("403: %v", err)
	}
	if _, err := c.Correlations(context.Background(), now.Add(-time.Minute), now); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("redirect: %v", err)
	}
}

func TestNewRefusesBadConfig(t *testing.T) {
	dir, _ := pki(t)
	for _, u := range []string{"", "http://10.4.2.10:9200", "https://", "https://10.4.2.10:9200/sdp-api", "https://u:p@10.4.2.10:9200", "https://10.4.2.10:9200?x=1"} {
		if _, err := New(Config{URL: u, CertDir: dir}); err == nil {
			t.Errorf("New(%q) accepted", u)
		}
	}
	if _, err := New(Config{URL: "https://10.4.2.10:9200", CertDir: t.TempDir()}); err == nil {
		t.Error("New without certificate files accepted")
	}
	if _, err := New(Config{URL: "https://10.4.2.10:9200/", CertDir: dir}); err != nil {
		t.Errorf("New with a trailing slash: %v", err)
	}
}

// Without the client certificate the server refuses the handshake: the client presents it.
func TestClientPresentsCertificate(t *testing.T) {
	c, reqs, mu := siemServer(t, func(*http.Request) (int, string) { return 200, `{"alerts":[]}` })
	if _, err := c.MonitorAlerts(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if (*reqs)[0].clientCN != "portfolio-api-g1" {
		t.Fatalf("client CN %q", (*reqs)[0].clientCN)
	}
}
