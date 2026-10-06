package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/incidents"
)

type stubCorrelation struct{ v incidents.View }

func (s stubCorrelation) JSON() []byte {
	b, _ := json.Marshal(s.v)
	return b
}

func TestCorrelationWithoutSIEM(t *testing.T) {
	ts := httptest.NewServer(New(Config{}).Public())
	defer ts.Close()
	raw := getRaw(t, ts.URL+"/api/correlation")
	want := `{"available":false,"checked_at":null,"rules":{"commit":"","applied_at":null,"status":"unknown"},"health":{"ingest":"unknown","evidence_rewritten":false,"disk":"unknown"},"metrics":{"since":null,"incidents":0,"median_ttd_ms":null,"median_tti_ms":null,"median_twin_dwell_ms":null,"host_findings":0,"ingest_lag_ms":null},"incidents":[]}` + "\n"
	if raw != want {
		t.Fatalf("got\n%s\nwant\n%s", raw, want)
	}
	checkGolden(t, "/api/correlation/rules", getRaw(t, ts.URL+"/api/correlation/rules"),
		map[string]string{"rules": "array", "monitors": "array", "correlations": "array"})
	// GET only, JSON 405 otherwise, like every /api path.
	for _, c := range []struct{ method, path string }{{"POST", "/api/correlation"}, {"DELETE", "/api/correlation"},
		{"PUT", "/api/correlation/rules"}, {"POST", "/api/correlation/rules"}} {
		req, _ := http.NewRequest(c.method, ts.URL+c.path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Content-Type") != "application/json" {
			t.Errorf("%s %s: %d %s", c.method, c.path, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
	}
}

// The payload's key set (ADR 0036 "Endpoints"); the web parses exactly these.
func TestCorrelationShape(t *testing.T) {
	at := time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)
	yes := true
	ttd, seq := int64(800), 3
	v := incidents.View{Available: true, CheckedAt: &at, Rules: incidents.RulesView{Commit: "0123456789abcdef0123456789abcdef01234567", AppliedAt: &at, Status: "applied"},
		Health:  incidents.HealthView{Ingest: "ok", Disk: "ok"},
		Metrics: incidents.MetricsView{Since: &at, Incidents: 1, MedianTTDMs: &ttd, IngestLagMs: map[string]*int64{"falco": &ttd, "api": nil}},
		Incidents: []incidents.Incident{{ID: "5f0c3d2a9b7e4c11", Kind: "dns-exfil", Severity: "critical", Title: "x", RunID: "3755e65530aa11bb",
			FirstAt: at, LastAt: at, Attack: []string{"T1048.003"}, FlagMatch: &yes, TTDMs: &ttd,
			Steps:    []incidents.Step{{At: at, Source: "api", CommandSeq: &seq, Detail: "command dns-exfil started"}},
			Evidence: []incidents.Evidence{{Type: "finding", ID: "f1"}}}}}
	ts := httptest.NewServer(New(Config{Correlation: stubCorrelation{v}}).Public())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/api/correlation")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("headers %v", resp.Header)
	}
	_ = resp.Body.Close()
	raw := getRaw(t, ts.URL+"/api/correlation")
	checkGolden(t, "/api/correlation", raw, map[string]string{
		"available": "bool", "checked_at": "string", "rules.commit": "string", "rules.applied_at": "string", "rules.status": "string",
		"health.ingest": "string", "health.evidence_rewritten": "bool", "health.disk": "string",
		"metrics.since": "string", "metrics.incidents": "number", "metrics.median_ttd_ms": "number", "metrics.median_tti_ms": "null",
		"metrics.median_twin_dwell_ms": "null", "metrics.host_findings": "number", "metrics.ingest_lag_ms": "object", "metrics.ingest_lag_ms.falco": "number", "metrics.ingest_lag_ms.api": "null", "incidents": "array",
		"incidents.[].id": "string", "incidents.[].kind": "string", "incidents.[].severity": "string", "incidents.[].title": "string",
		"incidents.[].run_id": "string", "incidents.[].arm": "string", "incidents.[].first_at": "string", "incidents.[].last_at": "string",
		"incidents.[].attack": "array", "incidents.[].falco_events": "number", "incidents.[].flag_match": "bool",
		"incidents.[].ttd_ms": "number", "incidents.[].tti_ms": "null", "incidents.[].steps": "array", "incidents.[].evidence": "array",
		"incidents.[].steps.[].at": "string", "incidents.[].steps.[].source": "string", "incidents.[].steps.[].rule": "string",
		"incidents.[].steps.[].rule_id": "string", "incidents.[].steps.[].command_seq": "number", "incidents.[].steps.[].detail": "string",
		"incidents.[].evidence.[].type": "string", "incidents.[].evidence.[].id": "string",
	})
	// Nothing beyond the contract's fields.
	var doc map[string]any
	_ = json.Unmarshal([]byte(raw), &doc)
	inc := doc["incidents"].([]any)[0].(map[string]any)
	if len(doc) != 6 || len(inc) != 15 || len(inc["steps"].([]any)[0].(map[string]any)) != 6 {
		t.Fatalf("unexpected fields: %d top, %d incident, step %v", len(doc), len(inc), inc["steps"])
	}
}
