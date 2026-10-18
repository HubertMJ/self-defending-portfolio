package lab

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/siem"
)

// fakeSource records the query it was given and returns a fixed result.
type fakeSource struct {
	gotIndices []string
	gotQuery   siem.Query
	res        siem.SearchResult
	err        error
	calls      int
}

func (f *fakeSource) Search(_ context.Context, indices []string, q siem.Query) (siem.SearchResult, error) {
	f.calls++
	f.gotIndices = indices
	f.gotQuery = q
	return f.res, f.err
}

// hit wraps a run document (as a map, the way siem.Hit.Source holds it) in a one-hit result.
func hit(src map[string]any) siem.SearchResult {
	return siem.SearchResult{Total: 1, Hits: []siem.Hit{{ID: "x", Index: siem.LabRunsIndex, Source: src}}}
}

// doc is a minimal but complete schema-1 run document with one variant and one event.
func doc() map[string]any {
	var m map[string]any
	if err := json.Unmarshal([]byte(`{
		"schema": 1,
		"sample": false,
		"run": {"id": "lab-20261018T090000Z-abc123", "mode": "generated",
			"started_at": "2026-10-18T09:00:00.000Z", "finished_at": "2026-10-18T09:40:05.000Z"},
		"scenario": {"id": "C", "title": "A new hash and a new name for every copy", "summary": "s"},
		"artefact": {"name": "update-helper.exe", "path": "C:\\Temp\\update-helper.exe"},
		"beacon": "lab beacon :8080",
		"risk_threshold": 100,
		"rules": [{"id": "ioc-update-helper-sha256", "title": "Known-bad hash", "kind": "sigma",
			"technique": "T1204.002", "score": 50, "logic": "hash"}],
		"variants": [{
			"n": 1, "host": "ws1",
			"sha256": "1a849258c42f9603a2a8715cb1a490b5269a0a8d0f8b80616bb6e9fce381c8a6",
			"renamed": "update-helper.exe",
			"events": [{"@timestamp": "2026-10-18T09:00:00.000Z", "event.code": "1",
				"event.action": "process-create", "host.name": "ws1", "process.name": "update-helper.exe",
				"destination.port": 8080}],
			"ground_truth": {"@timestamp": "2026-10-18T09:00:00.000Z", "host": "ws1",
				"techniques": ["T1204.002"], "variant_sha256": "1a849258c42f9603a2a8715cb1a490b5269a0a8d0f8b80616bb6e9fce381c8a6"},
			"findings": [{"rule": "ioc-update-helper-sha256", "delay_s": 58}],
			"caught_by_hash": true
		}],
		"incident": {"opened_at_variant": 1, "delay_s": 312, "key": "beacon"},
		"techniques": {"expected": ["T1204.002"], "detected": ["T1204.002"]}
	}`), &m); err != nil {
		panic(err)
	}
	return m
}

func TestLatestHappyPath(t *testing.T) {
	f := &fakeSource{res: hit(doc())}
	r := New(Config{Source: f})
	body, ok := r.Latest(context.Background())
	if !ok {
		t.Fatal("ok = false, want a run")
	}
	// The query is the fixed one: the lab-runs index, size 1, newest by run.finished_at.
	if len(f.gotIndices) != 1 || f.gotIndices[0] != siem.LabRunsIndex {
		t.Fatalf("indices = %v", f.gotIndices)
	}
	if f.gotQuery.Size != 1 || f.gotQuery.SortField != "run.finished_at" || f.gotQuery.TimeField != "run.finished_at" {
		t.Fatalf("query = %+v", f.gotQuery)
	}
	var rep Replay
	if err := json.Unmarshal(body, &rep); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if rep.Schema != 1 || rep.Sample || rep.Run.Mode != "generated" || len(rep.Variants) != 1 {
		t.Fatalf("projected shape wrong: %+v", rep)
	}
	if rep.Variants[0].CaughtByHash != true || len(rep.Variants[0].Findings) != 1 {
		t.Fatalf("variant projection wrong: %+v", rep.Variants[0])
	}
	if rep.Incident.OpenedAtVariant == nil || *rep.Incident.OpenedAtVariant != 1 || rep.Incident.Key != "beacon" {
		t.Fatalf("incident projection wrong: %+v", rep.Incident)
	}
	if len(rep.Techniques.Detected) != 1 || rep.Techniques.Detected[0] != "T1204.002" {
		t.Fatalf("techniques projection wrong: %+v", rep.Techniques)
	}
}

func TestLatestEmptyIndex(t *testing.T) {
	f := &fakeSource{res: siem.SearchResult{Total: 0}}
	if body, ok := New(Config{Source: f}).Latest(context.Background()); ok || body != nil {
		t.Fatalf("empty index: ok=%v body=%q, want no run", ok, body)
	}
}

func TestLatestQueryError(t *testing.T) {
	f := &fakeSource{err: context.DeadlineExceeded}
	if _, ok := New(Config{Source: f}).Latest(context.Background()); ok {
		t.Fatal("query error: ok=true, want no run")
	}
}

func TestLatestNilSource(t *testing.T) {
	if _, ok := New(Config{}).Latest(context.Background()); ok {
		t.Fatal("nil source: ok=true, want no run")
	}
}

func TestLatestOversized(t *testing.T) {
	d := doc()
	// A scenario summary larger than the cap: the whole document is refused.
	d["scenario"].(map[string]any)["summary"] = strings.Repeat("x", maxDoc+1)
	f := &fakeSource{res: hit(d)}
	if _, ok := New(Config{Source: f}).Latest(context.Background()); ok {
		t.Fatal("oversized: ok=true, want no run")
	}
}

func TestLatestInvalidShape(t *testing.T) {
	for name, mut := range map[string]func(map[string]any){
		"wrong schema":  func(d map[string]any) { d["schema"] = 2 },
		"no variants":   func(d map[string]any) { d["variants"] = []any{} },
		"variants gone": func(d map[string]any) { delete(d, "variants") },
	} {
		d := doc()
		mut(d)
		f := &fakeSource{res: hit(d)}
		if _, ok := New(Config{Source: f}).Latest(context.Background()); ok {
			t.Errorf("%s: ok=true, want no run", name)
		}
	}
}

func TestProjectDropsUnexpectedFields(t *testing.T) {
	d := doc()
	// An unexpected top-level field that would leak an address, and an unexpected event key.
	d["leak"] = "10.4.2.10"
	v := d["variants"].([]any)[0].(map[string]any)
	ev := v["events"].([]any)[0].(map[string]any)
	ev["lab.variant"] = 1          // ground-truth aid, must never be published
	ev["source.ip"] = "10.4.2.10"  // not in the event allow-list

	body := project(d)
	if body == nil {
		t.Fatal("project returned nil for a valid document")
	}
	s := string(body)
	for _, bad := range []string{"leak", "10.4.2.10", "lab.variant", "source.ip"} {
		if strings.Contains(s, bad) {
			t.Errorf("response still contains dropped field %q: %s", bad, s)
		}
	}
	// The allow-listed event keys survive, with their types.
	var rep Replay
	if err := json.Unmarshal(body, &rep); err != nil {
		t.Fatal(err)
	}
	evOut := rep.Variants[0].Events[0]
	if _, keep := evOut["host.name"]; !keep {
		t.Fatalf("allow-listed key host.name was dropped: %v", evOut)
	}
	if string(evOut["destination.port"]) != "8080" {
		t.Fatalf("destination.port not preserved as a number: %q", evOut["destination.port"])
	}
}

func TestLatestCaches(t *testing.T) {
	now := time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)
	f := &fakeSource{res: hit(doc())}
	r := New(Config{Source: f, Now: func() time.Time { return now }, TTL: 10 * time.Second})
	for i := 0; i < 3; i++ {
		if _, ok := r.Latest(context.Background()); !ok {
			t.Fatal("want a run")
		}
	}
	if f.calls != 1 {
		t.Fatalf("calls = %d within the TTL, want 1", f.calls)
	}
	now = now.Add(11 * time.Second) // past the TTL: one more query
	if _, ok := r.Latest(context.Background()); !ok {
		t.Fatal("want a run after the TTL")
	}
	if f.calls != 2 {
		t.Fatalf("calls = %d after the TTL, want 2", f.calls)
	}
}
