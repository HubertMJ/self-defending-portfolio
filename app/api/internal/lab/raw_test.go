package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/siem"
)

// rawAnswerJSON is GET /api/lab/raw's answer as the page reads it.
type rawAnswerJSON struct {
	RunID     string           `json:"run_id"`
	Records   []map[string]any `json:"records"`
	Truncated bool             `json:"truncated"`
}

// rawAnswer runs Raw on f and decodes the answer.
func rawAnswer(t *testing.T, f *fakeSource) (rawAnswerJSON, bool) {
	t.Helper()
	body, ok := New(Config{Source: f}).Raw(context.Background())
	if !ok {
		return rawAnswerJSON{}, false
	}
	if len(body) > maxRaw {
		t.Fatalf("answer of %d bytes, over the cap", len(body))
	}
	var got rawAnswerJSON
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	return got, true
}

func TestRawRealRun(t *testing.T) {
	v := loadVMRun(t)
	// The fake returns ties in reverse order of the file, so the same-second markers (drained and
	// poweroff_requested) come back in the wrong order and only the ingest time can put them right.
	docs := slices.Clone(v.Docs)
	slices.Reverse(docs)
	// An older VM run and a newer generated run in the window are not this run's records.
	docs = append(docs,
		markerDoc("lab-20261018T030001Z-cccccc", "rollback", "2026-10-18T03:00:00.000Z"),
		map[string]any{"@timestamp": "2026-10-20T09:00:00.000Z", "event": map[string]any{"code": "1"},
			"lab": map[string]any{"mode": "generated", "run_id": "lab-20261020T090000Z-dddddd"}})
	f := &fakeSource{docs: docs}
	got, ok := rawAnswer(t, f)
	if !ok {
		t.Fatal("ok = false")
	}
	if got.RunID != v.RunID || len(got.Records) != len(v.Docs) {
		t.Fatalf("run %q with %d records, want %q with %d", got.RunID, len(got.Records), v.RunID, len(v.Docs))
	}
	// Oldest first, the first a rollback and the last the poweroff request.
	for i := 1; i < len(got.Records); i++ {
		if got.Records[i-1]["@timestamp"].(string) > got.Records[i]["@timestamp"].(string) {
			t.Fatalf("records %d and %d out of order", i-1, i)
		}
	}
	if m := at(got.Records[0], "lab.marker"); m != "rollback" {
		t.Errorf("first record is %v, want the rollback", m)
	}
	if m := at(got.Records[len(got.Records)-1], "lab.marker"); m != "poweroff_requested" {
		t.Errorf("last record is %v, want poweroff_requested", m)
	}
	// Nested as indexed: a Sysmon event keeps its objects and its values' types.
	var proc map[string]any
	for _, r := range got.Records {
		if at(r, "event.code") == "1" {
			proc = r
			break
		}
	}
	if proc == nil || at(proc, "process.hash.sha256") == nil || at(proc, "process.parent.pid") == nil ||
		reflect.TypeOf(at(proc, "process.pid")).Kind() != reflect.Float64 {
		t.Fatalf("process-create record not kept as indexed: %v", proc)
	}
	// event.overwrite is in every indexed document but not on the allow-list.
	body, _ := json.Marshal(got)
	if strings.Contains(string(body), "overwrite") {
		t.Errorf("event.overwrite survived: %s", body)
	}
	// The queries: the newest VM record's run id, then that run's records with the allow-list.
	first, second := f.queries[0], f.queries[1]
	if f.gotIndices[0] != siem.LabStream || first.Size != runScan ||
		!reflect.DeepEqual(first.Filters, []map[string]any{term("lab.mode", "isolated-vm")}) {
		t.Fatalf("first query = %+v", first)
	}
	if second.Size != siem.MaxSize || !reflect.DeepEqual(second.Source, rawSource) ||
		!reflect.DeepEqual(second.Filters, []map[string]any{term("lab.mode", "isolated-vm"), term("lab.run_id", v.RunID)}) {
		t.Fatalf("second query = %+v", second)
	}
}

const testRunID = "lab-20261019T191309Z-abcdef"

func TestRawAllowList(t *testing.T) {
	// A record carrying fields a shipper must never publish: each one is dropped, with the leaves
	// around it kept; an allow-listed path holding an object or an array is dropped as well.
	rec := map[string]any{
		"@timestamp":  "2026-10-19T19:13:10.251Z",
		"event":       map[string]any{"code": "3", "action": "network-connection", "original": "<Event>...</Event>"},
		"lab":         map[string]any{"mode": "isolated-vm", "run_id": testRunID, "variant": 1.0},
		"source":      map[string]any{"ip": "10.4.2.30", "port": 51000.0},
		"user":        map[string]any{"name": "root"},
		"host":        map[string]any{"name": []any{"lab-vm", "pve"}, "ip": "10.4.2.30"},
		"process":     map[string]any{"pid": 816.0, "hash": map[string]any{"sha256": "f8", "md5": "aa"}, "name": map[string]any{"x": "y"}},
		"destination": map[string]any{"ip": "198.51.100.10", "port": 8080.0},
		"agent":       "fluent-bit",
	}
	got, ok := rawAnswer(t, &fakeSource{docs: []map[string]any{rec}})
	if !ok {
		t.Fatal("ok = false")
	}
	want := map[string]any{
		"@timestamp":  "2026-10-19T19:13:10.251Z",
		"event":       map[string]any{"code": "3", "action": "network-connection"},
		"lab":         map[string]any{"mode": "isolated-vm", "run_id": testRunID, "variant": 1.0},
		"process":     map[string]any{"pid": 816.0, "hash": map[string]any{"sha256": "f8"}},
		"destination": map[string]any{"ip": "198.51.100.10", "port": 8080.0},
	}
	if len(got.Records) != 1 || !reflect.DeepEqual(got.Records[0], want) {
		t.Fatalf("record =\n%v\nwant\n%v", got.Records, want)
	}
}

func TestRawValueChecks(t *testing.T) {
	// Allow-listed keys whose values are not what the field holds: each one is dropped on its own,
	// the rest of the record kept.
	long := strings.Repeat("a", maxText+1)
	for _, tc := range []struct {
		name, path string
		value      any
		keep       bool
	}{
		{"beacon address", "destination.ip", "198.51.100.10", true},
		{"other TEST-NET address", "destination.ip", "198.51.100.255", true},
		{"internal address", "destination.ip", "10.4.2.30", false},
		{"public address", "destination.ip", "8.8.8.8", false},
		{"IPv6", "destination.ip", "2001:db8::1", false},
		{"IPv4-mapped beacon", "destination.ip", "::ffff:198.51.100.10", false},
		{"address with a port", "destination.ip", "198.51.100.10:8080", false},
		{"address label", "destination.ip", "lab beacon :8080", false},
		{"port as text", "destination.port", "8080", false},
		{"port as number", "destination.port", 8080.0, true},
		{"pid as text", "process.pid", "816", false},
		{"ppid as bool", "process.parent.pid", true, false},
		{"variant as text", "lab.variant", "1", false},
		{"offset as text", "lab.offset_s", "25", false},
		{"offset as number", "lab.offset_s", 25.0, true},
		{"Sysmon code", "event.code", "11", true},
		{"code too long", "event.code", "1234", false},
		{"code not digits", "event.code", "1; rm", false},
		{"code as number", "event.code", 1.0, false},
		{"string at the cap", "process.executable", strings.Repeat("a", maxText), true},
		{"string over the cap", "process.executable", long, false},
		{"name as number", "process.name", 5.0, false},
		{"host as null", "host.name", nil, false},
	} {
		rec := map[string]any{"@timestamp": "2026-10-19T19:13:10.251Z",
			"lab": map[string]any{"mode": "isolated-vm", "run_id": testRunID}}
		parts := strings.Split(tc.path, ".")
		m := rec
		for _, p := range parts[:len(parts)-1] {
			if _, ok := m[p].(map[string]any); !ok {
				m[p] = map[string]any{}
			}
			m = m[p].(map[string]any)
		}
		m[parts[len(parts)-1]] = tc.value
		got, ok := rawAnswer(t, &fakeSource{docs: []map[string]any{rec}})
		if !ok || len(got.Records) != 1 {
			t.Fatalf("%s: no record", tc.name)
		}
		if v := at(got.Records[0], tc.path); (v != nil) != tc.keep || (tc.keep && !reflect.DeepEqual(v, tc.value)) {
			t.Errorf("%s: %s = %v, keep %v", tc.name, tc.path, v, tc.keep)
		}
		if at(got.Records[0], "lab.run_id") != testRunID {
			t.Errorf("%s: the rest of the record went too: %v", tc.name, got.Records[0])
		}
	}
}

func TestRawRunIDs(t *testing.T) {
	// The newest VM record has a malformed run id: it names no run, and the newest well-formed one
	// is served instead. The malformed record is never published.
	docs := []map[string]any{
		{"@timestamp": "2026-10-19T20:00:00.000Z", "lab": map[string]any{"mode": "isolated-vm", "run_id": "lab-evil/../x"}},
		{"@timestamp": "2026-10-19T19:59:00.000Z", "lab": map[string]any{"mode": "isolated-vm", "run_id": "LAB-20261019T195900Z-ABCDEF"}},
		{"@timestamp": "2026-10-19T19:13:10.251Z", "lab": map[string]any{"mode": "isolated-vm", "run_id": testRunID}},
	}
	got, ok := rawAnswer(t, &fakeSource{docs: docs})
	if !ok || got.RunID != testRunID || len(got.Records) != 1 {
		t.Fatalf("got %+v, want the well-formed run", got)
	}
	// Only malformed ids: no run.
	if _, ok := rawAnswer(t, &fakeSource{docs: docs[:2]}); ok {
		t.Fatal("malformed ids only: ok = true")
	}
}

func TestRawLegacyFlatKeys(t *testing.T) {
	// Older documents were written with flat dotted keys; they read exactly like the nested ones:
	// the run is found and every record comes out nested.
	flat := map[string]any{"@timestamp": "2026-10-19T19:12:45.000Z", "event.action": "lifecycle",
		"lab.mode": "isolated-vm", "lab.run_id": testRunID, "lab.marker": "rollback", "lab.offset_s": 0.0,
		"source.ip": "10.4.2.30"}
	mixed := map[string]any{"@timestamp": "2026-10-19T19:13:10.251Z", "event": map[string]any{"action": "process-create"},
		"event.code": "1", "lab": map[string]any{"mode": "isolated-vm"}, "lab.run_id": testRunID,
		"process.pid": 816.0}
	got, ok := rawAnswer(t, &fakeSource{docs: []map[string]any{flat, mixed}})
	if !ok {
		t.Fatal("ok = false")
	}
	want := []map[string]any{
		{"@timestamp": "2026-10-19T19:12:45.000Z", "event": map[string]any{"action": "lifecycle"},
			"lab": map[string]any{"mode": "isolated-vm", "run_id": testRunID, "marker": "rollback", "offset_s": 0.0}},
		{"@timestamp": "2026-10-19T19:13:10.251Z", "event": map[string]any{"action": "process-create", "code": "1"},
			"lab": map[string]any{"mode": "isolated-vm", "run_id": testRunID}, "process": map[string]any{"pid": 816.0}},
	}
	if got.RunID != testRunID || !reflect.DeepEqual(got.Records, want) {
		t.Fatalf("records =\n%v\nwant\n%v", got.Records, want)
	}
}

func TestNest(t *testing.T) {
	in := map[string]any{"lab": "x", "lab.run_id": "y", "a.b.c": 1.0, "a": map[string]any{"b": map[string]any{"d": 2.0}, "e.f": 3.0}}
	want := map[string]any{"lab": "x", "a": map[string]any{"b": map[string]any{"c": 1.0, "d": 2.0}, "e": map[string]any{"f": 3.0}}}
	if got := nest(in); !reflect.DeepEqual(got, want) {
		t.Fatalf("nest = %v, want %v", got, want)
	}
	if _, still := in["a"].(map[string]any)["e.f"]; !still {
		t.Fatal("nest modified its input")
	}
}

func TestRawNoRun(t *testing.T) {
	v := loadVMRun(t)
	for name, f := range map[string]*fakeSource{
		"empty stream": {docs: []map[string]any{}},
		"only generated runs": {docs: []map[string]any{{"@timestamp": "2026-10-20T09:00:00.000Z",
			"lab": map[string]any{"mode": "generated", "run_id": "lab-20261020T090000Z-000000"}}}},
		"no run id": {docs: []map[string]any{{"@timestamp": "2026-10-20T09:00:00.000Z",
			"lab": map[string]any{"mode": "isolated-vm"}}}},
		"first query fails":  {err: context.DeadlineExceeded},
		"second query fails": {docs: v.Docs, fail: func(q siem.Query) bool { return q.Size == siem.MaxSize }},
	} {
		if body, ok := New(Config{Source: f}).Raw(context.Background()); ok || body != nil {
			t.Errorf("%s: ok=%v body=%.80s, want no run", name, ok, body)
		}
	}
	if _, ok := New(Config{}).Raw(context.Background()); ok {
		t.Error("nil source: ok = true")
	}
}

func TestRawTruncated(t *testing.T) {
	// Records of about 3 KiB each: over the cap, the oldest are left out until the answer fits, and
	// the answer says so; the newest record is always kept.
	big := func(i int) map[string]any {
		return map[string]any{"@timestamp": fmt.Sprintf("2026-10-19T19:%02d:%02d.000Z", i/60, i%60),
			"lab":  map[string]any{"mode": "isolated-vm", "run_id": testRunID, "offset_s": float64(i)},
			"host": map[string]any{"name": strings.Repeat("h", maxText)},
			"file": map[string]any{"path": strings.Repeat("f", maxText)},
			"process": map[string]any{"name": strings.Repeat("n", maxText), "executable": strings.Repeat("e", maxText),
				"hash": map[string]any{"sha256": strings.Repeat("s", maxText)}, "parent": map[string]any{"name": strings.Repeat("p", maxText)}}}
	}
	var docs []map[string]any
	for i := 0; i < 200; i++ {
		docs = append(docs, big(i))
	}
	got, ok := rawAnswer(t, &fakeSource{docs: docs})
	if !ok || !got.Truncated || len(got.Records) == 0 || len(got.Records) >= 200 {
		t.Fatalf("over the cap: ok=%v truncated=%v records=%d, want a truncated answer", ok, got.Truncated, len(got.Records))
	}
	if first, last := at(got.Records[0], "lab.offset_s"), at(got.Records[len(got.Records)-1], "lab.offset_s"); last != 199.0 ||
		first != float64(200-len(got.Records)) {
		t.Fatalf("kept offsets %v..%v of %d records, want the newest", first, last, len(got.Records))
	}

	// Under the cap: everything, not truncated.
	if got, ok := rawAnswer(t, &fakeSource{docs: docs[:50]}); !ok || got.Truncated || len(got.Records) != 50 {
		t.Fatalf("under the cap: ok=%v truncated=%v records=%d", ok, got.Truncated, len(got.Records))
	}

	// More records than one search returns: truncated, though the answer fits.
	var many []map[string]any
	for i := 0; i < siem.MaxSize+1; i++ {
		many = append(many, map[string]any{"@timestamp": fmt.Sprintf("2026-10-19T%02d:%02d:%02d.000Z", 10+i/3600, i/60%60, i%60),
			"lab": map[string]any{"mode": "isolated-vm", "run_id": testRunID}})
	}
	if got, ok := rawAnswer(t, &fakeSource{docs: many}); !ok || !got.Truncated || len(got.Records) != siem.MaxSize {
		t.Fatalf("over one search: ok=%v truncated=%v records=%d", ok, got.Truncated, len(got.Records))
	}
}
