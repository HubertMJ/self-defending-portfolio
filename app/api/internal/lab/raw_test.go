package lab

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/siem"
)

// rawAnswer runs Raw on docs and decodes the answer.
func rawAnswer(t *testing.T, f *fakeSource) (rawRun, bool) {
	t.Helper()
	body, ok := New(Config{Source: f}).Raw(context.Background())
	if !ok {
		return rawRun{}, false
	}
	var got rawRun
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
	if f.gotIndices[0] != siem.LabStream || first.Size != 1 ||
		!reflect.DeepEqual(first.Filters, []map[string]any{term("lab.mode", "isolated-vm")}) {
		t.Fatalf("first query = %+v", first)
	}
	if second.Size != siem.MaxSize || !reflect.DeepEqual(second.Source, rawSource) ||
		!reflect.DeepEqual(second.Filters, []map[string]any{term("lab.mode", "isolated-vm"), term("lab.run_id", v.RunID)}) {
		t.Fatalf("second query = %+v", second)
	}
}

func TestRawAllowList(t *testing.T) {
	// A record carrying fields a shipper must never publish: each one is dropped, with the leaves
	// around it kept; an allow-listed path holding an object or an array is dropped as well.
	rec := map[string]any{
		"@timestamp":  "2026-10-19T19:13:10.251Z",
		"event":       map[string]any{"code": "3", "action": "network-connection", "original": "<Event>...</Event>"},
		"lab":         map[string]any{"mode": "isolated-vm", "run_id": "lab-x", "variant": 1.0},
		"source":      map[string]any{"ip": "10.4.2.30", "port": 51000.0},
		"user":        map[string]any{"name": "root"},
		"host":        map[string]any{"name": []any{"lab-vm", "pve"}, "ip": "10.4.2.30"},
		"process":     map[string]any{"pid": 816.0, "hash": map[string]any{"sha256": "f8", "md5": "aa"}, "name": map[string]any{"x": "y"}},
		"destination": map[string]any{"ip": "198.51.100.10", "port": 8080.0},
		"file.path":   "/root/.config/systemd/user/update-helper.service", // a flat dotted key matches too
		"agent":       "fluent-bit",
	}
	got, ok := rawAnswer(t, &fakeSource{docs: []map[string]any{rec}})
	if !ok {
		t.Fatal("ok = false")
	}
	want := map[string]any{
		"@timestamp":  "2026-10-19T19:13:10.251Z",
		"event":       map[string]any{"code": "3", "action": "network-connection"},
		"lab":         map[string]any{"mode": "isolated-vm", "run_id": "lab-x", "variant": 1.0},
		"process":     map[string]any{"pid": 816.0, "hash": map[string]any{"sha256": "f8"}},
		"destination": map[string]any{"ip": "198.51.100.10", "port": 8080.0},
		"file.path":   "/root/.config/systemd/user/update-helper.service",
	}
	if len(got.Records) != 1 || !reflect.DeepEqual(got.Records[0], want) {
		t.Fatalf("record =\n%v\nwant\n%v", got.Records, want)
	}
}

func TestRawNoRun(t *testing.T) {
	v := loadVMRun(t)
	for name, f := range map[string]*fakeSource{
		"empty stream": {docs: []map[string]any{}},
		"only generated runs": {docs: []map[string]any{{"@timestamp": "2026-10-20T09:00:00.000Z",
			"lab": map[string]any{"mode": "generated", "run_id": "lab-g"}}}},
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

func TestRawSizeCap(t *testing.T) {
	// A run whose records exceed the cap is refused whole, never cut.
	var docs []map[string]any
	for i := 0; i < 200; i++ {
		docs = append(docs, map[string]any{"@timestamp": "2026-10-19T19:13:10.251Z",
			"lab":     map[string]any{"mode": "isolated-vm", "run_id": "lab-big"},
			"process": map[string]any{"executable": "/tmp/" + strings.Repeat("x", 2000)}})
	}
	if _, ok := rawAnswer(t, &fakeSource{docs: docs}); ok {
		t.Fatalf("over %d bytes: ok = true, want refused", maxRaw)
	}
	if _, ok := rawAnswer(t, &fakeSource{docs: docs[:50]}); !ok {
		t.Fatal("under the cap: ok = false")
	}
}
