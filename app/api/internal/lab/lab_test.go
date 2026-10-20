package lab

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/siem"
)

// fakeSource records the queries it was given and returns a fixed result - or, with docs set,
// answers like an index: the docs matching every term filter (and, with ranged, the time range),
// newest first by SortField, at most Size. It ignores the _source filter, so a field it returns that
// the response lacks was dropped in code. fail, when set, fails the queries it picks. Like the real
// client it fails on a cancelled context, and it records whether the context had a deadline.
type fakeSource struct {
	gotIndices []string
	gotQuery   siem.Query
	queries    []siem.Query
	res        siem.SearchResult
	err        error
	calls      int
	docs       []map[string]any
	ranged     bool
	fail       func(siem.Query) bool
	noDeadline bool // a query ran without a deadline
}

func (f *fakeSource) Search(ctx context.Context, indices []string, q siem.Query) (siem.SearchResult, error) {
	f.calls++
	f.gotIndices = indices
	f.gotQuery = q
	f.queries = append(f.queries, q)
	if _, ok := ctx.Deadline(); !ok {
		f.noDeadline = true
	}
	if err := ctx.Err(); err != nil {
		return siem.SearchResult{}, err
	}
	if f.fail != nil && f.fail(q) {
		return siem.SearchResult{}, context.DeadlineExceeded
	}
	if f.docs == nil {
		return f.res, f.err
	}
	var match []map[string]any
	for _, d := range f.docs {
		if matches(d, q.Filters) && (!f.ranged || inRange(d, q)) {
			match = append(match, d)
		}
	}
	sort.SliceStable(match, func(i, j int) bool {
		a, _ := at(match[i], q.SortField).(string)
		b, _ := at(match[j], q.SortField).(string)
		return a > b
	})
	res := siem.SearchResult{Total: len(match)}
	for i, d := range match {
		if i == q.Size {
			break
		}
		res.Hits = append(res.Hits, siem.Hit{ID: "x", Index: indices[0], Source: d})
	}
	return res, nil
}

// matches applies the term filters the package builds ({"term": {field: value}}).
func matches(d map[string]any, filters []map[string]any) bool {
	for _, f := range filters {
		for field, v := range f["term"].(map[string]any) {
			if at(d, field) != v {
				return false
			}
		}
	}
	return true
}

// inRange applies the query's time range to a document's TimeField.
func inRange(d map[string]any, q siem.Query) bool {
	s, _ := at(d, q.TimeField).(string)
	t, err := time.Parse(time.RFC3339Nano, s)
	return err == nil && !t.Before(q.Since) && !t.After(q.Until)
}

// at reads a dotted path of a document: a flat dotted key, as older documents have, or the nested
// objects.
func at(d map[string]any, path string) any {
	if v, ok := d[path]; ok {
		return v
	}
	var v any = d
	for _, k := range strings.Split(path, ".") {
		m, _ := v.(map[string]any)
		v = m[k]
	}
	return v
}

// fixture reads a JSON file of testdata into v.
func fixture(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
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
	// The query is the fixed one: the lab-runs index, size 1, newest by run.finished_at - first an
	// isolated-VM run (the fake ignores the filter here), then the history of the served run's mode.
	if len(f.gotIndices) != 1 || f.gotIndices[0] != siem.LabRunsIndex {
		t.Fatalf("indices = %v", f.gotIndices)
	}
	if q := f.queries[0]; q.Size != 1 || q.SortField != "run.finished_at" || q.TimeField != "run.finished_at" ||
		!reflect.DeepEqual(q.Filters, []map[string]any{term("run.mode", "isolated-vm")}) {
		t.Fatalf("query = %+v", q)
	}
	if len(f.queries) != 2 {
		t.Fatalf("queries = %d, want the run and its history", len(f.queries))
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
	ev["lab.variant"] = 1         // ground-truth aid, must never be published
	ev["source.ip"] = "10.4.2.10" // not in the event allow-list

	rep := project(d)
	if rep == nil {
		t.Fatal("project returned nil for a valid document")
	}
	body, _ := json.Marshal(rep)
	s := string(body)
	for _, bad := range []string{"leak", "10.4.2.10", "lab.variant", "source.ip"} {
		if strings.Contains(s, bad) {
			t.Errorf("response still contains dropped field %q: %s", bad, s)
		}
	}
	// The allow-listed event keys survive, with their types.
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
	// One fetch is two queries: the run and its history.
	if f.calls != 2 {
		t.Fatalf("calls = %d within the TTL, want 2", f.calls)
	}
	now = now.Add(11 * time.Second) // past the TTL: one more query
	if _, ok := r.Latest(context.Background()); !ok {
		t.Fatal("want a run after the TTL")
	}
	if f.calls != 4 {
		t.Fatalf("calls = %d after the TTL, want 4", f.calls)
	}
}

// generic decodes JSON into plain maps and slices, for comparing documents regardless of field order.
func generic(t *testing.T, b []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestProjectVariantB(t *testing.T) {
	// A real isolated-VM run document carries only allow-listed fields, so its projection is itself:
	// run.duration_s, lifecycle, counters, the per-variant pid/ppid, the events' offset_s and pids,
	// the findings' and the incident's at_offset_s all survive.
	var d map[string]any
	fixture(t, "run2-doc.json", &d)
	// run.complete (false when the validator timed out) postdates this run; false must survive too.
	d["run"].(map[string]any)["complete"] = false
	want, _ := json.Marshal(d)

	// The same unexpected fields at every level as for a generated run must still be dropped.
	d["leak"] = "10.4.2.10"
	d["history"] = []any{map[string]any{"id": "forged"}}
	d["run"].(map[string]any)["vm_host"] = "pve"
	d["lifecycle"].([]any)[0].(map[string]any)["node"] = "pve"
	d["counters"].(map[string]any)["hosts"] = 3
	v := d["variants"].([]any)[0].(map[string]any)
	v["vmid"] = 9001
	v["events"].([]any)[0].(map[string]any)["lab.variant"] = 1
	v["findings"].([]any)[0].(map[string]any)["finding_id"] = "x"

	rep := project(d)
	if rep == nil {
		t.Fatal("project refused the real run document")
	}
	got, _ := json.Marshal(rep)
	if !reflect.DeepEqual(generic(t, got), generic(t, want)) {
		t.Fatalf("projection of run2-doc.json differs from the document:\ngot  %s\nwant %s", got, want)
	}
}

func TestProjectVariantAHasNoBFields(t *testing.T) {
	// A generated run has none of variant B's fields, and the projection adds none of them.
	body, _ := json.Marshal(project(doc()))
	for _, key := range []string{"duration_s", "complete", "lifecycle", "counters", "history", "pid", "ppid", "at_offset_s", "offset_s"} {
		if strings.Contains(string(body), `"`+key+`"`) {
			t.Errorf("generated run gained %q: %s", key, body)
		}
	}
}

// runDoc is doc() as a run of mode, finished at finished; opened false means no incident opened.
func runDoc(id, mode, finished string, opened bool) map[string]any {
	d := doc()
	run := d["run"].(map[string]any)
	run["id"], run["mode"], run["finished_at"] = id, mode, finished
	if !opened {
		d["incident"].(map[string]any)["opened_at_variant"] = nil
	}
	return d
}

func TestLatestPrefersIsolatedVM(t *testing.T) {
	for _, tc := range []struct {
		name string
		docs []map[string]any
		want string // the served run's id
	}{
		{"vm run older than a generated one", []map[string]any{
			runDoc("gen-new", "generated", "2026-10-20T09:40:00.000Z", true),
			runDoc("vm-old", "isolated-vm", "2026-10-19T19:15:55.000Z", true),
		}, "vm-old"},
		{"no vm run: the newest of any mode", []map[string]any{
			runDoc("gen-old", "generated", "2026-10-18T09:40:00.000Z", true),
			runDoc("gen-new", "generated", "2026-10-20T09:40:00.000Z", true),
		}, "gen-new"},
	} {
		f := &fakeSource{docs: tc.docs}
		body, ok := New(Config{Source: f}).Latest(context.Background())
		if !ok {
			t.Fatalf("%s: no run", tc.name)
		}
		var rep Replay
		if err := json.Unmarshal(body, &rep); err != nil {
			t.Fatal(err)
		}
		if rep.Run.ID != tc.want {
			t.Errorf("%s: served %q, want %q", tc.name, rep.Run.ID, tc.want)
		}
		// The history is of the served run's mode only.
		for _, h := range rep.History {
			if !strings.HasPrefix(h.ID, tc.want[:3]) {
				t.Errorf("%s: history has %q of another mode", tc.name, h.ID)
			}
		}
	}
}

func TestLatestHistory(t *testing.T) {
	// Nine VM runs, one generated: the history is the newest seven VM runs, newest first, ok when the
	// run opened its incident, duration_s and complete only where the run document has them.
	var docs []map[string]any
	for i := 1; i <= 9; i++ {
		d := runDoc("vm-"+string(rune('0'+i)), "isolated-vm", "2026-10-1"+string(rune('0'+i))+"T03:05:00.000Z", i%3 != 0)
		if i%2 == 0 {
			d["run"].(map[string]any)["duration_s"] = 190
		}
		if i >= 8 {
			d["run"].(map[string]any)["complete"] = i == 9
		}
		docs = append(docs, d)
	}
	docs = append(docs, runDoc("gen", "generated", "2026-10-20T09:40:00.000Z", true))
	f := &fakeSource{docs: docs}
	body, ok := New(Config{Source: f}).Latest(context.Background())
	if !ok {
		t.Fatal("no run")
	}
	var got struct {
		History []map[string]any `json:"history"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	want := []map[string]any{
		{"id": "vm-9", "finished_at": "2026-10-19T03:05:00.000Z", "complete": true, "ok": false},
		{"id": "vm-8", "finished_at": "2026-10-18T03:05:00.000Z", "duration_s": 190.0, "complete": false, "ok": true},
		{"id": "vm-7", "finished_at": "2026-10-17T03:05:00.000Z", "ok": true},
		{"id": "vm-6", "finished_at": "2026-10-16T03:05:00.000Z", "duration_s": 190.0, "ok": false},
		{"id": "vm-5", "finished_at": "2026-10-15T03:05:00.000Z", "ok": true},
		{"id": "vm-4", "finished_at": "2026-10-14T03:05:00.000Z", "duration_s": 190.0, "ok": true},
		{"id": "vm-3", "finished_at": "2026-10-13T03:05:00.000Z", "ok": false},
	}
	if !reflect.DeepEqual(got.History, want) {
		t.Fatalf("history =\n%v\nwant\n%v", got.History, want)
	}
	q := f.queries[len(f.queries)-1]
	if q.Size != 7 || !reflect.DeepEqual(q.Source, []string{"run", "incident"}) ||
		!reflect.DeepEqual(q.Filters, []map[string]any{term("run.mode", "isolated-vm")}) {
		t.Fatalf("history query = %+v", q)
	}
}

func TestLatestHistoryOmitted(t *testing.T) {
	// A failing history query never hides the run: the history is just left out.
	f := &fakeSource{docs: []map[string]any{runDoc("vm-1", "isolated-vm", "2026-10-19T19:15:55.000Z", true)},
		fail: func(q siem.Query) bool { return q.Size == historySize }}
	body, ok := New(Config{Source: f}).Latest(context.Background())
	if !ok {
		t.Fatal("no run")
	}
	if strings.Contains(string(body), `"history"`) {
		t.Fatalf("history present after a failed query: %s", body)
	}
}

func TestLatestPrefersOnlyRecentVMRun(t *testing.T) {
	// A VM run is preferred only while it is recent: once variant B has stopped for longer than
	// PreferVM, the newest run of any mode (A) is served, with A's history.
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		vmAt     string
		preferVM time.Duration
		want     string
	}{
		{"vm run two days old", "2026-10-18T13:00:00.000Z", 0, "vm-1"},
		{"vm run four days old", "2026-10-16T11:00:00.000Z", 0, "gen-1"},
		{"four days old, preferred within five", "2026-10-16T11:00:00.000Z", 5 * 24 * time.Hour, "vm-1"},
	} {
		f := &fakeSource{ranged: true, docs: []map[string]any{
			runDoc("gen-1", "generated", "2026-10-20T09:40:00.000Z", true),
			runDoc("vm-1", "isolated-vm", tc.vmAt, true),
		}}
		body, ok := New(Config{Source: f, Now: func() time.Time { return now }, PreferVM: tc.preferVM}).Latest(context.Background())
		if !ok {
			t.Fatalf("%s: no run", tc.name)
		}
		var rep Replay
		if err := json.Unmarshal(body, &rep); err != nil {
			t.Fatal(err)
		}
		if rep.Run.ID != tc.want || len(rep.History) != 1 || rep.History[0].ID != tc.want {
			t.Errorf("%s: served %q with history %+v, want %q", tc.name, rep.Run.ID, rep.History, tc.want)
		}
	}
}

func TestCacheDetachedFromRequest(t *testing.T) {
	// The first visitor's request is already cancelled (it disconnected): the fetch still runs under
	// its own deadline, and neither this visitor's cancellation nor a 404 is cached for the next one.
	now := time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)
	f := &fakeSource{res: hit(doc())}
	r := New(Config{Source: f, Now: func() time.Time { return now }})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.Latest(ctx)
	body, ok := r.Latest(context.Background())
	if !ok || body == nil {
		t.Fatal("the cancelled first request poisoned the cache")
	}
	if f.calls != 2 || f.noDeadline {
		t.Fatalf("calls = %d (want one fetch of 2), a query without a deadline: %v", f.calls, f.noDeadline)
	}
}

// blockingSource holds every search until release is closed.
type blockingSource struct {
	release chan struct{}
	calls   atomic.Int32
}

func (b *blockingSource) Search(ctx context.Context, _ []string, _ siem.Query) (siem.SearchResult, error) {
	b.calls.Add(1)
	<-b.release
	return hit(doc()), nil
}

func TestCacheWaitersGiveUp(t *testing.T) {
	// While OpenSearch is slow, a visitor waits only as long as its own context allows, and the one
	// fetch in flight is shared rather than repeated.
	b := &blockingSource{release: make(chan struct{})}
	r := New(Config{Source: b})
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		start := time.Now()
		if _, ok := r.Latest(ctx); ok {
			t.Fatal("answered before the fetch finished")
		}
		cancel()
		if waited := time.Since(start); waited > 2*time.Second {
			t.Fatalf("waited %s past its own deadline", waited)
		}
	}
	close(b.release)
	if _, ok := r.Latest(context.Background()); !ok {
		t.Fatal("no run after the fetch finished")
	}
	if n := b.calls.Load(); n != 2 { // one fetch: the run and its history
		t.Fatalf("searches = %d, want one fetch of 2", n)
	}
}

func TestCacheStaleOnError(t *testing.T) {
	now := time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)
	f := &fakeSource{res: hit(doc())}
	var logs strings.Builder
	r := New(Config{Source: f, Now: func() time.Time { return now }, TTL: 10 * time.Second,
		Log: slog.New(slog.NewTextHandler(&logs, nil))})
	good, ok := r.Latest(context.Background())
	if !ok {
		t.Fatal("no run")
	}
	// OpenSearch starts refusing (a 403 before roles.yml is applied): the good answer is still
	// served, the failure logged once per fetch, and retried after failTTL rather than every request.
	f.err = &siem.StatusError{Method: "POST", Path: "/lab-runs/_search", Code: 403}
	now = now.Add(11 * time.Second)
	for i := 0; i < 3; i++ {
		if body, ok := r.Latest(context.Background()); !ok || string(body) != string(good) {
			t.Fatalf("after an error: ok=%v, want the previous answer", ok)
		}
	}
	if f.calls != 3 {
		t.Fatalf("calls = %d, want 2 + one failed fetch", f.calls)
	}
	if n := strings.Count(logs.String(), "lab query failed"); n != 1 ||
		!strings.Contains(logs.String(), "endpoint=latest") || !strings.Contains(logs.String(), "status=403") {
		t.Fatalf("log = %q, want one warning with endpoint and status", logs.String())
	}
	now = now.Add(failTTL)
	r.Latest(context.Background())
	if f.calls != 4 {
		t.Fatalf("calls = %d after failTTL, want a retry", f.calls)
	}
	// A fetch that succeeds with nothing to show does replace the answer.
	f.err, f.res = nil, siem.SearchResult{}
	now = now.Add(failTTL)
	if _, ok := r.Latest(context.Background()); ok {
		t.Fatal("an empty index still served the old run")
	}
}

func TestCacheErrorWithoutPreviousAnswer(t *testing.T) {
	// No previous answer: a failure answers false and is remembered for failTTL, not the TTL.
	now := time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)
	f := &fakeSource{err: context.DeadlineExceeded}
	r := New(Config{Source: f, Now: func() time.Time { return now }, TTL: 10 * time.Second,
		Log: slog.New(slog.DiscardHandler)})
	for i := 0; i < 3; i++ {
		if _, ok := r.Latest(context.Background()); ok {
			t.Fatal("ok = true on error")
		}
	}
	if f.calls != 1 {
		t.Fatalf("calls = %d within failTTL, want 1", f.calls)
	}
	f.err, f.res = nil, hit(doc())
	now = now.Add(failTTL)
	if _, ok := r.Latest(context.Background()); !ok {
		t.Fatal("no recovery after failTTL")
	}
}
