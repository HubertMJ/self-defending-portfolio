package lab

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/siem"
)

// vmRunDocs is testdata/vm-run-docs.json: the 39 sdp-lab documents of one real isolated-VM run.
type vmRunDocs struct {
	RunID string           `json:"run_id"`
	Docs  []map[string]any `json:"docs"`
}

func loadVMRun(t *testing.T) vmRunDocs {
	t.Helper()
	var v vmRunDocs
	fixture(t, "vm-run-docs.json", &v)
	return v
}

// markerDocs are the run's lifecycle markers, without the ones named in drop.
func markerDocs(v vmRunDocs, drop ...string) []map[string]any {
	var out []map[string]any
next:
	for _, d := range v.Docs {
		if at(d, "event.action") != "lifecycle" {
			continue
		}
		for _, m := range drop {
			if at(d, "lab.marker") == m {
				continue next
			}
		}
		out = append(out, d)
	}
	return out
}

// markerDoc is one lifecycle marker document of run id.
func markerDoc(runID, marker, ts string) map[string]any {
	return map[string]any{"@timestamp": ts, "event": map[string]any{"action": "lifecycle"},
		"lab": map[string]any{"mode": "isolated-vm", "run_id": runID, "marker": marker}}
}

func TestVM(t *testing.T) {
	v := loadVMRun(t)
	ts := func(s string) time.Time {
		tm, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return tm
	}
	// The real run: rollback 19:12:45, poweroff_requested 19:15:55 on 2026-10-19.
	for _, tc := range []struct {
		name string
		docs []map[string]any
		now  time.Time
		want vmStatus
	}{
		{"powered off", markerDocs(v), ts("2026-10-19T20:00:00Z"), vmStatus{
			State:         "off",
			LastRun:       vmRun{ID: v.RunID, StartedAt: "2026-10-19T19:12:45.000Z", FinishedAt: "2026-10-19T19:15:55.000Z"},
			LastRestore:   "2026-10-19T19:12:45.000Z",
			SnapshotClean: true,
			NextRun:       "2026-10-20T03:00:00.000Z",
			CheckedAt:     "2026-10-19T20:00:00.000Z",
		}},
		{"running: no poweroff, newest marker fresh", markerDocs(v, "poweroff_requested", "drained"), ts("2026-10-19T19:14:00Z"), vmStatus{
			State:         "running",
			LastRun:       vmRun{ID: v.RunID, StartedAt: "2026-10-19T19:12:45.000Z"},
			LastRestore:   "2026-10-19T19:12:45.000Z",
			SnapshotClean: true,
			NextRun:       "2026-10-20T03:00:00.000Z",
			CheckedAt:     "2026-10-19T19:14:00.000Z",
		}},
		{"no poweroff but silent for 30 min: off", markerDocs(v, "poweroff_requested"), ts("2026-10-19T19:45:55Z"), vmStatus{
			State:         "off",
			LastRun:       vmRun{ID: v.RunID, StartedAt: "2026-10-19T19:12:45.000Z"},
			LastRestore:   "2026-10-19T19:12:45.000Z",
			SnapshotClean: true,
			NextRun:       "2026-10-20T03:00:00.000Z",
			CheckedAt:     "2026-10-19T19:45:55.000Z",
		}},
		{"no rollback: not clean, no restore", markerDocs(v, "rollback"), ts("2026-10-19T20:00:00Z"), vmStatus{
			State:         "off",
			LastRun:       vmRun{ID: v.RunID, StartedAt: "2026-10-19T19:12:46.000Z", FinishedAt: "2026-10-19T19:15:55.000Z"},
			SnapshotClean: false,
			NextRun:       "2026-10-20T03:00:00.000Z",
			CheckedAt:     "2026-10-19T20:00:00.000Z",
		}},
		{"a newer run started: it is the last run", append(markerDocs(v),
			markerDoc("lab-20261020T030001Z-aaaaaa", "rollback", "2026-10-20T03:00:00.000Z"),
			markerDoc("lab-20261020T030001Z-aaaaaa", "start", "2026-10-20T03:00:01.000Z"),
		), ts("2026-10-20T03:01:00Z"), vmStatus{
			State:         "running",
			LastRun:       vmRun{ID: "lab-20261020T030001Z-aaaaaa", StartedAt: "2026-10-20T03:00:00.000Z"},
			LastRestore:   "2026-10-20T03:00:00.000Z",
			SnapshotClean: true,
			NextRun:       "2026-10-21T03:00:00.000Z",
			CheckedAt:     "2026-10-20T03:01:00.000Z",
		}},
		{"newer run without rollback: the older restore stays", append(markerDocs(v),
			markerDoc("lab-20261020T030001Z-bbbbbb", "start", "2026-10-20T03:00:01.000Z"),
		), ts("2026-10-20T03:01:00Z"), vmStatus{
			State:         "running",
			LastRun:       vmRun{ID: "lab-20261020T030001Z-bbbbbb", StartedAt: "2026-10-20T03:00:01.000Z"},
			LastRestore:   "2026-10-19T19:12:45.000Z",
			SnapshotClean: false,
			NextRun:       "2026-10-21T03:00:00.000Z",
			CheckedAt:     "2026-10-20T03:01:00.000Z",
		}},
	} {
		now := tc.now
		f := &fakeSource{docs: tc.docs}
		body, ok := New(Config{Source: f, Now: func() time.Time { return now }}).VM(context.Background())
		if !ok {
			t.Fatalf("%s: ok = false", tc.name)
		}
		var got vmStatus
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("%s:\ngot  %+v\nwant %+v", tc.name, got, tc.want)
		}
	}
}

func TestVMQuery(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	f := &fakeSource{docs: markerDocs(loadVMRun(t))}
	if _, ok := New(Config{Source: f, Now: func() time.Time { return now }}).VM(context.Background()); !ok {
		t.Fatal("ok = false")
	}
	q := f.gotQuery
	if len(f.gotIndices) != 1 || f.gotIndices[0] != siem.LabStream {
		t.Fatalf("indices = %v", f.gotIndices)
	}
	if q.TimeField != "@timestamp" || q.SortField != "@timestamp" || q.Size != 200 ||
		!q.Since.Equal(now.Add(-72*time.Hour)) ||
		!reflect.DeepEqual(q.Filters, []map[string]any{term("event.action", "lifecycle"), term("lab.mode", "isolated-vm")}) ||
		!reflect.DeepEqual(q.Source, []string{"@timestamp", "lab.run_id", "lab.marker"}) {
		t.Fatalf("query = %+v", q)
	}
}

func TestVMUnavailable(t *testing.T) {
	for name, f := range map[string]*fakeSource{
		"no markers":  {docs: []map[string]any{}},
		"query error": {err: context.DeadlineExceeded},
		// A marker without a run id or a parseable time is not evidence of anything.
		"unusable markers": {docs: []map[string]any{
			markerDoc("", "rollback", "2026-10-19T19:12:45.000Z"),
			markerDoc("lab-x", "start", "yesterday"),
		}},
	} {
		if body, ok := New(Config{Source: f}).VM(context.Background()); ok || body != nil {
			t.Errorf("%s: ok=%v body=%s, want unavailable", name, ok, body)
		}
	}
	if _, ok := New(Config{}).VM(context.Background()); ok {
		t.Error("nil source: ok = true")
	}
}

func TestNextRun(t *testing.T) {
	day := func(h, m, s int) time.Time { return time.Date(2026, 10, 20, h, m, s, 0, time.UTC) }
	tomorrow3 := time.Date(2026, 10, 21, 3, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		now   time.Time
		start time.Duration
		want  time.Time
	}{
		{"just before", day(2, 59, 59), 3 * time.Hour, day(3, 0, 0)},
		{"exactly at the start: the next day's", day(3, 0, 0), 3 * time.Hour, tomorrow3},
		{"just after", day(3, 0, 1), 3 * time.Hour, tomorrow3},
		{"late evening", day(23, 59, 59), 3 * time.Hour, tomorrow3},
		{"midnight", day(0, 0, 0), 3 * time.Hour, day(3, 0, 0)},
		{"another zone, same instant", day(2, 30, 0).In(time.FixedZone("UTC+5", 5*3600)), 3 * time.Hour, day(3, 0, 0)},
		{"configured 01:30", day(2, 0, 0), 90 * time.Minute, time.Date(2026, 10, 21, 1, 30, 0, 0, time.UTC)},
		{"configured midnight", day(0, 0, 0), 24 * time.Hour, time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)},
		{"month end", time.Date(2026, 10, 31, 4, 0, 0, 0, time.UTC), 3 * time.Hour, time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC)},
	} {
		if got := nextRun(tc.now, tc.start); !got.Equal(tc.want) {
			t.Errorf("%s: nextRun(%s) = %s, want %s", tc.name, tc.now, got, tc.want)
		}
	}
	// The default comes from Config: zero takes 03:00.
	if r := New(Config{}); r.dailyStart != 3*time.Hour || r.runningFor != 30*time.Minute {
		t.Errorf("defaults: dailyStart %s, runningFor %s", r.dailyStart, r.runningFor)
	}
}

func TestVMAndRawCache(t *testing.T) {
	v := loadVMRun(t)
	for _, tc := range []struct {
		name     string
		get      func(*Reader) ([]byte, bool)
		perFetch int // queries per fetch: raw finds the run, then reads its records
	}{
		{"vm", func(r *Reader) ([]byte, bool) { return r.VM(context.Background()) }, 1},
		{"raw", func(r *Reader) ([]byte, bool) { return r.Raw(context.Background()) }, 2},
	} {
		now := time.Date(2026, 10, 19, 20, 0, 0, 0, time.UTC)
		f := &fakeSource{docs: v.Docs}
		r := New(Config{Source: f, Now: func() time.Time { return now }, TTL: 10 * time.Second})
		for i := 0; i < 3; i++ {
			if _, ok := tc.get(r); !ok {
				t.Fatalf("%s: ok = false", tc.name)
			}
		}
		if f.calls != tc.perFetch {
			t.Errorf("%s: calls = %d within the TTL, want %d", tc.name, f.calls, tc.perFetch)
		}
		now = now.Add(11 * time.Second)
		if _, ok := tc.get(r); !ok {
			t.Fatalf("%s: ok = false after the TTL", tc.name)
		}
		if f.calls != 2*tc.perFetch {
			t.Errorf("%s: calls = %d after the TTL, want %d", tc.name, f.calls, 2*tc.perFetch)
		}
	}
}
