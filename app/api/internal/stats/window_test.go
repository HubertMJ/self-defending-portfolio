package stats

import (
	"context"
	"encoding/json"
	"math/rand/v2"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// clock is a settable time source for the window tests.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) set(t time.Time) { c.mu.Lock(); c.t = t; c.mu.Unlock() }

// t0 is mid-hour, so an hour boundary is never the edge being tested by accident.
var t0 = time.Date(2026, 10, 3, 10, 30, 0, 0, time.UTC)

func hourOf(t time.Time) int64 { return t.Unix() / 3600 }

func persisted(t *testing.T, c *Collector) agg {
	t.Helper()
	b, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var a agg
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	return a
}

// The window is the current hour and the 23 before it: an alert 23 hours ago (by the hour) still
// counts, one 24 hours ago does not, and a write prunes the buckets that left.
func TestWindowEdges(t *testing.T) {
	clk := &clock{t: t0}
	c := New(newStore(t), clk.now)
	alerts, actions := c.AlertCounter(), c.ActionCounter()
	alerts.Add()
	actions.Add()

	clk.set(t0.Add(23 * time.Hour))
	if alerts.Count() != 1 || actions.Count() != 1 {
		t.Fatalf("at H+23: alerts %d actions %d, want 1 and 1", alerts.Count(), actions.Count())
	}
	w := c.Snapshot().Last24h
	if w.FalcoAlerts != 1 || w.TalonActions != 1 || !w.Since.Equal(t0) {
		t.Fatalf("at H+23: %+v, want 1/1 since the collector started (%s)", w, t0)
	}

	clk.set(t0.Add(24 * time.Hour))
	if alerts.Count() != 0 || actions.Count() != 0 {
		t.Fatalf("at H+24: alerts %d actions %d, want 0", alerts.Count(), actions.Count())
	}
	w = c.Snapshot().Last24h
	if wantSince := time.Date(2026, 10, 3, 11, 0, 0, 0, time.UTC); w.FalcoAlerts != 0 || !w.Since.Equal(wantSince) {
		t.Fatalf("at H+24: %+v, want 0 since %s (the start of the oldest hour)", w, wantSince)
	}
	if !c.Since24h().Equal(w.Since) {
		t.Fatalf("Since24h %s != last_24h.since %s", c.Since24h(), w.Since)
	}

	alerts.Add() // a write: the bucket of 24 h ago is pruned
	a := persisted(t, c)
	if len(a.Hourly) != 1 || a.Hourly[0].H != hourOf(t0)+24 || a.Hourly[0].Alerts != 1 {
		t.Fatalf("hourly after a write a day later = %+v, want only the current hour", a.Hourly)
	}
}

// The live production blob of ecbca9b (before the window existed) loads with every all-time field as
// it was, an empty window starting now and no last run time.
func TestProductionBlobLoads(t *testing.T) {
	blob, err := os.ReadFile("testdata/stats-ecbca9b.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 3, 19, 5, 0, 0, time.UTC)
	c := New(newStore(t), func() time.Time { return now })
	if err := c.Load(blob); err != nil {
		t.Fatalf("the production blob was rejected: %v", err)
	}
	var want agg
	if err := json.Unmarshal(blob, &want); err != nil {
		t.Fatal(err)
	}
	got := persisted(t, c)
	if len(got.Hourly) != 0 || !got.WindowSince.Equal(now) || !got.LastRunAt.IsZero() {
		t.Fatalf("window = %+v since %s last run %s, want empty since %s", got.Hourly, got.WindowSince, got.LastRunAt, now)
	}
	got.Hourly, got.WindowSince, got.LastRunAt = nil, time.Time{}, time.Time{}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("all-time fields changed:\n got %+v\nwant %+v", got, want)
	}
	s := c.Snapshot()
	if s.Runs != 19 || !s.Since.Equal(time.Date(2026, 10, 3, 6, 44, 28, 269361673, time.UTC)) ||
		s.ByScenario["terminal"] != (ScenarioStat{Runs: 11, Detected: 7, Responded: 7}) || s.ResponseMS.Min != 21 {
		t.Fatalf("snapshot = %+v", s)
	}
	if s.LastRunAt != nil || s.Last24h != (Window{Since: now}) {
		t.Fatalf("last_run_at %v last_24h %+v, want null and an empty window since %s", s.LastRunAt, s.Last24h, now)
	}
}

func windowBlob(t *testing.T, fields map[string]any) []byte {
	t.Helper()
	m := map[string]any{"Since": t0.Add(-48 * time.Hour), "Runs": 7,
		"ByScenario": map[string]any{"shell-in-container": map[string]int{"runs": 7, "detected": 5, "responded": 4}}}
	for k, v := range fields {
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A damaged window is cleaned up, not a reason to drop the all-time totals beside it; only counts no
// writer produces reject the blob.
func TestWindowSanitising(t *testing.T) {
	nowH := hourOf(t0)
	c := New(newStore(t), func() time.Time { return t0 })
	err := c.Load(windowBlob(t, map[string]any{
		"Hourly": []map[string]any{
			{"H": nowH + 5, "Runs": 3},                // the future: dropped
			{"H": nowH - 30, "Runs": 2},               // stale: dropped
			{"H": nowH - 1, "Runs": 1, "Detected": 1}, // kept, and summed with the next
			{"H": nowH - 1, "Runs": 2, "Alerts": 4},
			{"H": nowH + 1, "Actions": 1}, // the next hour: clock slack, kept
		},
		"WindowSince": t0.Add(48 * time.Hour),
		"LastRunAt":   t0.Add(48 * time.Hour),
	}))
	if err != nil {
		t.Fatalf("a sanitisable blob was rejected: %v", err)
	}
	if s := c.Snapshot(); s.Runs != 7 || s.ByScenario["shell-in-container"].Responded != 4 {
		t.Fatalf("totals not loaded: %+v", s)
	}
	a := persisted(t, c)
	want := []HourBucket{{H: nowH - 1, Runs: 3, Detected: 1, Alerts: 4}, {H: nowH + 1, Actions: 1}}
	if !reflect.DeepEqual(a.Hourly, want) {
		t.Fatalf("hourly = %+v, want %+v", a.Hourly, want)
	}
	if !a.WindowSince.Equal(t0) || !a.LastRunAt.Equal(t0) {
		t.Fatalf("window_since %s last_run_at %s, want both clamped to %s", a.WindowSince, a.LastRunAt, t0)
	}

	// validateAgg clamps on its own, whatever the merge with the running collector does afterwards.
	direct := agg{WindowSince: t0.Add(time.Hour), LastRunAt: t0.Add(time.Hour)}
	if err := validateAgg(&direct, t0); err != nil || !direct.WindowSince.Equal(t0) || !direct.LastRunAt.Equal(t0) {
		t.Fatalf("validateAgg: %v window_since %s last_run_at %s, want both %s", err, direct.WindowSince, direct.LastRunAt, t0)
	}

	inRange := func(n int) []map[string]any {
		bs := make([]map[string]any, n)
		for i := range bs {
			bs[i] = map[string]any{"H": nowH - int64(i%24), "Runs": 1}
		}
		return bs
	}
	// The cap counts buckets after same-hour ones are summed: 26 entries over 24 hours load, summed.
	c26 := New(newStore(t), func() time.Time { return t0 })
	if err := c26.Load(windowBlob(t, map[string]any{"Hourly": inRange(maxHourly + 1)})); err != nil {
		t.Fatalf("%d entries in range rejected: %v", maxHourly+1, err)
	}
	if w := c26.Snapshot().Last24h; w.Runs != maxHourly+1 || len(persisted(t, c26).Hourly) != windowHours {
		t.Fatalf("26 entries: last_24h %+v, want %d runs in %d buckets", w, maxHourly+1, windowHours)
	}
	// A window no writer produces is discarded whole and restarts now; the all-time totals load.
	for name, hourly := range map[string]any{
		"negative":                     []map[string]any{{"H": nowH - 1, "Runs": 1}, {"H": nowH, "Runs": -1}},
		"past 2^40":                    []map[string]any{{"H": nowH - 1, "Runs": 1}, {"H": nowH, "Alerts": int64(maxCounter) + 1}},
		"negative, stale":              []map[string]any{{"H": nowH - 1, "Runs": 1}, {"H": nowH - 100, "Detected": -5}},
		"duplicates summing past 2^40": []map[string]any{{"H": nowH, "Alerts": int64(maxCounter)}, {"H": nowH, "Alerts": int64(maxCounter)}},
	} {
		later := t0.Add(10 * time.Minute)
		c := New(newStore(t), func() time.Time { return later })
		if err := c.Load(windowBlob(t, map[string]any{"Hourly": hourly, "WindowSince": t0.Add(-5 * time.Hour)})); err != nil {
			t.Errorf("%s: the blob was rejected (%v), want only its window discarded", name, err)
			continue
		}
		s := c.Snapshot()
		if s.Runs != 7 || s.ByScenario["shell-in-container"].Detected != 5 {
			t.Errorf("%s: the all-time totals were lost: %+v", name, s)
		}
		if s.Last24h != (Window{Since: later}) || len(persisted(t, c).Hourly) != 0 {
			t.Errorf("%s: last_24h %+v, want an empty window since %s", name, s.Last24h, later)
		}
	}
	// A malformed all-time section still rejects the blob, window or not.
	c = New(newStore(t), func() time.Time { return t0 })
	if err := c.Load(windowBlob(t, map[string]any{"Runs": -1, "Hourly": inRange(3)})); err == nil || c.Snapshot().Runs != 0 {
		t.Errorf("a negative all-time counter loaded (err %v): %+v", err, c.Snapshot())
	}
}

// The window survives a restart through the ConfigMap: buckets, window start and last run time.
func TestWindowConfigMapRoundTrip(t *testing.T) {
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "portfolio-stats", Namespace: "portfolio-api"}}
	kube := fake.NewClientset(cm)
	store := NewStore(kube, "portfolio-api", "portfolio-stats", nil)
	clk := &clock{t: t0}
	c := New(newStore(t), clk.now)
	store.Load(context.Background(), c)
	c.Record(ev("run", map[string]any{"run_id": "r1", "scenario": "shell-in-container", "state": "queued", "at": t0}))
	c.Record(ev("run", map[string]any{"run_id": "r1", "scenario": "shell-in-container", "state": "detected", "at": t0}))
	c.AlertCounter().Add()
	clk.set(t0.Add(2 * time.Hour))
	c.ActionCounter().Add()
	if err := store.Save(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	before := persisted(t, c)

	clk.set(t0.Add(3 * time.Hour)) // the restart
	c2 := New(newStore(t), clk.now)
	store.Load(context.Background(), c2)
	after := persisted(t, c2)
	if !reflect.DeepEqual(after.Hourly, before.Hourly) || len(after.Hourly) != 2 {
		t.Fatalf("hourly %+v, want %+v", after.Hourly, before.Hourly)
	}
	if !after.WindowSince.Equal(t0) || !after.LastRunAt.Equal(t0) {
		t.Fatalf("window_since %s last_run_at %s, want %s for both", after.WindowSince, after.LastRunAt, t0)
	}
	s := c2.Snapshot()
	if s.Last24h != (Window{Since: t0, Runs: 1, Detected: 1, FalcoAlerts: 1, TalonActions: 1}) || s.LastRunAt == nil || !s.LastRunAt.Equal(t0) {
		t.Fatalf("after restart: last_24h %+v last_run_at %v", s.Last24h, s.LastRunAt)
	}
}

// A read that only succeeds later adds the persisted hours to what was counted meanwhile.
func TestLateReadSumsHours(t *testing.T) {
	nowH := hourOf(t0)
	c := New(newStore(t), func() time.Time { return t0 })
	c.AlertCounter().Add()
	c.AlertCounter().Add()
	c.Record(ev("run", map[string]any{"run_id": "r1", "scenario": "shell-in-container", "state": "queued", "at": t0}))
	err := c.Load(windowBlob(t, map[string]any{
		"Hourly":      []map[string]any{{"H": nowH, "Runs": 4, "Alerts": 3}, {"H": nowH - 2, "Actions": 1}},
		"WindowSince": t0.Add(-5 * time.Hour),
		"LastRunAt":   t0.Add(-time.Hour),
	}))
	if err != nil {
		t.Fatal(err)
	}
	a := persisted(t, c)
	want := []HourBucket{{H: nowH - 2, Actions: 1}, {H: nowH, Runs: 5, Alerts: 5}}
	if !reflect.DeepEqual(a.Hourly, want) {
		t.Fatalf("hourly = %+v, want %+v", a.Hourly, want)
	}
	if !a.WindowSince.Equal(t0.Add(-5*time.Hour)) || !a.LastRunAt.Equal(t0) {
		t.Fatalf("window_since %s (want the earliest) last_run_at %s (want the latest)", a.WindowSince, a.LastRunAt)
	}
}

// A run's detection and response are counted in the hour the run was queued, so one window never
// holds a detection without its run.
func TestBucketedByQueuedHour(t *testing.T) {
	queued := time.Date(2026, 10, 3, 10, 59, 59, 0, time.UTC)
	c := New(newStore(t), func() time.Time { return queued.Add(30 * time.Minute) })
	c.Record(ev("run", map[string]any{"run_id": "r1", "scenario": "shell-in-container", "state": "queued", "at": queued}))
	c.Record(ev("run", map[string]any{"run_id": "r1", "scenario": "shell-in-container", "state": "detected", "at": queued.Add(2 * time.Second)}))
	c.Record(ev("run", map[string]any{"run_id": "r1", "scenario": "shell-in-container", "state": "responded", "at": queued.Add(3 * time.Second)}))
	a := persisted(t, c)
	want := []HourBucket{{H: hourOf(queued), Runs: 1, Detected: 1, Responded: 1}}
	if !reflect.DeepEqual(a.Hourly, want) {
		t.Fatalf("hourly = %+v, want everything in the 10:00 bucket %+v", a.Hourly, want)
	}
	if s := c.Snapshot(); s.LastRunAt == nil || !s.LastRunAt.Equal(queued) {
		t.Fatalf("last_run_at = %v, want %s", s.LastRunAt, queued)
	}
}

// A run event stamped ahead of this clock counts in the current hour and as a run now, not later.
func TestFutureRunClamped(t *testing.T) {
	c := New(newStore(t), func() time.Time { return t0 })
	c.Record(ev("run", map[string]any{"run_id": "r1", "scenario": "shell-in-container", "state": "queued", "at": t0.Add(3 * time.Hour)}))
	c.Record(ev("run", map[string]any{"run_id": "r1", "scenario": "shell-in-container", "state": "detected", "at": t0.Add(3 * time.Hour)}))
	s := c.Snapshot()
	if s.LastRunAt == nil || !s.LastRunAt.Equal(t0) {
		t.Fatalf("last_run_at = %v, want clamped to %s", s.LastRunAt, t0)
	}
	if s.Last24h.Runs != 1 || s.Last24h.Detected != 1 {
		t.Fatalf("last_24h = %+v, want the run in the current hour", s.Last24h)
	}
	if a := persisted(t, c); len(a.Hourly) != 1 || a.Hourly[0].H != hourOf(t0) {
		t.Fatalf("hourly = %+v, want only the current hour", a.Hourly)
	}
}

// The next hour's bucket (a writer whose clock ran ahead) is kept but not counted until that hour.
func TestNextHourNotCounted(t *testing.T) {
	c := New(newStore(t), func() time.Time { return t0 })
	if err := c.Load(windowBlob(t, map[string]any{"Hourly": []map[string]any{{"H": hourOf(t0) + 1, "Actions": 2, "Alerts": 3}}})); err != nil {
		t.Fatal(err)
	}
	if w := c.Snapshot().Last24h; w.TalonActions != 0 || w.FalcoAlerts != 0 || c.ActionCounter().Count() != 0 {
		t.Fatalf("last_24h %+v counts the next hour", w)
	}
	if a := persisted(t, c); len(a.Hourly) != 1 {
		t.Fatalf("hourly = %+v, want the next hour kept", a.Hourly)
	}
}

// A run whose queued hour left the window before its detection arrived adds no stale bucket.
func TestDetectionAfterRolloverNoStaleBucket(t *testing.T) {
	queued := time.Date(2026, 10, 3, 10, 59, 30, 0, time.UTC)
	clk := &clock{t: queued}
	c := New(newStore(t), clk.now)
	c.Record(ev("run", map[string]any{"run_id": "r1", "scenario": "shell-in-container", "state": "queued", "at": queued}))
	clk.set(queued.Add(23*time.Hour + time.Minute)) // 10:00 has left the window (oldest hour 11:00)
	c.Record(ev("run", map[string]any{"run_id": "r1", "scenario": "shell-in-container", "state": "detected", "at": clk.now()}))
	c.Record(ev("run", map[string]any{"run_id": "r1", "scenario": "shell-in-container", "state": "responded", "at": clk.now()}))
	if a := persisted(t, c); len(a.Hourly) != 0 {
		t.Fatalf("hourly = %+v, want no bucket for the hour that left", a.Hourly)
	}
	if s := c.Snapshot(); s.ByScenario["shell-in-container"].Detected != 1 {
		t.Fatalf("the all-time detection was lost: %+v", s.ByScenario)
	}
}

// A run never seen queued adds no detection to any window.
func TestNeverQueuedNotInWindow(t *testing.T) {
	c := New(newStore(t), func() time.Time { return t0 })
	c.Record(ev("run", map[string]any{"run_id": "r2", "scenario": "shell-in-container", "state": "detected", "at": t0}))
	c.Record(ev("run", map[string]any{"run_id": "r2", "scenario": "shell-in-container", "state": "responded", "at": t0}))
	if w := c.Snapshot().Last24h; w.Detected != 0 || w.Responded != 0 {
		t.Fatalf("never-queued run in the window: %+v", w)
	}
}

// Terminal Talon-first: `responded` comes before any `detected`. The window counts the response
// with the detection, never before it.
func TestRespondedBeforeDetected(t *testing.T) {
	c := New(newStore(t), func() time.Time { return t0 })
	c.Record(ev("run", map[string]any{"run_id": "r1", "scenario": "terminal", "state": "queued", "at": t0}))
	c.Record(ev("run", map[string]any{"run_id": "r1", "scenario": "terminal", "state": "responded", "at": t0, "command_seq": 1}))
	if w := c.Snapshot().Last24h; w.Runs != 1 || w.Detected != 0 || w.Responded != 0 {
		t.Fatalf("before the detection: %+v, want the response held back", w)
	}
	c.Record(ev("run", map[string]any{"run_id": "r1", "scenario": "terminal", "state": "detected", "at": t0, "command_seq": 1}))
	if w := c.Snapshot().Last24h; w.Detected != 1 || w.Responded != 1 {
		t.Fatalf("after the detection: %+v, want 1 and 1", w)
	}
	if s := c.Snapshot().ByScenario["terminal"]; s.Responded != 1 || s.Detected != 1 {
		t.Fatalf("all-time: %+v", s)
	}
}

// The last run time only moves forward: an older queued time arriving later does not replace it.
func TestLastRunAtMonotonic(t *testing.T) {
	c := New(newStore(t), func() time.Time { return t0 })
	c.Record(ev("run", map[string]any{"run_id": "r1", "scenario": "shell-in-container", "state": "queued", "at": t0}))
	c.Record(ev("run", map[string]any{"run_id": "r2", "scenario": "shell-in-container", "state": "queued", "at": t0.Add(-time.Hour)}))
	if s := c.Snapshot(); s.LastRunAt == nil || !s.LastRunAt.Equal(t0) {
		t.Fatalf("last_run_at = %v, want %s", s.LastRunAt, t0)
	}
}

// A webhook delivery is a change to persist, like every other counter.
func TestWindowCounterMarksDirty(t *testing.T) {
	for name, counter := range map[string]func(*Collector) WindowCounter{
		"alerts": (*Collector).AlertCounter, "actions": (*Collector).ActionCounter,
	} {
		c := New(newStore(t), func() time.Time { return t0 })
		c.TakeDirty()
		counter(c).Add()
		if !c.TakeDirty() {
			t.Errorf("%s: Add did not mark the counters dirty", name)
		}
	}
	// And it reaches the ConfigMap with nothing else having happened.
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "portfolio-stats", Namespace: "portfolio-api"}}
	kube := fake.NewClientset(cm)
	store := NewStore(kube, "portfolio-api", "portfolio-stats", nil)
	c := New(newStore(t), func() time.Time { return t0 })
	store.Load(context.Background(), c)
	c.AlertCounter().Add()
	store.tick(context.Background(), c)
	c2 := New(newStore(t), func() time.Time { return t0 })
	store.Load(context.Background(), c2)
	if n := c2.AlertCounter().Count(); n != 1 {
		t.Fatalf("alerts after a tick and a reload = %d, want 1", n)
	}
}

// runs >= detected >= responded in every window of three days of random runs, whatever hour
// boundaries the runs straddle.
func TestWindowOrderingRandomised(t *testing.T) {
	r := rand.New(rand.NewPCG(35, 2026))
	clk := &clock{t: t0}
	c := New(newStore(t), clk.now)
	end := t0.Add(72 * time.Hour)
	for i := 0; clk.now().Before(end); i++ {
		id := string(rune('a'+i%26)) + time.Duration(i).String()
		at := clk.now()
		send := func(state string) {
			c.Record(ev("run", map[string]any{"run_id": id, "scenario": "shell-in-container", "state": state, "at": clk.now()}))
		}
		send("queued")
		if r.IntN(6) == 0 {
			// Terminal Talon-first: the response is published before the detection.
			clk.set(clk.now().Add(time.Duration(r.IntN(90)) * time.Second))
			c.ActionCounter().Add()
			send("responded")
			if w := c.Snapshot().Last24h; w.Detected < w.Responded {
				t.Fatalf("talon-first at %s: %+v", clk.now(), w)
			}
			if r.IntN(3) > 0 {
				clk.set(clk.now().Add(time.Duration(r.IntN(3)) * time.Second))
				c.AlertCounter().Add()
				send("detected")
			}
		} else if r.IntN(4) > 0 {
			clk.set(clk.now().Add(time.Duration(r.IntN(90)) * time.Second))
			if r.IntN(3) > 0 {
				c.AlertCounter().Add()
			}
			send("detected")
			if r.IntN(4) > 0 {
				clk.set(clk.now().Add(time.Duration(r.IntN(30)) * time.Second))
				c.ActionCounter().Add()
				send("responded")
			}
		}
		send("finished")
		clk.set(at.Add(time.Duration(5+r.IntN(40)) * time.Minute))
		if w := c.Snapshot().Last24h; w.Runs < w.Detected || w.Detected < w.Responded {
			t.Fatalf("at %s: %+v breaks runs >= detected >= responded", clk.now(), w)
		}
	}
}
