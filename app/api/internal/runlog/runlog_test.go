package runlog

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/events"
)

func feed(h *events.Hub, typ string, v any) {
	if err := h.Publish(typ, v); err != nil {
		panic(err)
	}
}

func TestRecordsARunWithItsAlerts(t *testing.T) {
	s := New(50, 500, 0, 0)
	h := events.NewHub(10)
	h.Tap(s.Record)
	feed(h, "run", map[string]string{"run_id": "r1", "scenario": "network-tool", "state": "queued"})
	feed(h, "falco", map[string]string{"pod": "network-tool-r1", "rule": "too early, pod unknown"})
	feed(h, "run", map[string]string{"run_id": "r1", "scenario": "network-tool", "state": "started", "pod": "network-tool-r1"})
	feed(h, "pod", map[string]any{"run_id": "r1", "pod": "network-tool-r1", "phase": "Running"})
	feed(h, "falco", map[string]string{"pod": "network-tool-r1", "rule": "SDP network tool in sandbox"})
	feed(h, "talon", map[string]string{"pod": "network-tool-r1", "status": "success"})
	feed(h, "falco", map[string]string{"pod": "someone-else", "rule": "x"})

	run, ok := s.Get("r1")
	if !ok || run.Scenario != "network-tool" || run.Truncated {
		t.Fatalf("%+v %v", run, ok)
	}
	var types string
	for _, e := range run.Events {
		types += e.Type + " "
	}
	if types != "run run pod falco talon " {
		t.Fatalf("types: %q", types)
	}
	if run.Events[0].ID != 1 || run.Events[3].ID != 5 {
		t.Fatalf("ids: %+v", run.Events)
	}
	b, _ := json.Marshal(run.Events[3])
	if string(b) != `{"id":5,"type":"falco","data":{"pod":"network-tool-r1","rule":"SDP network tool in sandbox"}}` {
		t.Fatalf("%s", b)
	}
	if _, ok := s.Get("nope"); ok {
		t.Fatal("unknown run found")
	}
}

func TestBounds(t *testing.T) {
	s := New(3, 4, 0, 0)
	for i := range 5 {
		s.Record(events.Event{ID: uint64(i), Type: "run",
			Data: []byte(fmt.Sprintf(`{"run_id":"r%d","pod":"p%d"}`, i, i))})
	}
	if _, ok := s.Get("r1"); ok {
		t.Fatal("oldest runs not evicted")
	}
	if _, ok := s.Get("r4"); !ok {
		t.Fatal("newest run missing")
	}
	s.Record(events.Event{ID: 9, Type: "falco", Data: []byte(`{"pod":"p1"}`)})
	if _, ok := s.Get("r1"); ok {
		t.Fatal("evicted run revived by its pod")
	}
	for i := range 10 {
		s.Record(events.Event{ID: uint64(10 + i), Type: "victim", Data: []byte(`{"run_id":"r4"}`)})
	}
	run, _ := s.Get("r4")
	if len(run.Events) != 4 || !run.Truncated {
		t.Fatalf("cap: %d events, truncated=%v", len(run.Events), run.Truncated)
	}
	s.Record(events.Event{Type: "run", Data: []byte(`not json`)})
}

func TestByteBudgets(t *testing.T) {
	ev := func(id uint64, run string, pad int) events.Event {
		return events.Event{ID: id, Type: "falco", Data: []byte(fmt.Sprintf(`{"run_id":%q,"x":%q}`, run, strings.Repeat("a", pad)))}
	}
	// Per run: 100 bytes. Each event is ~60 bytes, so the second one does not fit.
	s := New(10, 100, 100, 1000)
	s.Record(ev(1, "r1", 30))
	s.Record(ev(2, "r1", 30))
	run, _ := s.Get("r1")
	if len(run.Events) != 1 || !run.Truncated {
		t.Fatalf("per-run budget: %d events, truncated=%v", len(run.Events), run.Truncated)
	}
	// Total: 1000 bytes. Ten runs of ~90 bytes fit; more evict the oldest, never exceed the total.
	s = New(50, 100, 1000, 1000)
	for i := range 20 {
		s.Record(ev(uint64(i), fmt.Sprintf("r%02d", i), 60))
	}
	if _, ok := s.Get("r00"); ok {
		t.Fatal("oldest run kept past the total budget")
	}
	if run, ok := s.Get("r19"); !ok || run.Truncated || len(run.Events) != 1 {
		t.Fatalf("newest run: %+v %v", run, ok)
	}
	if s.total > 1000 {
		t.Fatalf("total %d over budget", s.total)
	}
	// A single run larger than the total is truncated, not allowed to grow past it.
	s = New(50, 100, 5000, 300)
	for i := range 10 {
		s.Record(ev(uint64(i), "big", 60))
	}
	if run, _ := s.Get("big"); !run.Truncated || s.total > 300 {
		t.Fatalf("lone run: truncated=%v total=%d", run.Truncated, s.total)
	}
}

// However many other events a run produces, its terminal-state events - each command's end and the
// run's final state - are kept: they have a reserve the rest cannot use. The run record therefore
// ends with the final `run` event, and the per-run caps still hold.
func TestTerminalStateEventsAreReserved(t *testing.T) {
	s := New(10, 20, 0, 0) // a reserve of 2 events
	rec := func(id uint64, typ, data string) { s.Record(events.Event{ID: id, Type: typ, Data: []byte(data)}) }
	rec(1, "run", `{"run_id":"r","pod":"p","state":"started"}`)
	for i := range 40 { // a rule firing in a loop, and output
		rec(uint64(2+i), "falco", `{"pod":"p","rule":"loop"}`)
		rec(uint64(100+i), "command", `{"run_id":"r","seq":1,"state":"output","chunk":"x"}`)
	}
	run, _ := s.Get("r")
	if len(run.Events) != 18 || !run.Truncated {
		t.Fatalf("other events: %d kept, truncated=%v; want 18 (20 minus the reserve of 2)", len(run.Events), run.Truncated)
	}
	rec(200, "command", `{"run_id":"r","seq":1,"state":"killed"}`)
	rec(201, "run", `{"run_id":"r","state":"finished","detail":"killed"}`)
	rec(202, "falco", `{"pod":"p","rule":"late"}`)
	rec(203, "run", `{"run_id":"r","state":"timeout"}`) // past the whole cap: dropped
	run, _ = s.Get("r")
	if len(run.Events) != 20 {
		t.Fatalf("%d events kept, want the cap of 20", len(run.Events))
	}
	if last := string(run.Events[19].Data); !strings.Contains(last, `"finished"`) ||
		!strings.Contains(string(run.Events[18].Data), `"killed"`) {
		t.Fatalf("the run does not end with its command's end and its final state: %s / %s", run.Events[18].Data, last)
	}
}
