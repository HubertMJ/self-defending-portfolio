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

// The byte reserve, for every final state: about a hundred Falco events of 2.5 KiB, then smaller ones
// that fill what is left of the budget to within a few bytes, still leave the run's command end and
// its final `run` event (finished, timeout or failed) in the record, last. Without the reserve, or
// with the final state not counted as one, nothing is left for them.
func TestTerminalStateByteReserve(t *testing.T) {
	for _, final := range []string{"finished", "timeout", "failed"} {
		s := New(0, 0, 0, 0)
		rec := func(id uint64, typ, data string) { s.Record(events.Event{ID: id, Type: typ, Data: []byte(data)}) }
		rec(1, "run", `{"run_id":"r","pod":"p","state":"started"}`)
		// Falco events of exactly `size` bytes: 110 of 2.5 KiB, more than the budget, then halving
		// sizes down to the smallest event, so whatever budget other events may use is filled to
		// within 24 bytes - less than any `run` or `command` event.
		alert := func(size int) string {
			const frame = `{"pod":"p","output":""}`
			return `{"pod":"p","output":"` + strings.Repeat("a", size-len(frame)) + `"}`
		}
		id := uint64(2)
		sizes := []int{1280, 640, 320, 160, 80, 40, 24}
		for range 110 {
			sizes = append([]int{2560}, sizes...)
		}
		for _, size := range sizes {
			rec(id, "falco", alert(size))
			id++
		}
		rec(id, "command", `{"run_id":"r","seq":1,"state":"exited","exit_code":0}`)
		rec(id+1, "run", `{"run_id":"r","state":"`+final+`","detail":"x"}`)
		run, _ := s.Get("r")
		if !run.Truncated || run.bytes > DefaultRunBytes || len(run.Events) > DefaultRunEvents {
			t.Fatalf("%s: truncated=%v bytes=%d events=%d", final, run.Truncated, run.bytes, len(run.Events))
		}
		n := len(run.Events)
		if !strings.Contains(string(run.Events[n-1].Data), `"state":"`+final+`"`) ||
			!strings.Contains(string(run.Events[n-2].Data), `"state":"exited"`) {
			t.Fatalf("%s: the record ends with %s / %s, not the command's end and the run's final state",
				final, run.Events[n-2].Type, run.Events[n-1].Type)
		}
	}
}

// The list is newest first, capped like the store, consistent with it after evictions, and built
// from the runs' own `run` events only.
func TestList(t *testing.T) {
	s := New(3, 0, 0, 0)
	h := events.NewHub(10)
	h.Tap(s.Record)
	at := func(sec int) string { return fmt.Sprintf("2026-10-03T18:00:%02dZ", sec) }
	for i := range 5 {
		id := fmt.Sprintf("r%d", i)
		feed(h, "run", map[string]string{"run_id": id, "scenario": "network-tool", "state": "queued", "at": at(i * 10)})
		feed(h, "run", map[string]string{"run_id": id, "scenario": "network-tool", "state": "started", "pod": "p" + id, "at": at(i*10 + 1)})
	}
	feed(h, "falco", map[string]string{"pod": "pr4", "rule": "x", "state": "detected"})
	feed(h, "command", map[string]string{"run_id": "r4", "id": "whoami", "state": "exited"})
	feed(h, "run", map[string]string{"run_id": "r4", "state": "detected", "at": at(43)})
	feed(h, "run", map[string]string{"run_id": "r4", "state": "responded", "at": at(44)})
	feed(h, "run", map[string]string{"run_id": "r4", "state": "finished", "at": at(45)})
	feed(h, "command", map[string]string{"run_id": "r4", "id": "whoami", "state": "started"})
	feed(h, "falco", map[string]string{"pod": "pr3", "rule": "y"})

	list := s.List()
	var ids []string
	for _, r := range list {
		ids = append(ids, r.RunID)
		if _, ok := s.Get(r.RunID); !ok {
			t.Errorf("listed run %s is not in the store", r.RunID)
		}
	}
	if strings.Join(ids, ",") != "r4,r3,r2" || s.Kept() != 3 {
		t.Fatalf("list = %v kept %d, want r4,r3,r2 of 3", ids, s.Kept())
	}
	r4, r3 := list[0], list[1]
	if r4.State != "finished" || !r4.Detected || !r4.Responded || r4.EndedAt == nil || r4.EndedAt.Format("15:04:05") != "18:00:45" ||
		r4.StartedAt.Format("15:04:05") != "18:00:40" || r4.Events != 8 || r4.Scenario != "network-tool" || r4.Truncated {
		t.Fatalf("r4 = %+v", r4)
	}
	if r3.State != "started" || r3.Detected || r3.EndedAt != nil || r3.Events != 3 {
		t.Fatalf("r3 = %+v (a falco event must not make it detected)", r3)
	}
	b, _ := json.Marshal(r3)
	if !strings.Contains(string(b), `"ended_at":null`) || strings.Contains(string(b), "pr3") {
		t.Fatalf("%s", b)
	}
	if b, _ := json.Marshal(New(0, 0, 0, 0).List()); string(b) != "[]" {
		t.Fatalf("empty list = %s", b)
	}
}
