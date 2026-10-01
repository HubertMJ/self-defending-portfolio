package runlog

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/events"
)

func feed(h *events.Hub, typ string, v any) {
	if err := h.Publish(typ, v); err != nil {
		panic(err)
	}
}

func TestRecordsARunWithItsAlerts(t *testing.T) {
	s := New(50, 500)
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
	s := New(3, 4)
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
