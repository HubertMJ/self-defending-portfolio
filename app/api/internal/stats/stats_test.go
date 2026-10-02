package stats

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/events"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/scenarios"
)

const catalogue = `
- id: shell-in-container
  title: Shell
  response: terminate
  pod: {containers: [{name: v, image: ghcr.io/hubertmj/self-defending-portfolio/scenario@sha256:` + zeros + `}]}
- id: terminal
  title: Terminal
  interactive: true
  objectives: [{id: recon, title: Look}, {id: creds, title: Creds}]
  commands:
    - {id: whoami, input: "id", objective: recon, command: [id], outcome: allowed, layer: runtime}
    - {id: read-shadow, input: "cat /etc/shadow", objective: creds, command: [cat, /etc/shadow], outcome: detected, layer: runtime, detection: X, response: terminate}
  pod: {containers: [{name: target, image: ghcr.io/hubertmj/self-defending-portfolio/scenario@sha256:` + zeros + `}]}
`

const zeros = "0000000000000000000000000000000000000000000000000000000000000000"

func newStore(t *testing.T) *scenarios.Store {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s.yaml")
	if err := os.WriteFile(p, []byte(catalogue), 0o600); err != nil {
		t.Fatal(err)
	}
	return scenarios.NewStore(p, nil)
}

func ev(typ string, v any) events.Event {
	b, _ := json.Marshal(v)
	return events.Event{Type: typ, Data: b}
}

func TestCollectorScriptedRun(t *testing.T) {
	c := New(newStore(t), func() time.Time { return time.Unix(0, 0) })
	base := time.Unix(1000, 0).UTC()
	c.Record(ev("run", map[string]any{"run_id": "r1", "scenario": "shell-in-container", "state": "queued", "at": base}))
	c.Record(ev("run", map[string]any{"run_id": "r1", "scenario": "shell-in-container", "state": "detected", "at": base.Add(time.Second)}))
	c.Record(ev("run", map[string]any{"run_id": "r1", "scenario": "shell-in-container", "state": "responded", "at": base.Add(1500 * time.Millisecond)}))
	c.Record(ev("run", map[string]any{"run_id": "r1", "scenario": "shell-in-container", "state": "finished", "at": base.Add(2 * time.Second)}))

	s := c.Snapshot()
	if s.Runs != 1 || s.ByScenario["shell-in-container"].Detected != 1 || s.ByScenario["shell-in-container"].Responded != 1 {
		t.Fatalf("by scenario: %+v", s)
	}
	if s.ResponseMS.Last != 500 || s.ResponseMS.Min != 500 || s.ResponseMS.Max != 500 || s.ResponseMS.P50 != 500 {
		t.Fatalf("response_ms: %+v", s.ResponseMS)
	}
	if s.Unanswered != 0 {
		t.Fatalf("unanswered: %d", s.Unanswered)
	}
}

func TestCollectorUnanswered(t *testing.T) {
	c := New(newStore(t), nil)
	c.Record(ev("run", map[string]any{"run_id": "r2", "scenario": "shell-in-container", "state": "queued", "at": time.Now()}))
	c.Record(ev("run", map[string]any{"run_id": "r2", "scenario": "shell-in-container", "state": "detected", "at": time.Now()}))
	c.Record(ev("run", map[string]any{"run_id": "r2", "scenario": "shell-in-container", "state": "timeout", "at": time.Now()}))
	if s := c.Snapshot(); s.Unanswered != 1 {
		t.Fatalf("unanswered = %d", s.Unanswered)
	}
}

func TestCollectorTerminal(t *testing.T) {
	c := New(newStore(t), nil)
	start := time.Unix(2000, 0).UTC()
	c.Record(ev("run", map[string]any{"run_id": "t1", "scenario": "terminal", "state": "queued", "at": start}))
	// whoami: allowed, achieved recon
	c.Record(ev("command", map[string]any{"run_id": "t1", "id": "whoami", "state": "started"}))
	c.Record(ev("command", map[string]any{"run_id": "t1", "id": "whoami", "state": "exited", "achieved": true}))
	// read-shadow: detected, achieved creds
	c.Record(ev("command", map[string]any{"run_id": "t1", "id": "read-shadow", "state": "started"}))
	c.Record(ev("command", map[string]any{"run_id": "t1", "id": "read-shadow", "state": "exited", "achieved": true}))
	c.Record(ev("run", map[string]any{"run_id": "t1", "scenario": "terminal", "state": "finished", "at": start.Add(42 * time.Second)}))

	s := c.Snapshot()
	if s.Terminal.Runs != 1 || s.Terminal.BestObjectives != 2 || s.Terminal.MedianSurvivalS != 42 {
		t.Fatalf("terminal: %+v", s.Terminal)
	}
	if s.Commands["whoami"].Attempts != 1 || s.Commands["whoami"].Allowed != 1 {
		t.Fatalf("whoami: %+v", s.Commands["whoami"])
	}
	if s.Commands["read-shadow"].Detected != 1 {
		t.Fatalf("read-shadow: %+v", s.Commands["read-shadow"])
	}
	if s.Objectives["recon"].Attempts != 1 || s.Objectives["recon"].Achieved != 1 || s.Objectives["creds"].Achieved != 1 {
		t.Fatalf("objectives: %+v", s.Objectives)
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	c := New(newStore(t), nil)
	c.Record(ev("run", map[string]any{"run_id": "r", "scenario": "shell-in-container", "state": "queued", "at": time.Now()}))
	blob, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	c2 := New(newStore(t), nil)
	if err := c2.Load(blob); err != nil {
		t.Fatal(err)
	}
	if c2.Snapshot().Runs != 1 {
		t.Fatalf("round trip lost runs: %+v", c2.Snapshot())
	}
	if !c.TakeDirty() {
		t.Fatal("expected dirty after recording")
	}
	if c.TakeDirty() {
		t.Fatal("dirty not cleared")
	}
}
