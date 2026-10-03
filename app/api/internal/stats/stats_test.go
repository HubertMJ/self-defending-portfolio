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

// Unanswered counts only a detected run that ended on the timeout; a terminal run the visitor left
// (or that was killed/idle) after a detection is not an escape (item 18).
func TestUnansweredOnlyTimeout(t *testing.T) {
	for _, end := range []struct {
		state string
		want  int
	}{{"timeout", 1}, {"finished", 0}, {"failed", 0}} {
		c := New(newStore(t), nil)
		c.Record(ev("run", map[string]any{"run_id": "r", "scenario": "shell-in-container", "state": "queued"}))
		c.Record(ev("run", map[string]any{"run_id": "r", "scenario": "shell-in-container", "state": "detected"}))
		c.Record(ev("run", map[string]any{"run_id": "r", "scenario": "shell-in-container", "state": end.state, "at": time.Now()}))
		if got := c.Snapshot().Unanswered; got != end.want {
			t.Fatalf("end=%s unanswered=%d want %d", end.state, got, end.want)
		}
	}
}

// An objective reached three times in one run counts once (item 19): attempts and achieved are
// per run, so a run that tries recon twice and reaches it twice is attempts 1, achieved 1.
func TestObjectivesCountedPerRun(t *testing.T) {
	c := New(newStore(t), nil)
	c.Record(ev("run", map[string]any{"run_id": "t", "scenario": "terminal", "state": "queued"}))
	for i := 0; i < 3; i++ {
		c.Record(ev("command", map[string]any{"run_id": "t", "id": "whoami", "state": "started"}))
		c.Record(ev("command", map[string]any{"run_id": "t", "id": "whoami", "state": "exited", "achieved": true}))
	}
	c.Record(ev("run", map[string]any{"run_id": "t", "scenario": "terminal", "state": "finished", "at": time.Now()}))
	o := c.Snapshot().Objectives["recon"]
	if o.Attempts != 1 || o.Achieved != 1 {
		t.Fatalf("objective recon = %+v, want attempts 1 achieved 1", o)
	}
	// But the command attempts counter is per run of the command (3).
	if c.Snapshot().Commands["whoami"].Attempts != 3 {
		t.Fatalf("whoami attempts = %d, want 3", c.Snapshot().Commands["whoami"].Attempts)
	}
}

// A corrupt persisted blob must not panic Snapshot or install bad counters (item 20).
func TestLoadRejectsCorrupt(t *testing.T) {
	for _, blob := range []string{
		`{"ByScenario":{"x":null}}`,          // nil map value -> would nil-deref in Snapshot
		`{"Runs":-5}`,                        // negative counter
		`{"Commands":{"a":{"Attempts":-1}}}`, // negative nested counter
		`not json`,
	} {
		c := New(newStore(t), nil)
		c.Record(ev("run", map[string]any{"run_id": "r", "scenario": "shell-in-container", "state": "queued"}))
		before := c.Snapshot().Runs
		if err := c.Load([]byte(blob)); err == nil {
			t.Fatalf("Load(%q) accepted a bad blob", blob)
		}
		// The counters are unchanged and Snapshot still works (no panic).
		if c.Snapshot().Runs != before {
			t.Fatalf("Load(%q) mutated counters on failure", blob)
		}
	}
}

// response_ms.min handles a genuine 0 ms response (item 21): a 0 then a 900 gives min 0, not 900.
func TestResponseMinHandlesZero(t *testing.T) {
	c := New(newStore(t), nil)
	base := time.Unix(100, 0).UTC()
	run := func(id string, gap time.Duration) {
		c.Record(ev("run", map[string]any{"run_id": id, "scenario": "shell-in-container", "state": "queued"}))
		c.Record(ev("run", map[string]any{"run_id": id, "scenario": "shell-in-container", "state": "detected", "at": base}))
		c.Record(ev("run", map[string]any{"run_id": id, "scenario": "shell-in-container", "state": "responded", "at": base.Add(gap)}))
	}
	run("a", 0)
	run("b", 900*time.Millisecond)
	if m := c.Snapshot().ResponseMS; m.Min != 0 || m.Max != 900 {
		t.Fatalf("response_ms = %+v, want min 0 max 900", m)
	}
}

// A terminal run's response is measured against the detection of the same command: an unanswered
// detection at 2 s and a 400 ms response to another command at 102 s record 400, not 100400. A
// response tied to no detection records nothing.
func TestResponsePairedByCommand(t *testing.T) {
	c := New(newStore(t), nil)
	base := time.Unix(1000, 0).UTC()
	run := func(state string, at time.Duration, seq int) {
		c.Record(ev("run", map[string]any{"run_id": "t", "scenario": "terminal", "state": state,
			"at": base.Add(at), "command_seq": seq}))
	}
	run("queued", 0, 0)
	run("detected", 2*time.Second, 1) // no response ever comes for command 1
	run("detected", 102*time.Second, 9)
	run("responded", 102400*time.Millisecond, 9)
	run("responded", 110*time.Second, 4) // command 4 was never detected: not measured
	run("finished", 111*time.Second, 0)
	if got := c.Snapshot().ResponseMS; got != (ResponseMS{Last: 400, P50: 400, Min: 400, Max: 400}) {
		t.Fatalf("response_ms = %+v, want 400 throughout", got)
	}

	// A response with no detection of its own at all records no latency.
	c2 := New(newStore(t), nil)
	c2.Record(ev("run", map[string]any{"run_id": "u", "scenario": "terminal", "state": "queued", "at": base}))
	c2.Record(ev("run", map[string]any{"run_id": "u", "scenario": "terminal", "state": "detected", "at": base, "command_seq": 2}))
	c2.Record(ev("run", map[string]any{"run_id": "u", "scenario": "terminal", "state": "responded", "at": base.Add(time.Second)}))
	if got := c2.Snapshot().ResponseMS; got != (ResponseMS{}) {
		t.Fatalf("unpaired response recorded %+v", got)
	}
}

// Hostile or nonsensical persisted blobs are refused, leaving the counters as they were: negative
// latencies and samples, a since in year 9999, a counter at MaxInt64 (the next increment would
// overflow), a best-objectives count no run can reach, a min above the max.
func TestLoadRejectsOutOfRange(t *testing.T) {
	for _, blob := range []string{
		`{"RespMin":-5,"RespMax":-9,"RespLast":-1,"RespCount":3}`,
		`{"RespLast":-1}`,
		`{"RespSamples":[100,-200]}`,
		`{"SurvivalSamples":[-1]}`,
		`{"Since":"9999-12-31T00:00:00Z"}`,
		`{"Runs":9223372036854775807}`,
		`{"ByScenario":{"x":{"Runs":9223372036854775807}}}`,
		`{"Commands":{"x":{"Attempts":1099511627777}}}`,
		`{"BestObjectives":1000000,"TerminalRuns":5}`,
		`{"BestObjectives":2,"TerminalRuns":0}`,
		`{"RespCount":2,"RespMin":900,"RespMax":100}`,
	} {
		c := New(newStore(t), nil)
		queuedRun(c, "r")
		if err := c.Load([]byte(blob)); err == nil {
			t.Fatalf("Load(%s) accepted it: %+v", blob, c.Snapshot())
		}
		if s := c.Snapshot(); s.Runs != 1 || s.ResponseMS != (ResponseMS{}) {
			t.Fatalf("Load(%s) changed the counters on failure: %+v", blob, s)
		}
	}
	// The bounds are not a reason to refuse a plausible blob.
	c := New(newStore(t), nil)
	if err := c.Load([]byte(`{"Since":"2026-01-01T00:00:00Z","Runs":412,"TerminalRuns":40,"BestObjectives":5,` +
		`"RespCount":2,"RespMin":0,"RespMax":900,"RespLast":0,"RespSamples":[900,0],"SurvivalSamples":[0,120]}`)); err != nil {
		t.Fatalf("a plausible blob was refused: %v", err)
	}
}

// A blob saved before RespCount existed carries samples but a count of 0. The count is derived from
// the samples, so the old min survives a slower response: min 200, not 900.
func TestLoadDerivesRespCount(t *testing.T) {
	c := New(newStore(t), nil)
	if err := c.Load([]byte(`{"RespMin":200,"RespMax":200,"RespLast":200,"RespSamples":[200]}`)); err != nil {
		t.Fatal(err)
	}
	base := time.Unix(100, 0).UTC()
	queuedRun(c, "a")
	c.Record(ev("run", map[string]any{"run_id": "a", "scenario": "shell-in-container", "state": "detected", "at": base}))
	c.Record(ev("run", map[string]any{"run_id": "a", "scenario": "shell-in-container", "state": "responded", "at": base.Add(900 * time.Millisecond)}))
	if m := c.Snapshot().ResponseMS; m.Min != 200 || m.Max != 900 || m.Last != 900 {
		t.Fatalf("response_ms = %+v, want min 200 max 900 last 900", m)
	}
}

func queuedRun(c *Collector, id string) {
	c.Record(ev("run", map[string]any{"run_id": id, "scenario": "shell-in-container", "state": "queued"}))
}

// A terminal run is unanswered when a detected command got no response before the run ended at its
// deadline - once per run however many such commands. Answered detections, or an end other than the
// deadline (left, idle, killed), are not.
func TestTerminalUnanswered(t *testing.T) {
	type step struct {
		state string
		seq   int
	}
	for _, tc := range []struct {
		name   string
		steps  []step
		detail string
		want   int
	}{
		{"detected, no response, deadline", []step{{"detected", 2}}, "deadline", 1},
		{"two unanswered commands count once", []step{{"detected", 2}, {"detected", 5}}, "deadline", 1},
		{"one answered, a later one not", []step{{"detected", 2}, {"responded", 2}, {"detected", 5}}, "deadline", 1},
		{"all answered", []step{{"detected", 2}, {"responded", 2}}, "deadline", 0},
		{"a response tied to no command is not command 2's", []step{{"detected", 2}, {"responded", 0}}, "deadline", 1},
		{"a response tied to no command answers the detection tied to none", []step{{"detected", 0}, {"responded", 0}}, "deadline", 0},
		{"a response that came before its alert", []step{{"responded", 3}, {"detected", 3}}, "deadline", 0},
		{"unanswered, but the visitor left", []step{{"detected", 2}}, "left", 0},
		{"unanswered, but idle", []step{{"detected", 2}}, "idle", 0},
		{"nothing detected", nil, "deadline", 0},
	} {
		c := New(newStore(t), nil)
		at := time.Unix(1000, 0).UTC()
		c.Record(ev("run", map[string]any{"run_id": "t", "scenario": "terminal", "state": "queued", "at": at}))
		for _, s := range tc.steps {
			c.Record(ev("run", map[string]any{"run_id": "t", "scenario": "terminal", "state": s.state, "at": at, "command_seq": s.seq}))
		}
		c.Record(ev("run", map[string]any{"run_id": "t", "scenario": "terminal", "state": "finished", "detail": tc.detail, "at": at}))
		if got := c.Snapshot().Unanswered; got != tc.want {
			t.Fatalf("%s: unanswered = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// A late alert (no command_seq) answered by a late response (no command_seq): the two are a pair, so
// the latency is measured and the run is answered. A response tied to no command does not pair with a
// command's detection, however late: no latency, and that command stays unanswered (the runner would
// have published the response under the command's seq had it answered it).
func TestResponseTiedToNoCommand(t *testing.T) {
	at := time.Unix(1000, 0).UTC()
	run := func(c *Collector, state string, d time.Duration, seq int, detail string) {
		c.Record(ev("run", map[string]any{"run_id": "t", "scenario": "terminal", "state": state,
			"at": at.Add(d), "command_seq": seq, "detail": detail}))
	}
	c := New(newStore(t), nil)
	run(c, "queued", 0, 0, "")
	run(c, "detected", time.Second, 0, "")
	run(c, "responded", 1700*time.Millisecond, 0, "")
	run(c, "finished", 3*time.Second, 0, "deadline")
	if s := c.Snapshot(); s.ResponseMS != (ResponseMS{Last: 700, P50: 700, Min: 700, Max: 700}) || s.Unanswered != 0 {
		t.Fatalf("seq-0 pair: response_ms %+v unanswered %d, want 700 ms and answered", s.ResponseMS, s.Unanswered)
	}

	c = New(newStore(t), nil)
	run(c, "queued", 0, 0, "")
	run(c, "detected", time.Second, 4, "")
	run(c, "responded", 1700*time.Millisecond, 0, "")
	run(c, "finished", 3*time.Second, 0, "deadline")
	if s := c.Snapshot(); s.ResponseMS != (ResponseMS{}) || s.Unanswered != 1 {
		t.Fatalf("unmatched: response_ms %+v unanswered %d, want none and unanswered", s.ResponseMS, s.Unanswered)
	}
}
