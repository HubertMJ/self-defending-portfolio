package runner

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/events"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/scenarios"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/stats"
)

// beaconExec: `beacon` (wget) exits 1 at once, as against the real pod; `whoami` (id) hangs until its
// bound, so a response can land while it runs.
type beaconExec struct{ fakeExec }

func (b *beaconExec) ExecStream(ctx context.Context, _, _, _ string, cmd []string, _ bool, _, _ io.Writer) (int, error) {
	if cmd[0] == "id" {
		<-ctx.Done()
		return -1, ctx.Err()
	}
	return 1, nil
}

// teePub publishes to the test's recorder and to a real hub, whose tap feeds the stats collector with
// the real catalogue - the stream as production records it.
type teePub struct {
	*recorder
	hub *events.Hub
}

func (p teePub) Publish(typ string, v any) error {
	if err := p.hub.Publish(typ, v); err != nil {
		return err
	}
	return p.recorder.Publish(typ, v)
}

func statsTee(t *testing.T) (teePub, *stats.Collector) {
	t.Helper()
	hub := events.NewHub(100)
	col := stats.New(scenarios.NewStore("../scenarios/testdata/scenarios-real.yaml", nil), nil)
	hub.Tap(col.Record)
	return teePub{newRecorder(), hub}, col
}

// pairingRun is a terminal run ending at its 3 s deadline, with a clock that can be moved past the
// 2 s command window.
func pairingRun(t *testing.T, pub teePub) (*Runner, func(), string, string, <-chan struct{}) {
	t.Helper()
	c := fake.NewClientset()
	readyOnCreate(c)
	r := New(c, &beaconExec{}, pub, nil, Config{PollInterval: 10 * time.Millisecond, QuarantineLinger: -1,
		CommandTimeout: 1500 * time.Millisecond, DeleteWait: 200 * time.Millisecond})
	var mu sync.Mutex
	var skew time.Duration
	r.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return time.Now().Add(skew) }
	later := func() { mu.Lock(); skew = 3 * time.Second; mu.Unlock() }
	release, done := released()
	sc := terminalScenario()
	sc.TimeoutSeconds = 3
	id, token := r.StartTerminal(sc, release)
	pub.waitFor(t, StatePodReady)
	return r, later, id, token, done
}

// Route 1: Falco's alert ties to `beacon` (seq 1); the visitor types the next command at once, and
// Talon's quarantine of beacon arrives while that one runs. The response belongs to beacon: no
// `detected` is made up for seq 2, the latency is the real one (the 300 ms the test waits), and the
// run - answered - is not `unanswered` when it ends at its deadline. Before: `detected seq=2` invented
// at the instant of the response, response_ms 0, unanswered 1.
func TestResponsePairedWithItsDetectionNotTheRunningCommand(t *testing.T) {
	pub, col := statsTee(t)
	r, _, id, token, done := pairingRun(t, pub)
	pod := podName("terminal", id)
	s1 := sendCommand(t, r, id, token, "beacon")
	waitCommand(t, pub.recorder, s1, CommandStarted)
	r.ObserveFalco("sandbox", pod, "SDP network tool in sandbox")
	waitCommand(t, pub.recorder, s1, CommandExited)
	s2 := sendCommand(t, r, id, token, "whoami")
	waitCommand(t, pub.recorder, s2, CommandStarted)
	time.Sleep(300 * time.Millisecond)
	r.ObserveTalon("sandbox", pod, "success", "kubernetes:label")
	if ev := pub.waitFor(t, StateFinished); ev.Detail != "deadline" {
		t.Fatalf("finish detail = %q", ev.Detail)
	}
	<-done

	if ds := runStates(pub.recorder, StateDetected); len(ds) != 1 || ds[0].CommandSeq != s1 {
		t.Fatalf("detected = %+v, want only beacon's (seq %d)", ds, s1)
	}
	if rs := runStates(pub.recorder, StateResponded); len(rs) != 1 || rs[0].CommandSeq != s1 || rs[0].Detail != "quarantine" {
		t.Fatalf("responded = %+v, want one for beacon (seq %d)", rs, s1)
	}
	s := col.Snapshot()
	if s.Runs != 1 || s.Unanswered != 0 || s.ByScenario["terminal"] != (stats.ScenarioStat{Runs: 1, Detected: 1, Responded: 1}) {
		t.Fatalf("stats = runs %d unanswered %d %+v", s.Runs, s.Unanswered, s.ByScenario["terminal"])
	}
	if s.ResponseMS.Last < 250 || s.ResponseMS.Min != s.ResponseMS.Last {
		t.Fatalf("response_ms = %+v, want the real ~300 ms", s.ResponseMS)
	}
}

// Route 2: beacon is detected and answered; then the same rule's alert arrives again more than 2 s
// after the command ended. It is beacon's alert, late - not a new detection with no command that
// nobody answered - so the run ending at its deadline is not `unanswered`.
func TestLateRepeatOfAnsweredAlertIsNotUnanswered(t *testing.T) {
	pub, col := statsTee(t)
	r, later, id, token, done := pairingRun(t, pub)
	pod := podName("terminal", id)
	s1 := sendCommand(t, r, id, token, "beacon")
	waitCommand(t, pub.recorder, s1, CommandStarted)
	r.ObserveFalco("sandbox", pod, "SDP network tool in sandbox")
	r.ObserveTalon("sandbox", pod, "success", "kubernetes:label")
	waitCommand(t, pub.recorder, s1, CommandExited)
	later()
	r.ObserveFalco("sandbox", pod, "SDP network tool in sandbox")
	r.ObserveTalon("sandbox", pod, "success", "kubernetes:label") // Talon answering that alert again
	if ev := pub.waitFor(t, StateFinished); ev.Detail != "deadline" {
		t.Fatalf("finish detail = %q", ev.Detail)
	}
	<-done
	if ds := runStates(pub.recorder, StateDetected); len(ds) != 1 || ds[0].CommandSeq != s1 {
		t.Fatalf("detected = %+v, want only beacon's", ds)
	}
	if rs := runStates(pub.recorder, StateResponded); len(rs) != 1 {
		t.Fatalf("responded = %+v, want the repeat dropped", rs)
	}
	if s := col.Snapshot(); s.Unanswered != 0 || s.ByScenario["terminal"].Detected != 1 {
		t.Fatalf("stats = unanswered %d %+v", s.Unanswered, s.ByScenario["terminal"])
	}
}

// Two detected commands in flight - beacon (quarantine), then read-shadow (terminate) - and Talon's
// quarantine arrives after both alerts: it answers beacon, the most recent detection of its kind, not
// read-shadow, the most recent of all.
func TestResponsePairedByKind(t *testing.T) {
	pub, _ := statsTee(t)
	r, _, id, token, done := pairingRun(t, pub)
	pod := podName("terminal", id)
	s1 := sendCommand(t, r, id, token, "beacon")
	waitCommand(t, pub.recorder, s1, CommandStarted)
	r.ObserveFalco("sandbox", pod, "SDP network tool in sandbox")
	waitCommand(t, pub.recorder, s1, CommandExited)
	s2 := sendCommand(t, r, id, token, "read-shadow")
	waitCommand(t, pub.recorder, s2, CommandStarted)
	r.ObserveFalco("sandbox", pod, "Read sensitive file untrusted")
	r.ObserveTalon("sandbox", pod, "success", "kubernetes:label")
	r.ObserveTalon("sandbox", pod, "success", "kubernetes:terminate")
	pub.waitFor(t, StateFinished)
	<-done
	rs := runStates(pub.recorder, StateResponded)
	if len(rs) != 2 || rs[0].CommandSeq != s1 || rs[0].Detail != "quarantine" || rs[1].CommandSeq != s2 || rs[1].Detail != "terminate" {
		t.Fatalf("responded = %+v, want quarantine for seq %d then terminate for seq %d", rs, s1, s2)
	}
}
