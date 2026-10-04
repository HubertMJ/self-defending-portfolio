package siemlog

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/events"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/runner"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/scenarios"
)

var update = flag.Bool("update", false, "rewrite testdata/lines.golden")

// The catalogue entries the tests use, as in cluster/infra/sandbox/scenarios/scenarios.yaml.
type catalogue map[string]scenarios.Scenario

func (c catalogue) Get(id string) (scenarios.Scenario, bool) { sc, ok := c[id]; return sc, ok }

var testCatalogue = catalogue{
	"terminal": {ID: "terminal", Interactive: true, Commands: []scenarios.Command{
		{ID: "whoami", Objective: "recon", Technique: "T1033", Outcome: "allowed"},
		{ID: "read-flag", Objective: "credentials", Technique: "T1552.001", Outcome: "allowed"},
		{ID: "read-shadow", Objective: "credentials", Technique: "T1003.008", Outcome: "detected",
			Detection: "Read sensitive file untrusted", Response: "terminate"},
		{ID: "touch-bin", Technique: "T1543", Outcome: "prevented"},
	}},
	"shell-in-container": {ID: "shell-in-container", Technique: "T1059.004"},
}

const (
	flagValue = "SDP{0123456789abcdef}"
	token     = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	saName    = "system:serviceaccount:portfolio-api:portfolio-api"
	clientIP  = "203.0.113.9"
	podIP     = "10.42.0.17"
)

var t0 = time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)

func at(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }

func intp(n int) *int { return &n }

// harness feeds a real hub whose tap is the recorder, as main.go wires it, and collects the lines
// with the production JSON handler minus the wall-clock `time` key.
type harness struct {
	hub  *events.Hub
	rec  *Recorder
	buf  *bytes.Buffer
	stop func()
}

func newHarness(t *testing.T, cfg Config) *harness {
	t.Helper()
	buf := &bytes.Buffer{}
	cfg.Log = slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		}}))
	if cfg.Catalogue == nil {
		cfg.Catalogue = testCatalogue
	}
	if cfg.Namespace == "" {
		cfg.Namespace, cfg.UnguardedNamespace = "sandbox", "sandbox-unguarded"
	}
	rec := New(cfg)
	hub := events.NewHub(10)
	hub.Tap(rec.Record)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); rec.Run(ctx) }()
	return &harness{hub: hub, rec: rec, buf: buf, stop: func() { cancel(); wg.Wait() }}
}

func (h *harness) publish(t *testing.T, typ string, v any) {
	t.Helper()
	if err := h.hub.Publish(typ, v); err != nil {
		t.Fatal(err)
	}
}

// lines stops the recorder (which writes everything queued first) and returns the decoded lines.
func (h *harness) lines(t *testing.T) []map[string]any {
	t.Helper()
	h.stop()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(h.buf.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not JSON: %q: %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

func siemLines(lines []map[string]any, msg string) []map[string]any {
	var out []map[string]any
	for _, l := range lines {
		if l["msg"] == msg {
			out = append(out, l)
		}
	}
	return out
}

// terminalSession publishes a terminal run as the runner does: whoami, read-flag (whose output is
// the flag), touch-bin (refused), read-shadow (detected, the pod killed), with the Falco, Talon,
// pod and victim events around it carrying a pod IP, a client IP and the API's ServiceAccount.
func terminalSession(t *testing.T, h *harness) {
	const id, pod = "3755e65530aa11bb", "terminal-3755e65530"
	run := func(state, detail string, ms, seq int) {
		ev := runner.RunEvent{RunID: id, Scenario: "terminal", State: state, At: at(ms), Detail: detail, CommandSeq: seq}
		if state != runner.StateQueued {
			ev.Pod = pod
		}
		h.publish(t, "run", ev)
	}
	cmd := func(seq int, cid, state string, ms int, chunk string, exit *int, achieved bool) {
		h.publish(t, "command", runner.CommandEvent{RunID: id, Seq: seq, ID: cid, State: state, At: at(ms),
			Stream: map[bool]string{true: "stdout"}[chunk != ""], Chunk: chunk, ExitCode: exit, Achieved: achieved})
	}
	run(runner.StateQueued, "", 0, 0)
	run(runner.StateStarted, "", 120, 0)
	h.publish(t, "pod", map[string]any{"run_id": id, "pod": pod, "phase": "Running", "pod_ip": podIP})
	run(runner.StatePodReady, "5e1e5688c4ee", 2400, 0)
	cmd(1, "whoami", runner.CommandStarted, 5000, "", nil, false)
	cmd(1, "whoami", runner.CommandOutput, 5030, "shop\n", nil, false)
	cmd(1, "whoami", runner.CommandExited, 5040, "", intp(0), false)
	cmd(2, "read-flag", runner.CommandStarted, 9000, "", nil, false)
	cmd(2, "read-flag", runner.CommandOutput, 9020, flagValue+"\n", nil, false)
	cmd(2, "read-flag", runner.CommandExited, 9025, "", intp(0), true)
	cmd(3, "touch-bin", runner.CommandStarted, 12000, "", nil, false)
	cmd(3, "touch-bin", runner.CommandOutput, 12010, "touch: /bin/backdoor: Read-only file system\n", nil, false)
	cmd(3, "touch-bin", runner.CommandExited, 12015, "", intp(1), false)
	cmd(4, "read-shadow", runner.CommandStarted, 15000, "", nil, false)
	h.publish(t, "falco", map[string]any{"rule": "Read sensitive file untrusted", "pod": pod,
		"output": "user=" + saName + " client=" + clientIP + " ip=" + podIP + " " + flagValue})
	run(runner.StateDetected, "Read sensitive file untrusted "+clientIP+" "+saName+" "+token, 15300, 4)
	h.publish(t, "talon", map[string]any{"pod": pod, "action": "Terminate Pod", "status": "success", "by": saName})
	cmd(4, "read-shadow", runner.CommandKilled, 15400, "", nil, false)
	run(runner.StateResponded, "Terminate Pod", 15450, 4)
	h.publish(t, "victim", map[string]any{"run_id": id, "state": "unreachable", "target": podIP + ":8080"})
	run(runner.StateFinished, "killed", 16000, 0)
}

// compareRun publishes a one-click compare run (ADR 0031): Pods names both arms, Pod the guarded one
// from `started` on.
func compareRun(t *testing.T, h *harness) {
	const id = "a1b2c3d4e5f60718"
	pods := map[string]string{"guarded": "shell-in-container-a1b2c3d4e5", "unguarded": "shell-in-container-a1b2c3d4e5-u"}
	for i, state := range []string{runner.StateQueued, runner.StateStarted, runner.StateDetected, runner.StateResponded, runner.StateFinished} {
		ev := runner.RunEvent{RunID: id, Scenario: "shell-in-container", State: state, At: at(30000 + 1000*i), Pods: pods}
		if state != runner.StateQueued {
			ev.Pod = pods["guarded"]
		}
		h.publish(t, "run", ev)
	}
}

func TestLinesMatchGolden(t *testing.T) {
	h := newHarness(t, Config{})
	terminalSession(t, h)
	compareRun(t, h)
	h.stop()
	got := h.buf.Bytes()
	const golden = "testdata/lines.golden"
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("lines differ from %s (go test -run TestLinesMatchGolden -update to rewrite after a contract change)\ngot:\n%s\nwant:\n%s", golden, got, want)
	}
}

// The key sets are the contract (siem/fields/api.yaml); the golden pins the values.
func TestKeySetPerLineType(t *testing.T) {
	h := newHarness(t, Config{})
	terminalSession(t, h)
	compareRun(t, h)
	lines := h.lines(t)
	want := map[string][]string{
		MsgRun:     {"arm", "at", "command_seq", "level", "msg", "pod_ref", "run_id", "scenario", "state"},
		MsgCommand: {"achieved", "at", "command_id", "exit_code", "level", "msg", "objective", "outcome", "pod_ref", "run_id", "seq", "state", "technique"},
	}
	counts := map[string]int{}
	for _, l := range lines {
		msg, _ := l["msg"].(string)
		keys, ok := want[msg]
		if !ok {
			t.Fatalf("unexpected line %v", l)
		}
		counts[msg]++
		var got []string
		for k := range l {
			got = append(got, k)
		}
		sort.Strings(got)
		if !reflect.DeepEqual(got, keys) {
			t.Fatalf("%s keys %v, want %v", msg, got, keys)
		}
	}
	// 6 run states of the terminal run + 5 of the compare run's guarded arm + its started and
	// finished for the twin; 4 commands x (started + exited|killed).
	if counts[MsgRun] != 13 || counts[MsgCommand] != 8 {
		t.Fatalf("counts %v", counts)
	}
}

// ADR 0017/0021/0030: no flag, token, IP or ServiceAccount in any siem line, whatever the events
// around the run carry; output events are skipped and never decoded.
func TestTerminalRunWithReadFlagLeaksNothing(t *testing.T) {
	h := newHarness(t, Config{})
	terminalSession(t, h)
	lines := h.lines(t)
	var cmds int
	var raw strings.Builder
	for _, l := range lines {
		if l["msg"] != MsgRun && l["msg"] != MsgCommand {
			continue
		}
		b, _ := json.Marshal(l)
		raw.Write(b)
		raw.WriteByte('\n')
		if l["msg"] == MsgCommand && l["command_id"] == "read-flag" {
			cmds++
			if l["state"] == runner.CommandExited && l["achieved"] != true {
				t.Fatalf("read-flag exit not achieved: %v", l)
			}
		}
	}
	if cmds != 2 {
		t.Fatalf("read-flag lines: %d, want started + exited", cmds)
	}
	text := raw.String()
	for _, bad := range []string{"SDP{", "0123456789abcdef", token, "serviceaccount", "portfolio-api", "chunk", "stream",
		"detail", "Read sensitive file", "Terminate Pod", "shop\\n", "Read-only"} {
		if strings.Contains(text, bad) {
			t.Fatalf("siem lines contain %q:\n%s", bad, text)
		}
	}
	if ip := regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b`).FindString(text); ip != "" {
		t.Fatalf("siem lines contain IP %s:\n%s", ip, text)
	}
}

func TestOutputEventsProduceNoLines(t *testing.T) {
	h := newHarness(t, Config{})
	h.publish(t, "run", runner.RunEvent{RunID: "3755e65530aa11bb", Scenario: "terminal", State: runner.StateStarted, At: at(0), Pod: "terminal-3755e65530"})
	for i := 0; i < 64; i++ {
		h.publish(t, "command", runner.CommandEvent{RunID: "3755e65530aa11bb", Seq: 1, ID: "read-flag",
			State: runner.CommandOutput, At: at(i), Stream: "stdout", Chunk: flagValue})
	}
	lines := h.lines(t)
	if n := len(siemLines(lines, MsgCommand)); n != 0 {
		t.Fatalf("%d command lines from output events: %v", n, lines)
	}
	if n := len(siemLines(lines, MsgRun)); n != 1 {
		t.Fatalf("run lines: %d", n)
	}
}

func TestTwinArmUsesTheTwinNamespace(t *testing.T) {
	h := newHarness(t, Config{})
	compareRun(t, h)
	// A command event stamped with the unguarded arm (the terminal never runs in the twin today, but
	// the ref must follow the arm if it ever does).
	h.publish(t, "run", runner.RunEvent{RunID: "b1b2c3d4e5f60718", Scenario: "terminal", State: runner.StateStarted, At: at(0),
		Pod: "terminal-b1b2c3d4e5", Pods: map[string]string{"guarded": "terminal-b1b2c3d4e5", "unguarded": "terminal-b1b2c3d4e5-u"}})
	h.publish(t, "command", runner.CommandEvent{RunID: "b1b2c3d4e5f60718", Seq: 1, ID: "whoami", State: runner.CommandStarted, At: at(1), Arm: "unguarded"})
	lines := h.lines(t)
	var guarded, unguarded []string
	for _, l := range siemLines(lines, MsgRun) {
		if l["run_id"] != "a1b2c3d4e5f60718" || l["state"] == runner.StateQueued {
			continue
		}
		state, _ := l["state"].(string)
		switch l["arm"] {
		case "guarded":
			guarded = append(guarded, state)
			if l["pod_ref"] != "sandbox_shell-in-container-a1b2c3d4e5" {
				t.Fatalf("guarded ref %v", l)
			}
		case "unguarded":
			unguarded = append(unguarded, state)
			if l["pod_ref"] != "sandbox-unguarded_shell-in-container-a1b2c3d4e5-u" {
				t.Fatalf("twin ref %v", l)
			}
		default:
			t.Fatalf("arm %v", l)
		}
	}
	// Detection and response are the guarded arm's alone: the twin is never answered.
	if strings.Join(guarded, " ") != "started detected responded finished" || strings.Join(unguarded, " ") != "started finished" {
		t.Fatalf("guarded %v unguarded %v", guarded, unguarded)
	}
	cmds := siemLines(lines, MsgCommand)
	if len(cmds) != 1 || cmds[0]["pod_ref"] != "sandbox-unguarded_terminal-b1b2c3d4e5-u" {
		t.Fatalf("twin command ref %v", cmds)
	}
}

// A compare run that fails before its guarded pod is visible still names the twin in its final
// line: the twin's name comes from Pods, not from the guarded pod's visibility.
func TestTwinNamedWithoutAVisibleGuardedPod(t *testing.T) {
	h := newHarness(t, Config{})
	pods := map[string]string{"guarded": "shell-in-container-c1b2c3d4e5", "unguarded": "shell-in-container-c1b2c3d4e5-u"}
	h.publish(t, "run", runner.RunEvent{RunID: "c1b2c3d4e5f60718", Scenario: "shell-in-container", State: runner.StateQueued, At: at(0), Pods: pods})
	h.publish(t, "run", runner.RunEvent{RunID: "c1b2c3d4e5f60718", Scenario: "shell-in-container", State: runner.StateFailed, At: at(1), Pods: pods})
	runs := siemLines(h.lines(t), MsgRun)
	if len(runs) != 3 {
		t.Fatalf("runs %v", runs)
	}
	final := runs[2]
	if final["arm"] != "unguarded" || final["state"] != runner.StateFailed || final["pod_ref"] != "sandbox-unguarded_shell-in-container-c1b2c3d4e5-u" {
		t.Fatalf("twin final line %v", final)
	}
	if runs[1]["arm"] != "guarded" || runs[1]["pod_ref"] != nil {
		t.Fatalf("guarded final line %v", runs[1])
	}
}

// Record runs under the hub lock: a full queue must drop and count, never wait.
func TestFullQueueDropsAndCountsInsteadOfBlocking(t *testing.T) {
	buf := &bytes.Buffer{}
	rec := New(Config{Log: slog.New(slog.NewJSONHandler(buf, nil)), Buffer: 4, DropReport: 10 * time.Millisecond,
		Namespace: "sandbox"})
	data, _ := json.Marshal(runner.RunEvent{RunID: "3755e65530aa11bb", Scenario: "terminal", State: runner.StateStarted, At: at(0)})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 10; i++ {
			rec.Record(events.Event{ID: uint64(i + 1), Type: "run", Data: data})
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Record blocked on a full queue")
	}
	if rec.Dropped() != 6 {
		t.Fatalf("dropped %d, want 6", rec.Dropped())
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { defer close(stopped); rec.Run(ctx) }()
	cancel()
	<-stopped
	out := buf.String()
	if strings.Count(out, `"msg":"siem.run"`) != 4 {
		t.Fatalf("queued lines not written:\n%s", out)
	}
	if !strings.Contains(out, `"msg":"siem events dropped","dropped":6,"dropped_total":6`) {
		t.Fatalf("drops not reported:\n%s", out)
	}
}

// After Run has ended nothing is queued any more: a late event is counted as dropped, and the final
// report covers the drops up to the close.
func TestRecordAfterShutdownCountsAsDropped(t *testing.T) {
	buf := &bytes.Buffer{}
	rec := New(Config{Log: slog.New(slog.NewJSONHandler(buf, nil)), Buffer: 1, DropReport: time.Hour, Namespace: "sandbox"})
	data, _ := json.Marshal(runner.RunEvent{RunID: "3755e65530aa11bb", Scenario: "terminal", State: runner.StateStarted, At: at(0)})
	ev := events.Event{Type: "run", Data: data}
	rec.Record(ev)
	rec.Record(ev) // the queue holds one: dropped before the close
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec.Run(ctx) // returns after the final drain and report
	out := buf.String()
	if strings.Count(out, `"msg":"siem.run"`) != 1 || !strings.Contains(out, `"msg":"siem events dropped","dropped":1,"dropped_total":1`) {
		t.Fatalf("final drain/report:\n%s", out)
	}
	rec.Record(ev)
	if rec.Dropped() != 2 || len(rec.ch) != 0 {
		t.Fatalf("after close: dropped %d, queued %d", rec.Dropped(), len(rec.ch))
	}
}

func TestDropsAreReportedPeriodically(t *testing.T) {
	var mu sync.Mutex
	buf := &bytes.Buffer{}
	rec := New(Config{Log: slog.New(slog.NewJSONHandler(lockedWriter{&mu, buf}, nil)), Buffer: 1, DropReport: 20 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rec.Run(ctx)
	rec.dropped.Add(3) // as if three events had found the queue full
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		s := buf.String()
		mu.Unlock()
		if strings.Contains(s, `"dropped":3`) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no drop report within 2 s")
}

type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// S0-#4: a value with a space can never match a rule; free text is written empty, not shipped.
func TestNonIdentifierValuesAreWrittenEmpty(t *testing.T) {
	cat := catalogue{"terminal": {ID: "terminal", Commands: []scenarios.Command{
		{ID: "whoami", Objective: "recon", Technique: "T1033 whoami", Outcome: "allowed"}}}}
	h := newHarness(t, Config{Catalogue: cat})
	h.publish(t, "run", runner.RunEvent{RunID: "3755e65530aa11bb", Scenario: "terminal", State: runner.StateStarted, At: at(0), Pod: "terminal_x"})
	h.publish(t, "run", runner.RunEvent{RunID: "4755e65530aa11bb", Scenario: "a scenario", State: runner.StateStarted, At: at(0), Pod: "p"})
	h.publish(t, "command", runner.CommandEvent{RunID: "3755e65530aa11bb", Seq: 1, ID: "whoami", State: runner.CommandStarted, At: at(1)})
	h.publish(t, "run", runner.RunEvent{RunID: "3755e65530aa11bb", Scenario: "terminal", State: "not-a-state", At: at(2)})
	lines := h.lines(t)
	runs, cmds := siemLines(lines, MsgRun), siemLines(lines, MsgCommand)
	if len(runs) != 2 || len(cmds) != 1 {
		t.Fatalf("runs %v cmds %v", runs, cmds)
	}
	if runs[0]["pod_ref"] != nil || runs[1]["scenario"] != "" || runs[1]["pod_ref"] != "sandbox_p" {
		t.Fatalf("runs %v", runs)
	}
	if cmds[0]["technique"] != "" || cmds[0]["objective"] != "recon" {
		t.Fatalf("cmd %v", cmds[0])
	}
}

func TestRunMapIsBounded(t *testing.T) {
	rec := New(Config{Log: slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)), Namespace: "sandbox"})
	for i := 0; i < 3*maxRuns; i++ {
		id := fmt.Sprintf("%016x", i)
		data, _ := json.Marshal(runner.RunEvent{RunID: id, Scenario: "terminal", State: runner.StateStarted, At: at(i), Pod: "p"})
		rec.write(events.Event{Type: "run", Data: data})
	}
	if len(rec.runs) > maxRuns {
		t.Fatalf("%d runs tracked, cap %d", len(rec.runs), maxRuns)
	}
	data, _ := json.Marshal(runner.RunEvent{RunID: "3755e65530aa11bb", Scenario: "terminal", State: runner.StateStarted, At: at(0), Pod: "p"})
	rec.write(events.Event{Type: "run", Data: data})
	data, _ = json.Marshal(runner.RunEvent{RunID: "3755e65530aa11bb", Scenario: "terminal", State: runner.StateFinished, At: at(1), Pod: "p"})
	rec.write(events.Event{Type: "run", Data: data})
	if _, ok := rec.runs["3755e65530aa11bb"]; ok {
		t.Fatal("a finished run is still tracked")
	}
}
