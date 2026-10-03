package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/scenarios"
)

func terminalScenario() scenarios.Scenario {
	sc := scenarios.Scenario{ID: "terminal", Title: "Terminal", Interactive: true, TimeoutSeconds: 120, IdleSeconds: 30}
	sc.Objectives = []scenarios.Objective{{ID: "recon", Title: "Look"}, {ID: "credentials", Title: "Creds"}}
	sc.Commands = []scenarios.Command{
		{ID: "whoami", Input: "id", Objective: "recon", Command: []string{"id"}, Outcome: "allowed", Layer: "runtime", Control: "none", Explain: "ok"},
		{ID: "read-shadow", Input: "cat /etc/shadow", Objective: "credentials", Command: []string{"cat", "/etc/shadow"},
			Outcome: "detected", Layer: "runtime", Control: "Falco", Detection: "Read sensitive file untrusted", Response: "terminate", Explain: "x"},
		{ID: "beacon", Input: "wget", Command: []string{"wget", "http://127.0.0.1:9/"}, Outcome: "detected", Layer: "network",
			Control: "Falco", Detection: "SDP network tool in sandbox", Response: "quarantine", Explain: "x"},
		{ID: "shell", Input: "sh -i", Objective: "credentials", Command: []string{"sh", "-i"}, TTY: true, Outcome: "detected",
			Layer: "runtime", Control: "Falco", Detection: "Terminal shell in container", Response: "terminate", Explain: "x"},
	}
	sc.Template.Spec.Containers = []corev1.Container{{Name: scenarios.TerminalContainer, Image: img}}
	return sc
}

func terminalRunner(c *fake.Clientset, ex Execer, rec *recorder) *Runner {
	return New(c, ex, rec, nil, Config{PollInterval: 10 * time.Millisecond, QuarantineLinger: -1,
		CommandTimeout: 500 * time.Millisecond, DeleteWait: 200 * time.Millisecond})
}

// sendCommand retries past the brief window between pod_ready and the run accepting commands.
func sendCommand(t *testing.T, r *Runner, id, token, cmd string) int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		seq, err := r.Command(id, token, cmd)
		if err == nil {
			return seq
		}
		if !errors.Is(err, ErrRunBusy) || time.Now().After(deadline) {
			t.Fatalf("Command(%q): %v", cmd, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestTerminalAllowedCommandAndLeave(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	ex := &fakeExec{stdout: "uid=10001 gid=10001\n", code: 0}
	r := terminalRunner(c, ex, rec)
	release, done := released()

	sc := terminalScenario()
	id, token := r.StartTerminal(sc, release)
	if len(token) != 32 {
		t.Fatalf("token = %q", token)
	}
	rec.waitFor(t, StatePodReady)
	seq := sendCommand(t, r, id, token, "whoami")
	if seq != 1 {
		t.Fatalf("seq = %d", seq)
	}
	// Wait for the exited event of that command.
	waitCommand(t, rec, 1, CommandExited)

	cmds := rec.of("command")
	var started, output, exited *CommandEvent
	for i := range cmds {
		ev := cmds[i].v.(CommandEvent)
		switch ev.State {
		case CommandStarted:
			started = &ev
		case CommandOutput:
			output = &ev
		case CommandExited:
			exited = &ev
		}
	}
	if started == nil || output == nil || exited == nil {
		t.Fatalf("missing command events: %s", rec.order())
	}
	if output.Stream != "stdout" || !strings.Contains(output.Chunk, "uid=10001") {
		t.Fatalf("output: %+v", output)
	}
	if exited.ExitCode == nil || *exited.ExitCode != 0 || !exited.Achieved {
		t.Fatalf("exited: %+v", exited)
	}

	if err := r.Leave(id, token); err != nil {
		t.Fatal(err)
	}
	ev := rec.waitFor(t, StateFinished)
	if ev.Detail != "left" {
		t.Fatalf("finish detail = %q", ev.Detail)
	}
	<-done
}

func TestTerminalDetectedTerminateKillsRun(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	ex := &fakeExec{stdout: "root:*:...\n", code: 0}
	r := terminalRunner(c, ex, rec)
	release, done := released()
	sc := terminalScenario()
	id, token := r.StartTerminal(sc, release)
	pod := podName(sc.ID, id)
	rec.waitFor(t, StatePodReady)
	seq := sendCommand(t, r, id, token, "read-shadow")

	// command_seq is the running (or just-ran) command.
	deadline := time.Now().Add(time.Second)
	for r.CommandSeqFor("sandbox", pod) != seq && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := r.CommandSeqFor("sandbox", pod); got != seq {
		t.Fatalf("CommandSeqFor = %d, want %d", got, seq)
	}
	r.ObserveFalco("sandbox", pod, "Read sensitive file untrusted")
	rec.waitFor(t, StateDetected)
	// Talon terminates: the pod is deleted, which ends the run as killed.
	_ = c.CoreV1().Pods("sandbox").Delete(context.Background(), pod, metav1.DeleteOptions{})
	r.ObserveTalon("sandbox", pod, "success")
	ev := rec.waitFor(t, StateFinished)
	if ev.Detail != "killed" {
		t.Fatalf("finish detail = %q", ev.Detail)
	}
	<-done
	if !strings.Contains(rec.order(), "run:responded") {
		t.Fatalf("no responded: %s", rec.order())
	}
}

func TestTerminalIdleEndsRun(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := New(c, &fakeExec{}, rec, nil, Config{PollInterval: 10 * time.Millisecond, QuarantineLinger: -1,
		CommandTimeout: 200 * time.Millisecond})
	release, done := released()
	sc := terminalScenario()
	sc.IdleSeconds, sc.TimeoutSeconds = 1, 60 // idle (1 s) fires well before the deadline (60 s)
	id, _ := r.StartTerminal(sc, release)
	_ = id
	rec.waitFor(t, StatePodReady)
	start := time.Now()
	ev := rec.waitFor(t, StateFinished)
	if ev.Detail != "idle" {
		t.Fatalf("finish detail = %q, want idle", ev.Detail)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("idle took %v; the 60 s deadline, not idle, ended it", d)
	}
	<-done
}

// A command still running when the pod is deleted under it ends as `killed`, not `exited`.
func TestTerminalCommandKilledState(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	ex := &fakeExec{streamBlock: true} // the exec blocks until its context is cancelled
	r := terminalRunner(c, ex, rec)
	release, done := released()
	sc := terminalScenario()
	id, token := r.StartTerminal(sc, release)
	pod := podName(sc.ID, id)
	rec.waitFor(t, StatePodReady)
	seq := sendCommand(t, r, id, token, "shell") // a TTY detected command
	waitCommand(t, rec, seq, CommandStarted)
	// Talon terminates: the pod goes away under the running command.
	_ = c.CoreV1().Pods("sandbox").Delete(context.Background(), pod, metav1.DeleteOptions{})
	r.ObserveTalon("sandbox", pod, "success")
	waitCommand(t, rec, seq, CommandKilled)
	rec.waitFor(t, StateFinished)
	<-done
}

// DELETE while a command runs ends the run as `left` (not `deadline`), promptly.
func TestTerminalDeleteDuringCommand(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := terminalRunner(c, &fakeExec{streamBlock: true}, rec)
	release, done := released()
	sc := terminalScenario()
	sc.TimeoutSeconds = 120
	id, token := r.StartTerminal(sc, release)
	rec.waitFor(t, StatePodReady)
	seq := sendCommand(t, r, id, token, "shell") // TTY command that never returns on its own
	waitCommand(t, rec, seq, CommandStarted)
	start := time.Now()
	if err := r.Leave(id, token); err != nil {
		t.Fatal(err)
	}
	ev := rec.waitFor(t, StateFinished)
	if ev.Detail != "left" {
		t.Fatalf("finish detail = %q, want left", ev.Detail)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("leave took %v; it did not end the running command", d)
	}
	<-done
}

// A non-TTY command that never returns is cut off at CommandTimeout and reported `exited` with no
// exit code (not a synthetic -1).
func TestTerminalNonTTYTimeout(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := New(c, &fakeExec{streamBlock: true}, rec, nil, Config{PollInterval: 10 * time.Millisecond,
		QuarantineLinger: -1, CommandTimeout: 100 * time.Millisecond})
	release, done := released()
	sc := terminalScenario()
	id, token := r.StartTerminal(sc, release)
	rec.waitFor(t, StatePodReady)
	seq := sendCommand(t, r, id, token, "whoami")
	waitCommand(t, rec, seq, CommandExited)
	for _, p := range rec.of("command") {
		ev := p.v.(CommandEvent)
		if ev.Seq == seq && ev.State == CommandExited {
			if ev.ExitCode != nil {
				t.Fatalf("cut-short command reported exit_code %d; expected none", *ev.ExitCode)
			}
		}
	}
	if err := r.Leave(id, token); err != nil {
		t.Fatal(err)
	}
	rec.waitFor(t, StateFinished)
	<-done
}

// A quarantine command does not end the run; a later terminate command does. Both detected and
// responded are published more than once, and commands keep working after the quarantine.
func TestTerminalQuarantineThenTerminate(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := terminalRunner(c, &fakeExec{}, rec)
	release, done := released()
	sc := terminalScenario()
	id, token := r.StartTerminal(sc, release)
	pod := podName(sc.ID, id)
	rec.waitFor(t, StatePodReady)

	// A quarantine command: detected + responded, run continues.
	s1 := sendCommand(t, r, id, token, "beacon")
	waitCommand(t, rec, s1, CommandExited)
	r.ObserveFalco("sandbox", pod, "SDP network tool in sandbox")
	r.ObserveTalon("sandbox", pod, "success")
	rec.waitFor(t, StateResponded)

	// The run is still alive: another command runs.
	s2 := sendCommand(t, r, id, token, "whoami")
	waitCommand(t, rec, s2, CommandExited)

	// A terminate command: the pod is deleted, the run ends killed.
	s3 := sendCommand(t, r, id, token, "read-shadow")
	waitCommand(t, rec, s3, CommandExited)
	r.ObserveFalco("sandbox", pod, "Read sensitive file untrusted")
	_ = c.CoreV1().Pods("sandbox").Delete(context.Background(), pod, metav1.DeleteOptions{})
	r.ObserveTalon("sandbox", pod, "success")
	ev := rec.waitFor(t, StateFinished)
	if ev.Detail != "killed" {
		t.Fatalf("finish detail = %q", ev.Detail)
	}
	<-done
	if n := strings.Count(rec.order(), "run:detected"); n < 2 {
		t.Fatalf("expected detected more than once, got %d: %s", n, rec.order())
	}
	if n := strings.Count(rec.order(), "run:responded"); n < 2 {
		t.Fatalf("expected responded more than once, got %d: %s", n, rec.order())
	}
}

func TestTerminalCommandErrors(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := terminalRunner(c, &fakeExec{}, rec)
	release, done := released()
	sc := terminalScenario()
	id, token := r.StartTerminal(sc, release)
	rec.waitFor(t, StatePodReady)
	// ensure ready
	sendCommand(t, r, id, token, "whoami")
	waitCommand(t, rec, 1, CommandExited)

	if _, err := r.Command(id, "deadbeef", "whoami"); !errors.Is(err, ErrBadToken) {
		t.Fatalf("bad token: %v", err)
	}
	if _, err := r.Command("0000000000000000", token, "whoami"); !errors.Is(err, ErrUnknownRun) {
		t.Fatalf("unknown run: %v", err)
	}
	if _, err := r.Command(id, token, "no-such"); !errors.Is(err, ErrUnknownCmd) {
		t.Fatalf("unknown cmd: %v", err)
	}
	if err := r.Leave(id, "deadbeef"); !errors.Is(err, ErrBadToken) {
		t.Fatalf("leave bad token: %v", err)
	}
	if err := r.Leave(id, token); err != nil {
		t.Fatal(err)
	}
	rec.waitFor(t, StateFinished)
	<-done
}

func TestTerminalOutputSanitizedAndCapped(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	// ANSI escape, a carriage return, an external IP (scrubbed), loopback (kept), then a big blob.
	out := "\x1b[31mred\x1b[0m\rline\ncall 8.8.8.8 and 127.0.0.1\n" + strings.Repeat("A", 6000) + "\n"
	ex := &fakeExec{stdout: out, code: 0}
	r := terminalRunner(c, ex, rec)
	release, done := released()
	sc := terminalScenario()
	id, token := r.StartTerminal(sc, release)
	rec.waitFor(t, StatePodReady)
	sendCommand(t, r, id, token, "whoami")
	waitCommand(t, rec, 1, CommandExited)

	var text strings.Builder
	truncated := false
	for _, p := range rec.of("command") {
		ev := p.v.(CommandEvent)
		if ev.State == CommandOutput {
			text.WriteString(ev.Chunk)
		}
		if ev.State == CommandExited && ev.Truncated {
			truncated = true
		}
	}
	s := text.String()
	if strings.Contains(s, "\x1b") || strings.Contains(s, "\r") {
		t.Fatalf("control characters survived: %q", s)
	}
	if !strings.Contains(s, "red") || !strings.Contains(s, "line") {
		t.Fatalf("text dropped: %q", s)
	}
	if strings.Contains(s, "8.8.8.8") || !strings.Contains(s, "127.0.0.1") {
		t.Fatalf("scrub wrong: %q", s)
	}
	if !truncated || len(s) > commandOutBytes {
		t.Fatalf("not capped: len=%d truncated=%v", len(s), truncated)
	}
	if err := r.Leave(id, token); err != nil {
		t.Fatal(err)
	}
	rec.waitFor(t, StateFinished)
	<-done
}

// waitCommand waits until a command event with the given seq and state has been published.
func waitCommand(t *testing.T, rec *recorder, seq int, state string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, p := range rec.of("command") {
			ev := p.v.(CommandEvent)
			if ev.Seq == seq && ev.State == state {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for command seq %d state %q; order=%s", seq, state, rec.order())
}

// runStates is the run events of one state, in order.
func runStates(rec *recorder, state string) []RunEvent {
	var out []RunEvent
	for _, p := range rec.of("run") {
		if ev := p.v.(RunEvent); ev.State == state {
			out = append(out, ev)
		}
	}
	return out
}

// A Falco alert that arrives more than 2 s after the command ended still becomes `detected` (without
// a command_seq), and Talon's response after it is not preceded by a second, made-up detection; a
// response with no alert at all gets one backfilled; a late response after a correlated detection
// gets none. Before, the late alert was dropped and `responded` was published alone, so the stats
// counted a run as answered but never detected.
func TestTerminalLateAlertIsDetected(t *testing.T) {
	cases := []struct {
		name          string
		falcoInWindow bool // the alert arrives while the command runs (correlated)
		falcoLate     bool // the alert arrives after the window
		wantDetected  []int
	}{
		{"late alert, late response", false, true, []int{0}},
		{"no alert, late response", false, false, []int{0}},
		{"correlated alert, late response", true, false, []int{1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := fake.NewClientset()
			readyOnCreate(c)
			rec := newRecorder()
			r := terminalRunner(c, &fakeExec{stdout: "x\n"}, rec)
			late := false
			var mu sync.Mutex
			// Once late is set, the clock is 3 s ahead, so the finished command is out of the window.
			r.now = func() time.Time {
				mu.Lock()
				defer mu.Unlock()
				if late {
					return time.Now().Add(3 * time.Second)
				}
				return time.Now()
			}
			release, done := released()
			sc := terminalScenario()
			id, token := r.StartTerminal(sc, release)
			pod := podName(sc.ID, id)
			rec.waitFor(t, StatePodReady)
			seq := sendCommand(t, r, id, token, "beacon")
			if tc.falcoInWindow {
				waitCommand(t, rec, seq, CommandStarted)
				r.ObserveFalco("sandbox", pod, "SDP network tool in sandbox")
			}
			waitCommand(t, rec, seq, CommandExited)
			mu.Lock()
			late = true
			mu.Unlock()
			if r.CommandSeqFor("sandbox", pod) != 0 {
				t.Fatal("the command is still inside the 2 s window")
			}
			if tc.falcoLate {
				r.ObserveFalco("sandbox", pod, "SDP network tool in sandbox")
				r.ObserveFalco("sandbox", pod, "SDP network tool in sandbox") // once per run
			}
			r.ObserveTalon("sandbox", pod, "success")
			rec.waitFor(t, StateResponded)
			_ = r.Leave(id, token)
			rec.waitFor(t, StateFinished)
			<-done

			o := rec.order()
			if !strings.Contains(o, "run:detected") || strings.Index(o, "run:detected") > strings.Index(o, "run:responded") {
				t.Fatalf("responded without a detection before it: %s", o)
			}
			var got []int
			for _, ev := range runStates(rec, StateDetected) {
				got = append(got, ev.CommandSeq)
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.wantDetected) {
				t.Fatalf("detected command_seqs = %v, want %v", got, tc.wantDetected)
			}
			if tc.falcoLate {
				if d := runStates(rec, StateDetected)[0].Detail; d != "SDP network tool in sandbox" {
					t.Fatalf("late detection detail = %q, want the rule", d)
				}
			}
			if rs := runStates(rec, StateResponded); len(rs) != 1 || rs[0].CommandSeq != 0 {
				t.Fatalf("responded = %+v", rs)
			}
		})
	}
}

// killExec stands in for the production ExecStream when Talon kills the pod under a command: the
// container dies, the stream reports the shell's SIGKILL as a clean exit 137, and it does so at once,
// before the pod watch has reported the deletion.
type killExec struct {
	fakeExec
	c *fake.Clientset
}

func (k *killExec) ExecStream(ctx context.Context, ns, pod, _ string, _ []string, _ bool, _, _ io.Writer) (int, error) {
	_ = k.c.CoreV1().Pods(ns).Delete(context.Background(), pod, metav1.DeleteOptions{})
	return 137, nil
}

// A command whose pod is deleted under it ends `killed`, even when the exec returns (137, nil) before
// the watch reports the deletion; before, it ended `exited` with exit_code 137 while the run ended
// `killed`.
func TestTerminalSignalExitIsKilled(t *testing.T) {
	for i := 0; i < 5; i++ {
		c := fake.NewClientset()
		readyOnCreate(c)
		rec := newRecorder()
		r := terminalRunner(c, &killExec{c: c}, rec)
		release, done := released()
		id, token := r.StartTerminal(terminalScenario(), release)
		rec.waitFor(t, StatePodReady)
		seq := sendCommand(t, r, id, token, "shell")
		if ev := rec.waitFor(t, StateFinished); ev.Detail != "killed" {
			t.Fatalf("run detail = %q", ev.Detail)
		}
		<-done
		for _, p := range rec.of("command") {
			if ev := p.v.(CommandEvent); ev.Seq == seq && ev.State != CommandStarted && ev.State != CommandOutput {
				if ev.State != CommandKilled || ev.ExitCode != nil {
					t.Fatalf("iteration %d: command ended %s exit_code=%v, want killed", i, ev.State, ev.ExitCode)
				}
			}
		}
	}
}

// An exit status above 128 with no pod deletion is still the command's own exit, reported once the
// bounded wait for a deletion has passed.
func TestTerminalSignalExitWithoutDeletion(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := terminalRunner(c, &fakeExec{code: 137}, rec)
	release, done := released()
	id, token := r.StartTerminal(terminalScenario(), release)
	rec.waitFor(t, StatePodReady)
	seq := sendCommand(t, r, id, token, "whoami")
	waitCommand(t, rec, seq, CommandExited)
	for _, p := range rec.of("command") {
		if ev := p.v.(CommandEvent); ev.Seq == seq && ev.State == CommandExited && (ev.ExitCode == nil || *ev.ExitCode != 137) {
			t.Fatalf("exited without exit_code 137: %+v", ev)
		}
	}
	_ = r.Leave(id, token)
	rec.waitFor(t, StateFinished)
	<-done
}

// A TTY shell that nobody kills does not hold the run (and the global slot) until the deadline: idle
// counts from the command's start and bounds the command, so with idle 1 s and a 4 s deadline the
// run ends `idle` about 1 s after the command started. Before, it ended `deadline` after 4 s.
func TestTerminalIdleBoundsTTYCommand(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := terminalRunner(c, &fakeExec{streamBlock: true}, rec)
	release, done := released()
	sc := terminalScenario()
	sc.IdleSeconds, sc.TimeoutSeconds = 1, 4
	id, token := r.StartTerminal(sc, release)
	rec.waitFor(t, StatePodReady)
	seq := sendCommand(t, r, id, token, "shell")
	ev := rec.waitFor(t, StateFinished)
	<-done
	if ev.Detail != "idle" {
		t.Fatalf("finish detail = %q, want idle", ev.Detail)
	}
	var startedAt time.Time
	for _, p := range rec.of("command") {
		if c := p.v.(CommandEvent); c.Seq == seq && c.State == CommandStarted {
			startedAt = c.At
		}
	}
	// Idle from the start: ~1 s. Idle from the command's end would be ~2 s (1 s bound + 1 s idle).
	if d := ev.At.Sub(startedAt); d > 1700*time.Millisecond {
		t.Fatalf("run ended %v after the command started; idle (1 s) should count from the start", d)
	}
}

// A TTY command is cut off at TTYCommandTimeout when the pod is not deleted: it ends `exited` with no
// exit code, and the run goes on accepting commands.
func TestTerminalTTYCommandBounded(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := New(c, &fakeExec{streamBlock: true}, rec, nil, Config{PollInterval: 10 * time.Millisecond, QuarantineLinger: -1,
		CommandTimeout: 100 * time.Millisecond, TTYCommandTimeout: 200 * time.Millisecond, DeleteWait: 200 * time.Millisecond})
	release, done := released()
	sc := terminalScenario()
	sc.IdleSeconds, sc.TimeoutSeconds = 30, 60
	id, token := r.StartTerminal(sc, release)
	rec.waitFor(t, StatePodReady)
	seq := sendCommand(t, r, id, token, "shell")
	waitCommand(t, rec, seq, CommandExited) // within waitCommand's 5 s, far below idle and deadline
	for _, p := range rec.of("command") {
		if ev := p.v.(CommandEvent); ev.Seq == seq && ev.State == CommandExited && ev.ExitCode != nil {
			t.Fatalf("a TTY command cut at its bound reported exit_code %d", *ev.ExitCode)
		}
	}
	next := sendCommand(t, r, id, token, "whoami")
	waitCommand(t, rec, next, CommandExited)
	_ = r.Leave(id, token)
	if ev := rec.waitFor(t, StateFinished); ev.Detail != "left" {
		t.Fatalf("finish detail = %q", ev.Detail)
	}
	<-done
}

// A leave (or a command) while the run's loop has ended and its pod is being deleted is 409: the run
// is over. Before, Leave answered 202 for a run that was already finishing for another reason.
func TestTerminalLeaveDuringCleanupIs409(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	deleting, unblock := make(chan struct{}), make(chan struct{})
	var once sync.Once
	c.PrependReactor("delete", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		once.Do(func() { close(deleting) })
		<-unblock
		return false, nil, nil
	})
	rec := newRecorder()
	r := terminalRunner(c, &fakeExec{}, rec)
	release, done := released()
	sc := terminalScenario()
	sc.IdleSeconds = 1
	id, token := r.StartTerminal(sc, release)
	rec.waitFor(t, StatePodReady)
	<-deleting // idle ended the loop; the cleanup's delete is in flight
	if err := r.Leave(id, token); !errors.Is(err, ErrRunBusy) {
		t.Fatalf("Leave during cleanup: %v, want ErrRunBusy", err)
	}
	if _, err := r.Command(id, token, "whoami"); !errors.Is(err, ErrRunBusy) {
		t.Fatalf("Command during cleanup: %v, want ErrRunBusy", err)
	}
	close(unblock)
	if ev := rec.waitFor(t, StateFinished); ev.Detail != "idle" {
		t.Fatalf("finish detail = %q, want idle", ev.Detail)
	}
	<-done
	// Released and unregistered: still 409, from the record of ended runs.
	if err := r.Leave(id, token); !errors.Is(err, ErrRunBusy) {
		t.Fatalf("Leave after the end: %v, want ErrRunBusy", err)
	}
}
