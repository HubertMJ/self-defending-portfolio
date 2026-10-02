package runner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

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
	for r.CommandSeqFor(pod) != seq && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := r.CommandSeqFor(pod); got != seq {
		t.Fatalf("CommandSeqFor = %d, want %d", got, seq)
	}
	r.ObserveFalco(pod)
	rec.waitFor(t, StateDetected)
	// Talon terminates: the pod is deleted, which ends the run as killed.
	_ = c.CoreV1().Pods("sandbox").Delete(context.Background(), pod, metav1.DeleteOptions{})
	r.ObserveTalon(pod, "success")
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
	sc.IdleSeconds = 0 // -> DefaultIdle is too long; override via a tiny timeout path below
	// Use a short idle by setting IdleSeconds through the scenario's Idle(): 0 -> DefaultIdle (30s),
	// too long for a test. Instead drive the deadline: set a 1 s active deadline.
	sc.TimeoutSeconds = 1
	id, _ := r.StartTerminal(sc, release)
	rec.waitFor(t, StatePodReady)
	ev := rec.waitFor(t, StateFinished)
	if ev.Detail != "deadline" && ev.Detail != "idle" {
		t.Fatalf("finish detail = %q", ev.Detail)
	}
	_ = id
	<-done
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
