package runner

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/events"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/runlog"
)

// lineExec prints n short lines, one write each - the most `output` events a command can make, since
// the sink publishes what one write completes - and exits 0.
type lineExec struct {
	fakeExec
	n int
}

func (l *lineExec) ExecStream(_ context.Context, _, _, _ string, _ []string, _ bool, stdout, _ io.Writer) (int, error) {
	for range l.n {
		_, _ = io.WriteString(stdout, "line\n")
	}
	return 0, nil
}

// End to end with the real hub and run log (item 2): a terminal run that produces the maximum number
// of `output` events (runOutEvents) while a Falco rule fires in a loop on its pod still has, in GET
// /api/runs/{id}, every command's end event, and ends with its final `finished`. An SSE subscriber
// that falls a whole command's burst behind is not dropped for it.
func TestRunHistoryKeepsEndsAtMaximumOutput(t *testing.T) {
	hub := events.NewHub(100)
	store := runlog.New(0, 0, 0, 0)
	hub.Tap(store.Record)
	c := fake.NewClientset()
	readyOnCreate(c)
	r := New(c, &lineExec{n: commandOutEvents + 10}, hub, nil, Config{PollInterval: 10 * time.Millisecond,
		QuarantineLinger: -1, CommandTimeout: 500 * time.Millisecond, DeleteWait: 100 * time.Millisecond})
	release, done := released()
	sc := terminalScenario()
	id, token := r.StartTerminal(sc, release)
	pod := podName(sc.ID, id)

	// A viewer that stops reading for exactly one command: the burst fits its buffer.
	sub, _ := hub.Subscribe(0)
	defer hub.Unsubscribe(sub)
	drain := func() {
		for {
			select {
			case _, ok := <-sub.C:
				if !ok {
					t.Fatal("the SSE subscriber was dropped by one command's burst")
				}
			default:
				return
			}
		}
	}

	seqs := map[int]bool{}
	runCmd := func() {
		deadline := time.Now().Add(5 * time.Second)
		for {
			seq, err := r.Command(id, token, "whoami")
			if err == nil {
				seqs[seq] = true
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("command: %v", err)
			}
			time.Sleep(5 * time.Millisecond)
		}
		for r.lookupID(id).isRunning() {
			time.Sleep(2 * time.Millisecond)
		}
	}
	drain()
	runCmd() // one command, unread by the subscriber
	if hub.Subscribers() != 1 {
		t.Fatal("the SSE subscriber was dropped by one command's burst")
	}
	drain()
	for len(seqs) < runOutEvents/commandOutEvents+1 { // enough to reach the per-run output cap
		runCmd()
		drain()
	}
	for range 300 { // a rule firing in a loop on the run's pod
		_ = hub.Publish("falco", map[string]string{"pod": pod, "rule": "loop"})
		drain()
	}
	for range 5 { // commands after the flood: no output left in the run's budget, but they end
		runCmd()
		drain()
	}
	if err := r.Leave(id, token); err != nil {
		t.Fatal(err)
	}
	<-done

	run, ok := store.Get(id)
	if !ok {
		t.Fatal("run not recorded")
	}
	if !run.Truncated {
		t.Fatalf("expected the flood to truncate the run (%d events)", len(run.Events))
	}
	outputs, ended := 0, map[int]bool{}
	for _, e := range run.Events {
		var d struct {
			Seq   int    `json:"seq"`
			State string `json:"state"`
		}
		_ = json.Unmarshal(e.Data, &d)
		if e.Type == "command" && d.State == CommandOutput {
			outputs++
		}
		if e.Type == "command" && (d.State == CommandExited || d.State == CommandKilled) {
			ended[d.Seq] = true
		}
	}
	if outputs != runOutEvents {
		t.Fatalf("the run recorded %d output events; the test needs the maximum, %d", outputs, runOutEvents)
	}
	for seq := range seqs {
		if !ended[seq] {
			t.Fatalf("command %d has no end event in /api/runs/{id}", seq)
		}
	}
	last := run.Events[len(run.Events)-1]
	if last.Type != "run" || !strings.Contains(string(last.Data), `"state":"finished"`) {
		t.Fatalf("/api/runs/{id} ends with %s %s, not the final finished", last.Type, last.Data)
	}
}

// isRunning reports whether a command of the run is executing.
func (rn *run) isRunning() bool {
	rn.tmu.Lock()
	defer rn.tmu.Unlock()
	return rn.running
}
