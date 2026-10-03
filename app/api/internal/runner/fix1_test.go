package runner

import (
	"context"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// FIX 1 (item 12): a quarantine run with no victim poller lingers a short fixed time, not the full
// cap - there is no `unreachable` to wait for, so waiting the cap would just stall the slot.
func TestQuarantineNoVictimShortLinger(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := New(c, &fakeExec{block: true}, rec, nil, Config{PollInterval: 10 * time.Millisecond,
		QuarantineLinger: 300 * time.Millisecond, QuarantineLingerMax: 10 * time.Second})
	release, done := released()
	sc := scenario("quarantine", true)
	sc.Victim, sc.TimeoutSeconds = false, 30 // no victim app, so no `unreachable`
	id := start(t, r, sc, release)
	pod := podName(sc.ID, id)
	rec.waitFor(t, StatePodReady)
	r.ObserveTalon("sandbox", pod, "success", "")
	respondedAt := rec.waitFor(t, StateResponded).At
	finishedAt := rec.waitFor(t, StateFinished).At
	<-done
	if d := finishedAt.Sub(respondedAt); d > 3*time.Second {
		t.Fatalf("quarantine without a poller lingered %v; expected a short fixed linger, not the 10 s cap", d)
	}
	// And it does linger: the pod is not deleted the instant Talon answers.
	if d := finishedAt.Sub(respondedAt); d < 300*time.Millisecond {
		t.Fatalf("quarantine without a poller lingered only %v; expected QuarantineLinger (300 ms)", d)
	}
	if podExists(t, c, pod) {
		t.Fatal("pod not cleaned up after the linger")
	}
}

// FIX 1 (item 11): a pod deleted during the linger ends the wait at once, not at the cap.
func TestQuarantineLingerEndsOnGone(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := New(c, &fakeExec{block: true}, rec, nil, Config{PollInterval: 10 * time.Millisecond, DeleteWait: 50 * time.Millisecond,
		QuarantineLinger: 50 * time.Millisecond, QuarantineLingerMax: 30 * time.Second})
	release, done := released()
	sc := scenario("quarantine", true)
	sc.Victim, sc.TimeoutSeconds = false, 30
	id := start(t, r, sc, release)
	pod := podName(sc.ID, id)
	rec.waitFor(t, StatePodReady)
	r.ObserveTalon("sandbox", pod, "success", "")
	respondedAt := rec.waitFor(t, StateResponded).At
	// Something else deletes the pod mid-linger: the run must not wait the 30 s cap.
	go func() {
		time.Sleep(80 * time.Millisecond)
		_ = c.CoreV1().Pods("sandbox").Delete(context.Background(), pod, metav1.DeleteOptions{})
	}()
	finishedAt := rec.waitFor(t, StateFinished).At
	<-done
	if d := finishedAt.Sub(respondedAt); d > 5*time.Second {
		t.Fatalf("linger ignored the pod deletion: waited %v", d)
	}
}

// FIX 1: when the victim does go `unreachable`, the run lingers from that event (the visible cut),
// not from a fixed delay or the cap, and the cut is published before the run finishes. The cap (3 s)
// is well inside waitFor's 5 s, and the end must come long before it, so a run that missed the cut
// and sat out the cap fails here on the assertion, not by the helper timing out.
func TestQuarantineLingersFromUnreachable(t *testing.T) {
	app := newVictimApp(t)
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := New(c, defacer{app}, rec, nil, Config{PollInterval: 10 * time.Millisecond,
		QuarantineLinger: 50 * time.Millisecond, QuarantineLingerMax: 3 * time.Second,
		VictimPort: app.port, VictimInterval: 20 * time.Millisecond, VictimTimeout: 200 * time.Millisecond})
	release, done := released()
	sc := scenario("quarantine", true)
	sc.Victim, sc.TimeoutSeconds = true, 30
	id := start(t, r, sc, release)
	pod := podName(sc.ID, id)
	waitOrder(t, rec, "victim:defaced")
	r.ObserveTalon("sandbox", pod, "success", "")
	respondedAt := rec.waitFor(t, StateResponded).At
	// The quarantine policy cuts the pod: the app stops answering.
	app.srv.CloseClientConnections()
	_ = app.srv.Listener.Close()
	finishedAt := rec.waitFor(t, StateFinished).At
	<-done
	if d := finishedAt.Sub(respondedAt); d > 1500*time.Millisecond {
		t.Fatalf("finished %v after the response; the cut should end the linger well before the 3 s cap", d)
	}
	o := rec.order()
	if !strings.Contains(o, "victim:unreachable") {
		t.Fatalf("no unreachable before finish: %s", o)
	}
	if strings.Index(o, "victim:unreachable") > strings.LastIndex(o, "run:finished") {
		t.Fatalf("finished before the cut was published: %s", o)
	}
}

// gatedPub holds the run's `responded` event until the test opens the gate, so the test can make the
// cut visible in the window between Talon's webhook and the run goroutine reaching the linger.
type gatedPub struct {
	*recorder
	gate chan struct{}
}

func (g gatedPub) Publish(typ string, v any) error {
	if ev, ok := v.(RunEvent); ok && ev.State == StateResponded {
		<-g.gate
	}
	return g.recorder.Publish(typ, v)
}

// FIX 1, item 10: the cut is published after Talon's response was observed but before the run
// goroutine reaches the linger. It is a cut after the response, so the linger ends from it. Before,
// the linger drained that signal as "seen before the response" and waited the full cap for a second
// `unreachable` that the poller (which publishes changes only) never sends.
func TestQuarantineCutBeforeLingerCounts(t *testing.T) {
	app := newVictimApp(t)
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	pub := gatedPub{rec, make(chan struct{})}
	r := New(c, defacer{app}, pub, nil, Config{PollInterval: 10 * time.Millisecond,
		QuarantineLinger: 50 * time.Millisecond, QuarantineLingerMax: 3 * time.Second,
		VictimPort: app.port, VictimInterval: 20 * time.Millisecond, VictimTimeout: 200 * time.Millisecond})
	release, done := released()
	sc := scenario("quarantine", true)
	sc.Victim, sc.TimeoutSeconds = true, 30
	id := start(t, r, sc, release)
	pod := podName(sc.ID, id)
	waitOrder(t, rec, "victim:defaced")
	r.ObserveTalon("sandbox", pod, "success", "") // the run goroutine now blocks publishing `responded`
	app.srv.CloseClientConnections()
	_ = app.srv.Listener.Close()
	waitOrder(t, rec, "victim:unreachable") // the cut is on record before the linger has begun
	opened := time.Now()
	close(pub.gate)
	rec.waitFor(t, StateFinished)
	<-done
	if d := time.Since(opened); d > 1500*time.Millisecond {
		t.Fatalf("the run lingered %v after a cut that followed the response; want ~QuarantineLinger, not the 3 s cap", d)
	}
}
