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
		QuarantineLinger: 60 * time.Millisecond, QuarantineLingerMax: 10 * time.Second})
	release, done := released()
	sc := scenario("quarantine", true)
	sc.Victim, sc.TimeoutSeconds = false, 30 // no victim app, so no `unreachable`
	id := r.Start(sc, release)
	pod := podName(sc.ID, id)
	rec.waitFor(t, StatePodReady)
	r.ObserveTalon("sandbox", pod, "success")
	respondedAt := rec.waitFor(t, StateResponded).At
	finishedAt := rec.waitFor(t, StateFinished).At
	<-done
	if d := finishedAt.Sub(respondedAt); d > 3*time.Second {
		t.Fatalf("quarantine without a poller lingered %v; expected a short fixed linger, not the 10 s cap", d)
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
	id := r.Start(sc, release)
	pod := podName(sc.ID, id)
	rec.waitFor(t, StatePodReady)
	r.ObserveTalon("sandbox", pod, "success")
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
// not from a fixed delay, and the cut is published before the run finishes.
func TestQuarantineLingersFromUnreachable(t *testing.T) {
	app := newVictimApp(t)
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := New(c, defacer{app}, rec, nil, Config{PollInterval: 10 * time.Millisecond,
		QuarantineLinger: 50 * time.Millisecond, QuarantineLingerMax: 5 * time.Second,
		VictimPort: app.port, VictimInterval: 20 * time.Millisecond, VictimTimeout: 200 * time.Millisecond})
	release, done := released()
	sc := scenario("quarantine", true)
	sc.Victim, sc.TimeoutSeconds = true, 30
	id := r.Start(sc, release)
	pod := podName(sc.ID, id)
	waitOrder(t, rec, "victim:defaced")
	r.ObserveTalon("sandbox", pod, "success")
	rec.waitFor(t, StateResponded)
	// The quarantine policy cuts the pod: the app stops answering.
	app.srv.CloseClientConnections()
	_ = app.srv.Listener.Close()
	rec.waitFor(t, StateFinished)
	<-done
	o := rec.order()
	if !strings.Contains(o, "victim:unreachable") {
		t.Fatalf("no unreachable before finish: %s", o)
	}
	if strings.Index(o, "victim:unreachable") > strings.LastIndex(o, "run:finished") {
		t.Fatalf("finished before the cut was published: %s", o)
	}
}
