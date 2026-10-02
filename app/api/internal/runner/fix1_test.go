package runner

import (
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
)

// FIX 1: a quarantine run with no `unreachable` event still ends, but only after the linger cap,
// not immediately - the old fixed linger deleted the pod before Cilium had cut it off.
func TestQuarantineLingersUntilCap(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	// Linger enabled: grace 50 ms after the first unreachable, capped at 250 ms overall.
	r := New(c, &fakeExec{block: true}, rec, nil, Config{PollInterval: 10 * time.Millisecond,
		QuarantineLinger: 50 * time.Millisecond, QuarantineLingerMax: 250 * time.Millisecond})
	release, done := released()
	sc := scenario("quarantine", true)
	sc.Victim, sc.TimeoutSeconds = false, 30 // no victim app, so no `unreachable`: the cap governs
	id := r.Start(sc, release)
	pod := podName(sc.ID, id)
	rec.waitFor(t, StatePodReady)
	r.ObserveTalon(pod, "success")
	respondedAt := rec.waitFor(t, StateResponded).At
	finishedAt := rec.waitFor(t, StateFinished).At
	<-done
	if d := finishedAt.Sub(respondedAt); d < 150*time.Millisecond {
		t.Fatalf("quarantine lingered only %v; the cap (250 ms) should hold the pod", d)
	}
	if podExists(t, c, pod) {
		t.Fatal("pod not cleaned up after the linger")
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
	r.ObserveTalon(pod, "success")
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
