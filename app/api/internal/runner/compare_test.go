package runner

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/scenarios"
)

func compareRunner(c *fake.Clientset, ex Execer, rec *recorder) *Runner {
	return New(c, ex, rec, nil, Config{PollInterval: 10 * time.Millisecond, QuarantineLinger: -1,
		DeleteWait: 100 * time.Millisecond, UnguardedNamespace: "sandbox-unguarded", CompareHold: 50 * time.Millisecond})
}

func TestCompareTwoArms(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	ex := &fakeExec{} // returns at once, so the exec follows the pre-exec
	r := compareRunner(c, ex, rec)
	var mu sync.Mutex
	var releasedAt time.Time
	done := make(chan struct{})
	release := func() { mu.Lock(); releasedAt = time.Now(); mu.Unlock(); close(done) }

	sc := scenario("terminate", true)
	sc.TimeoutSeconds = 30
	sc.PreExec = &scenarios.Exec{Command: []string{"sh", "-c", "deface"}}
	id := startCompare(t, r, sc, release)
	guardedPod := podName(sc.ID, id)
	unguardedPod := guardedPod + "-u"

	// Observe through the event stream, not the fake clientset (polling it concurrently with the
	// runner's creates is itself racy in client-go's fake).
	rec.waitFor(t, StatePodReady) // the guarded arm is up
	waitArm(t, rec, "guarded", false)
	waitArm(t, rec, "unguarded", false)

	if !hasPodsMap(rec) {
		t.Fatalf("run event missing pods map: %s", rec.order())
	}
	if got := r.ArmFor("sandbox-unguarded", unguardedPod); got != "unguarded" {
		t.Fatalf("ArmFor(unguarded) = %q", got)
	}
	if got := r.ArmFor("sandbox", guardedPod); got != "guarded" {
		t.Fatalf("ArmFor(guarded) = %q", got)
	}

	// The guarded arm responds (terminate): its pod is deleted; the unguarded one is held CompareHold,
	// then the API deletes it - which the watch reports as a `pod` Deleted event for that arm.
	_ = c.CoreV1().Pods("sandbox").Delete(context.Background(), guardedPod, metav1.DeleteOptions{})
	r.ObserveTalon("sandbox", guardedPod, "success", "")
	finished := rec.waitFor(t, StateFinished)
	waitArm(t, rec, "unguarded", true) // the twin was cleaned up
	<-done

	// The run is `finished` only once both pods are gone - the twin's deletion is published before it
	// - and the slot is released only after it, so the page cannot start a new run while the twin is
	// still up.
	twinDeleted, finishedAt := -1, -1
	rec.mu.Lock()
	for i, p := range rec.all {
		if ev, ok := p.v.(PodEvent); ok && ev.Arm == "unguarded" && ev.Deleted {
			twinDeleted = i
		}
		if ev, ok := p.v.(RunEvent); ok && ev.State == StateFinished {
			finishedAt = i
		}
	}
	rec.mu.Unlock()
	if twinDeleted < 0 || twinDeleted > finishedAt {
		t.Fatalf("finished (event %d) published before the twin was deleted (event %d): %s", finishedAt, twinDeleted, rec.order())
	}
	mu.Lock()
	if releasedAt.Before(finished.At) {
		t.Fatal("the slot was released before the run finished")
	}
	mu.Unlock()

	// The same attack in both pods: the pre-exec, then the exec, in each.
	ex.mu.Lock()
	calls := strings.Join(ex.calls, "\n")
	ex.mu.Unlock()
	for _, want := range []string{
		"sandbox/" + guardedPod + "/victim:sh -c deface", "sandbox/" + guardedPod + "/victim:sh -c id",
		"sandbox-unguarded/" + unguardedPod + "/victim:sh -c deface", "sandbox-unguarded/" + unguardedPod + "/victim:sh -c id",
	} {
		if !strings.Contains(calls, want) {
			t.Fatalf("exec %q not sent; calls:\n%s", want, calls)
		}
	}
}

func TestCompareFallsBackWithoutTwin(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := New(c, &fakeExec{block: true}, rec, nil, Config{PollInterval: 10 * time.Millisecond, QuarantineLinger: -1})
	release, done := released()
	sc := scenario("terminate", true)
	sc.TimeoutSeconds = 30
	id := startCompare(t, r, sc, release)
	// Wait until the pod is Ready (waitReady's Gets are done) before deleting it, so the delete
	// cannot race the first Get on the fake clientset (a test-only client-go hazard).
	rec.waitFor(t, StatePodReady)
	_ = c.CoreV1().Pods("sandbox").Delete(context.Background(), podName(sc.ID, id), metav1.DeleteOptions{})
	r.ObserveTalon("sandbox", podName(sc.ID, id), "success", "")
	rec.waitFor(t, StateFinished)
	<-done
	if hasPodsMap(rec) {
		t.Fatal("single run should not carry a pods map")
	}
}

// waitArm waits for a `pod` event stamped with arm and the given deleted flag.
func waitArm(t *testing.T, rec *recorder, arm string, deleted bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, p := range rec.of("pod") {
			if ev, ok := p.v.(PodEvent); ok && ev.Arm == arm && ev.Deleted == deleted {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no pod event arm=%q deleted=%v; order=%s", arm, deleted, rec.order())
}

func hasPodsMap(rec *recorder) bool {
	for _, p := range rec.of("run") {
		if ev, ok := p.v.(RunEvent); ok && len(ev.Pods) == 2 {
			return true
		}
	}
	return false
}

// A terminal scenario handed to Start or StartCompare is refused with ErrInteractive - with the twin
// configured and without it - and nothing is started: no event, no pod, release not called. Before,
// StartCompare fell back to Start, whose run had none of the terminal loop's channels, and the loop's
// end crashed the whole process with `close of nil channel`.
func TestStartRefusesInteractive(t *testing.T) {
	for _, twin := range []string{"sandbox-unguarded", ""} {
		c := fake.NewClientset()
		readyOnCreate(c)
		rec := newRecorder()
		r := New(c, &fakeExec{}, rec, nil, Config{PollInterval: 10 * time.Millisecond, QuarantineLinger: -1,
			UnguardedNamespace: twin})
		released := 0
		release := func() { released++ }
		sc := terminalScenario()
		sc.IdleSeconds = 1 // a wrongly started run reaches the end of its loop within a second
		if _, err := r.StartCompare(sc, release); !errors.Is(err, ErrInteractive) {
			t.Fatalf("twin %q: StartCompare(terminal) err = %v, want ErrInteractive", twin, err)
		}
		if _, err := r.Start(sc, release); !errors.Is(err, ErrInteractive) {
			t.Fatalf("twin %q: Start(terminal) err = %v, want ErrInteractive", twin, err)
		}
		// Let a run that was started anyway get to its end (and crash), then wait for it.
		time.Sleep(1500 * time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := r.Shutdown(ctx); err != nil {
			t.Fatal(err)
		}
		cancel()
		if released != 0 || len(rec.of("run")) != 0 {
			t.Fatalf("twin %q: a refused scenario was started: release called %d times, events %s", twin, released, rec.order())
		}
		for _, ns := range []string{"sandbox", "sandbox-unguarded"} {
			if l, _ := c.CoreV1().Pods(ns).List(context.Background(), metav1.ListOptions{}); len(l.Items) != 0 {
				t.Fatalf("twin %q: a pod was created in %s", twin, ns)
			}
		}
	}
}

// The API's own deletion of the twin is not the victim being killed: the unguarded arm publishes no
// `gone` (ADR 0021: `gone` is someone else's delete) and no `unreachable`, while the guarded arm, which
// Talon terminated, does publish `gone`.
func TestCompareTwinDeleteIsNotGone(t *testing.T) {
	app := newVictimApp(t)
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := New(c, &fakeExec{block: true}, rec, nil, Config{PollInterval: 10 * time.Millisecond, QuarantineLinger: -1,
		DeleteWait: 100 * time.Millisecond, UnguardedNamespace: "sandbox-unguarded", CompareHold: 200 * time.Millisecond,
		VictimPort: app.port, VictimInterval: 20 * time.Millisecond, VictimTimeout: 200 * time.Millisecond})
	release, done := released()
	sc := scenario("terminate", true)
	sc.Victim, sc.TimeoutSeconds = true, 30
	id := startCompare(t, r, sc, release)
	guardedPod := podName(sc.ID, id)
	rec.waitFor(t, StatePodReady)
	waitVictim(t, rec, "guarded", VictimUp)
	waitVictim(t, rec, "unguarded", VictimUp)
	_ = c.CoreV1().Pods("sandbox").Delete(context.Background(), guardedPod, metav1.DeleteOptions{})
	r.ObserveTalon("sandbox", guardedPod, "success", "")
	rec.waitFor(t, StateFinished)
	<-done
	waitVictim(t, rec, "guarded", VictimGone)
	for _, p := range rec.of("victim") {
		if ev := p.v.(VictimEvent); ev.Arm == "unguarded" && (ev.Status == VictimGone || ev.Status == VictimUnreachable) {
			t.Fatalf("the twin's own cleanup was published as victim %q", ev.Status)
		}
	}
}

// waitVictim waits for a `victim` event of the given arm and status.
func waitVictim(t *testing.T, rec *recorder, arm, status string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, p := range rec.of("victim") {
			if ev := p.v.(VictimEvent); ev.Arm == arm && ev.Status == status {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no victim %q event for arm %q; order=%s", status, arm, rec.order())
}
