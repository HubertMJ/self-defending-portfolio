package runner

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func compareRunner(c *fake.Clientset, ex Execer, rec *recorder) *Runner {
	return New(c, ex, rec, nil, Config{PollInterval: 10 * time.Millisecond, QuarantineLinger: -1,
		DeleteWait: 100 * time.Millisecond, UnguardedNamespace: "sandbox-unguarded", CompareHold: 50 * time.Millisecond})
}

func TestCompareTwoArms(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := compareRunner(c, &fakeExec{block: true}, rec)
	release, done := released()

	sc := scenario("terminate", true)
	sc.TimeoutSeconds = 30
	id := r.StartCompare(sc, release)
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
	if got := r.ArmFor(unguardedPod); got != "unguarded" {
		t.Fatalf("ArmFor(unguarded) = %q", got)
	}
	if got := r.ArmFor(guardedPod); got != "guarded" {
		t.Fatalf("ArmFor(guarded) = %q", got)
	}

	// The guarded arm responds (terminate): its pod is deleted; the unguarded one is held CompareHold,
	// then the API deletes it - which the watch reports as a `pod` Deleted event for that arm.
	_ = c.CoreV1().Pods("sandbox").Delete(context.Background(), guardedPod, metav1.DeleteOptions{})
	r.ObserveTalon(guardedPod, "success")
	rec.waitFor(t, StateFinished)
	waitArm(t, rec, "unguarded", true) // the twin was cleaned up
	<-done
}

func TestCompareFallsBackWithoutTwin(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := New(c, &fakeExec{block: true}, rec, nil, Config{PollInterval: 10 * time.Millisecond, QuarantineLinger: -1})
	release, done := released()
	sc := scenario("terminate", true)
	sc.TimeoutSeconds = 30
	id := r.StartCompare(sc, release)
	rec.waitFor(t, StateStarted)
	_ = c.CoreV1().Pods("sandbox").Delete(context.Background(), podName(sc.ID, id), metav1.DeleteOptions{})
	r.ObserveTalon(podName(sc.ID, id), "success")
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
