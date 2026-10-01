package runner

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/scenarios"
)

const img = "ghcr.io/hubertmj/self-defending-portfolio/scenario:main@sha256:0000000000000000000000000000000000000000000000000000000000000000"

// recorder is a Publisher that keeps run events and lets a test wait for a state.
type recorder struct {
	mu     sync.Mutex
	events []RunEvent
	ch     chan RunEvent
}

func newRecorder() *recorder { return &recorder{ch: make(chan RunEvent, 100)} }

func (r *recorder) Publish(typ string, v any) error {
	ev := v.(RunEvent)
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
	r.ch <- ev
	return nil
}

func (r *recorder) waitFor(t *testing.T, state string) RunEvent {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-r.ch:
			if ev.State == state {
				return ev
			}
		case <-deadline:
			t.Fatalf("timed out waiting for state %q; got %v", state, r.states())
		}
	}
}

func (r *recorder) states() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, e := range r.events {
		out = append(out, e.State)
	}
	return out
}

type fakeExec struct {
	mu    sync.Mutex
	calls []string
	tty   bool
	block bool
}

func (f *fakeExec) Exec(ctx context.Context, ns, pod, container string, cmd []string, tty bool) error {
	f.mu.Lock()
	f.calls = append(f.calls, ns+"/"+pod+"/"+container+":"+strings.Join(cmd, " "))
	f.tty = tty
	f.mu.Unlock()
	if f.block {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func (f *fakeExec) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

// readyOnCreate makes the fake API server report every created pod as Running and Ready, which is
// what the kubelet would do for a healthy scenario pod.
func readyOnCreate(c *fake.Clientset) {
	c.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		p := a.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
		p.Status.Phase = corev1.PodRunning
		p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		return false, nil, nil
	})
}

func scenario(response string, exec bool) scenarios.Scenario {
	sc := scenarios.Scenario{ID: "shell-in-container", Title: "t", Response: response, TimeoutSeconds: 1,
		Detection: "Terminal shell in container"}
	sc.Template.Labels = map[string]string{"app.kubernetes.io/name": "victim", LabelQuarantine: "true"}
	sc.Template.Spec.Containers = []corev1.Container{{Name: "victim", Image: img}}
	if exec {
		sc.Exec = &scenarios.Exec{Command: []string{"sh", "-c", "id"}, TTY: true}
	}
	return sc
}

func newTestRunner(c *fake.Clientset, ex Execer, rec *recorder) *Runner {
	return New(c, ex, rec, nil, Config{PollInterval: 10 * time.Millisecond, QuarantineLinger: -1})
}

func released() (func(), <-chan struct{}) {
	ch := make(chan struct{})
	var once sync.Once
	return func() { once.Do(func() { close(ch) }) }, ch
}

func podExists(t *testing.T, c *fake.Clientset, name string) bool {
	t.Helper()
	_, err := c.CoreV1().Pods("sandbox").Get(context.Background(), name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
	return err == nil
}

func TestTerminateRunLifecycle(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	ex := &fakeExec{}
	r := newTestRunner(c, ex, rec)
	release, done := released()

	sc := scenario("terminate", true)
	sc.TimeoutSeconds = 30
	id := r.Start(sc, release)
	pod := podName(sc.ID, id)

	rec.waitFor(t, StateQueued)
	started := rec.waitFor(t, StateStarted)
	if started.RunID != id || started.Scenario != "shell-in-container" {
		t.Fatalf("started event: %+v", started)
	}

	p, err := c.CoreV1().Pods("sandbox").Get(context.Background(), pod, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Labels[LabelRunID] != id || p.Labels[LabelQuarantine] != "false" || p.Labels[LabelManagedBy] != ManagedBy ||
		p.Labels["app.kubernetes.io/name"] != "victim" {
		t.Fatalf("labels: %v", p.Labels)
	}
	if *p.Spec.ActiveDeadlineSeconds != 30 || *p.Spec.AutomountServiceAccountToken || *p.Spec.EnableServiceLinks ||
		p.Spec.RestartPolicy != corev1.RestartPolicyNever {
		t.Fatalf("spec hardening not applied: %+v", p.Spec)
	}

	// Unrelated pods and failed actions do not move the run.
	r.ObserveFalco("someone-else")
	r.ObserveTalon(pod, "failure")
	r.ObserveFalco(pod)
	r.ObserveFalco(pod) // duplicates are harmless
	if ev := rec.waitFor(t, StateDetected); ev.Detail != "Terminal shell in container" {
		t.Fatalf("detected detail %q", ev.Detail)
	}
	// Talon deletes the pod before it reports.
	_ = c.CoreV1().Pods("sandbox").Delete(context.Background(), pod, metav1.DeleteOptions{})
	r.ObserveTalon(pod, "success")
	rec.waitFor(t, StateResponded)
	rec.waitFor(t, StateFinished)
	<-done

	if got := strings.Join(rec.states(), ","); got != "queued,started,detected,responded,finished" {
		t.Fatalf("states = %s", got)
	}
	if ex.count() != 1 || !ex.tty {
		t.Fatalf("exec calls = %v tty=%v", ex.calls, ex.tty)
	}
	if r.lookup(pod) != nil {
		t.Fatal("run still registered after it ended")
	}
}

func TestQuarantineRunDeletesPod(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := newTestRunner(c, &fakeExec{block: true}, rec)
	release, done := released()
	sc := scenario("quarantine", true)
	sc.TimeoutSeconds = 30
	id := r.Start(sc, release)
	pod := podName(sc.ID, id)
	rec.waitFor(t, StateStarted)
	// The response arrives before the alert: detected is still reported, first.
	r.ObserveTalon(pod, "success")
	<-done
	if got := strings.Join(rec.states(), ","); got != "queued,started,detected,responded,finished" {
		t.Fatalf("states = %s", got)
	}
	if podExists(t, c, pod) {
		t.Fatal("quarantined pod was not cleaned up")
	}
}

func TestTimeoutCleansUp(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := newTestRunner(c, &fakeExec{}, rec)
	release, done := released()
	sc := scenario("terminate", false)
	id := r.Start(sc, release)
	rec.waitFor(t, StateStarted)
	r.ObserveFalco(podName(sc.ID, id))
	ev := rec.waitFor(t, StateTimeout)
	<-done
	if !strings.Contains(ev.Detail, "detected") {
		t.Fatalf("timeout detail = %q", ev.Detail)
	}
	if podExists(t, c, podName(sc.ID, id)) {
		t.Fatal("pod left behind after timeout")
	}
}

func TestPodNeverReady(t *testing.T) {
	c := fake.NewClientset() // no readiness reactor
	rec := newRecorder()
	r := newTestRunner(c, &fakeExec{}, rec)
	release, done := released()
	sc := scenario("terminate", true)
	id := r.Start(sc, release)
	rec.waitFor(t, StateTimeout)
	<-done
	if podExists(t, c, podName(sc.ID, id)) {
		t.Fatal("pod left behind")
	}
}

func TestAdmissionRejection(t *testing.T) {
	c := fake.NewClientset()
	c.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "x",
			errorString("admission webhook \"validate.kyverno.svc-fail\" denied the request"))
	})
	rec := newRecorder()
	r := newTestRunner(c, &fakeExec{}, rec)
	release, done := released()
	r.Start(scenario("terminate", true), release)
	ev := rec.waitFor(t, StateFailed)
	<-done
	if !strings.Contains(ev.Detail, "admission refused") {
		t.Fatalf("detail = %q", ev.Detail)
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }

func TestShutdownCleansUp(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := newTestRunner(c, &fakeExec{block: true}, rec)
	release, done := released()
	sc := scenario("terminate", true)
	sc.TimeoutSeconds = 60
	id := r.Start(sc, release)
	rec.waitFor(t, StateStarted)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	<-done
	if podExists(t, c, podName(sc.ID, id)) {
		t.Fatal("pod left behind on shutdown")
	}
}

func TestCleanupOrphans(t *testing.T) {
	orphan := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "old", Namespace: "sandbox",
		Labels: map[string]string{LabelManagedBy: ManagedBy}}}
	foreign := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "runtime-test-victim", Namespace: "sandbox"}}
	c := fake.NewClientset(orphan, foreign)
	r := newTestRunner(c, &fakeExec{}, newRecorder())
	if err := r.CleanupOrphans(context.Background()); err != nil {
		t.Fatal(err)
	}
	if podExists(t, c, "old") {
		t.Fatal("orphan not deleted")
	}
	if !podExists(t, c, "runtime-test-victim") {
		t.Fatal("a pod this API does not manage was deleted")
	}
}

func TestRunEventJSON(t *testing.T) {
	b, _ := json.Marshal(RunEvent{RunID: "r", Scenario: "s", State: StateQueued, At: time.Unix(0, 0).UTC()})
	want := `{"run_id":"r","scenario":"s","state":"queued","at":"1970-01-01T00:00:00Z","detail":""}`
	if string(b) != want {
		t.Fatalf("%s", b)
	}
}

func TestPodName(t *testing.T) {
	if n := podName(strings.Repeat("a", 40), newRunID()); len(n) > 63 {
		t.Fatalf("pod name %q is %d characters", n, len(n))
	}
}
