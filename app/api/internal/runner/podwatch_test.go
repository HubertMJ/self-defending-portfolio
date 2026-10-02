package runner

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// waitOrder waits until the recorder's event order contains want.
func waitOrder(t *testing.T, rec *recorder, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(rec.order(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("order %q does not contain %q", rec.order(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPodEventsFollowThePod(t *testing.T) {
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := newTestRunner(c, &fakeExec{block: true}, rec)
	release, done := released()
	sc := scenario("quarantine", true)
	sc.TimeoutSeconds = 30
	id := start(t, r, sc, release)
	pod := podName(sc.ID, id)
	rec.waitFor(t, StatePodReady)
	waitOrder(t, rec, "pod:Running")

	first := rec.of("pod")[0].v.(PodEvent)
	if first.RunID != id || first.Pod != pod || first.UID != "0b6c1d6e-0000-4000-8000-000000000001" ||
		first.ContainerID != "4f1c2b3a5d6e" || first.Deleted ||
		first.Image != "ghcr.io/hubertmj/self-defending-portfolio/scenario@sha256:"+strings.Repeat("ab", 32) {
		t.Fatalf("first pod event: %+v", first)
	}
	if v := first.LabelsDelta[LabelQuarantine]; v == nil || *v != "false" || len(first.LabelsDelta) != 5 {
		t.Fatalf("first labels_delta: %v", first.LabelsDelta)
	}

	// Talon's label lands: only that label is in the delta.
	p, err := c.CoreV1().Pods("sandbox").Get(context.Background(), pod, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p.Labels[LabelQuarantine] = "true"
	if _, err := c.CoreV1().Pods("sandbox").Update(context.Background(), p, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(rec.of("pod")) < 2 {
		if time.Now().After(deadline) {
			t.Fatal("no pod event for the label change")
		}
		time.Sleep(5 * time.Millisecond)
	}
	second := rec.of("pod")[1].v.(PodEvent)
	if v, ok := second.LabelsDelta[LabelQuarantine]; !ok || v == nil || *v != "true" || len(second.LabelsDelta) != 1 {
		t.Fatalf("label delta: %v", second.LabelsDelta)
	}

	r.ObserveTalon("sandbox", pod, "success")
	<-done
	// The cleanup's deletion is reported before the run's final state.
	if o := rec.order(); !strings.HasSuffix(o, "pod:Deleted run:finished") {
		t.Fatalf("order: %s", o)
	}
	last := rec.of("pod")
	if ev := last[len(last)-1].v.(PodEvent); !ev.Deleted || len(ev.LabelsDelta) != 0 {
		t.Fatalf("deleted event: %+v", ev)
	}
	// Nothing about the node or the network is ever published.
	for _, p := range rec.all {
		for _, secret := range []string{"node-secret", "192.0.2.77", "127.0.0.1", "nodeName", "hostIP", "podIP"} {
			if strings.Contains(p.json, secret) {
				t.Fatalf("%s event leaks %q: %s", p.typ, secret, p.json)
			}
		}
	}
}

func TestPodEventJSON(t *testing.T) {
	v := "true"
	b, _ := json.Marshal(PodEvent{RunID: "r", Pod: "p", UID: "u", Phase: "Running", ContainerID: "abc",
		Image: "i@sha256:x", LabelsDelta: map[string]*string{"a": &v, "b": nil}, At: time.Unix(0, 0).UTC()})
	want := `{"run_id":"r","pod":"p","uid":"u","phase":"Running","reason":"","container_id":"abc","image":"i@sha256:x",` +
		`"labels_delta":{"a":"true","b":null},"deleted":false,"at":"1970-01-01T00:00:00Z"}`
	if string(b) != want {
		t.Fatalf("%s", b)
	}
}

func TestViewOf(t *testing.T) {
	now := metav1.Now()
	pending := &corev1.Pod{
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "target", Image: "ghcr.io/x/scenario:main@sha256:aa"}}},
		Status: corev1.PodStatus{Phase: corev1.PodPending, ContainerStatuses: []corev1.ContainerStatus{{Name: "target",
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}}}}},
	}
	if v := viewOf(pending, "target", false); v.phase != "ContainerCreating" || v.reason != "ContainerCreating" ||
		v.image != "ghcr.io/x/scenario@sha256:aa" || v.containerID != "" {
		t.Fatalf("pending: %+v", v)
	}
	if v := viewOf(&corev1.Pod{}, "target", false); v.phase != "Pending" || v.image != "" {
		t.Fatalf("empty: %+v", v)
	}
	pending.DeletionTimestamp = &now
	if v := viewOf(pending, "target", false); v.phase != "Terminating" {
		t.Fatalf("terminating: %+v", v)
	}
	if v := viewOf(pending, "target", true); v.phase != "Deleted" || !v.deleted {
		t.Fatalf("deleted: %+v", v)
	}
	failed := &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodFailed, Reason: "DeadlineExceeded"}}
	if v := viewOf(failed, "target", false); v.phase != "Failed" || v.reason != "DeadlineExceeded" {
		t.Fatalf("failed: %+v", v)
	}
}

func TestImageRef(t *testing.T) {
	d1, d2 := "sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64)
	cases := []struct{ imageID, spec, want string }{
		{"ghcr.io/a/b@" + d1, "ghcr.io/a/b:main@" + d2, "ghcr.io/a/b@" + d1},
		// The repository is the spec's, never the runtime's name for it.
		{"docker-pullable://mirror.internal:5000/x/y@" + d1, "ghcr.io/a/b@" + d2, "ghcr.io/a/b@" + d1},
		{d1, "ghcr.io/a/b:main@" + d2, "ghcr.io/a/b@" + d1},
		{"ghcr.io/a/b@sha256:short", "ghcr.io/a/b@" + d2, "ghcr.io/a/b@" + d2},
		{"", "registry:5000/a/b:tag@" + d2, "registry:5000/a/b@" + d2},
		{"", "ghcr.io/a/b:main", ""},
		{d1, "", ""},
	}
	for _, c := range cases {
		if got := imageRef(c.imageID, c.spec); got != c.want {
			t.Errorf("imageRef(%q, %q) = %q, want %q", c.imageID, c.spec, got, c.want)
		}
	}
	if got := shortContainerID("containerd://0123456789abcdef"); got != "0123456789ab" {
		t.Errorf("short id %q", got)
	}
	if got := shortContainerID(""); got != "" {
		t.Errorf("empty id %q", got)
	}
}

func TestLabelsDelta(t *testing.T) {
	prev := map[string]string{"a": "1", "b": "2", "c": "3"}
	cur := map[string]string{"a": "1", "b": "x", "d": "4"}
	d := labelsDelta(prev, cur, false)
	if len(d) != 3 || *d["b"] != "x" || *d["d"] != "4" || d["c"] != nil {
		t.Fatalf("%v", d)
	}
	if _, ok := d["c"]; !ok {
		t.Fatal("removed label missing from delta")
	}
	if d := labelsDelta(nil, cur, true); len(d) != 3 {
		t.Fatalf("first: %v", d)
	}
}
