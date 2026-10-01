package posture

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func obj(gvr schema.GroupVersionResource, kind, ns, name string, fields map[string]any) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{}}
	for k, v := range fields {
		u.Object[k] = v
	}
	u.SetAPIVersion(gvr.Group + "/" + gvr.Version)
	u.SetKind(kind)
	u.SetNamespace(ns)
	u.SetName(name)
	return u
}

func result(source, policy, res string) map[string]any {
	return map[string]any{"source": source, "policy": policy, "result": res}
}

func vuln(ns, name, repo, digest string, c, h, m, l int64) *unstructured.Unstructured {
	return obj(VulnerabilityReports, "VulnerabilityReport", ns, name, map[string]any{
		"report": map[string]any{
			"registry": map[string]any{"server": "ghcr.io"},
			"artifact": map[string]any{"repository": repo, "digest": digest, "tag": "main"},
			"summary":  map[string]any{"criticalCount": c, "highCount": h, "mediumCount": m, "lowCount": l},
		},
	})
}

type fixedCounter int

func (f fixedCounter) Count() int { return int(f) }

func newDyn(objs ...runtime.Object) *dynfake.FakeDynamicClient {
	return dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		PolicyReports:        "PolicyReportList",
		ClusterPolicyReports: "ClusterPolicyReportList",
		VulnerabilityReports: "VulnerabilityReportList",
	}, objs...)
}

func TestAggregate(t *testing.T) {
	dyn := newDyn(
		obj(PolicyReports, "PolicyReport", "hello", "a", map[string]any{"results": []any{
			result("kyverno", "verify-portfolio-images", "pass"),
			result("kyverno", "pod-security-restricted", "fail"),
			result("kyverno", "pod-security-restricted", "warn"),
			result("Trivy Vulnerability", "CVE-2026-1", "fail"), // the adapter's, not counted
		}}),
		obj(PolicyReports, "PolicyReport", "sandbox", "b", map[string]any{"results": []any{
			result("kyverno", "verify-portfolio-images", "pass"),
			result("kyverno", "verify-portfolio-images", "error"),
		}}),
		obj(ClusterPolicyReports, "ClusterPolicyReport", "", "c", map[string]any{"results": []any{
			result("kyverno", "disallow-latest-tag", "pass"),
		}}),
		vuln("hello", "rs-hello-1", "hubertmj/self-defending-portfolio/web", "sha256:aa", 0, 1, 2, 3),
		vuln("hello", "rs-hello-2", "hubertmj/self-defending-portfolio/web", "sha256:aa", 0, 1, 2, 3), // same image
		vuln("falco", "ds-falco", "falcosecurity/falco", "sha256:bb", 1, 0, 0, 0),
	)
	kube := fake.NewClientset()
	clk := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	a := New(Config{Dynamic: dyn, Kube: kube, FalcoAlerts: fixedCounter(7), TalonActions: fixedCounter(2),
		Now: func() time.Time { return clk }})

	s := a.Get(context.Background())
	want := []PolicyCount{
		{Name: "disallow-latest-tag", Pass: 1},
		{Name: "pod-security-restricted", Fail: 1, Warn: 1},
		{Name: "verify-portfolio-images", Pass: 2, Fail: 1},
	}
	if len(s.Kyverno.Policies) != len(want) {
		t.Fatalf("policies = %+v", s.Kyverno.Policies)
	}
	for i := range want {
		if s.Kyverno.Policies[i] != want[i] {
			t.Errorf("policy %d = %+v, want %+v", i, s.Kyverno.Policies[i], want[i])
		}
	}
	if s.Trivy != (Trivy{Images: 2, Critical: 1, High: 1, Medium: 2, Low: 3}) {
		t.Errorf("trivy = %+v", s.Trivy)
	}
	if s.KubeBench.LastRun != nil {
		t.Errorf("kube-bench without a run: %+v", s.KubeBench)
	}
	if s.Falco.Alerts24h != 7 || s.Talon.Actions24h != 2 || !s.GeneratedAt.Equal(clk) {
		t.Errorf("counters/time: %+v", s)
	}
}

func TestCacheAndStaleOnError(t *testing.T) {
	dyn := newDyn(obj(PolicyReports, "PolicyReport", "hello", "a", map[string]any{"results": []any{
		result("kyverno", "p", "pass"),
	}}))
	var lists atomic.Int32
	var failing atomic.Bool
	dyn.PrependReactor("list", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
		lists.Add(1)
		if failing.Load() {
			return true, nil, errors.New("api server unavailable")
		}
		return false, nil, nil
	})
	var now atomic.Int64
	now.Store(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC).UnixNano())
	a := New(Config{Dynamic: dyn, Kube: fake.NewClientset(), Now: func() time.Time { return time.Unix(0, now.Load()) }})

	first := a.Get(context.Background())
	n := lists.Load()
	_ = a.Get(context.Background())
	if lists.Load() != n {
		t.Fatal("second call within the TTL hit the API server")
	}
	failing.Store(true)
	now.Add(int64(61 * time.Second))
	stale := a.Get(context.Background())
	if len(stale.Kyverno.Policies) != 1 || stale.Kyverno.Policies[0] != first.Kyverno.Policies[0] {
		t.Fatalf("failed refresh lost the previous values: %+v", stale.Kyverno)
	}
	if !stale.GeneratedAt.After(first.GeneratedAt) {
		t.Fatal("generated_at not advanced")
	}
}

func TestNewestSucceededBenchPodIsPicked(t *testing.T) {
	old := benchPod("kube-bench-1", corev1.PodSucceeded, time.Date(2026, 9, 29, 3, 18, 0, 0, time.UTC))
	failed := benchPod("kube-bench-3", corev1.PodFailed, time.Date(2026, 10, 1, 3, 18, 0, 0, time.UTC))
	latest := benchPod("kube-bench-2", corev1.PodSucceeded, time.Date(2026, 9, 30, 3, 18, 0, 0, time.UTC))
	p, at := newestSucceeded([]corev1.Pod{*old, *failed, *latest})
	if p == nil || p.Name != "kube-bench-2" || !at.Equal(time.Date(2026, 9, 30, 3, 18, 0, 0, time.UTC)) {
		t.Fatalf("picked %v at %v", p, at)
	}
	if p, _ := newestSucceeded([]corev1.Pod{*failed}); p != nil {
		t.Fatal("a failed run was picked")
	}

	// The fake clientset's log stream is the literal "fake logs", which holds no benchmark: the
	// section must stay at its previous (zero) value rather than fail the whole snapshot.
	a := New(Config{Dynamic: newDyn(), Kube: fake.NewClientset(old, failed, latest)})
	if _, err := a.kubeBench(context.Background()); !errors.Is(err, ErrNoBenchJSON) {
		t.Fatalf("err = %v", err)
	}
	if s := a.Get(context.Background()); s.KubeBench.LastRun != nil {
		t.Fatalf("%+v", s.KubeBench)
	}
}

func benchPod(name string, phase corev1.PodPhase, finished time.Time) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "kube-bench", Labels: map[string]string{"app.kubernetes.io/name": "kube-bench"}},
		Status: corev1.PodStatus{Phase: phase, ContainerStatuses: []corev1.ContainerStatus{{
			State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{FinishedAt: metav1.NewTime(finished)}},
		}}},
	}
}

func TestParseKubeBench(t *testing.T) {
	single := []byte(`I1001 03:17:01.000 util.go:1] some glog line
{"Controls":[{"id":"1","total_pass":40,"total_fail":10,"total_warn":9,"total_info":0},
 {"id":"4","total_pass":15,"total_fail":2,"total_warn":7,"total_info":0}],
 "Totals":{"total_pass":55,"total_fail":12,"total_warn":16,"total_info":0}}
W1001 03:17:02.000 trailing warning
`)
	kb, err := ParseKubeBench(single)
	if err != nil || kb.Pass != 55 || kb.Fail != 12 || kb.Warn != 16 || kb.Info != 0 {
		t.Fatalf("single: %+v %v", kb, err)
	}
	// Older layout: one document per target, no Totals.
	multi := []byte(`{"id":"1","Controls":null}
{"Controls":[{"total_pass":1,"total_fail":2,"total_warn":3,"total_info":4}]}
{"Controls":[{"total_pass":10,"total_fail":0,"total_warn":0,"total_info":1}]}
`)
	kb, err = ParseKubeBench(multi)
	if err != nil || kb.Pass != 11 || kb.Fail != 2 || kb.Warn != 3 || kb.Info != 5 {
		t.Fatalf("multi: %+v %v", kb, err)
	}
	if _, err := ParseKubeBench([]byte("fake logs")); !errors.Is(err, ErrNoBenchJSON) {
		t.Fatalf("garbage: %v", err)
	}
}
