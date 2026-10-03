package posture

import (
	"context"
	"errors"
	"strings"
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
	kube := fake.NewClientset(
		runningPod("hello", "hello-1", "ghcr.io/hubertmj/self-defending-portfolio/web@sha256:aa"),
		runningPod("falco", "falco-x", "docker.io/falcosecurity/falco@sha256:bb"),
	)
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
	tr := s.Trivy
	if tr.Images != 2 || tr.Critical != 1 || tr.High != 1 || tr.Medium != 2 || tr.Low != 3 {
		t.Errorf("trivy = %+v", tr)
	}
	if tr.Own != (TrivyGroup{Images: 1, High: 1}) || tr.ThirdParty != (TrivyGroup{Images: 1, Critical: 1}) {
		t.Errorf("own/third-party = %+v / %+v", tr.Own, tr.ThirdParty)
	}
	if s.KubeBench.LastRun != nil {
		t.Errorf("kube-bench without a run: %+v", s.KubeBench)
	}
	if s.Falco.Alerts24h != 7 || s.Talon.Actions24h != 2 || !s.GeneratedAt.Equal(clk) {
		t.Errorf("counters/time: %+v", s)
	}
}

// vulnReport is a VulnerabilityReport the way Trivy Operator writes one, with a findings list.
func vulnReport(ns, name, server, repo, tag, digest string, findings ...map[string]any) *unstructured.Unstructured {
	var c, h int64
	list := []any{}
	for _, f := range findings {
		switch f["severity"] {
		case "CRITICAL":
			c++
		case "HIGH":
			h++
		}
		list = append(list, f)
	}
	return obj(VulnerabilityReports, "VulnerabilityReport", ns, name, map[string]any{
		"report": map[string]any{
			"registry":        map[string]any{"server": server},
			"artifact":        map[string]any{"repository": repo, "digest": digest, "tag": tag},
			"summary":         map[string]any{"criticalCount": c, "highCount": h, "mediumCount": int64(0), "lowCount": int64(0)},
			"vulnerabilities": list,
		},
	})
}

func finding(sev, fixed string) map[string]any {
	return map[string]any{"severity": sev, "fixedVersion": fixed}
}

// The split and the breakdown partition the totals; nothing is dropped, and the totals are what they
// were before the split existed.
func TestTrivyBreakdown(t *testing.T) {
	dyn := newDyn(
		// Third-party, docker.io: the operator records the whole reference as the tag.
		vulnReport("argocd", "rs-ksops", "index.docker.io", "viaductoss/ksops", "viaductoss/ksops:v4.5.1", "sha256:1111111111111111aaaa",
			finding("CRITICAL", "1.2.3"), finding("HIGH", "1.2.3"), finding("HIGH", ""), finding("MEDIUM", "9")),
		// The same image in a second workload: counted once.
		vulnReport("argocd", "rs-ksops-2", "index.docker.io", "viaductoss/ksops", "viaductoss/ksops:v4.5.1", "sha256:1111111111111111aaaa",
			finding("CRITICAL", "1.2.3"), finding("HIGH", "1.2.3"), finding("HIGH", ""), finding("MEDIUM", "9")),
		vulnReport("argocd", "rs-redis", "public.ecr.aws", "docker/library/redis", "8.2.3-alpine", "sha256:2222222222222222bbbb",
			finding("HIGH", "8.2.4")),
		// Own images: two digests of api:main (an old ReplicaSet still scanned) are one row, summed.
		vulnReport("portfolio-api", "rs-api-1", "ghcr.io", "hubertmj/self-defending-portfolio/api", "main", "sha256:3333333333333333cccc",
			finding("HIGH", "")),
		vulnReport("portfolio-api", "rs-api-2", "ghcr.io", "hubertmj/self-defending-portfolio/api", "main", "sha256:4444444444444444dddd",
			finding("HIGH", "2")),
		vulnReport("hello", "rs-web", "ghcr.io", "hubertmj/self-defending-portfolio/web", "main", "sha256:5555555555555555eeee"),
		// Not ours, despite the owner: only the build-images.yml path counts as own.
		vulnReport("x", "rs-other", "ghcr.io", "hubertmj/other", "", "sha256:6666666666666666ffff", finding("CRITICAL", "")),
	)
	a := New(Config{Dynamic: dyn, Kube: fake.NewClientset(
		runningPod("argocd", "repo-server", "docker.io/viaductoss/ksops@sha256:1111111111111111aaaa"),
		runningPod("argocd", "redis", "public.ecr.aws/docker/library/redis@sha256:2222222222222222bbbb"),
		// Mid-rollout: both api digests run.
		runningPod("portfolio-api", "api-old", "ghcr.io/hubertmj/self-defending-portfolio/api@sha256:3333333333333333cccc"),
		runningPod("portfolio-api", "api-new", "ghcr.io/hubertmj/self-defending-portfolio/api@sha256:4444444444444444dddd"),
		runningPod("hello", "web", "ghcr.io/hubertmj/self-defending-portfolio/web@sha256:5555555555555555eeee"),
		runningPod("x", "other", "ghcr.io/hubertmj/other@sha256:6666666666666666ffff"),
	)})
	tr, err := a.trivy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tr.Images != 6 || tr.Critical != 2 || tr.High != 5 {
		t.Fatalf("totals = %+v", tr)
	}
	if tr.Own != (TrivyGroup{Images: 3, High: 2, Fixable: 1}) {
		t.Errorf("own = %+v", tr.Own)
	}
	if tr.ThirdParty != (TrivyGroup{Images: 3, Critical: 2, High: 3, Fixable: 3}) {
		t.Errorf("third party = %+v", tr.ThirdParty)
	}
	if tr.Own.Images+tr.ThirdParty.Images != tr.Images ||
		tr.Own.Critical+tr.ThirdParty.Critical != tr.Critical || tr.Own.High+tr.ThirdParty.High != tr.High {
		t.Errorf("split does not add up to the totals: %+v", tr)
	}
	want := []ImageVulns{
		{Image: "docker.io/viaductoss/ksops:v4.5.1", Critical: 1, High: 2, Fixable: 2},
		{Image: "ghcr.io/hubertmj/self-defending-portfolio/api:main", Own: true, High: 2, Fixable: 1},
		{Image: "ghcr.io/hubertmj/other@sha256:666666666666", Critical: 1},
		{Image: "public.ecr.aws/docker/library/redis:8.2.3-alpine", High: 1, Fixable: 1},
		{Image: "ghcr.io/hubertmj/self-defending-portfolio/web:main", Own: true},
	}
	if len(tr.ByImage) != len(want) {
		t.Fatalf("by_image = %+v", tr.ByImage)
	}
	for i := range want {
		if tr.ByImage[i] != want[i] {
			t.Errorf("by_image[%d] = %+v, want %+v", i, tr.ByImage[i], want[i])
		}
	}
}

// runningPod is a started pod whose containers the runtime resolved to the given imageIDs.
func runningPod(ns, name string, imageIDs ...string) *corev1.Pod {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	for i, id := range imageIDs {
		c := "c" + string(rune('0'+i))
		p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: c, Image: "ignored:tag"})
		p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, corev1.ContainerStatus{Name: c, ImageID: id})
	}
	return p
}

// Only images a pod runs count. A Deployment's old ReplicaSet, scaled to 0, keeps its report until
// Trivy Operator garbage-collects the ReplicaSet; its findings must not reach the totals. Nothing
// that runs is ever dropped: init containers, completed Job pods, pods still pulling their image
// (matched by tag), and reports that cannot be matched at all.
func TestTrivyCountsOnlyRunningImages(t *testing.T) {
	dyn := newDyn(
		vulnReport("trivy-system", "rs-new", "ghcr.io", "hubertmj/self-defending-portfolio/trivy-operator", "main", "sha256:new",
			finding("HIGH", "1")),
		// Old ReplicaSet (0 replicas), upstream image: no pod runs it.
		vulnReport("trivy-system", "rs-old", "mirror.gcr.io", "aquasec/trivy-operator", "0.30.0", "sha256:old",
			finding("HIGH", "1"), finding("HIGH", "1")),
		// Init container of a running pod.
		vulnReport("kube-system", "ds-cilium-init", "ghcr.io", "hubertmj/self-defending-portfolio/cilium", "main", "sha256:init",
			finding("CRITICAL", "")),
		// The last completed run of a CronJob.
		vulnReport("kube-bench", "cj-kube-bench", "ghcr.io", "hubertmj/self-defending-portfolio/kube-bench", "main", "sha256:bench"),
		// A pod still pulling: no imageID yet, matched by its tag (Docker Hub spelled two ways).
		vulnReport("cloudflared", "rs-cloudflared", "index.docker.io", "cloudflare/cloudflared", "cloudflare/cloudflared:2026.9.3", "sha256:cf",
			finding("HIGH", "")),
		// The same tag at a different digest, and no pod resolved to it: still running by tag, so kept.
		// (A pull in progress cannot say which digest it will get.)
		vulnReport("cloudflared", "rs-cloudflared-old", "index.docker.io", "cloudflare/cloudflared", "cloudflare/cloudflared:2026.9.3", "sha256:cf-old"),
		// No repository: cannot be matched, kept rather than risk hiding it.
		vulnReport("x", "odd", "", "", "", "", finding("CRITICAL", "")),
	)
	cilium := runningPod("kube-system", "cilium-abc", "ghcr.io/hubertmj/self-defending-portfolio/cilium@sha256:agent")
	cilium.Spec.InitContainers = []corev1.Container{{Name: "mount-cgroup", Image: "ghcr.io/hubertmj/self-defending-portfolio/cilium:main"}}
	cilium.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "mount-cgroup", ImageID: "ghcr.io/hubertmj/self-defending-portfolio/cilium@sha256:init"}}
	bench := runningPod("kube-bench", "kube-bench-1", "ghcr.io/hubertmj/self-defending-portfolio/kube-bench@sha256:bench")
	bench.Status.Phase = corev1.PodSucceeded
	pulling := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "cloudflared", Name: "cloudflared-1"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "cloudflared", Image: "cloudflare/cloudflared:2026.9.3"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}
	kube := fake.NewClientset(
		runningPod("trivy-system", "trivy-operator-1", "ghcr.io/hubertmj/self-defending-portfolio/trivy-operator@sha256:new"),
		cilium, bench, pulling,
	)
	tr, err := New(Config{Dynamic: dyn, Kube: kube}).trivy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tr.Images != 6 || tr.Critical != 2 || tr.High != 2 {
		t.Fatalf("totals = %+v (by_image %+v)", tr, tr.ByImage)
	}
	for _, r := range tr.ByImage {
		if strings.Contains(r.Image, "aquasec/trivy-operator") {
			t.Fatalf("the scaled-to-0 ReplicaSet's image was counted: %+v", r)
		}
	}
}

func TestTrivyFailsWhenPodsCannotBeListed(t *testing.T) {
	kube := fake.NewClientset()
	kube.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("forbidden")
	})
	dyn := newDyn(vulnReport("hello", "rs", "ghcr.io", "a/b", "1", "sha256:x", finding("HIGH", "")))
	if _, err := New(Config{Dynamic: dyn, Kube: kube}).trivy(context.Background()); err == nil {
		t.Fatal("trivy succeeded without the pod list; it would have reported zero images")
	}
}

func TestNormalizeRef(t *testing.T) {
	for in, want := range map[string]string{
		"nginx":                           "docker.io/library/nginx:latest",
		"nginx:1.29":                      "docker.io/library/nginx:1.29",
		"cloudflare/cloudflared:2026.9.3": "docker.io/cloudflare/cloudflared:2026.9.3",
		"index.docker.io/cloudflare/x:1":  "docker.io/cloudflare/x:1",
		"docker.io/library/redis:8":       "docker.io/library/redis:8",
		"ghcr.io/a/b:main":                "ghcr.io/a/b:main",
		"localhost:5000/a:1":              "localhost:5000/a:1",
		"registry.local:5000/team/app":    "registry.local:5000/team/app:latest",
	} {
		if got := normalizeRef(in); got != want {
			t.Errorf("normalizeRef(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEmptySnapshotHasAnEmptyBreakdown(t *testing.T) {
	s := New(Config{Dynamic: newDyn(), Kube: fake.NewClientset()}).Get(context.Background())
	if s.Trivy.ByImage == nil || len(s.Trivy.ByImage) != 0 {
		t.Fatalf("by_image = %#v, want [] (never null in the JSON)", s.Trivy.ByImage)
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

// liveCounter is a webhook counter that changes between calls.
type liveCounter struct{ n atomic.Int64 }

func (c *liveCounter) Count() int { return int(c.n.Load()) }

// The webhook counts are not part of the cached refresh: an alert that arrives between two calls
// within the TTL shows on the second one, as it does on /api/stats (ADR 0035).
func TestCountsReadOnEveryCall(t *testing.T) {
	var lists atomic.Int32
	dyn := newDyn()
	dyn.PrependReactor("list", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
		lists.Add(1)
		return false, nil, nil
	})
	alerts, actions := &liveCounter{}, &liveCounter{}
	since := time.Date(2026, 10, 3, 19, 5, 0, 0, time.UTC)
	a := New(Config{Dynamic: dyn, Kube: fake.NewClientset(), FalcoAlerts: alerts, TalonActions: actions,
		CountedSince: func() time.Time { return since }})
	first := a.Get(context.Background())
	if first.Falco.Alerts24h != 0 || first.Falco.CountedSince == nil || !first.Falco.CountedSince.Equal(since) {
		t.Fatalf("first: %+v", first.Falco)
	}
	n := lists.Load()
	alerts.n.Add(3)
	actions.n.Add(2)
	second := a.Get(context.Background())
	if lists.Load() != n {
		t.Fatal("the second call within the TTL refreshed the reports")
	}
	if second.Falco.Alerts24h != 3 || second.Talon.Actions24h != 2 {
		t.Fatalf("on a cache hit: alerts %d actions %d, want 3 and 2", second.Falco.Alerts24h, second.Talon.Actions24h)
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
