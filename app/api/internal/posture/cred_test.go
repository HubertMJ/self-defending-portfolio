package posture

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func failResult(policy, rule, res string) map[string]any {
	return map[string]any{"source": "kyverno", "policy": policy, "rule": rule, "result": res,
		"message": "validation error: image registry is not allowed for falco-talon-5c9f"}
}

func scope(kind, ns, name, uid string) map[string]any {
	return map[string]any{"kind": kind, "namespace": ns, "name": name, "uid": uid}
}

// ownedPod is a pod in the given phase owned by the object with uid owner.
func ownedPod(ns, name string, phase corev1.PodPhase, owner string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(name + "-uid"),
		OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "rs", UID: types.UID(owner)}}},
		Status: corev1.PodStatus{Phase: phase}}
}

func boolp(b bool) *bool { return &b }

func TestKyvernoViolations(t *testing.T) {
	dyn := newDyn(
		// Seven old ReplicaSets at 0 replicas: one group, nothing runs.
		obj(PolicyReports, "PolicyReport", "falco-response", "r1", map[string]any{
			"scope":   scope("ReplicaSet", "falco-response", "falco-talon-5c9f", "rs-old-1"),
			"results": []any{failResult("restrict-image-registries", "autogen-validate-registries", "fail"), result("kyverno", "restrict-image-registries", "pass")},
		}),
		obj(PolicyReports, "PolicyReport", "falco-response", "r2", map[string]any{
			"scope":   scope("ReplicaSet", "falco-response", "falcosidekick-77aa", "rs-old-2"),
			"results": []any{failResult("restrict-image-registries", "autogen-validate-registries", "error")},
		}),
		// A ReplicaSet with a Running pod.
		obj(PolicyReports, "PolicyReport", "hello", "r3", map[string]any{
			"scope":   scope("ReplicaSet", "hello", "hello-abc", "rs-live"),
			"results": []any{failResult("require-pod-resources", "check", "fail")},
		}),
		// A Deployment: no pods are owned by it directly, so running is unknown.
		obj(PolicyReports, "PolicyReport", "hello", "r4", map[string]any{
			"scope":   scope("Deployment", "hello", "hello", "dep-1"),
			"results": []any{failResult("require-pod-resources", "check", "fail")},
		}),
		// No uid: unknown.
		obj(PolicyReports, "PolicyReport", "hello", "r5", map[string]any{
			"scope":   scope("ReplicaSet", "hello", "hello-nouid", ""),
			"results": []any{failResult("require-pod-resources", "check", "fail")},
		}),
		// An older report without a scope: the result's resources[0], and a pod that is Pending.
		obj(PolicyReports, "PolicyReport", "sandbox", "r6", map[string]any{
			"results": []any{map[string]any{"source": "kyverno", "policy": "disallow-latest-tag", "rule": "tag", "result": "fail",
				"resources": []any{scope("Pod", "sandbox", "victim-1", "victim-1-uid")}}},
		}),
		// Succeeded pods do not run anything.
		obj(PolicyReports, "PolicyReport", "kube-bench", "r7", map[string]any{
			"scope":   scope("Job", "kube-bench", "kube-bench-1", "job-done"),
			"results": []any{failResult("require-pod-resources", "check", "fail")},
		}),
	)
	pending := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "sandbox", Name: "victim-1", UID: "victim-1-uid"},
		Status: corev1.PodStatus{Phase: corev1.PodPending}}
	kube := fake.NewClientset(ownedPod("hello", "hello-abc-1", corev1.PodRunning, "rs-live"),
		ownedPod("kube-bench", "kube-bench-1-x", corev1.PodSucceeded, "job-done"), pending)
	a := New(Config{Dynamic: dyn, Kube: kube})
	k, err := a.kyverno(context.Background(), mustPods(t, a))
	if err != nil {
		t.Fatal(err)
	}
	want := []Violation{
		{Policy: "restrict-image-registries", Rule: "autogen-validate-registries", Kind: "ReplicaSet", Namespace: "falco-response", Count: 2, Running: boolp(false)},
		{Policy: "disallow-latest-tag", Rule: "tag", Kind: "Pod", Namespace: "sandbox", Count: 1, Running: boolp(true)},
		{Policy: "require-pod-resources", Rule: "check", Kind: "Deployment", Namespace: "hello", Count: 1},
		{Policy: "require-pod-resources", Rule: "check", Kind: "Job", Namespace: "kube-bench", Count: 1, Running: boolp(false)},
		{Policy: "require-pod-resources", Rule: "check", Kind: "ReplicaSet", Namespace: "hello", Count: 1},
		{Policy: "require-pod-resources", Rule: "check", Kind: "ReplicaSet", Namespace: "hello", Count: 1, Running: boolp(true)},
	}
	if !reflect.DeepEqual(k.Violations, want) {
		got, _ := json.Marshal(k.Violations)
		t.Fatalf("violations = %s", got)
	}
	sum, fail := 0, 0
	for _, v := range k.Violations {
		sum += v.Count
	}
	for _, p := range k.Policies {
		fail += p.Fail
	}
	if sum != fail || k.ViolationsTruncated {
		t.Fatalf("sum(count) %d != sum(fail) %d (truncated %v)", sum, fail, k.ViolationsTruncated)
	}
	b, _ := json.Marshal(k)
	for _, leak := range []string{"falco-talon-5c9f", "falcosidekick-77aa", "hello-abc", "victim-1", "validation error", "rs-old-1", "uid"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("published %q: %s", leak, b)
		}
	}

	// The pod list failed this refresh: running is unknown everywhere, the counts unchanged.
	k, err = a.kyverno(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range k.Violations {
		if v.Running != nil {
			t.Fatalf("running known without a pod list: %+v", v)
		}
	}
}

func TestKyvernoViolationsCapAndEmpty(t *testing.T) {
	a := New(Config{Dynamic: newDyn(), Kube: fake.NewClientset()})
	k, err := a.kyverno(context.Background(), mustPods(t, a))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(k); !strings.Contains(string(b), `"violations":[]`) {
		t.Fatalf("no violations marshals as %s, want []", b)
	}
	if s := a.Get(context.Background()); s.Kyverno.Violations == nil || s.KubeBench.Failing == nil {
		t.Fatalf("empty snapshot has a null list: %+v", s)
	}

	var objs []runtime.Object
	for i := range maxViolations + 5 {
		objs = append(objs, obj(PolicyReports, "PolicyReport", "ns", "r"+string(rune('a'+i%26))+string(rune('a'+i/26)), map[string]any{
			"scope":   scope("ReplicaSet", "ns-"+string(rune('a'+i%26))+string(rune('a'+i/26)), "x", "u"),
			"results": []any{failResult("p", "r", "fail")},
		}))
	}
	a = New(Config{Dynamic: newDyn(objs...), Kube: fake.NewClientset()})
	k, err = a.kyverno(context.Background(), mustPods(t, a))
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Violations) != maxViolations || !k.ViolationsTruncated || k.Policies[0].Fail != maxViolations+5 {
		t.Fatalf("%d rows truncated=%v fail=%d", len(k.Violations), k.ViolationsTruncated, k.Policies[0].Fail)
	}
}

// The live kube-bench log of the k3s node: three FAIL checks, named by id, title and remediation, and
// nothing that describes the node.
func TestKubeBenchFailingLive(t *testing.T) {
	log, err := os.ReadFile("testdata/kube-bench-live.log")
	if err != nil {
		t.Fatal(err)
	}
	kb, err := ParseKubeBench(log)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, f := range kb.Failing {
		ids = append(ids, f.ID)
		if f.Title == "" || f.Remediation == "" {
			t.Errorf("%s has no title or remediation: %+v", f.ID, f)
		}
	}
	if strings.Join(ids, ",") != "1.1.9,1.1.10,1.2.26" || kb.Fail != 3 {
		t.Fatalf("failing = %v (total fail %d)", ids, kb.Fail)
	}
	if !strings.HasPrefix(kb.Failing[0].Title, "Ensure that the Container Network Interface file permissions") {
		t.Fatalf("title = %q", kb.Failing[0].Title)
	}
	b, _ := json.Marshal(kb)
	for _, leak := range []string{"node-fixture", `"audit"`, `"actual_value"`, `"expected_result"`, `"reason"`, `"AuditEnv"`, `"AuditConfig"`, "journalctl", "192.0.2.10"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("published %q", leak)
		}
	}
}

func TestKubeBenchFailingRules(t *testing.T) {
	doc := func(results ...map[string]any) []byte {
		rs := make([]any, len(results))
		for i, r := range results {
			rs[i] = r
		}
		b, _ := json.Marshal(map[string]any{"Controls": []any{map[string]any{"tests": []any{map[string]any{"results": rs}}}},
			"Totals": map[string]any{"total_fail": len(results)}})
		return b
	}
	fail := func(id, desc string) map[string]any {
		return map[string]any{"test_number": id, "test_desc": desc, "remediation": "fix it", "status": "FAIL",
			"audit": "cat /etc/x", "actual_value": "secret", "reason": "host node-fixture"}
	}
	kb, err := ParseKubeBench(doc(
		fail("1.2.3", "Reach the API at 192.0.2.10 or https://node-fixture.example:6443"),
		fail("1.2.3; rm -rf /", "bad id"),
		fail("4", "too short"),
		fail("1.2.3.4.5", "too long"),
		map[string]any{"test_number": "1.2.4", "test_desc": "passes", "status": "PASS"},
		fail("5.1.1", strings.Repeat("t", 500)),
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(kb.Failing) != 2 || kb.Failing[0].ID != "1.2.3" || kb.Failing[1].ID != "5.1.1" {
		t.Fatalf("failing = %+v", kb.Failing)
	}
	if got := kb.Failing[0].Title; strings.Contains(got, "192.0.2.10") || strings.Contains(got, "node-fixture") || !strings.Contains(got, "[ip]") {
		t.Fatalf("title not scrubbed: %q", got)
	}
	if n := len([]rune(kb.Failing[1].Title)); n != maxBenchTitle {
		t.Fatalf("title %d runes, want the cap %d", n, maxBenchTitle)
	}
	many := make([]map[string]any, maxFailing+3)
	for i := range many {
		many[i] = fail("1.1."+strings.Repeat("1", 1+i%3), "x")
	}
	if kb, _ := ParseKubeBench(doc(many...)); len(kb.Failing) != maxFailing {
		t.Fatalf("%d failing, want the cap %d", len(kb.Failing), maxFailing)
	}
	kb, err = ParseKubeBench(doc(map[string]any{"test_number": "1.1.1", "status": "PASS"}))
	if err != nil || kb.Failing == nil || len(kb.Failing) != 0 {
		t.Fatalf("no failures: %#v %v", kb.Failing, err)
	}
}

// The bench pod's node name never reaches a published text, even when kube-bench quotes it in a
// title or a remediation - including at the edge of the cap, where a cut could leave half of it.
func TestKubeBenchRedactsNode(t *testing.T) {
	const node = "node-fixture"
	log, err := os.ReadFile("testdata/kube-bench-live.log")
	if err != nil {
		t.Fatal(err)
	}
	quoting := strings.Replace(string(log), `"test_desc":"Ensure that the --etcd-cafile`, `"test_desc":"On `+node+`, ensure that the --etcd-cafile`, 1)
	quoting = strings.Replace(quoting, `"remediation":"By default, K3s sets the CNI`, `"remediation":"`+strings.Repeat("x", maxBenchRemedy-8)+node+` By default, K3s sets the CNI`, 1)
	if quoting == string(log) || strings.Count(quoting, node) < 3 {
		t.Fatal("the fixture no longer has the texts this test edits")
	}
	kb, err := parseKubeBench([]byte(quoting), node)
	if err != nil {
		t.Fatal(err)
	}
	if len(kb.Failing) != 3 {
		t.Fatalf("failing = %+v", kb.Failing)
	}
	for _, f := range kb.Failing {
		for _, v := range []string{f.ID, f.Title, f.Remediation} {
			if strings.Contains(v, node) || strings.Contains(v, "node-f") {
				t.Errorf("%s publishes the node name: %q", f.ID, v)
			}
		}
	}
	if !strings.Contains(kb.Failing[2].Title, "On [node], ensure") || !strings.Contains(kb.Failing[0].Remediation, "[node]") {
		t.Fatalf("not redacted in place: %q / %q", kb.Failing[2].Title, kb.Failing[0].Remediation)
	}
}

// last_scan is the newest report of a running image; a newer report of an image nothing runs (an
// old ReplicaSet's) does not count.
func TestTrivyLastScan(t *testing.T) {
	withTS := func(u interface {
		SetUnstructuredContent(map[string]any)
		UnstructuredContent() map[string]any
	}, ts string) {
		c := u.UnstructuredContent()
		c["report"].(map[string]any)["updateTimestamp"] = ts
	}
	running := vulnReport("hello", "rs-web", "ghcr.io", "hubertmj/self-defending-portfolio/web", "main", "sha256:run")
	withTS(running, "2026-10-03T15:10:31Z")
	old := vulnReport("hello", "rs-web-old", "ghcr.io", "hubertmj/self-defending-portfolio/web", "old", "sha256:gone")
	withTS(old, "2026-10-03T18:00:00Z")
	a := New(Config{Dynamic: newDyn(running, old), Kube: fake.NewClientset(
		runningPod("hello", "web", "ghcr.io/hubertmj/self-defending-portfolio/web@sha256:run"))})
	tr, err := a.trivy(context.Background(), mustPods(t, a))
	if err != nil {
		t.Fatal(err)
	}
	if tr.LastScan == nil || !tr.LastScan.Equal(time.Date(2026, 10, 3, 15, 10, 31, 0, time.UTC)) {
		t.Fatalf("last_scan = %v, want the running image's 15:10:31", tr.LastScan)
	}
	a = New(Config{Dynamic: newDyn(), Kube: fake.NewClientset()})
	if tr, _ := a.trivy(context.Background(), mustPods(t, a)); tr.LastScan != nil {
		t.Fatalf("last_scan without reports = %v, want null", tr.LastScan)
	}
}

func digestN(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

// The deployed api/web images: exact repositories, Running pods only, distinct and sorted; a failed
// pod list keeps the previous images and the time they were seen.
func TestDeployedImages(t *testing.T) {
	const own = "ghcr.io/hubertmj/self-defending-portfolio/"
	// An init container on the api image is not what serves: only containers count.
	withInit := runningPod("portfolio-api", "api-init", own+"api@"+digestN('b'))
	withInit.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "init", ImageID: own + "api@" + digestN('1')}}
	pending := runningPod("portfolio-api", "api-next", own+"api@"+digestN('c'))
	pending.Status.Phase = corev1.PodPending
	kube := fake.NewClientset(
		runningPod("portfolio-api", "api-1", own+"api@"+digestN('b')),
		runningPod("portfolio-api", "api-2", own+"api@"+digestN('a')),
		runningPod("portfolio-api", "api-4", own+"api@"+digestN('7')),
		runningPod("portfolio-api", "api-5", own+"api@"+digestN('5')),
		runningPod("portfolio-api", "api-6", own+"api@"+digestN('9')),
		runningPod("portfolio-api", "api-7", own+"api@"+digestN('0')),
		runningPod("portfolio-api", "api-3", own+"api@"+digestN('b')), // same digest: once
		withInit,
		runningPod("hello", "hello-1", own+"web@"+digestN('d')),
		runningPod("hello", "hello-2", own+"web@"+digestN('d')),
		runningPod("x", "api-x", own+"api-x@"+digestN('e')),
		runningPod("sandbox", "victim", own+"scenario@"+digestN('f')),
		runningPod("y", "short", own+"api@sha256:abc"),
		pending,
	)
	var failing bool
	kube.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		if failing {
			return true, nil, errors.New("api server unavailable")
		}
		return false, nil, nil
	})
	clk := time.Date(2026, 10, 3, 19, 0, 0, 0, time.UTC)
	now := clk
	a := New(Config{Dynamic: newDyn(), Kube: kube, Now: func() time.Time { return now }})
	d := a.Get(context.Background()).Deployed
	wantAPI := []string{own + "api@" + digestN('0'), own + "api@" + digestN('5'), own + "api@" + digestN('7'),
		own + "api@" + digestN('9'), own + "api@" + digestN('a'), own + "api@" + digestN('b')}
	wantWeb := []string{own + "web@" + digestN('d')}
	if !reflect.DeepEqual(d.API, wantAPI) || !reflect.DeepEqual(d.Web, wantWeb) || d.ObservedAt == nil || !d.ObservedAt.Equal(clk) {
		t.Fatalf("deployed = %+v", d)
	}
	failing = true
	now = clk.Add(2 * time.Minute)
	d = a.Get(context.Background()).Deployed
	if !reflect.DeepEqual(d.API, wantAPI) || !reflect.DeepEqual(d.Web, wantWeb) || d.ObservedAt == nil || !d.ObservedAt.Equal(clk) {
		t.Fatalf("after a failed list: %+v, want the previous images seen at %s", d, clk)
	}
	if s, _ := json.Marshal(a.Get(context.Background())); strings.Contains(string(s), "sha256:aaaa") {
		t.Fatalf("/api/posture carries the deployed images: %s", s)
	}
}
