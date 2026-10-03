package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/events"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/limits"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/posture"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/ruleindex"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/runlog"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/runner"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/scenarios"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/stats"
)

const ownPrefix = "ghcr.io/hubertmj/self-defending-portfolio/"

func digest(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

func pod(ns, name string, phase corev1.PodPhase, imageID string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "x:1"}}},
		Status: corev1.PodStatus{Phase: phase, ContainerStatuses: []corev1.ContainerStatus{{Name: "c", ImageID: imageID}}}}
}

func newDyn(objs ...runtime.Object) *dynfake.FakeDynamicClient {
	return dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		posture.PolicyReports:        "PolicyReportList",
		posture.ClusterPolicyReports: "ClusterPolicyReportList",
		posture.VulnerabilityReports: "VulnerabilityReportList",
	}, objs...)
}

func getJSON[T any](t *testing.T, url string) T {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d", url, resp.StatusCode)
	}
	return decode[T](t, resp.Body)
}

func getRaw(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestProvenance(t *testing.T) {
	kube := fake.NewClientset(
		pod("portfolio-api", "portfolio-api-7d9f-abcde", corev1.PodRunning, ownPrefix+"api@"+digest('b')),
		pod("portfolio-api", "portfolio-api-6c8e-fghij", corev1.PodRunning, ownPrefix+"api@"+digest('a')),
		pod("hello", "hello-5b7c-klmno", corev1.PodRunning, ownPrefix+"web@"+digest('d')),
		pod("hello", "hello-5b7c-pqrst", corev1.PodRunning, ownPrefix+"web@"+digest('d')),
		pod("hello", "hello-old", corev1.PodSucceeded, ownPrefix+"web@"+digest('e')),
		pod("x", "x", corev1.PodRunning, ownPrefix+"api-x@"+digest('f')),
		pod("sandbox", "victim", corev1.PodRunning, ownPrefix+"scenario@"+digest('9')),
	)
	var failing bool
	var mu sync.Mutex
	kube.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		mu.Lock()
		defer mu.Unlock()
		if failing {
			return true, nil, errors.New("api server unavailable")
		}
		return false, nil, nil
	})
	clk := time.Date(2026, 10, 3, 19, 0, 0, 0, time.UTC)
	now := clk
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	started := time.Date(2026, 10, 3, 18, 55, 0, 0, time.FixedZone("CEST", 2*3600))
	srv := New(Config{Posture: posture.New(posture.Config{Dynamic: newDyn(), Kube: kube, Now: clock}), Now: clock,
		Commit: "0123456789abcdef0123456789abcdef01234567", CIRunID: "18234567890", StartedAt: started})
	ts := httptest.NewServer(srv.Public())
	defer ts.Close()

	raw := getRaw(t, ts.URL+"/api/provenance")
	want := `{"generated_at":"2026-10-03T19:00:00Z","api":{"commit":"0123456789abcdef0123456789abcdef01234567",` +
		`"ci_run_id":"18234567890","started_at":"2026-10-03T16:55:00Z","images":["` + ownPrefix + "api@" + digest('a') + `","` +
		ownPrefix + "api@" + digest('b') + `"]},"web":{"images":["` + ownPrefix + "web@" + digest('d') + `"]},` +
		`"images_observed_at":"2026-10-03T19:00:00Z"}` + "\n"
	if raw != want {
		t.Fatalf("provenance =\n%s\nwant\n%s", raw, want)
	}
	for _, leak := range []string{"portfolio-api-", "hello-", "\"hello\"", "portfolio-api\"", "sandbox", "victim"} {
		if strings.Contains(raw, leak) {
			t.Errorf("published %q", leak)
		}
	}

	// A failed pod list after the cache expires keeps the images and the time they were seen.
	mu.Lock()
	failing, now = true, clk.Add(2*time.Minute)
	mu.Unlock()
	p := getJSON[Provenance](t, ts.URL+"/api/provenance")
	if len(p.API.Images) != 2 || len(p.Web.Images) != 1 || p.ImagesObservedAt == nil || !p.ImagesObservedAt.Equal(clk) ||
		!p.GeneratedAt.Equal(clk.Add(2*time.Minute)) {
		t.Fatalf("after a failed list: %+v", p)
	}

	for _, c := range []struct{ commit, run string }{{"unknown", "12a"}, {"", "123456789012345678901"}, {"0123456", "-1"}} {
		s := New(Config{Commit: c.commit, CIRunID: c.run})
		ts := httptest.NewServer(s.Public())
		p := getJSON[Provenance](t, ts.URL+"/api/provenance")
		ts.Close()
		if p.API.CIRunID != "" || (c.commit != "0123456" && p.API.Commit != "") || p.API.StartedAt.IsZero() ||
			p.API.Images == nil || p.Web.Images == nil || p.ImagesObservedAt != nil {
			t.Errorf("%+v -> %+v", c, p)
		}
	}
}

func TestRunsList(t *testing.T) {
	hub := events.NewHub(10)
	runs := runlog.New(0, 0, 0, 0)
	hub.Tap(runs.Record)
	srv := New(Config{Hub: hub, Runs: runs})
	ts := httptest.NewServer(srv.Public())
	defer ts.Close()
	if raw := getRaw(t, ts.URL+"/api/runs"); raw != `{"runs":[],"kept":50}`+"\n" {
		t.Fatalf("empty: %s", raw)
	}
	at := time.Date(2026, 10, 3, 18, 0, 0, 0, time.UTC)
	for i, id := range []string{"00000000000000a1", "00000000000000a2"} {
		_ = hub.Publish("run", runner.RunEvent{RunID: id, Scenario: "network-tool", State: "queued", At: at.Add(time.Duration(i) * time.Minute)})
	}
	_ = hub.Publish("run", runner.RunEvent{RunID: "00000000000000a1", Scenario: "network-tool", State: "finished", At: at.Add(30 * time.Second)})
	l := getJSON[RunList](t, ts.URL+"/api/runs")
	if len(l.Runs) != 2 || l.Kept != 50 || l.Runs[0].RunID != "00000000000000a2" || l.Runs[1].State != "finished" ||
		l.Runs[1].EndedAt == nil || l.Runs[0].EndedAt != nil || l.Runs[1].Events != 2 {
		t.Fatalf("runs = %+v", l)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/api/runs", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("POST /api/runs: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}

type fixedPosture struct{ s posture.Snapshot }

func (f fixedPosture) Get(context.Context) posture.Snapshot { return f.s }

func TestPostureViolationFiles(t *testing.T) {
	rules, err := ruleindex.Load()
	if err != nil {
		t.Fatal(err)
	}
	cached := []posture.Violation{
		{Policy: "restrict-image-registries", Rule: "autogen-validate-registries", Kind: "ReplicaSet", Namespace: "falco-response", Count: 7},
		{Policy: "not-in-the-index", Rule: "r", Kind: "Pod", Namespace: "x", Count: 1},
		{Policy: "quarantine", Rule: "r", Kind: "Pod", Namespace: "x", Count: 1}, // a network policy's name, not a Kyverno one
	}
	srv := New(Config{Rules: rules, Posture: fixedPosture{posture.Snapshot{Kyverno: posture.Kyverno{Policies: []posture.PolicyCount{}, Violations: cached}}}})
	ts := httptest.NewServer(srv.Public())
	defer ts.Close()
	s := getJSON[posture.Snapshot](t, ts.URL+"/api/posture")
	if s.Kyverno.Violations[0].File != "cluster/infra/kyverno-policies/restrict-image-registries.yaml" ||
		s.Kyverno.Violations[1].File != "" || s.Kyverno.Violations[2].File != "" {
		t.Fatalf("files: %+v", s.Kyverno.Violations)
	}
	if cached[0].File != "" {
		t.Fatal("the handler wrote into the cached snapshot")
	}
	srv = New(Config{Posture: fixedPosture{posture.Snapshot{}}})
	ts2 := httptest.NewServer(srv.Public())
	defer ts2.Close()
	if raw := getRaw(t, ts2.URL+"/api/posture"); !strings.Contains(raw, `"violations":[]`) {
		t.Fatalf("no violations: %s", raw)
	}
}

// tickEnv is a bare server for the stream tests: its own hub, a fixed clock.
func tickEnv(t *testing.T, heartbeat time.Duration) (*events.Hub, *httptest.Server) {
	t.Helper()
	hub := events.NewHub(10)
	clk := time.Date(2026, 10, 3, 19, 0, 0, 123000000, time.UTC)
	srv := New(Config{Hub: hub, Streams: limits.NewConns(4, 10), Heartbeat: heartbeat,
		Now: func() time.Time { return clk }, StartedAt: time.Date(2026, 10, 3, 18, 55, 0, 0, time.UTC)})
	ts := httptest.NewServer(srv.Public())
	t.Cleanup(ts.Close)
	return hub, ts
}

// readStream returns the first n bytes of a stream.
func readStream(t *testing.T, url, lastID string, n int) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	buf := make([]byte, n)
	if _, err := io.ReadFull(bufio.NewReader(resp.Body), buf); err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return string(buf)
}

const tickFrameWant = "event: tick\ndata: {\"at\":\"2026-10-03T19:00:00.123Z\",\"started_at\":\"2026-10-03T18:55:00Z\"}\n\n"

func TestEventStreamTick(t *testing.T) {
	hub, ts := tickEnv(t, 40*time.Millisecond)
	// slow never beats within a read's 3 s: a tick there can only be the one right after the replay.
	slowHub, slow := tickEnv(t, time.Hour)
	for _, h := range []*events.Hub{hub, slowHub} {
		_ = h.Publish("run", map[string]string{"run_id": "r1", "state": "queued"})
		_ = h.Publish("run", map[string]string{"run_id": "r1", "state": "started"})
	}
	f1 := "id: 1\nevent: run\ndata: {\"run_id\":\"r1\",\"state\":\"queued\"}\n\n"
	f2 := "id: 2\nevent: run\ndata: {\"run_id\":\"r1\",\"state\":\"started\"}\n\n"

	// Without tick=1: byte for byte today's stream - preamble, replay, heartbeat comments.
	plain := streamPreamble + f1 + f2 + ": heartbeat\n\n" + ": heartbeat\n\n"
	if got := readStream(t, ts.URL+"/api/events", "", len(plain)); got != plain {
		t.Fatalf("plain stream =\n%q\nwant\n%q", got, plain)
	}
	// With tick=1: a tick right after the replay, then a tick instead of each heartbeat; no id line.
	ticked := streamPreamble + f1 + f2 + tickFrameWant + tickFrameWant + tickFrameWant
	if got := readStream(t, ts.URL+"/api/events?tick=1", "", len(ticked)); got != ticked {
		t.Fatalf("tick stream =\n%q\nwant\n%q", got, ticked)
	}
	// Resuming after event 1 with ticks: only event 2 is replayed, then the tick.
	resumed := streamPreamble + f2 + tickFrameWant
	if got := readStream(t, slow.URL+"/api/events?tick=1", "1", len(resumed)); got != resumed {
		t.Fatalf("resumed tick stream =\n%q\nwant\n%q", got, resumed)
	}
	if got := readStream(t, ts.URL+"/api/events?tick=yes", "", len(plain)); got != plain {
		t.Fatalf("tick=yes is not tick=1: %q", got)
	}
}

// golden is today's (ecbca9b) shape of a document: every path and its JSON type. "*" is any key of
// a keyed table, "[]" every element of an array.
func checkGolden(t *testing.T, name, raw string, golden map[string]string) {
	t.Helper()
	var doc any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	for path, typ := range golden {
		vals := []any{doc}
		for _, seg := range strings.Split(path, ".") {
			var next []any
			for _, v := range vals {
				switch seg {
				case "*", "[]":
					switch c := v.(type) {
					case map[string]any:
						for _, x := range c {
							next = append(next, x)
						}
					case []any:
						next = append(next, c...)
					}
				default:
					if m, ok := v.(map[string]any); ok {
						if x, ok := m[seg]; ok {
							next = append(next, x)
						}
					}
				}
			}
			vals = next
		}
		if len(vals) == 0 {
			t.Errorf("%s: %s is missing", name, path)
			continue
		}
		for _, v := range vals {
			got := "null"
			switch v.(type) {
			case string:
				got = "string"
			case float64:
				got = "number"
			case bool:
				got = "bool"
			case map[string]any:
				got = "object"
			case []any:
				got = "array"
			}
			if !strings.Contains("|"+typ+"|", "|"+got+"|") {
				t.Errorf("%s: %s is %s, want %s", name, path, got, typ)
			}
		}
	}
}

var postureGolden = map[string]string{
	"generated_at": "string", "kyverno": "object", "kyverno.policies": "array",
	"kyverno.policies.[].name": "string", "kyverno.policies.[].pass": "number", "kyverno.policies.[].fail": "number", "kyverno.policies.[].warn": "number",
	"trivy": "object", "trivy.images": "number", "trivy.critical": "number", "trivy.high": "number", "trivy.medium": "number", "trivy.low": "number",
	"trivy.own": "object", "trivy.own.images": "number", "trivy.own.critical": "number", "trivy.own.high": "number", "trivy.own.fixable": "number",
	"trivy.third_party": "object", "trivy.third_party.images": "number", "trivy.third_party.critical": "number", "trivy.third_party.high": "number", "trivy.third_party.fixable": "number",
	"trivy.by_image": "array", "trivy.by_image.[].image": "string", "trivy.by_image.[].own": "bool", "trivy.by_image.[].critical": "number",
	"trivy.by_image.[].high": "number", "trivy.by_image.[].fixable": "number",
	"kube_bench": "object", "kube_bench.last_run": "string|null", "kube_bench.pass": "number", "kube_bench.fail": "number", "kube_bench.warn": "number", "kube_bench.info": "number",
	"falco": "object", "falco.alerts_24h": "number", "talon": "object", "talon.actions_24h": "number",
}

var statsGolden = map[string]string{
	"since": "string", "runs": "number", "by_scenario": "object",
	"by_scenario.*.runs": "number", "by_scenario.*.detected": "number", "by_scenario.*.responded": "number",
	"response_ms": "object", "response_ms.last": "number", "response_ms.p50": "number", "response_ms.min": "number", "response_ms.max": "number",
	"unanswered": "number", "commands": "object", "commands.*.attempts": "number", "commands.*.allowed": "number",
	"commands.*.prevented": "number", "commands.*.detected": "number", "objectives": "object", "objectives.*.attempts": "number",
	"objectives.*.achieved": "number", "terminal": "object", "terminal.runs": "number", "terminal.best_objectives": "number",
	"terminal.median_survival_s": "number",
}

// An old page on the new API: /api/posture and /api/stats still carry every field of today's shape
// with today's types.
func TestOldShapesKept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.yaml")
	if err := os.WriteFile(path, []byte(terminalCatalogue), 0o600); err != nil {
		t.Fatal(err)
	}
	store := scenarios.NewStore(path, nil)
	collector := stats.New(store, nil)
	now := time.Now().UTC()
	for _, e := range []struct {
		typ string
		v   map[string]any
	}{
		{"run", map[string]any{"run_id": "t1", "scenario": "terminal", "state": "queued", "at": now}},
		{"command", map[string]any{"run_id": "t1", "id": "whoami", "state": "started"}},
		{"command", map[string]any{"run_id": "t1", "id": "whoami", "state": "exited", "achieved": true}},
		{"run", map[string]any{"run_id": "t1", "scenario": "terminal", "state": "finished", "at": now}},
	} {
		b, _ := json.Marshal(e.v)
		collector.Record(events.Event{Type: e.typ, Data: b})
	}
	report := func(gvr schema.GroupVersionResource, kind, name string, fields map[string]any) *unstructured.Unstructured {
		u := &unstructured.Unstructured{Object: fields}
		u.SetAPIVersion(gvr.Group + "/" + gvr.Version)
		u.SetKind(kind)
		u.SetNamespace("hello")
		u.SetName(name)
		return u
	}
	dyn := newDyn(
		report(posture.PolicyReports, "PolicyReport", "p", map[string]any{"results": []any{
			map[string]any{"source": "kyverno", "policy": "require-pod-resources", "rule": "r", "result": "fail"}}}),
		report(posture.VulnerabilityReports, "VulnerabilityReport", "v", map[string]any{"report": map[string]any{
			"registry": map[string]any{"server": "ghcr.io"},
			"artifact": map[string]any{"repository": "hubertmj/self-defending-portfolio/web", "digest": digest('d'), "tag": "main"},
			"summary":  map[string]any{"criticalCount": int64(1), "highCount": int64(0), "mediumCount": int64(0), "lowCount": int64(0)}}}),
	)
	kube := fake.NewClientset(pod("hello", "hello-1", corev1.PodRunning, ownPrefix+"web@"+digest('d')))
	srv := New(Config{Stats: collector, Posture: posture.New(posture.Config{Dynamic: dyn, Kube: kube,
		FalcoAlerts: collector.AlertCounter(), TalonActions: collector.ActionCounter(), CountedSince: collector.Since24h})})
	ts := httptest.NewServer(srv.Public())
	defer ts.Close()
	checkGolden(t, "/api/posture", getRaw(t, ts.URL+"/api/posture"), postureGolden)
	checkGolden(t, "/api/stats", getRaw(t, ts.URL+"/api/stats"), statsGolden)
	// The additions are there too, so this is the new API and not a stale build.
	checkGolden(t, "/api/posture", getRaw(t, ts.URL+"/api/posture"), map[string]string{"kyverno.violations": "array",
		"kyverno.violations_truncated": "bool", "kube_bench.failing": "array", "trivy.last_scan": "string|null", "falco.counted_since": "string"})
	checkGolden(t, "/api/stats", getRaw(t, ts.URL+"/api/stats"), map[string]string{"last_run_at": "string", "last_24h.since": "string",
		"last_24h.runs": "number", "last_24h.detected": "number", "last_24h.responded": "number", "last_24h.falco_alerts": "number",
		"last_24h.talon_actions": "number"})
}

// counters is what the invariant test reads from the two endpoints.
type counters struct {
	alerts, actions, detected, responded, runs int
	countedSince, since                        time.Time
}

func readCounters(t *testing.T, url string) counters {
	t.Helper()
	p := getJSON[posture.Snapshot](t, url+"/api/posture")
	s := getJSON[stats.Snapshot](t, url+"/api/stats")
	c := counters{alerts: p.Falco.Alerts24h, actions: p.Talon.Actions24h, detected: s.Last24h.Detected,
		responded: s.Last24h.Responded, runs: s.Last24h.Runs, since: s.Last24h.Since}
	if p.Falco.CountedSince != nil {
		c.countedSince = *p.Falco.CountedSince
	}
	return c
}

// The page can no longer show more detections than alerts: N runs driven through the webhooks and
// the hub, before and after a restart, keep alerts_24h >= detected and actions_24h >= responded, with
// the one documented exception of a detection published on the Talon-first path while its Falco
// webhook is still on the way (ADR 0035).
func TestAlertsCoverDetections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.yaml")
	if err := os.WriteFile(path, []byte(catalogue), 0o600); err != nil {
		t.Fatal(err)
	}
	store := scenarios.NewStore(path, nil)
	start := func(c *stats.Collector) (*events.Hub, *httptest.Server, *httptest.Server) {
		hub := events.NewHub(50)
		hub.Tap(c.Record)
		kube := fake.NewClientset()
		run := runner.New(kube, noopExec{}, hub, nil, runner.Config{PollInterval: 5 * time.Millisecond, QuarantineLinger: -1})
		srv := New(Config{Scenarios: store, Runner: run, Hub: hub, Stats: c,
			FalcoAlerts: c.AlertCounter(), TalonActions: c.ActionCounter(),
			Posture: posture.New(posture.Config{Dynamic: newDyn(), Kube: kube, FalcoAlerts: c.AlertCounter(),
				TalonActions: c.ActionCounter(), CountedSince: c.Since24h})})
		pub, internal := httptest.NewServer(srv.Public()), httptest.NewServer(srv.Internal())
		t.Cleanup(func() {
			pub.Close()
			internal.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = run.Shutdown(ctx)
		})
		return hub, pub, internal
	}
	post := func(url, body string) {
		t.Helper()
		resp, err := http.Post(url, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("%s: %d", url, resp.StatusCode)
		}
	}
	falco := func(internal string, p string) {
		post(internal+"/internal/falco", fmt.Sprintf(`{"rule":"SDP network tool in sandbox","priority":"Warning","output":"x",
			"output_fields":{"k8s.ns.name":"sandbox","k8s.pod.name":%q}}`, p))
	}
	talon := func(internal string, p string) {
		post(internal+"/internal/talon", fmt.Sprintf(`{"objects":{"Pod":%q,"Namespace":"sandbox"},"action":"Quarantine Pod","status":"success"}`, p))
	}
	state := func(hub *events.Hub, id, s string) {
		_ = hub.Publish("run", runner.RunEvent{RunID: id, Scenario: "network-tool", State: s, At: time.Now()})
	}
	holds := func(when string, c counters) {
		t.Helper()
		if c.alerts < c.detected || c.actions < c.responded || c.runs < c.detected || !c.countedSince.Equal(c.since) {
			t.Fatalf("%s: %+v breaks alerts >= detected, actions >= responded or counted_since == since", when, c)
		}
	}

	c1 := stats.New(store, nil)
	hub, pub, internal := start(c1)
	_ = readCounters(t, pub.URL) // the posture cache is filled; every later read is a cache hit
	for i := range 4 {
		id := fmt.Sprintf("run-%d", i)
		state(hub, id, "queued")
		state(hub, id, "started")
		falco(internal.URL, id)
		holds(fmt.Sprintf("run %d alerted", i), readCounters(t, pub.URL))
		state(hub, id, "detected")
		talon(internal.URL, id)
		state(hub, id, "responded")
		state(hub, id, "finished")
		holds(fmt.Sprintf("run %d done", i), readCounters(t, pub.URL))
	}
	// A run that alerts in another namespace only adds alerts.
	post(internal.URL+"/internal/falco", `{"rule":"x","priority":"Notice","output":"x","output_fields":{"k8s.ns.name":"hello"}}`)

	// Talon first: the runner publishes detected and responded on Talon's notification; the Falco
	// webhook comes after. Until it does, there is one detection more than alerts - the exception.
	before := readCounters(t, pub.URL)
	state(hub, "talon-first", "queued")
	talon(internal.URL, "talon-first")
	state(hub, "talon-first", "detected")
	state(hub, "talon-first", "responded")
	mid := readCounters(t, pub.URL)
	if mid.detected != before.detected+1 || mid.alerts != before.alerts || mid.actions < mid.responded {
		t.Fatalf("talon-first, before its alert: %+v (before %+v)", mid, before)
	}
	falco(internal.URL, "talon-first")
	state(hub, "talon-first", "finished")
	after := readCounters(t, pub.URL)
	holds("talon-first after its alert", after)
	if after.alerts != mid.alerts+1 || after.detected != 5 || after.responded != 5 {
		t.Fatalf("talon-first after its alert: %+v", after)
	}

	// Terminal Talon-first: the runner publishes `responded` before any `detected`. The window holds
	// the response back until its detection, so detected >= responded holds throughout.
	state(hub, "terminal-first", "queued")
	talon(internal.URL, "terminal-first")
	state(hub, "terminal-first", "responded")
	tf := readCounters(t, pub.URL)
	if tf.responded != after.responded || tf.detected < tf.responded || tf.actions < tf.responded {
		t.Fatalf("terminal talon-first, before its detection: %+v (before %+v)", tf, after)
	}
	falco(internal.URL, "terminal-first")
	state(hub, "terminal-first", "detected")
	state(hub, "terminal-first", "finished")
	after = readCounters(t, pub.URL)
	holds("terminal talon-first after its detection", after)
	if after.detected != 6 || after.responded != 6 {
		t.Fatalf("terminal talon-first after its detection: %+v", after)
	}

	// The restart: a new collector loads what the old one wrote.
	blob, err := c1.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	c2 := stats.New(store, nil)
	if err := c2.Load(blob); err != nil {
		t.Fatal(err)
	}
	hub2, pub2, internal2 := start(c2)
	restarted := readCounters(t, pub2.URL)
	holds("after the restart", restarted)
	if restarted.alerts != after.alerts || restarted.detected != after.detected || !restarted.since.Equal(after.since) {
		t.Fatalf("after the restart: %+v, before it %+v", restarted, after)
	}
	state(hub2, "post-restart", "queued")
	falco(internal2.URL, "post-restart")
	state(hub2, "post-restart", "detected")
	holds("a run after the restart", readCounters(t, pub2.URL))
}
