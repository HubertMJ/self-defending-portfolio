package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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

const img = "ghcr.io/hubertmj/self-defending-portfolio/scenario:main@sha256:0000000000000000000000000000000000000000000000000000000000000000"

const catalogue = `
- id: shell-in-container
  title: Terminal shell in container
  summary: s
  technique: T1059.004
  detection: Terminal shell in container
  response: terminate
  timeout_seconds: 20
  victim: true
  pod:
    securityContext: {runAsNonRoot: true, runAsUser: 10001, seccompProfile: {type: RuntimeDefault}}
    containers:
      - name: victim
        image: "` + img + `"
        securityContext:
          runAsUser: 10002
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities: {drop: [ALL]}
        resources: {requests: {cpu: 10m, memory: 16Mi}, limits: {cpu: 100m, memory: 32Mi}}
  exec: {command: [sh, -c, id], tty: true}
- id: network-tool
  title: Network tool
  summary: s
  technique: T1105
  detection: SDP network tool in sandbox
  response: quarantine
  timeout_seconds: 20
  pod:
    containers: [{name: victim, image: "` + img + `"}]
  exec: {command: [wget, -q, example.com], tty: false}
`

type noopExec struct{}

func (noopExec) Exec(ctx context.Context, _, _, _ string, _ []string, _ bool) error {
	<-ctx.Done()
	return ctx.Err()
}

func (noopExec) ExecStream(ctx context.Context, _, _, _ string, _ []string, _ bool, _, _ io.Writer) (int, error) {
	<-ctx.Done()
	return -1, ctx.Err()
}

type stubPosture struct{}

func (stubPosture) Get(context.Context) posture.Snapshot {
	return posture.Snapshot{Kyverno: posture.Kyverno{Policies: []posture.PolicyCount{}}}
}

type env struct {
	public, internal *httptest.Server
	attacks          *limits.Attacks
	runner           *runner.Runner
	kube             *fake.Clientset
}

func newEnv(t *testing.T, cfg limits.AttackConfig) *env {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scenarios.yaml")
	if err := os.WriteFile(path, []byte(catalogue), 0o600); err != nil {
		t.Fatal(err)
	}
	kube := fake.NewClientset()
	kube.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		p := a.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
		p.Status.Phase = corev1.PodRunning
		p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		return false, nil, nil
	})
	hub := events.NewHub(50)
	runs := runlog.New(0, 0, 0, 0)
	hub.Tap(runs.Record)
	rules, err := ruleindex.Load()
	if err != nil {
		t.Fatal(err)
	}
	run := runner.New(kube, noopExec{}, hub, nil, runner.Config{PollInterval: 5 * time.Millisecond, QuarantineLinger: -1})
	attacks := limits.NewAttacks(cfg, nil)
	store := scenarios.NewStore(path, nil)
	collector := stats.New(store, nil)
	srv := New(Config{
		Scenarios:     store,
		Runner:        run,
		Hub:           hub,
		Posture:       stubPosture{},
		Attacks:       attacks,
		Requests:      limits.NewRequests(1000, time.Minute, 1000, nil),
		Streams:       limits.NewConns(2, 10),
		FalcoAlerts:   collector.AlertCounter(),
		TalonActions:  collector.ActionCounter(),
		AllowedOrigin: "https://hubertjablon.ski",
		Heartbeat:     50 * time.Millisecond,
		Runs:          runs,
		Rules:         rules,
		Commit:        "0123456789abcdef0123456789abcdef01234567",
	})
	e := &env{public: httptest.NewServer(srv.Public()), internal: httptest.NewServer(srv.Internal()),
		attacks: attacks, runner: run, kube: kube}
	t.Cleanup(func() {
		e.public.Close()
		e.internal.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = run.Shutdown(ctx)
	})
	return e
}

func (e *env) post(t *testing.T, path, ip string, hdr map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", e.public.URL+path, nil)
	if ip != "" {
		req.Header.Set("CF-Connecting-IP", ip)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func decode[T any](t *testing.T, r io.Reader) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(r).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestHealthzAndScenarios(t *testing.T) {
	e := newEnv(t, limits.DefaultAttackConfig())
	resp, err := http.Get(e.public.URL + "/api/healthz")
	if err != nil {
		t.Fatal(err)
	}
	if got := decode[map[string]string](t, resp.Body); got["status"] != "ok" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("healthz: %v %v", got, resp.Header)
	}
	resp, _ = http.Get(e.public.URL + "/api/scenarios")
	list := decode[[]map[string]any](t, resp.Body)
	if len(list) != 2 || list[0]["id"] != "shell-in-container" || list[1]["response"] != "quarantine" {
		t.Fatalf("scenarios: %v", list)
	}
	if _, leaked := list[0]["pod"]; leaked {
		t.Fatal("pod spec exposed publicly")
	}
	for _, c := range []struct{ method, path string }{{"GET", "/api/attack/shell-in-container"}, {"POST", "/api/events"}, {"DELETE", "/api/posture"}} {
		req, _ := http.NewRequest(c.method, e.public.URL+c.path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Content-Type") != "application/json" {
			t.Errorf("%s %s: %d %s", c.method, c.path, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
	}
	for _, u := range []string{e.public.URL + "/internal/falco", e.public.URL + "/api/nope"} {
		resp, _ := http.Post(u, "application/json", strings.NewReader("{}"))
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d", u, resp.StatusCode)
		}
	}
}

func TestAttackStatusCodes(t *testing.T) {
	e := newEnv(t, limits.DefaultAttackConfig())
	if r := e.post(t, "/api/attack/does-not-exist", "198.51.100.1", nil); r.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown id: %d", r.StatusCode)
	}
	r := e.post(t, "/api/attack/shell-in-container", "198.51.100.1", nil)
	if r.StatusCode != http.StatusAccepted {
		t.Fatalf("first: %d", r.StatusCode)
	}
	body := decode[map[string]string](t, r.Body)
	if body["state"] != "queued" || body["scenario"] != "shell-in-container" || len(body["run_id"]) != 16 {
		t.Fatalf("202 body: %v", body)
	}
	if r := e.post(t, "/api/attack/network-tool", "198.51.100.2", nil); r.StatusCode != http.StatusConflict {
		t.Fatalf("concurrent: %d", r.StatusCode)
	}
	for name, hdr := range map[string]map[string]string{
		"foreign origin": {"Origin": "https://evil.example"},
		"cross-site":     {"Sec-Fetch-Site": "cross-site"},
	} {
		if r := e.post(t, "/api/attack/shell-in-container", "198.51.100.3", hdr); r.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %d", name, r.StatusCode)
		}
	}
	if r := e.post(t, "/api/attack/shell-in-container", "198.51.100.3",
		map[string]string{"Origin": "https://hubertjablon.ski", "Sec-Fetch-Site": "same-origin"}); r.StatusCode != http.StatusConflict {
		t.Errorf("same-origin browser request: %d, want 409 (run still active)", r.StatusCode)
	}
}

// TestHammer is the in-process version of tests/abuse/run.sh: many clients at once, then the
// arithmetic of the limits has to hold exactly.
func TestHammer(t *testing.T) {
	e := newEnv(t, limits.AttackConfig{PerKey: 3, PerKeyWindow: 10 * time.Minute, Global: 5, GlobalWindow: time.Hour, Concurrent: 1})

	// Phase 1: 40 simultaneous requests while nothing runs. Exactly one wins the slot.
	codes := hammer(t, e, 40, func(i int) string { return fmt.Sprintf("203.0.113.%d", i%8) })
	if codes[http.StatusAccepted] != 1 || codes[http.StatusConflict] != 39 {
		t.Fatalf("burst: %v", codes)
	}

	// Phase 2: run runs one after another (each run is ended through the webhook, as Talon would),
	// one visitor until their per-IP budget is spent, then fresh visitors until the global one is.
	finish := func() {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for e.attacks.Active() != 0 {
			pods, _ := e.kube.CoreV1().Pods("sandbox").List(context.Background(), metavOpts())
			for _, p := range pods.Items {
				talon := fmt.Sprintf(`{"objects":{"pod":%q,"namespace":"sandbox"},"action":"Terminate Pod","status":"success"}`, p.Name)
				resp, err := http.Post(e.internal.URL+"/internal/talon", "application/json", strings.NewReader(talon))
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()
			}
			if time.Now().After(deadline) {
				t.Fatal("run did not end")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	finish()
	sameIP := "203.0.113.200"
	for i := range 3 {
		if r := e.post(t, "/api/attack/shell-in-container", sameIP, nil); r.StatusCode != http.StatusAccepted {
			// Phase 1's winner (one of 203.0.113.0-7) used one global slot; this visitor has 3.
			t.Fatalf("same IP attempt %d: %d", i, r.StatusCode)
		}
		finish()
	}
	r := e.post(t, "/api/attack/shell-in-container", sameIP, nil)
	if r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("4th from one IP: %d", r.StatusCode)
	}
	if ra, _ := strconv.Atoi(r.Header.Get("Retry-After")); ra < 590 || ra > 600 {
		t.Fatalf("Retry-After = %q, want ~600", r.Header.Get("Retry-After"))
	}
	// An IPv6 visitor rotating addresses inside one /64 is one visitor.
	// Global: 1 (phase 1) + 3 = 4 used of 5.
	if r := e.post(t, "/api/attack/shell-in-container", "2001:db8:0:1::1", nil); r.StatusCode != http.StatusAccepted {
		t.Fatalf("v6 first: %d", r.StatusCode)
	}
	finish()
	r = e.post(t, "/api/attack/shell-in-container", "2001:db8:0:1::2", nil)
	if r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("global budget: %d", r.StatusCode)
	}
	if ra, _ := strconv.Atoi(r.Header.Get("Retry-After")); ra < 3500 || ra > 3600 {
		t.Fatalf("global Retry-After = %q", r.Header.Get("Retry-After"))
	}
	if n := len(mustList(t, e)); n != 0 {
		t.Fatalf("%d scenario pods left behind", n)
	}
}

func metavOpts() metav1.ListOptions { return metav1.ListOptions{} }

func mustList(t *testing.T, e *env) []corev1.Pod {
	t.Helper()
	pods, err := e.kube.CoreV1().Pods("sandbox").List(context.Background(), metavOpts())
	if err != nil {
		t.Fatal(err)
	}
	return pods.Items
}

func hammer(t *testing.T, e *env, n int, ip func(int) string) map[int]int {
	t.Helper()
	var mu sync.Mutex
	codes := map[int]int{}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			req, _ := http.NewRequest("POST", e.public.URL+"/api/attack/shell-in-container", nil)
			req.Header.Set("CF-Connecting-IP", ip(i))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			_ = resp.Body.Close()
			mu.Lock()
			codes[resp.StatusCode]++
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()
	return codes
}

// TestEventStream drives a whole run through the webhooks and reads it back from the SSE stream,
// including the replay a late subscriber gets and Last-Event-ID resumption.
func TestEventStream(t *testing.T) {
	e := newEnv(t, limits.DefaultAttackConfig())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := openStream(t, ctx, e, "192.0.2.10", "")

	r := e.post(t, "/api/attack/network-tool", "192.0.2.10", nil)
	if r.StatusCode != http.StatusAccepted {
		t.Fatalf("attack: %d", r.StatusCode)
	}
	runID := decode[map[string]string](t, r.Body)["run_id"]
	pod := "network-tool-" + runID[:10]
	stream.until(t, "run", `"state":"started"`)

	// An alert from another namespace is counted but not published; then the real one.
	sendInternal(t, e, "/internal/falco", `{"rule":"Read sensitive file untrusted","priority":"Warning","output":"x",
		"output_fields":{"k8s.ns.name":"hello","k8s.pod.name":"hello-1"}}`)
	sendInternal(t, e, "/internal/falco", fmt.Sprintf(`{"rule":"SDP network tool in sandbox","priority":"Warning",
		"output":"wget started","time":"2026-10-01T12:00:00Z","output_fields":{"k8s.ns.name":"sandbox","k8s.pod.name":%q}}`, pod))
	falco := stream.until(t, "falco", pod)
	if strings.Contains(falco, "hello-1") {
		t.Fatal("non-sandbox alert published")
	}
	stream.until(t, "run", `"state":"detected"`)
	sendInternal(t, e, "/internal/talon", fmt.Sprintf(`{"objects":{"Pod":%q,"Namespace":"sandbox"},"action":"Quarantine Pod","status":"success"}`, pod))
	stream.until(t, "talon", `"action":"Quarantine Pod"`)
	stream.until(t, "run", `"state":"responded"`)
	last := stream.until(t, "run", `"state":"finished"`)

	// The whole run, alerts included, is in the run store.
	resp, err := http.Get(e.public.URL + "/api/runs/" + runID)
	if err != nil {
		t.Fatal(err)
	}
	run := decode[runlog.Run](t, resp.Body)
	seen := map[string]bool{}
	for _, ev := range run.Events {
		seen[ev.Type] = true
		if ev.ID == 0 || len(ev.Data) < 2 || ev.Data[0] != '{' {
			t.Fatalf("event %+v", ev)
		}
	}
	if run.RunID != runID || run.Scenario != "network-tool" || !seen["run"] || !seen["falco"] || !seen["talon"] || !seen["pod"] {
		t.Fatalf("run record: %+v", run)
	}

	// A late visitor gets the run replayed; one resuming after the last id gets nothing old.
	late := openStream(t, ctx, e, "192.0.2.11", "")
	late.until(t, "run", `"state":"queued"`)
	late.until(t, "run", `"state":"finished"`)
	lastID := strings.TrimPrefix(strings.SplitN(last, "\n", 2)[0], "id: ")
	resumed := openStream(t, ctx, e, "192.0.2.12", lastID)
	if got := resumed.next(t, 300*time.Millisecond); got != "" {
		t.Fatalf("resumed stream replayed %q", got)
	}
	if !resumed.sawHeartbeat {
		t.Fatal("no heartbeat on an idle stream")
	}

	// Per-visitor stream cap is 2 in this environment.
	_ = openStream(t, ctx, e, "192.0.2.10", "")
	req, _ := http.NewRequestWithContext(ctx, "GET", e.public.URL+"/api/events", nil)
	req.Header.Set("CF-Connecting-IP", "192.0.2.10")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("third stream from one IP: %d", resp.StatusCode)
	}
}

func sendInternal(t *testing.T, e *env, path, body string) {
	t.Helper()
	resp, err := http.Post(e.internal.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("%s: %d", path, resp.StatusCode)
	}
}

// The stream must pass through compressing and buffering proxies (Cloudflare's edge, Envoy) as it is
// written: exact SSE media type, no-transform, and a preamble of at least 2 KiB before the first
// event, all of it flushed before anything is published.
func TestEventStreamHeadersAndPreamble(t *testing.T) {
	e := newEnv(t, limits.DefaultAttackConfig())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", e.public.URL+"/api/events", nil)
	req.Header.Set("CF-Connecting-IP", "192.0.2.20")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("Content-Type = %q, want exactly text/event-stream", got)
	}
	if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "no-transform") || !strings.Contains(got, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store and no-transform", got)
	}
	if got := resp.Header.Get("X-Accel-Buffering"); got != "no" {
		t.Errorf("X-Accel-Buffering = %q", got)
	}
	// Nothing has been published: everything readable now is the preamble, flushed on its own.
	buf := make([]byte, 4096)
	got := 0
	deadline := time.Now().Add(2 * time.Second)
	for got < len(streamPreamble) && time.Now().Before(deadline) {
		n, err := resp.Body.Read(buf[got:])
		got += n
		if err != nil {
			break
		}
	}
	if got < 2048 || !strings.HasPrefix(string(buf[:got]), "retry: 5000\n\n:") {
		t.Fatalf("preamble: read %d bytes %q, want retry plus a 2 KiB comment", got, string(buf[:min(got, 40)]))
	}
}

func TestInternalRejectsGarbage(t *testing.T) {
	e := newEnv(t, limits.DefaultAttackConfig())
	resp, _ := http.Post(e.internal.URL+"/internal/falco", "application/json", strings.NewReader("nope"))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("garbage: %d", resp.StatusCode)
	}
	big := strings.NewReader(`{"output":"` + strings.Repeat("a", maxWebhookBody) + `"}`)
	resp, _ = http.Post(e.internal.URL+"/internal/talon", "application/json", big)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized: %d", resp.StatusCode)
	}
	resp, _ = http.Get(e.internal.URL + "/api/healthz")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("public path on internal port: %d", resp.StatusCode)
	}
}

type sse struct {
	lines        chan string
	sawHeartbeat bool
}

func openStream(t *testing.T, ctx context.Context, e *env, ip, lastID string) *sse {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, "GET", e.public.URL+"/api/events", nil)
	req.Header.Set("CF-Connecting-IP", ip)
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("stream: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	s := &sse{lines: make(chan string, 100)}
	go func() {
		defer func() { _ = resp.Body.Close() }()
		sc := bufio.NewScanner(resp.Body)
		var frame []string
		for sc.Scan() {
			line := sc.Text()
			if line != "" {
				frame = append(frame, line)
				continue
			}
			if len(frame) > 0 {
				s.lines <- strings.Join(frame, "\n")
			}
			frame = nil
		}
		close(s.lines)
	}()
	return s
}

// next returns the next event frame (heartbeats and retry are noted and skipped), or "" on timeout.
func (s *sse) next(t *testing.T, timeout time.Duration) string {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case f, ok := <-s.lines:
			if !ok {
				return ""
			}
			if strings.HasPrefix(f, ":") {
				if strings.HasPrefix(f, ": heartbeat") {
					s.sawHeartbeat = true
				}
				continue
			}
			if strings.HasPrefix(f, "retry:") {
				continue
			}
			return f
		case <-deadline:
			return ""
		}
	}
}

func (s *sse) until(t *testing.T, typ, contains string) string {
	t.Helper()
	for {
		f := s.next(t, 5*time.Second)
		if f == "" {
			t.Fatalf("stream ended or timed out waiting for %s %s", typ, contains)
		}
		if strings.Contains(f, "\nevent: "+typ+"\n") && strings.Contains(f, contains) {
			return f
		}
	}
}

func TestDetails(t *testing.T) {
	e := newEnv(t, limits.DefaultAttackConfig())
	resp, err := http.Get(e.public.URL + "/api/scenarios/shell-in-container/details")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"exec_command", "pre_exec_command", "pod_security", "resources", "image", "falco_rule", "talon_rule", "policies", "commit", "victim"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("details lacks %q", k)
		}
	}
	var d Details
	b, _ := json.Marshal(raw)
	_ = json.Unmarshal(b, &d)
	ps := d.PodSecurity
	if strings.Join(d.ExecCommand, " ") != "sh -c id" || !d.ExecTTY || !d.Victim ||
		*ps.RunAsUser != 10002 || !*ps.RunAsNonRoot || !*ps.ReadOnlyRootFilesystem || *ps.AllowPrivilegeEscalation ||
		strings.Join(ps.CapabilitiesDrop, ",") != "ALL" || ps.Seccomp != "RuntimeDefault" || ps.AutomountServiceAccountToken {
		t.Fatalf("details: %+v %+v", d, ps)
	}
	if d.Resources.Limits["memory"] != "32Mi" || d.Resources.Requests["cpu"] != "10m" ||
		d.Image.Ref != img || d.Image.Digest != "sha256:"+strings.Repeat("0", 64) {
		t.Fatalf("resources/image: %+v %+v", d.Resources, d.Image)
	}
	if d.FalcoRule.Name != "Terminal shell in container" || d.FalcoRule.File != "" ||
		d.TalonRule.Name != "Kill terminal shell in sandbox" || d.TalonRule.File == "" || d.TalonRule.Line == 0 ||
		len(d.Policies) == 0 || d.Commit != "0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("rules: %+v %+v %v %q", d.FalcoRule, d.TalonRule, d.Policies, d.Commit)
	}

	resp, _ = http.Get(e.public.URL + "/api/scenarios/network-tool/details")
	d = decode[Details](t, resp.Body)
	if d.Victim || d.PodSecurity.RunAsUser != nil || len(d.PodSecurity.CapabilitiesDrop) != 0 ||
		d.FalcoRule.File == "" || d.FalcoRule.Line == 0 || d.TalonRule.Name != "Quarantine network tool in sandbox" {
		t.Fatalf("network-tool: %+v", d)
	}
	resp, _ = http.Get(e.public.URL + "/api/scenarios/nope/details")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown scenario: %d", resp.StatusCode)
	}
	if New(Config{Commit: "unknown"}).cfg.Commit != "" {
		t.Fatal("a non-hex commit is published")
	}
}

func TestRunsUnknown(t *testing.T) {
	e := newEnv(t, limits.DefaultAttackConfig())
	for _, id := range []string{"0123456789abcdef", "../../etc", "ZZ"} {
		resp, err := http.Get(e.public.URL + "/api/runs/" + id)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound || resp.Header.Get("Content-Type") != "application/json" {
			t.Errorf("%s: %d", id, resp.StatusCode)
		}
	}
}

func TestLimits(t *testing.T) {
	e := newEnv(t, limits.DefaultAttackConfig())
	get := func(ip string) Limits {
		t.Helper()
		req, _ := http.NewRequest("GET", e.public.URL+"/api/limits", nil)
		req.Header.Set("CF-Connecting-IP", ip)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		return decode[Limits](t, resp.Body)
	}
	l := get("198.51.100.9")
	if l.PerVisitor != (VisitorLimit{Limit: 3, WindowS: 600, Remaining: 3}) || l.Global != (GlobalLimit{Limit: 30, WindowS: 3600, Remaining: 30}) ||
		l.ActiveRun || l.StreamSlotsRemaining != 2 {
		t.Fatalf("fresh: %+v", l)
	}
	if r := e.post(t, "/api/attack/shell-in-container", "198.51.100.9", nil); r.StatusCode != http.StatusAccepted {
		t.Fatalf("attack: %d", r.StatusCode)
	}
	l = get("198.51.100.9")
	if l.PerVisitor.Remaining != 2 || l.PerVisitor.ResetInS < 599 || l.PerVisitor.ResetInS > 600 || l.Global.Remaining != 29 || !l.ActiveRun {
		t.Fatalf("after one attack: %+v", l)
	}
	if other := get("198.51.100.10"); other.PerVisitor.Remaining != 3 || !other.ActiveRun {
		t.Fatalf("other visitor: %+v", other)
	}
}
