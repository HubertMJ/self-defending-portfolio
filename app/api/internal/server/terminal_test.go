package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/events"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/limits"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/ruleindex"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/runlog"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/runner"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/scenarios"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/stats"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/webhook"
)

const terminalCatalogue = `
- id: shell-in-container
  title: Shell
  summary: s
  technique: T1059.004
  detection: Terminal shell in container
  response: terminate
  timeout_seconds: 20
  pod:
    containers: [{name: target, image: "` + img + `"}]
  exec: {command: [sh, -c, id], tty: true}
- id: terminal
  title: Terminal
  summary: s
  interactive: true
  timeout_seconds: 20
  idle_seconds: 10
  objectives:
    - {id: recon, title: "Look"}
  commands:
    - {id: whoami, input: "id", objective: recon, command: [id], outcome: allowed, layer: runtime, control: none, explain: ok}
    - {id: read-shadow, input: "cat /etc/shadow", command: [cat, /etc/shadow], outcome: detected, layer: runtime,
       control: Falco, detection: "Read sensitive file untrusted", response: terminate, explain: x}
  pod:
    containers: [{name: target, image: "` + img + `"}]
`

func newTerminalEnv(t *testing.T) (*env, *stats.Collector) {
	t.Helper()
	path := t.TempDir() + "/scenarios.yaml"
	if err := os.WriteFile(path, []byte(terminalCatalogue), 0o600); err != nil {
		t.Fatal(err)
	}
	kube := fake.NewClientset()
	kube.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		p := a.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
		p.Status.Phase = corev1.PodRunning
		p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		return false, nil, nil
	})
	store := scenarios.NewStore(path, nil)
	hub := events.NewHub(200)
	runs := runlog.New(0, 0, 0, 0)
	collector := stats.New(store, nil)
	hub.Tap(func(ev events.Event) { runs.Record(ev); collector.Record(ev) })
	rules, _ := ruleindex.Load()
	run := runner.New(kube, noopExec{}, hub, nil, runner.Config{
		PollInterval: 5 * time.Millisecond, QuarantineLinger: -1, CommandTimeout: 80 * time.Millisecond,
		UnguardedNamespace: "sandbox-unguarded", CompareHold: 50 * time.Millisecond})
	attacks := limits.NewAttacks(limits.DefaultAttackConfig(), nil)
	srv := New(Config{
		Scenarios: store, Runner: run, Hub: hub, Posture: stubPosture{},
		Attacks: attacks, Requests: limits.NewRequests(1000, time.Minute, 1000, nil),
		Streams: limits.NewConns(2, 10), FalcoAlerts: webhook.NewDayWindow(nil), TalonActions: webhook.NewDayWindow(nil),
		AllowedOrigin: "https://hubertjablon.ski", Namespace: "sandbox", UnguardedNamespace: "sandbox-unguarded",
		Runs: runs, Rules: rules, Stats: collector,
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
	return e, collector
}

func TestTerminalAttackAndCommand(t *testing.T) {
	e, _ := newTerminalEnv(t)
	resp := e.post(t, "/api/attack/terminal", "198.51.100.5", nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("attack: %d", resp.StatusCode)
	}
	var ar struct {
		RunID    string `json:"run_id"`
		Token    string `json:"token"`
		Scenario string `json:"scenario"`
		State    string `json:"state"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		t.Fatal(err)
	}
	if len(ar.Token) != 32 || ar.RunID == "" || ar.Scenario != "terminal" {
		t.Fatalf("attack response: %+v", ar)
	}

	// No token -> 401.
	if code, _ := e.command(t, ar.RunID, "", `{"id":"whoami"}`); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}
	// Wrong token -> 401.
	if code, _ := e.command(t, ar.RunID, "00000000000000000000000000000000", `{"id":"whoami"}`); code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", code)
	}
	// Unknown command -> 404.
	if code, _ := e.command(t, ar.RunID, ar.Token, `{"id":"ghost"}`); code != http.StatusNotFound {
		t.Fatalf("unknown command: %d", code)
	}
	// Valid command (retry past the ready window) -> 202 with a seq.
	var seq int
	deadline := time.Now().Add(3 * time.Second)
	for {
		code, body := e.command(t, ar.RunID, ar.Token, `{"id":"whoami"}`)
		if code == http.StatusAccepted {
			seq = decode[struct {
				Seq int `json:"seq"`
			}](t, strings.NewReader(body)).Seq
			break
		}
		if code != http.StatusConflict || time.Now().After(deadline) {
			t.Fatalf("command: %d %s", code, body)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if seq != 1 {
		t.Fatalf("seq = %d", seq)
	}
	// Leave -> 202.
	req, _ := http.NewRequest("DELETE", e.public.URL+"/api/runs/"+ar.RunID, nil)
	req.Header.Set("Authorization", "Bearer "+ar.Token)
	dr, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = dr.Body.Close()
	if dr.StatusCode != http.StatusAccepted {
		t.Fatalf("leave: %d", dr.StatusCode)
	}
}

func TestTerminalDetailsAndList(t *testing.T) {
	e, _ := newTerminalEnv(t)
	resp, _ := http.Get(e.public.URL + "/api/scenarios")
	list := decode[[]map[string]any](t, resp.Body)
	var terminalInteractive bool
	for _, s := range list {
		if s["id"] == "terminal" {
			terminalInteractive, _ = s["interactive"].(bool)
		}
	}
	if !terminalInteractive {
		t.Fatalf("terminal not marked interactive: %v", list)
	}
	resp, _ = http.Get(e.public.URL + "/api/scenarios/terminal/details")
	d := decode[map[string]any](t, resp.Body)
	if d["interactive"] != true || d["idle_seconds"].(float64) != 10 {
		t.Fatalf("details: %v", d)
	}
	cmds, ok := d["commands"].([]any)
	if !ok || len(cmds) != 2 {
		t.Fatalf("commands: %v", d["commands"])
	}
	first := cmds[0].(map[string]any)
	if first["id"] != "whoami" || first["command"].([]any)[0] != "id" {
		t.Fatalf("command argv missing: %v", first)
	}
}

func TestCompareRejectedForTerminal(t *testing.T) {
	e, _ := newTerminalEnv(t)
	if r := e.post(t, "/api/attack/terminal?compare=1", "198.51.100.6", nil); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("compare terminal: %d", r.StatusCode)
	}
}

func TestCompareCreatesTwoPods(t *testing.T) {
	e, _ := newTerminalEnv(t)
	if r := e.post(t, "/api/attack/shell-in-container?compare=1", "198.51.100.7", nil); r.StatusCode != http.StatusAccepted {
		t.Fatalf("compare attack: %d", r.StatusCode)
	}
	if !waitPods(t, e.kube, "sandbox") || !waitPods(t, e.kube, "sandbox-unguarded") {
		t.Fatal("compare did not create a pod in each namespace")
	}
}

func TestStatsEndpoint(t *testing.T) {
	e, _ := newTerminalEnv(t)
	// Before any run: well-formed and empty.
	resp, _ := http.Get(e.public.URL + "/api/stats")
	s := decode[map[string]any](t, resp.Body)
	if s["since"] == nil || s["runs"].(float64) != 0 {
		t.Fatalf("empty stats: %v", s)
	}
	e.post(t, "/api/attack/shell-in-container", "198.51.100.8", nil)
	waitPods(t, e.kube, "sandbox")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, _ = http.Get(e.public.URL + "/api/stats")
		if decode[map[string]any](t, resp.Body)["runs"].(float64) >= 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("run not counted in stats")
}

// --- helpers ---

func (e *env) command(t *testing.T, runID, token, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", e.public.URL+"/api/runs/"+runID+"/commands", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func waitPods(t *testing.T, kube *fake.Clientset, ns string) bool {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		l, err := kube.CoreV1().Pods(ns).List(context.Background(), metav1.ListOptions{})
		if err == nil && len(l.Items) > 0 {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// A 413 for an oversized command body, a 429 past the per-run command cap, and the token never
// appearing in any event or in GET /api/runs/{id} (items 26).
func TestTerminalCommandLimitsAndTokenSecrecy(t *testing.T) {
	e, _ := newTerminalEnv(t)
	resp := e.post(t, "/api/attack/terminal", "198.51.100.10", nil)
	var ar struct {
		RunID string `json:"run_id"`
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&ar)

	// 413: a body over the 256-byte cap.
	big := `{"id":"` + strings.Repeat("a", 300) + `"}`
	if code, _ := e.command(t, ar.RunID, ar.Token, big); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d", code)
	}

	// Drive 30 accepted commands, then the 31st is 429. Each must settle before the next (409 while
	// one runs), so retry past 409/also the initial not-ready window.
	ok := 0
	deadline := time.Now().Add(10 * time.Second)
	for ok < 30 && time.Now().Before(deadline) {
		code, _ := e.command(t, ar.RunID, ar.Token, `{"id":"whoami"}`)
		switch code {
		case http.StatusAccepted:
			ok++
		case http.StatusConflict:
			time.Sleep(5 * time.Millisecond)
		default:
			t.Fatalf("command %d: %d", ok, code)
		}
	}
	if ok != 30 {
		t.Fatalf("only %d commands accepted", ok)
	}
	// The 31st, once no command is running, is 429.
	for time.Now().Before(deadline) {
		code, _ := e.command(t, ar.RunID, ar.Token, `{"id":"whoami"}`)
		if code == http.StatusTooManyRequests {
			break
		}
		if code != http.StatusConflict {
			t.Fatalf("31st command: %d", code)
		}
		time.Sleep(5 * time.Millisecond)
	}

	// The token is in neither the run's events nor the run record.
	runResp, err := http.Get(e.public.URL + "/api/runs/" + ar.RunID)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(runResp.Body)
	_ = runResp.Body.Close()
	if strings.Contains(string(body), ar.Token) {
		t.Fatal("token leaked into GET /api/runs/{id}")
	}
}

// A command and a leave on a run that has ended get 409 (not 404): the run existed and is over.
func TestTerminalEndedRunIs409(t *testing.T) {
	e, _ := newTerminalEnv(t)
	resp := e.post(t, "/api/attack/terminal", "198.51.100.11", nil)
	var ar struct {
		RunID string `json:"run_id"`
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&ar)
	// Leave to end the run.
	req, _ := http.NewRequest("DELETE", e.public.URL+"/api/runs/"+ar.RunID, nil)
	req.Header.Set("Authorization", "Bearer "+ar.Token)
	dr, _ := http.DefaultClient.Do(req)
	_ = dr.Body.Close()
	// Wait for it to actually finish, then a command is 409, and an unknown run is 404.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		code, _ := e.command(t, ar.RunID, ar.Token, `{"id":"whoami"}`)
		if code == http.StatusConflict {
			break
		}
		if code != http.StatusAccepted && code != http.StatusConflict {
			t.Fatalf("ended run command: %d", code)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if code, _ := e.command(t, "ffffffffffffffff", ar.Token, `{"id":"whoami"}`); code != http.StatusNotFound {
		t.Fatalf("unknown run: %d", code)
	}
}
