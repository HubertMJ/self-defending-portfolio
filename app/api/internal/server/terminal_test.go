package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/ruleindex"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/runlog"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/runner"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/scenarios"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/stats"
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

// newTerminalEnv is a server with the terminal catalogue; opts adjust the runner's config.
func newTerminalEnv(t *testing.T, opts ...func(*runner.Config)) (*env, *stats.Collector) {
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
	rcfg := runner.Config{
		PollInterval: 5 * time.Millisecond, QuarantineLinger: -1, CommandTimeout: 80 * time.Millisecond,
		UnguardedNamespace: "sandbox-unguarded", CompareHold: 50 * time.Millisecond}
	for _, o := range opts {
		o(&rcfg)
	}
	run := runner.New(kube, noopExec{}, hub, nil, rcfg)
	attacks := limits.NewAttacks(limits.DefaultAttackConfig(), nil)
	srv := New(Config{
		Scenarios: store, Runner: run, Hub: hub, Posture: stubPosture{},
		Attacks: attacks, Requests: limits.NewRequests(1000, time.Minute, 1000, nil),
		Streams: limits.NewConns(2, 10), FalcoAlerts: collector.AlertCounter(), TalonActions: collector.ActionCounter(),
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
	// Both bounds the page shows, as the catalogue sets them (Timeout() and Idle(), not a default).
	if d["interactive"] != true || d["idle_seconds"] != float64(10) || d["timeout_seconds"] != float64(20) {
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
	// The 31st, once no command is running, is 429 - and must be seen before the deadline, not
	// assumed when the loop runs out of time, and must be the command cap's 429, not the
	// per-visitor request limiter's that this polling loop would reach on its own.
	saw429 := false
	for !saw429 && time.Now().Before(deadline) {
		code, body := e.command(t, ar.RunID, ar.Token, `{"id":"whoami"}`)
		if code == http.StatusTooManyRequests {
			if !strings.Contains(body, "too many commands in this run") {
				t.Fatalf("429 from something other than the command cap: %s", body)
			}
			saw429 = true
			break
		}
		if code != http.StatusConflict {
			t.Fatalf("31st command: %d", code)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !saw429 {
		t.Fatal("the 31st command never got 429")
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
	// Wait until the run has ended completely - pod deleted, slot released, the run no longer
	// registered - so the 409 comes from the record of ended runs, not from a run still finishing.
	deadline := time.Now().Add(5 * time.Second)
	for e.attacks.Active() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the run never released its slot")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if code, _ := e.command(t, ar.RunID, ar.Token, `{"id":"whoami"}`); code != http.StatusConflict {
		t.Fatalf("command on an ended run: %d, want 409", code)
	}
	req, _ = http.NewRequest("DELETE", e.public.URL+"/api/runs/"+ar.RunID, nil)
	req.Header.Set("Authorization", "Bearer "+ar.Token)
	dr, _ = http.DefaultClient.Do(req)
	_ = dr.Body.Close()
	if dr.StatusCode != http.StatusConflict {
		t.Fatalf("leave on an ended run: %d, want 409", dr.StatusCode)
	}
	if code, _ := e.command(t, "ffffffffffffffff", ar.Token, `{"id":"whoami"}`); code != http.StatusNotFound {
		t.Fatalf("unknown run: %d", code)
	}
}

// startTerminal POSTs /api/attack/terminal and returns the run id and token.
func startTerminal(t *testing.T, e *env, ip string) (string, string) {
	t.Helper()
	resp := e.post(t, "/api/attack/terminal", ip, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("attack: %d", resp.StatusCode)
	}
	ar := decode[struct {
		RunID string `json:"run_id"`
		Token string `json:"token"`
	}](t, resp.Body)
	return ar.RunID, ar.Token
}

// commandWithin POSTs a command and returns its status, failing the test if it takes longer than d -
// a command is answered at once, never held until the run can take it.
func commandWithin(t *testing.T, e *env, runID, token string, d time.Duration) int {
	t.Helper()
	got := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest("POST", e.public.URL+"/api/runs/"+runID+"/commands", strings.NewReader(`{"id":"whoami"}`))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			got <- 0
			return
		}
		_ = resp.Body.Close()
		got <- resp.StatusCode
	}()
	select {
	case code := <-got:
		return code
	case <-time.After(d):
		t.Fatalf("the command was not answered within %v", d)
		return 0
	}
}

// 409 before the pod is ready (the run exists, the command cannot run yet) and 409 while another
// command is running - answered at once in both cases.
func TestTerminalCommandNotReadyAndBusy(t *testing.T) {
	e, _ := newTerminalEnv(t, func(c *runner.Config) { c.CommandTimeout = 3 * time.Second })
	created := make(chan struct{})
	var once sync.Once
	create := func() { once.Do(func() { close(created) }) }
	// Registered after newTerminalEnv's cleanup, so it runs first: a held pod create (and any command
	// waiting on it) is let go before the servers and the runner are shut down.
	t.Cleanup(create)
	e.kube.PrependReactor("create", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		<-created // the pod is not created, so never ready, until the test says so
		return false, nil, nil
	})
	runID, token := startTerminal(t, e, "198.51.100.20")
	if code := commandWithin(t, e, runID, token, time.Second); code != http.StatusConflict {
		t.Fatalf("command before pod_ready: %d, want 409", code)
	}
	create()

	// Ready: the first command is accepted and runs (noopExec holds it for CommandTimeout, 3 s).
	deadline := time.Now().Add(3 * time.Second)
	for code := commandWithin(t, e, runID, token, time.Second); code != http.StatusAccepted; code = commandWithin(t, e, runID, token, time.Second) {
		if code != http.StatusConflict || time.Now().After(deadline) {
			t.Fatalf("first command: %d", code)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if code := commandWithin(t, e, runID, token, time.Second); code != http.StatusConflict {
		t.Fatalf("command while another runs: %d, want 409", code)
	}
}

// Concurrent POSTs on one run: while a command runs, exactly one of a burst is accepted, the rest
// are 409, and no seq is handed out twice.
func TestTerminalConcurrentCommands(t *testing.T) {
	e, _ := newTerminalEnv(t, func(c *runner.Config) { c.CommandTimeout = 3 * time.Second })
	runID, token := startTerminal(t, e, "198.51.100.21")
	waitRunState(t, e, runID, "pod_ready") // accepting commands, none run yet

	const n = 12
	var wg sync.WaitGroup
	codes := make(chan int, n)
	seqs := make(chan int, n)
	start := make(chan struct{})
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			code, body := e.command(t, runID, token, `{"id":"whoami"}`)
			codes <- code
			if code == http.StatusAccepted {
				seqs <- decode[struct {
					Seq int `json:"seq"`
				}](t, strings.NewReader(body)).Seq
			}
		}()
	}
	close(start)
	wg.Wait()
	close(codes)
	close(seqs)
	accepted, conflict := 0, 0
	for c := range codes {
		switch c {
		case http.StatusAccepted:
			accepted++
		case http.StatusConflict:
			conflict++
		default:
			t.Fatalf("concurrent command: %d", c)
		}
	}
	if accepted != 1 || conflict != n-1 {
		t.Fatalf("%d accepted, %d conflicts; want exactly one accepted while it runs", accepted, conflict)
	}
	if s := <-seqs; s != 1 {
		t.Fatalf("seq = %d, want 1", s)
	}
}

// The run's token never appears on the event stream: not in the attack's events, not in a
// command's, not in the run's end.
func TestTerminalTokenNotOnStream(t *testing.T) {
	e, _ := newTerminalEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := openStream(t, ctx, e, "198.51.100.22", "")
	runID, token := startTerminal(t, e, "198.51.100.23")
	deadline := time.Now().Add(3 * time.Second)
	for {
		code, _ := e.command(t, runID, token, `{"id":"whoami"}`)
		if code == http.StatusAccepted {
			break
		}
		if code != http.StatusConflict || time.Now().After(deadline) {
			t.Fatalf("command: %d", code)
		}
		time.Sleep(5 * time.Millisecond)
	}
	waitRunState(t, e, runID, "exited")
	req, _ := http.NewRequest("DELETE", e.public.URL+"/api/runs/"+runID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if dr, err := http.DefaultClient.Do(req); err == nil {
		_ = dr.Body.Close()
	}
	// Every frame of the stream, up to and including the run's end.
	var frames []string
	for !strings.Contains(strings.Join(frames, "\n"), `"state":"finished"`) {
		f := stream.next(t, 5*time.Second)
		if f == "" {
			t.Fatalf("stream ended before the run finished: %v", frames)
		}
		frames = append(frames, f)
	}
	all := strings.Join(frames, "\n")
	if !strings.Contains(all, runID) {
		t.Fatal("the stream did not carry the run (the check would prove nothing)")
	}
	if strings.Contains(all, token) {
		t.Fatal("the run's token appeared on the event stream")
	}
}

// waitRunState waits until GET /api/runs/{id} holds an event whose state is state.
func waitRunState(t *testing.T, e *env, runID, state string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(e.public.URL + "/api/runs/" + runID)
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if strings.Contains(string(b), `"state":"`+state+`"`) {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("run %s never reached %q", runID, state)
}

// refusingRunner is the real runner except that Start refuses every scenario, as it refuses one it
// cannot run.
type refusingRunner struct{ *runner.Runner }

func (refusingRunner) Start(scenarios.Scenario, func()) (string, error) {
	return "", runner.ErrInteractive
}

// When the runner refuses a scenario after the slot was taken, the server gives the slot back: the
// answer is 400, and the next attack is not told another one is running.
func TestRefusedStartReleasesSlot(t *testing.T) {
	path := t.TempDir() + "/scenarios.yaml"
	if err := os.WriteFile(path, []byte(terminalCatalogue), 0o600); err != nil {
		t.Fatal(err)
	}
	run := runner.New(fake.NewClientset(), noopExec{}, events.NewHub(10), nil, runner.Config{})
	attacks := limits.NewAttacks(limits.DefaultAttackConfig(), nil)
	srv := New(Config{Scenarios: scenarios.NewStore(path, nil), Runner: refusingRunner{run}, Hub: events.NewHub(10),
		Posture: stubPosture{}, Attacks: attacks, Requests: limits.NewRequests(1000, time.Minute, 1000, nil),
		Streams: limits.NewConns(2, 10), AllowedOrigin: "https://hubertjablon.ski"})
	e := &env{public: httptest.NewServer(srv.Public()), attacks: attacks}
	defer e.public.Close()
	for i := range 2 {
		resp := e.post(t, "/api/attack/shell-in-container", "198.51.100.30", nil)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("attack %d: %d, want 400", i, resp.StatusCode)
		}
		if n := attacks.Active(); n != 0 {
			t.Fatalf("attack %d: %d slots still held after a refused start", i, n)
		}
	}
}
