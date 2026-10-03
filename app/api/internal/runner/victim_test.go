package runner

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// victimApp is a stand-in for the scenario image's state server.
type victimApp struct {
	mu      sync.Mutex
	body    string
	ctype   string
	code    int
	delay   time.Duration
	srv     *httptest.Server
	port    int
	pathHit string
}

func newVictimApp(t *testing.T) *victimApp {
	t.Helper()
	a := &victimApp{body: `{"status":"up","title":"SDP Shop","banner":"Welcome","checksum":"00ff"}`,
		ctype: "application/json", code: 200}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		body, ctype, code, delay := a.body, a.ctype, a.code, a.delay
		a.pathHit = r.URL.Path
		a.mu.Unlock()
		time.Sleep(delay)
		if code == http.StatusFound {
			http.Redirect(w, r, "http://example.invalid/", code)
			return
		}
		w.Header().Set("Content-Type", ctype)
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(a.srv.Close)
	_, port, _ := net.SplitHostPort(a.srv.Listener.Addr().String())
	a.port, _ = strconv.Atoi(port)
	return a
}

func (a *victimApp) set(f func(a *victimApp)) { a.mu.Lock(); f(a); a.mu.Unlock() }

func TestVictimProbe(t *testing.T) {
	a := newVictimApp(t)
	p := newVictimProber(a.port, 300*time.Millisecond)
	ctx := context.Background()

	ev := p.probe(ctx, "127.0.0.1")
	if ev.Status != VictimUp || ev.Title != "SDP Shop" || ev.Banner != "Welcome" || ev.Checksum != "00ff" {
		t.Fatalf("up: %+v", ev)
	}
	if a.pathHit != "/state.json" {
		t.Fatalf("path %q", a.pathHit)
	}

	a.set(func(a *victimApp) {
		a.body = `{"status":"defaced","title":"<b>` + strings.Repeat("T", 100) + `</b>","banner":"line\none\u0007 <script>x</script>",` +
			`"checksum":"NOT-HEX","extra":"ignored"}`
	})
	ev = p.probe(ctx, "127.0.0.1")
	if ev.Status != VictimDefaced || len([]rune(ev.Title)) != victimMaxTitle || strings.ContainsAny(ev.Title+ev.Banner, "<>\n\a") ||
		ev.Banner != "line one scriptx/script" || ev.Checksum != "" {
		t.Fatalf("sanitised: %+v", ev)
	}

	bad := map[string]func(a *victimApp){
		"not json content type": func(a *victimApp) { a.body, a.ctype = `{"status":"up"}`, "text/html" },
		"unknown status":        func(a *victimApp) { a.body, a.ctype = `{"status":"pwned"}`, "application/json" },
		"not json":              func(a *victimApp) { a.body = `status=up` },
		"server error":          func(a *victimApp) { a.body, a.code = `{"status":"up"}`, 500 },
		"redirect":              func(a *victimApp) { a.code = http.StatusFound },
		"oversized":             func(a *victimApp) { a.code, a.body = 200, `{"status":"up","banner":"`+strings.Repeat("a", 5000)+`"}` },
	}
	for name, f := range bad {
		a.set(f)
		if ev := p.probe(ctx, "127.0.0.1"); ev.Status != VictimUnreachable || ev.Title != "" {
			t.Errorf("%s: %+v", name, ev)
		}
	}

	a.set(func(a *victimApp) {
		a.body, a.ctype, a.code, a.delay = `{"status":"up"}`, "application/json; charset=utf-8", 200, 0
	})
	if ev := p.probe(ctx, "127.0.0.1"); ev.Status != VictimUp {
		t.Fatalf("json with charset: %+v", ev)
	}
	a.set(func(a *victimApp) { a.delay = 600 * time.Millisecond })
	start := time.Now()
	if ev := p.probe(ctx, "127.0.0.1"); ev.Status != VictimUnreachable || ev.ProbeMS < 250 || ev.ProbeMS > 550 {
		t.Fatalf("slow: %+v", ev)
	}
	if time.Since(start) > 550*time.Millisecond {
		t.Fatal("probe did not give up at its timeout")
	}
	for _, ip := range []string{"", "localhost", "0.0.0.0", "example.com"} {
		if ev := p.probe(ctx, ip); ev.Status != VictimUnreachable {
			t.Errorf("address %q probed: %+v", ip, ev)
		}
	}
}

func TestPlainText(t *testing.T) {
	if got := plainText("  a\t\tb \r\n c  ", 80); got != "a b c" {
		t.Fatalf("%q", got)
	}
	if got := plainText("SDP\u202eShop\u200b\u2066!", 80); got != "SDPShop!" {
		t.Fatalf("format characters kept: %q", got)
	}
	if got := plainText(strings.Repeat("ż", 10), 5); got != "żżżż…" {
		t.Fatalf("%q", got)
	}
}

// defacer is an Execer that "runs" the scenario command by changing the victim app's state.
type defacer struct{ app *victimApp }

func (d defacer) Exec(ctx context.Context, _, _, _ string, _ []string, _ bool) error {
	d.app.set(func(a *victimApp) { a.body = `{"status":"defaced","title":"pwned","banner":"owned","checksum":"beef"}` })
	<-ctx.Done()
	return ctx.Err()
}

func (d defacer) ExecStream(ctx context.Context, _, _, _ string, _ []string, _ bool, _, _ io.Writer) (int, error) {
	d.app.set(func(a *victimApp) { a.body = `{"status":"defaced","title":"pwned","banner":"owned","checksum":"beef"}` })
	<-ctx.Done()
	return -1, ctx.Err()
}

func victimRunner(c *fake.Clientset, app *victimApp, rec *recorder) *Runner {
	return New(c, defacer{app}, rec, nil, Config{PollInterval: 10 * time.Millisecond, QuarantineLinger: -1,
		VictimPort: app.port, VictimInterval: 20 * time.Millisecond, VictimTimeout: 200 * time.Millisecond})
}

func TestVictimTerminatedByTalon(t *testing.T) {
	app := newVictimApp(t)
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := victimRunner(c, app, rec)
	release, done := released()
	sc := scenario("terminate", true)
	sc.Victim, sc.TimeoutSeconds = true, 30
	id := start(t, r, sc, release)
	pod := podName(sc.ID, id)

	waitOrder(t, rec, "victim:up")
	waitOrder(t, rec, "victim:defaced")
	if o := rec.order(); strings.Index(o, "run:pod_ready") > strings.Index(o, "victim:up") {
		t.Fatalf("victim probed before the pod was ready: %s", o)
	}
	// Talon deletes the pod, then reports.
	_ = c.CoreV1().Pods("sandbox").Delete(context.Background(), pod, metav1.DeleteOptions{})
	waitOrder(t, rec, "victim:gone")
	r.ObserveTalon("sandbox", pod, "success", "")
	<-done
	o := rec.order()
	if strings.Count(o, "victim:gone") != 1 || !strings.HasSuffix(o, "run:finished") ||
		strings.Index(o, "victim:gone") > strings.Index(o, "run:finished") {
		t.Fatalf("order: %s", o)
	}
	vs := rec.of("victim")
	if d := vs[1].v.(VictimEvent); d.Title != "pwned" || d.Checksum != "beef" || d.RunID != id || d.Pod != pod {
		t.Fatalf("defaced event: %+v", d)
	}
	// Only changes are published, not every probe.
	if len(vs) != 3 {
		t.Fatalf("victim events: %s", o)
	}
}

func TestVictimQuarantinedIsUnreachableNotGone(t *testing.T) {
	app := newVictimApp(t)
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := victimRunner(c, app, rec)
	release, done := released()
	sc := scenario("quarantine", true)
	sc.Victim, sc.TimeoutSeconds = true, 30
	id := start(t, r, sc, release)
	waitOrder(t, rec, "victim:defaced")
	// The quarantine policy: the app stops answering.
	app.srv.CloseClientConnections()
	_ = app.srv.Listener.Close()
	waitOrder(t, rec, "victim:unreachable")
	r.ObserveTalon("sandbox", podName(sc.ID, id), "success", "")
	<-done
	if o := rec.order(); strings.Contains(o, "victim:gone") {
		t.Fatalf("the API's own cleanup reported as a kill: %s", o)
	}
}

func TestNoVictimProbeWithoutFlag(t *testing.T) {
	app := newVictimApp(t)
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := victimRunner(c, app, rec)
	release, done := released()
	sc := scenario("terminate", true)
	sc.TimeoutSeconds = 30
	id := start(t, r, sc, release)
	rec.waitFor(t, StatePodReady)
	time.Sleep(60 * time.Millisecond)
	r.ObserveTalon("sandbox", podName(sc.ID, id), "success", "")
	<-done
	if n := len(rec.of("victim")); n != 0 {
		t.Fatalf("%d victim events for a scenario without the app", n)
	}
}

// Before the app has answered once it is starting, not unreachable; and a probe failing because
// Talon's delete got there first is reported as gone, not as a network cut.
func TestVictimStartingAndDyingAreNotUnreachable(t *testing.T) {
	app := newVictimApp(t)
	app.set(func(a *victimApp) { a.code = http.StatusServiceUnavailable })
	c := fake.NewClientset()
	readyOnCreate(c)
	rec := newRecorder()
	r := New(c, &fakeExec{block: true}, rec, nil, Config{PollInterval: 10 * time.Millisecond, QuarantineLinger: -1,
		VictimPort: app.port, VictimInterval: 40 * time.Millisecond, VictimTimeout: 200 * time.Millisecond})
	release, done := released()
	sc := scenario("terminate", true)
	sc.Victim, sc.TimeoutSeconds = true, 30
	id := start(t, r, sc, release)
	pod := podName(sc.ID, id)
	rec.waitFor(t, StatePodReady)
	time.Sleep(150 * time.Millisecond)
	app.set(func(a *victimApp) { a.code = http.StatusOK })
	waitOrder(t, rec, "victim:up")
	// The app dies first, the deletion is reported a moment later.
	app.srv.CloseClientConnections()
	_ = app.srv.Listener.Close()
	time.Sleep(10 * time.Millisecond)
	_ = c.CoreV1().Pods("sandbox").Delete(context.Background(), pod, metav1.DeleteOptions{})
	waitOrder(t, rec, "victim:gone")
	r.ObserveTalon("sandbox", pod, "success", "")
	<-done
	if o := rec.order(); strings.Contains(o, "victim:unreachable") || strings.Count(o, "victim:") != 2 {
		t.Fatalf("order: %s", o)
	}
}
