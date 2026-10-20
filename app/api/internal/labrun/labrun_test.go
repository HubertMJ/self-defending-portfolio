package labrun

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
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

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/lab"
)

var token = []byte(strings.Repeat("k", 43))

// fakeVM answers Markers with fixed markers.
type fakeVM struct {
	markers []lab.Marker
	running bool
	err     error
}

func (f *fakeVM) Markers(context.Context) ([]lab.Marker, bool, error) {
	return f.markers, f.running, f.err
}

// memStore is a Store with the same compare-and-swap semantics as the ConfigMap.
type memStore struct {
	mu      sync.Mutex
	data    []byte
	version int
	loads   int
	err     error
}

func (m *memStore) Load(context.Context) ([]byte, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loads++
	return m.data, strconv.Itoa(m.version), m.err
}

func (m *memStore) Save(_ context.Context, data []byte, version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if version != strconv.Itoa(m.version) {
		return ErrConflict
	}
	m.data, m.version = data, m.version+1
	return nil
}

func (m *memStore) state(t *testing.T) state {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	var st state
	if len(m.data) > 0 {
		if err := json.Unmarshal(m.data, &st); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

func (m *memStore) set(t *testing.T, st state) {
	t.Helper()
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.data, m.version = b, m.version+1
	m.mu.Unlock()
}

// at is a time on 2026-10-20 UTC.
func at(hms string) time.Time {
	t, err := time.Parse(time.RFC3339, "2026-10-20T"+hms+"Z")
	if err != nil {
		panic(err)
	}
	return t
}

func ptr(t time.Time) *time.Time { return &t }

func mk(run, name, hms string) lab.Marker { return lab.Marker{At: at(hms), RunID: run, Name: name} }

func newService(store Store, vm VMSource, now *time.Time) *Service {
	return New(Config{Store: store, VM: vm, Token: token, Now: func() time.Time { return *now }})
}

func TestEvaluate(t *testing.T) {
	const run = "lab-20261020T115005Z-aaaaaa"
	queuedAt := func(hms string) state { return state{Request: &request{ID: "req-1", RequestedAt: at(hms)}} }
	claimedAt := func(hms string) state {
		return state{Request: &request{ID: "req-1", RequestedAt: at(hms).Add(-10 * time.Second), ClaimedAt: ptr(at(hms))}}
	}
	today := func(n int) state { return state{Day: "2026-10-20", RunsToday: n} }
	for _, tc := range []struct {
		name      string
		st        state
		markers   []lab.Marker
		vmRunning bool
		now       string
		want      Status
	}{
		{"nothing at all", state{}, nil, false, "12:00:00",
			Status{State: "available", CanStart: true}},
		{"queued", queuedAt("11:59:00"), nil, false, "12:00:59",
			Status{State: "queued", Request: &RequestView{ID: "req-1", RequestedAt: "2026-10-20T11:59:00.000Z"}}},
		{"not claimed in 2 min: the agent is not answering", queuedAt("11:58:00"), nil, false, "12:00:00",
			Status{State: "unavailable", Reason: "trigger agent not answering", NextAllowedAt: "2026-10-20T12:10:00.000Z",
				Request: &RequestView{ID: "req-1", RequestedAt: "2026-10-20T11:58:00.000Z"}}},
		{"10 min after the expiry: available again", queuedAt("11:48:00"), nil, false, "12:00:00",
			Status{State: "available", CanStart: true}},
		{"claimed, no rollback yet: starting", claimedAt("11:56:00"), nil, false, "12:00:59",
			Status{State: "starting", Request: &RequestView{ID: "req-1", RequestedAt: "2026-10-20T11:55:50.000Z", ClaimedAt: "2026-10-20T11:56:00.000Z"}}},
		{"no rollback within 5 min: failed, the slot held for a cooldown", claimedAt("11:55:00"), nil, false, "12:00:00",
			Status{State: "cooldown", Reason: "the last requested run did not start", NextAllowedAt: "2026-10-20T12:30:00.000Z",
				Request: &RequestView{ID: "req-1", RequestedAt: "2026-10-20T11:54:50.000Z", ClaimedAt: "2026-10-20T11:55:00.000Z"}}},
		{"a cooldown after the failure: free again", claimedAt("11:25:00"), nil, false, "12:00:00",
			Status{State: "available", CanStart: true}},
		{"rollback stamped 30 s before the claim (clock skew) counts", claimedAt("11:50:00"), []lab.Marker{mk(run, "rollback", "11:49:30")}, true, "11:51:00",
			Status{State: "running", Request: &RequestView{ID: "req-1", RequestedAt: "2026-10-20T11:49:50.000Z", ClaimedAt: "2026-10-20T11:50:00.000Z"}}},
		{"31 s before is another run's", claimedAt("11:50:00"), []lab.Marker{mk(run, "rollback", "11:49:29")}, true, "11:51:00",
			Status{State: "starting", Request: &RequestView{ID: "req-1", RequestedAt: "2026-10-20T11:49:50.000Z", ClaimedAt: "2026-10-20T11:50:00.000Z"}}},
		{"a rollback before the claim is not this run's", claimedAt("11:56:00"), []lab.Marker{mk("lab-20261020T030000Z-dddddd", "rollback", "03:00:00")}, false, "11:57:00",
			Status{State: "starting", Request: &RequestView{ID: "req-1", RequestedAt: "2026-10-20T11:55:50.000Z", ClaimedAt: "2026-10-20T11:56:00.000Z"}}},
		{"rollback after the claim: running", claimedAt("11:50:00"), []lab.Marker{mk(run, "rollback", "11:50:05"), mk(run, "start", "11:50:06")}, true, "11:52:00",
			Status{State: "running", Request: &RequestView{ID: "req-1", RequestedAt: "2026-10-20T11:49:50.000Z", ClaimedAt: "2026-10-20T11:50:00.000Z"}}},
		{"rollback in the claim's second counts", claimedAt("11:50:00"), []lab.Marker{mk(run, "rollback", "11:50:00")}, true, "11:51:00",
			Status{State: "running", Request: &RequestView{ID: "req-1", RequestedAt: "2026-10-20T11:49:50.000Z", ClaimedAt: "2026-10-20T11:50:00.000Z"}}},
		{"powered off: cooldown for 30 min", claimedAt("11:50:00"), []lab.Marker{mk(run, "rollback", "11:50:05"), mk(run, "poweroff_requested", "11:53:15")}, false, "12:00:00",
			Status{State: "cooldown", NextAllowedAt: "2026-10-20T12:23:15.000Z"}},
		{"cooldown over exactly 30 min after the poweroff", state{}, []lab.Marker{mk(run, "poweroff_requested", "11:30:00")}, false, "12:00:00",
			Status{State: "available", CanStart: true}},
		{"one second short of it", state{}, []lab.Marker{mk(run, "poweroff_requested", "11:30:01")}, false, "12:00:00",
			Status{State: "cooldown", NextAllowedAt: "2026-10-20T12:00:01.000Z"}},
		{"the daily run is running", state{}, []lab.Marker{mk(run, "rollback", "11:59:00")}, true, "12:00:00",
			Status{State: "running"}},
		{"daily limit reached", today(12), nil, false, "12:00:00",
			Status{State: "cooldown", Reason: "daily limit", NextAllowedAt: "2026-10-21T00:00:00.000Z", RunsToday: 12}},
		{"one short of the limit", today(11), nil, false, "12:00:00",
			Status{State: "available", CanStart: true, RunsToday: 11}},
		{"yesterday's count does not carry over", state{Day: "2026-10-19", RunsToday: 12}, nil, false, "00:00:00",
			Status{State: "available", CanStart: true}},
		{"just before the window", state{}, nil, false, "02:49:59",
			Status{State: "available", CanStart: true}},
		{"the window opens at 02:50", state{}, nil, false, "02:50:00",
			Status{State: "closed", NextAllowedAt: "2026-10-20T03:50:00.000Z"}},
		{"still closed at 03:49:59", state{}, nil, false, "03:49:59",
			Status{State: "closed", NextAllowedAt: "2026-10-20T03:50:00.000Z"}},
		{"open again at 03:50", state{}, nil, false, "03:50:00",
			Status{State: "available", CanStart: true}},
		{"a queued request is dropped when the window opens", queuedAt("02:49:30"), nil, false, "02:50:10",
			Status{State: "closed", NextAllowedAt: "2026-10-20T03:50:00.000Z"}},
		{"a run started before the window still shows", claimedAt("02:49:00"), []lab.Marker{mk(run, "rollback", "02:49:05")}, true, "02:51:00",
			Status{State: "running", Request: &RequestView{ID: "req-1", RequestedAt: "2026-10-20T02:48:50.000Z", ClaimedAt: "2026-10-20T02:49:00.000Z"}}},
		{"a cooldown ending in the window: allowed after it", state{}, []lab.Marker{mk(run, "poweroff_requested", "02:30:00")}, false, "02:40:00",
			Status{State: "cooldown", NextAllowedAt: "2026-10-20T03:50:00.000Z"}},
		{"the cap and the cooldown: the later one", today(12), []lab.Marker{mk(run, "poweroff_requested", "23:50:00")}, false, "23:55:00",
			Status{State: "cooldown", NextAllowedAt: "2026-10-21T00:20:00.000Z", RunsToday: 12}},
	} {
		now := at(tc.now)
		s := newService(&memStore{}, &fakeVM{}, &now)
		tc.want.MaxPerDay = 12
		got := s.evaluate(tc.st, tc.markers, tc.vmRunning, now)
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(tc.want)
		if string(g) != string(w) {
			t.Errorf("%s:\ngot  %s\nwant %s", tc.name, g, w)
		}
	}
}

func TestRequest(t *testing.T) {
	const run = "lab-20261020T115005Z-aaaaaa"
	for _, tc := range []struct {
		name string
		st   state
		vm   *fakeVM
		now  string
		code int
		body string
	}{
		{"available", state{}, &fakeVM{}, "12:00:00", http.StatusAccepted, ""},
		{"queued already", state{Request: &request{ID: "req-0", RequestedAt: at("11:59:30")}}, &fakeVM{}, "12:00:00",
			http.StatusConflict, `{"error":"busy"}`},
		{"the VM is running", state{}, &fakeVM{running: true, markers: []lab.Marker{mk(run, "rollback", "11:59:00")}}, "12:00:00",
			http.StatusConflict, `{"error":"busy"}`},
		{"cooldown", state{}, &fakeVM{markers: []lab.Marker{mk(run, "poweroff_requested", "11:45:00")}}, "12:00:00",
			http.StatusTooManyRequests, `{"error":"cooldown","next_allowed_at":"2026-10-20T12:15:00.000Z"}`},
		{"daily limit", state{Day: "2026-10-20", RunsToday: 12}, &fakeVM{}, "12:00:00",
			http.StatusTooManyRequests, `{"error":"daily limit","next_allowed_at":"2026-10-21T00:00:00.000Z"}`},
		{"maintenance window", state{}, &fakeVM{}, "03:10:00",
			http.StatusLocked, `{"error":"closed","next_allowed_at":"2026-10-20T03:50:00.000Z"}`},
		{"agent not answering", state{Request: &request{ID: "req-0", RequestedAt: at("11:55:00")}}, &fakeVM{}, "12:00:00",
			http.StatusServiceUnavailable, `{"error":"unavailable","next_allowed_at":"2026-10-20T12:07:00.000Z","reason":"trigger agent not answering"}`},
		{"lab status unreadable", state{}, &fakeVM{err: errors.New("403")}, "12:00:00",
			http.StatusServiceUnavailable, `{"error":"unavailable","reason":"lab status unavailable"}`},
	} {
		now := at(tc.now)
		store := &memStore{}
		store.set(t, tc.st)
		q, ref := newService(store, tc.vm, &now).Request(context.Background())
		if ref != nil {
			b, _ := json.Marshal(ref)
			if ref.Code != tc.code || string(b) != tc.body {
				t.Errorf("%s: %d %s, want %d %s", tc.name, ref.Code, b, tc.code, tc.body)
			}
			continue
		}
		if tc.code != http.StatusAccepted {
			t.Errorf("%s: queued %+v, want %d", tc.name, q, tc.code)
			continue
		}
		st := store.state(t)
		if q.State != "queued" || !strings.HasPrefix(q.ID, "req-") || st.Request == nil || st.Request.ID != q.ID ||
			!st.Request.RequestedAt.Equal(now) || st.Request.ClaimedAt != nil {
			t.Errorf("%s: queued %+v, stored %+v", tc.name, q, st.Request)
		}
	}
	// Not configured: no token, no store or no lab.
	now := at("12:00:00")
	for name, cfg := range map[string]Config{
		"no token":    {Store: &memStore{}, VM: &fakeVM{}},
		"short token": {Store: &memStore{}, VM: &fakeVM{}, Token: []byte("short")},
		"no store":    {VM: &fakeVM{}, Token: token},
		"no lab":      {Store: &memStore{}, Token: token},
	} {
		cfg.Now = func() time.Time { return now }
		s := New(cfg)
		if _, ref := s.Request(context.Background()); ref == nil || ref.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: %+v, want 503", name, ref)
		}
		if st := s.Status(context.Background()); st.State != "unavailable" || st.CanStart {
			t.Errorf("%s: status %+v", name, st)
		}
	}
}

func TestRequestThenSecondRequestIsBusy(t *testing.T) {
	now := at("12:00:00")
	s := newService(&memStore{}, &fakeVM{}, &now)
	if _, ref := s.Request(context.Background()); ref != nil {
		t.Fatalf("first: %+v", ref)
	}
	if _, ref := s.Request(context.Background()); ref == nil || ref.Code != http.StatusConflict {
		t.Fatalf("second: %+v, want busy", ref)
	}
}

func TestRequestAfterFailedStart(t *testing.T) {
	// The agent claimed, but no rollback came within 5 min: a second POST is still refused (the run
	// may yet start), until a cooldown after the failure.
	now := at("12:00:00")
	store := &memStore{}
	s := newService(store, &fakeVM{}, &now)
	if _, ref := s.Request(context.Background()); ref != nil {
		t.Fatal(ref)
	}
	if c, _ := s.Claim(context.Background()); !c.Start {
		t.Fatal("no claim")
	}
	now = now.Add(5 * time.Minute)
	_, ref := s.Request(context.Background())
	if ref == nil || ref.Code != http.StatusTooManyRequests || ref.Error != "cooldown" || ref.NextAllowedAt != "2026-10-20T12:35:00.000Z" {
		t.Fatalf("after a failed start: %+v, want 429 cooldown until 12:35", ref)
	}
	now = at("12:35:00")
	if _, ref := s.Request(context.Background()); ref != nil {
		t.Fatalf("after the cooldown: %+v", ref)
	}
}

// countingVM counts the marker reads.
type countingVM struct {
	fakeVM
	mu    sync.Mutex
	calls int
}

func (c *countingVM) Markers(ctx context.Context) ([]lab.Marker, bool, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return c.fakeVM.Markers(ctx)
}

func TestRequestRefusedWithoutIO(t *testing.T) {
	// A fresh cached status that says no answers a POST with no store read and no search.
	now := at("12:00:00")
	store := &memStore{}
	vm := &countingVM{}
	s := newService(store, vm, &now)
	if _, ref := s.Request(context.Background()); ref != nil {
		t.Fatal(ref)
	}
	loads, calls := store.loads, vm.calls
	for i := 0; i < 20; i++ {
		if _, ref := s.Request(context.Background()); ref == nil || ref.Code != http.StatusConflict {
			t.Fatalf("POST %d: %+v, want busy", i, ref)
		}
	}
	if store.loads != loads || vm.calls != calls {
		t.Fatalf("refusals cost %d loads and %d searches, want none", store.loads-loads, vm.calls-calls)
	}
	// Once the status is older than the TTL, the next POST reads again (and is refused on the read).
	now = now.Add(2 * time.Second)
	if _, ref := s.Request(context.Background()); ref == nil || store.loads != loads+1 {
		t.Fatalf("after the TTL: %+v, loads %d", ref, store.loads-loads)
	}
}

// blockingStore signals entered on the first Load and holds every Load until release is closed.
type blockingStore struct {
	memStore
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (b *blockingStore) Load(ctx context.Context) ([]byte, string, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return b.memStore.Load(ctx)
}

func TestRequestSerialised(t *testing.T) {
	// While one POST of this pod is reading and writing, a concurrent one is busy at once, no I/O.
	now := at("12:00:00")
	store := &blockingStore{entered: make(chan struct{}), release: make(chan struct{})}
	s := newService(store, &fakeVM{}, &now)
	done := make(chan *Refusal)
	go func() {
		_, ref := s.Request(context.Background())
		done <- ref
	}()
	<-store.entered // the first Request holds the lock and is reading
	if _, ref := s.Request(context.Background()); ref == nil || ref.Code != http.StatusConflict {
		t.Fatalf("concurrent POST: %+v, want busy", ref)
	}
	close(store.release)
	if ref := <-done; ref != nil {
		t.Fatalf("first POST: %+v", ref)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.loads != 1 {
		t.Fatalf("loads = %d, want only the first POST's", store.loads)
	}
}

func TestClaim(t *testing.T) {
	now := at("12:00:00")
	store := &memStore{}
	s := newService(store, &fakeVM{}, &now)

	// Nothing queued: no start, nothing written.
	if c, err := s.Claim(context.Background()); err != nil || c.Start {
		t.Fatalf("empty: %+v %v", c, err)
	}
	q, ref := s.Request(context.Background())
	if ref != nil {
		t.Fatal(ref)
	}
	now = now.Add(30 * time.Second)
	c, err := s.Claim(context.Background())
	if err != nil || !c.Start || c.ID != q.ID {
		t.Fatalf("claim: %+v %v, want start for %s", c, err, q.ID)
	}
	st := store.state(t)
	if st.Request.ClaimedAt == nil || !st.Request.ClaimedAt.Equal(now) || st.Day != "2026-10-20" || st.RunsToday != 1 {
		t.Fatalf("stored after claim: %+v %+v", st, st.Request)
	}
	// Exactly once.
	if c, _ := s.Claim(context.Background()); c.Start {
		t.Fatal("second claim started again")
	}
	if got := s.Status(context.Background()); got.State != "starting" || got.RunsToday != 1 {
		t.Fatalf("status after claim: %+v", got)
	}

	// The day's counter restarts on a new UTC day.
	store.set(t, state{Day: "2026-10-19", RunsToday: 7, Request: &request{ID: "req-2", RequestedAt: at("12:10:00")}})
	now = at("12:10:30")
	if c, _ := s.Claim(context.Background()); !c.Start {
		t.Fatal("claim on a new day")
	}
	if st := store.state(t); st.Day != "2026-10-20" || st.RunsToday != 1 {
		t.Fatalf("counter not reset: %+v", st)
	}

	// An expired request, and one queued just before the window opened, are never handed out.
	for name, tc := range map[string]struct {
		req request
		now string
	}{
		"expired":       {request{ID: "req-3", RequestedAt: at("12:20:00")}, "12:22:00"},
		"window opened": {request{ID: "req-4", RequestedAt: at("02:49:30")}, "02:50:00"},
	} {
		store.set(t, state{Request: &tc.req})
		now = at(tc.now)
		if c, _ := s.Claim(context.Background()); c.Start {
			t.Errorf("%s: start = true", name)
		}
	}

	// A store error is the caller's (503), not a silent "no".
	store.err = errors.New("apiserver down")
	if _, err := s.Claim(context.Background()); err == nil {
		t.Fatal("store error swallowed")
	}
}

func TestAuthorized(t *testing.T) {
	s := New(Config{Store: &memStore{}, VM: &fakeVM{}, Token: token})
	for header, want := range map[string]bool{
		"Bearer " + string(token):        true,
		"Bearer " + string(token) + "\n": true,
		"Bearer " + string(token) + "x":  false,
		"Bearer " + string(token[:42]):   false,
		"bearer " + string(token):        false,
		string(token):                    false,
		"Bearer ":                        false,
		"":                               false,
	} {
		if got := s.Authorized(header); got != want {
			t.Errorf("Authorized(%q) = %v, want %v", header, got, want)
		}
	}
	if !s.ClaimEnabled() {
		t.Fatal("token configured: claim disabled")
	}
	for name, cfg := range map[string]Config{
		"no token":    {Store: &memStore{}},
		"short token": {Store: &memStore{}, Token: []byte(strings.Repeat("k", minToken-1))},
	} {
		s := New(cfg)
		if s.ClaimEnabled() || s.Authorized("Bearer ") || s.Authorized("Bearer "+string(cfg.Token)) {
			t.Errorf("%s: claim enabled or authorized", name)
		}
	}
}

func TestStatusCached(t *testing.T) {
	now := at("12:00:00")
	store := &memStore{}
	s := newService(store, &fakeVM{}, &now)
	for i := 0; i < 3; i++ {
		if st := s.Status(context.Background()); st.State != "available" {
			t.Fatalf("status %+v", st)
		}
	}
	if store.loads != 1 {
		t.Fatalf("loads = %d within 2 s, want 1", store.loads)
	}
	now = now.Add(2 * time.Second)
	s.Status(context.Background())
	if store.loads != 2 {
		t.Fatalf("loads = %d after 2 s, want 2", store.loads)
	}
	// A request shows at once, not after the TTL.
	if _, ref := s.Request(context.Background()); ref != nil {
		t.Fatal(ref)
	}
	if st := s.Status(context.Background()); st.State != "queued" {
		t.Fatalf("after a request: %+v", st)
	}
	// A cancelled visitor does not poison the cache.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	now = now.Add(3 * time.Second)
	s.Status(ctx)
	if st := s.Status(context.Background()); st.State != "queued" {
		t.Fatalf("after a cancelled request: %+v", st)
	}
}

// kubeWithVersions is a fake clientset whose ConfigMap updates are checked against the stored
// resourceVersion and bump it, as the API server does (the plain fake does neither).
func kubeWithVersions(t *testing.T, failFirst int) (*fake.Clientset, *int) {
	t.Helper()
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "lab-run-state", Namespace: "portfolio-api",
		ResourceVersion: "1", Labels: map[string]string{"app.kubernetes.io/instance": "portfolio-api"}}}
	kube := fake.NewClientset(cm)
	gvr := schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}
	var mu sync.Mutex
	rv, conflicts := 1, 0
	kube.PrependReactor("update", "configmaps", func(a k8stesting.Action) (bool, runtime.Object, error) {
		mu.Lock()
		defer mu.Unlock()
		obj := a.(k8stesting.UpdateAction).GetObject().(*corev1.ConfigMap).DeepCopy()
		cur, err := kube.Tracker().Get(gvr, obj.Namespace, obj.Name)
		if err != nil {
			return true, nil, err
		}
		if failFirst > 0 || cur.(*corev1.ConfigMap).ResourceVersion != obj.ResourceVersion {
			failFirst--
			conflicts++
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, obj.Name, errors.New("stale"))
		}
		rv++
		obj.ResourceVersion = strconv.Itoa(rv)
		return true, obj, kube.Tracker().Update(gvr, obj, obj.Namespace)
	})
	return kube, &conflicts
}

// barrierStore holds the first n loads until all n have happened, so n claims all read the same
// version before any of them writes - the race a real second replica could hit.
type barrierStore struct {
	Store
	mu      sync.Mutex
	n       int
	release chan struct{}
}

func (b *barrierStore) Load(ctx context.Context) ([]byte, string, error) {
	data, version, err := b.Store.Load(ctx)
	b.mu.Lock()
	first := b.n > 0
	if first {
		b.n--
		if b.n == 0 {
			close(b.release)
		}
	}
	b.mu.Unlock()
	if first {
		<-b.release
	}
	return data, version, err
}

func TestClaimAtomicAcrossReplicas(t *testing.T) {
	// Several replicas (one Service each, one ConfigMap) claim the same queued request at once: the
	// API server's version check lets exactly one of them start it.
	kube, _ := kubeWithVersions(t, 0)
	store := NewConfigMapStore(kube, "portfolio-api", "lab-run-state")
	now := at("12:00:00")
	if _, ref := newService(store, &fakeVM{}, &now).Request(context.Background()); ref != nil {
		t.Fatal(ref)
	}
	const replicas = 8
	racing := &barrierStore{Store: store, n: replicas, release: make(chan struct{})}
	var wg sync.WaitGroup
	starts := make(chan Claim, replicas)
	for i := 0; i < replicas; i++ {
		s := newService(racing, &fakeVM{}, &now)
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := s.Claim(context.Background())
			if err != nil {
				t.Error(err)
			}
			if c.Start {
				starts <- c
			}
		}()
	}
	wg.Wait()
	close(starts)
	// Every replica read the same version (the barrier); all but one are refused, by Save's own
	// version check or the API server's.
	if n := len(starts); n != 1 {
		t.Fatalf("%d starts, want exactly 1", n)
	}
	cm, _ := kube.CoreV1().ConfigMaps("portfolio-api").Get(context.Background(), "lab-run-state", metav1.GetOptions{})
	var st state
	if err := json.Unmarshal([]byte(cm.Data[dataKey]), &st); err != nil || st.RunsToday != 1 || st.Request.ClaimedAt == nil {
		t.Fatalf("stored %+v (%v)", st, err)
	}
	if cm.Labels["app.kubernetes.io/instance"] != "portfolio-api" {
		t.Fatalf("labels lost: %v", cm.Labels)
	}
}

func TestConfigMapConflictRetry(t *testing.T) {
	// The first two updates conflict (another writer): the request is re-derived and stored.
	kube, conflicts := kubeWithVersions(t, 2)
	store := NewConfigMapStore(kube, "portfolio-api", "lab-run-state")
	now := at("12:00:00")
	q, ref := newService(store, &fakeVM{}, &now).Request(context.Background())
	if ref != nil || *conflicts != 2 {
		t.Fatalf("ref %+v after %d conflicts", ref, *conflicts)
	}
	data, _, err := store.Load(context.Background())
	if err != nil || !strings.Contains(string(data), q.ID) {
		t.Fatalf("stored %s (%v), want %s", data, err, q.ID)
	}
	// A write based on a stale version is refused before it is sent.
	if err := store.Save(context.Background(), []byte("{}"), "1"); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale save: %v, want ErrConflict", err)
	}
	// Endless conflicts end in "busy", not a hang.
	kube2, _ := kubeWithVersions(t, 100)
	if _, ref := newService(NewConfigMapStore(kube2, "portfolio-api", "lab-run-state"), &fakeVM{}, &now).Request(context.Background()); ref == nil || ref.Code != http.StatusConflict {
		t.Fatalf("endless conflicts: %+v", ref)
	}
}

func TestMissingConfigMap(t *testing.T) {
	// The ConfigMap ships with the manifests; without it the run is unavailable, never created.
	now := at("12:00:00")
	s := newService(NewConfigMapStore(fake.NewClientset(), "portfolio-api", "lab-run-state"), &fakeVM{}, &now)
	if _, ref := s.Request(context.Background()); ref == nil || ref.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing configmap: %+v", ref)
	}
	if st := s.Status(context.Background()); st.State != "unavailable" || st.Reason != "lab status unavailable" {
		t.Fatalf("status %+v", st)
	}
}
