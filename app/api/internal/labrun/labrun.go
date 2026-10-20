// Package labrun lets a visitor start a real isolated-VM run of the detection lab (variant B) from
// the /lab/ page, within limits (ADR 0034 amendment 2026-10-20 (b)).
//
// The API never reaches the hypervisor. A visitor's POST /api/lab/run only queues a request in a
// ConfigMap; the trigger agent on the Proxmox host polls POST /api/lab/run/claim outbound with a
// bearer token, gets {"start":true} exactly once for a queued request, and starts the run itself.
// What happens next is read back from the run's own lifecycle markers in sdp-lab (internal/lab), so
// the API holds no state about the VM it did not see in the SIEM.
//
// One run at a time: a request is accepted only when no request is queued or starting, the VM is
// not running (any run, the daily one included), the newest run powered off at least Cooldown ago,
// fewer than MaxPerDay visitor runs were started in the current UTC day, and the time is outside the
// daily maintenance window (the 03:00 VM run and the 03:30 generated run). A queued request the agent
// does not claim within QueueTimeout expires; a claimed one with no rollback marker within
// StartTimeout has failed, and holds the slot for a Cooldown as if it had run (the agent may still
// be starting it: freeing the slot at once could start two). These are derived from the stored
// request, the clock and the markers, never written back, so no background loop is needed.
//
// The state is one ConfigMap, written with optimistic concurrency (the resourceVersion of the read
// it was derived from): a claim or a new request that raced another write is re-derived from the
// fresh object, so a request is handed to the agent once even with more than one API replica.
package labrun

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/lab"
)

// The defaults (Config's zero values take them).
const (
	defaultMaxPerDay    = 12
	defaultCooldown     = 30 * time.Minute
	defaultQueueTimeout = 2 * time.Minute
	defaultStartTimeout = 5 * time.Minute
	// defaultAgentRetry is how long the page says "unavailable" after a request the agent never
	// claimed: queuing another one while the agent is down would only expire again.
	defaultAgentRetry = 10 * time.Minute
	// The maintenance window, as offsets from 00:00 UTC: ten minutes before the daily VM run at 03:00
	// to twenty after the generated run at 03:30, so neither shares the SIEM with a visitor's run.
	defaultWindowStart = 2*time.Hour + 50*time.Minute
	defaultWindowEnd   = 3*time.Hour + 50*time.Minute
	defaultStatusTTL   = 2 * time.Second
	// clockSkew is how much earlier than the claim (the API's clock) a rollback marker (the lab's
	// clock) may be stamped and still count as the claimed run's.
	clockSkew = 30 * time.Second
	// opTimeout bounds one status refresh, request or claim (a marker search and a ConfigMap
	// read/write or two), detached from the visitor's request.
	opTimeout = 8 * time.Second
	// minToken is the shortest trigger token accepted: anything shorter is a misconfiguration.
	minToken = 32
	// saveAttempts bounds the read-derive-write retries after a write conflict.
	saveAttempts = 5
	stamp        = "2006-01-02T15:04:05.000Z"
)

// The public states of GET /api/lab/run.
const (
	StateAvailable   = "available"
	StateQueued      = "queued"
	StateStarting    = "starting"
	StateRunning     = "running"
	StateCooldown    = "cooldown"
	StateClosed      = "closed"
	StateUnavailable = "unavailable"
)

// ErrConflict is a Store's answer to a write based on a stale read.
var ErrConflict = errors.New("labrun: state changed since it was read")

// Store keeps the serialised state with a version: Save writes data only if the stored version is
// still version (else ErrConflict). Load of a never-written store returns empty data.
type Store interface {
	Load(ctx context.Context) (data []byte, version string, err error)
	Save(ctx context.Context, data []byte, version string) error
}

// VMSource is what this package needs from internal/lab: the VM runs' lifecycle markers and whether
// the newest run counts as running.
type VMSource interface {
	Markers(ctx context.Context) ([]lab.Marker, bool, error)
}

// Config wires a Service. Store, VM or Token missing means on-demand runs are unavailable (GET says
// so, POST answers 503, the claim endpoint 404). The durations and limits default when zero.
type Config struct {
	Store Store
	VM    VMSource
	// Token is the trigger agent's bearer token (the mounted Secret's content).
	Token []byte
	Now   func() time.Time
	Log   *slog.Logger

	MaxPerDay    int
	Cooldown     time.Duration
	QueueTimeout time.Duration
	StartTimeout time.Duration
	AgentRetry   time.Duration
	// WindowStart and WindowEnd bound the daily maintenance window, offsets from 00:00 UTC; the
	// window may not wrap past midnight.
	WindowStart, WindowEnd time.Duration
	StatusTTL              time.Duration
}

// Service is the request/claim state machine. Safe for concurrent use.
type Service struct {
	cfg       Config
	tokenHash [sha256.Size]byte

	mu      sync.Mutex
	until   time.Time     // the cached status is served without a refresh until then
	cached  Status        // the newest status
	pending chan struct{} // closed when the running refresh is done; nil when none runs

	// requestMu serialises Request in this pod: a burst of POSTs makes one read-and-write at a time,
	// and the others are turned down without any I/O.
	requestMu sync.Mutex
}

// New returns a Service; a token shorter than minToken is treated as none (and logged).
func New(cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	if cfg.MaxPerDay <= 0 {
		cfg.MaxPerDay = defaultMaxPerDay
	}
	def(&cfg.Cooldown, defaultCooldown)
	def(&cfg.QueueTimeout, defaultQueueTimeout)
	def(&cfg.StartTimeout, defaultStartTimeout)
	def(&cfg.AgentRetry, defaultAgentRetry)
	def(&cfg.StatusTTL, defaultStatusTTL)
	if cfg.WindowStart <= 0 || cfg.WindowEnd <= cfg.WindowStart || cfg.WindowEnd > 24*time.Hour {
		cfg.WindowStart, cfg.WindowEnd = defaultWindowStart, defaultWindowEnd
	}
	if n := len(cfg.Token); n > 0 && n < minToken {
		cfg.Log.Warn("lab run trigger token too short; on-demand runs off", "length", n)
		cfg.Token = nil
	}
	s := &Service{cfg: cfg}
	if len(cfg.Token) > 0 {
		s.tokenHash = sha256.Sum256(cfg.Token)
	}
	return s
}

// configured reports whether runs can be requested and claimed at all.
func (s *Service) configured() bool {
	return s.cfg.Store != nil && s.cfg.VM != nil && len(s.cfg.Token) > 0
}

// ClaimEnabled reports whether the claim endpoint exists (a token is configured).
func (s *Service) ClaimEnabled() bool { return len(s.cfg.Token) > 0 && s.cfg.Store != nil }

// Authorized checks an Authorization header against the token in constant time (both sides hashed
// first, so not even the length leaks).
func (s *Service) Authorized(header string) bool {
	tok, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || len(s.cfg.Token) == 0 {
		return false
	}
	h := sha256.Sum256([]byte(strings.TrimSpace(tok)))
	return subtle.ConstantTimeCompare(h[:], s.tokenHash[:]) == 1
}

// state is what the ConfigMap holds: the newest request (kept after it ends, so its outcome can be
// derived) and the visitor runs started on Day (UTC, yyyy-mm-dd).
type state struct {
	Request   *request `json:"request,omitempty"`
	Day       string   `json:"day,omitempty"`
	RunsToday int      `json:"runs_today"`
}

type request struct {
	ID          string     `json:"id"`
	RequestedAt time.Time  `json:"requested_at"`
	ClaimedAt   *time.Time `json:"claimed_at,omitempty"`
}

// phase is where a stored request stands now.
type phase int

const (
	phaseNone      phase = iota
	phaseQueued          // waiting for the agent's claim
	phaseStarting        // claimed, no rollback marker yet
	phaseRunning         // its run began and has not powered off
	phaseExpired         // never claimed within QueueTimeout
	phaseCancelled       // the maintenance window opened before it was claimed
	phaseFailed          // claimed, but no rollback marker within StartTimeout
	phaseDone            // its run powered off (or stopped writing markers)
)

// phaseOf derives a request's phase; ended is when an expired or failed request ended.
func (s *Service) phaseOf(r *request, markers []lab.Marker, vmRunning bool, now time.Time) (p phase, ended time.Time) {
	switch {
	case r == nil:
		return phaseNone, time.Time{}
	case r.ClaimedAt == nil:
		if expiry := r.RequestedAt.Add(s.cfg.QueueTimeout); !now.Before(expiry) {
			return phaseExpired, expiry
		}
		if s.inWindow(now) {
			return phaseCancelled, time.Time{}
		}
		return phaseQueued, time.Time{}
	}
	// The run's rollback marker is written after the claim, to the second and by another clock.
	claimed := r.ClaimedAt.Add(-clockSkew)
	var rollback *lab.Marker
	for i, m := range markers {
		if m.Name == "rollback" && !m.At.Before(claimed) && (rollback == nil || m.At.Before(rollback.At)) {
			rollback = &markers[i]
		}
	}
	if rollback == nil {
		if failed := r.ClaimedAt.Add(s.cfg.StartTimeout); !now.Before(failed) {
			return phaseFailed, failed
		}
		return phaseStarting, time.Time{}
	}
	for _, m := range markers {
		if m.RunID == rollback.RunID && m.Name == "poweroff_requested" {
			return phaseDone, time.Time{}
		}
	}
	if vmRunning {
		return phaseRunning, time.Time{}
	}
	return phaseDone, time.Time{}
}

// Status is GET /api/lab/run's answer.
type Status struct {
	State         string       `json:"state"`
	CanStart      bool         `json:"can_start"`
	NextAllowedAt string       `json:"next_allowed_at,omitempty"`
	RunsToday     int          `json:"runs_today"`
	MaxPerDay     int          `json:"max_per_day"`
	Request       *RequestView `json:"request,omitempty"`
	Reason        string       `json:"reason,omitempty"`
}

// RequestView is the public part of the newest request.
type RequestView struct {
	ID          string `json:"id"`
	RequestedAt string `json:"requested_at"`
	ClaimedAt   string `json:"claimed_at,omitempty"`
}

func view(r *request) *RequestView {
	v := &RequestView{ID: r.ID, RequestedAt: r.RequestedAt.UTC().Format(stamp)}
	if r.ClaimedAt != nil {
		v.ClaimedAt = r.ClaimedAt.UTC().Format(stamp)
	}
	return v
}

// evaluate derives the public status from the stored state, the markers and the clock. It is the one
// place the rules live: GET shows it, POST acts on it.
func (s *Service) evaluate(st state, markers []lab.Marker, vmRunning bool, now time.Time) Status {
	now = now.UTC()
	out := Status{MaxPerDay: s.cfg.MaxPerDay}
	if st.Day == now.Format(time.DateOnly) {
		out.RunsToday = st.RunsToday
	}
	ph, ended := s.phaseOf(st.Request, markers, vmRunning, now)
	switch ph {
	case phaseQueued, phaseStarting, phaseRunning:
		out.State = map[phase]string{phaseQueued: StateQueued, phaseStarting: StateStarting, phaseRunning: StateRunning}[ph]
		out.Request = view(st.Request)
		return out
	}
	if s.inWindow(now) {
		out.State, out.NextAllowedAt = StateClosed, s.allowedFrom(s.windowEnd(now), out.RunsToday, now)
		return out
	}
	if vmRunning {
		out.State = StateRunning
		return out
	}
	if ph == phaseExpired && now.Before(ended.Add(s.cfg.AgentRetry)) {
		out.State, out.Reason = StateUnavailable, "trigger agent not answering"
		out.NextAllowedAt = s.allowedFrom(s.latest(ended.Add(s.cfg.AgentRetry), markers), out.RunsToday, now)
		out.Request = view(st.Request)
		return out
	}
	if ph == phaseFailed && now.Before(ended.Add(s.cfg.Cooldown)) {
		// The agent was told to start it; a run that begins late must not meet a second one.
		out.State, out.Reason = StateCooldown, "the last requested run did not start"
		out.NextAllowedAt = s.allowedFrom(s.latest(ended.Add(s.cfg.Cooldown), markers), out.RunsToday, now)
		out.Request = view(st.Request)
		return out
	}
	if t := s.latest(time.Time{}, markers); now.Before(t) {
		out.State, out.NextAllowedAt = StateCooldown, s.allowedFrom(t, out.RunsToday, now)
		return out
	}
	if out.RunsToday >= s.cfg.MaxPerDay {
		out.State, out.Reason = StateCooldown, "daily limit"
		out.NextAllowedAt = s.allowedFrom(now, out.RunsToday, now)
		return out
	}
	out.State, out.CanStart = StateAvailable, true
	return out
}

// latest is the later of t and the end of the cooldown after the newest poweroff marker.
func (s *Service) latest(t time.Time, markers []lab.Marker) time.Time {
	for _, m := range markers {
		if m.Name == "poweroff_requested" && m.At.Add(s.cfg.Cooldown).After(t) {
			t = m.At.Add(s.cfg.Cooldown)
		}
	}
	return t
}

// allowedFrom moves t past every other limit: the daily cap (to the next UTC midnight while it is
// reached today) and the maintenance window.
func (s *Service) allowedFrom(t time.Time, runsToday int, now time.Time) string {
	t = t.UTC()
	if runsToday >= s.cfg.MaxPerDay && t.Before(midnight(now).Add(24*time.Hour)) {
		t = midnight(now).Add(24 * time.Hour)
	}
	if s.inWindow(t) {
		t = s.windowEnd(t)
	}
	return t.Format(stamp)
}

func midnight(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

func (s *Service) inWindow(t time.Time) bool {
	off := t.UTC().Sub(midnight(t))
	return off >= s.cfg.WindowStart && off < s.cfg.WindowEnd
}

func (s *Service) windowEnd(t time.Time) time.Time { return midnight(t).Add(s.cfg.WindowEnd) }

// snapshot reads everything a decision needs: the stored state and its version, the markers.
type snapshot struct {
	st        state
	version   string
	markers   []lab.Marker
	vmRunning bool
}

// errVM marks a failed marker read, so it is told apart from a store failure.
var errVM = errors.New("labrun: lab status unavailable")

func (s *Service) read(ctx context.Context, withMarkers bool) (snapshot, error) {
	var sn snapshot
	data, version, err := s.cfg.Store.Load(ctx)
	if err != nil {
		return sn, err
	}
	sn.version = version
	if len(data) > 0 {
		if err := json.Unmarshal(data, &sn.st); err != nil {
			// An unreadable state is replaced by the next write; nothing in it is load-bearing beyond
			// the day's counter, which then starts again from zero.
			s.cfg.Log.Warn("lab run state unparseable; starting from empty", "err", err)
			sn.st = state{}
		}
	}
	if withMarkers {
		if sn.markers, sn.vmRunning, err = s.cfg.VM.Markers(ctx); err != nil {
			return sn, errors.Join(errVM, err)
		}
	}
	return sn, nil
}

func (s *Service) write(ctx context.Context, st state, version string) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.cfg.Store.Save(ctx, data, version)
}

// Status returns the current status, cached for StatusTTL. The refresh runs detached from the
// visitor's request (its own timeout), one at a time, and a visitor waits for it only as long as
// its own context allows.
func (s *Service) Status(ctx context.Context) Status {
	if !s.configured() {
		return s.unavailable("on-demand runs are not configured")
	}
	s.mu.Lock()
	if !s.until.IsZero() && s.cfg.Now().Before(s.until) {
		defer s.mu.Unlock()
		return s.cached
	}
	if s.pending == nil {
		s.pending = make(chan struct{})
		go s.refresh(context.WithoutCancel(ctx), s.pending)
	}
	wait := s.pending
	s.mu.Unlock()
	select {
	case <-wait:
	case <-ctx.Done():
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached.State == "" {
		return s.unavailable("lab status unavailable")
	}
	return s.cached
}

func (s *Service) refresh(ctx context.Context, done chan struct{}) {
	defer close(done)
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	st := s.unavailable("lab status unavailable")
	if sn, err := s.read(ctx, true); err != nil {
		s.cfg.Log.Warn("lab run status failed", "err", err)
	} else {
		st = s.evaluate(sn.st, sn.markers, sn.vmRunning, s.cfg.Now())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cached, s.until, s.pending = st, s.cfg.Now().Add(s.cfg.StatusTTL), nil
}

func (s *Service) unavailable(reason string) Status {
	return Status{State: StateUnavailable, MaxPerDay: s.cfg.MaxPerDay, Reason: reason}
}

// remember caches a status Request has just derived from a fresh read, so the GETs and POSTs of the
// next StatusTTL are answered from it.
func (s *Service) remember(st Status) {
	s.mu.Lock()
	s.cached, s.until = st, s.cfg.Now().Add(s.cfg.StatusTTL)
	s.mu.Unlock()
}

// invalidate drops the cached status after a write, so the next GET shows the change.
func (s *Service) invalidate() {
	s.mu.Lock()
	s.until = time.Time{}
	s.mu.Unlock()
}

// Refusal is a request POST /api/lab/run turns down: the HTTP status and the JSON error body.
type Refusal struct {
	Code          int    `json:"-"`
	Error         string `json:"error"`
	NextAllowedAt string `json:"next_allowed_at,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

// Queued is POST /api/lab/run's 202 answer.
type Queued struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

// Request queues a run if the rules allow one now, else says why not. While the cached status is
// fresh and says no, or another Request of this pod is in flight, it answers without any I/O: the
// button can be hammered without each click costing a search and a ConfigMap read.
func (s *Service) Request(ctx context.Context) (Queued, *Refusal) {
	if !s.configured() {
		return Queued{}, &Refusal{Code: http.StatusServiceUnavailable, Error: "unavailable", Reason: "on-demand runs are not configured"}
	}
	s.mu.Lock()
	fresh, cached := !s.until.IsZero() && s.cfg.Now().Before(s.until), s.cached
	s.mu.Unlock()
	if fresh && !cached.CanStart {
		return Queued{}, refusal(cached)
	}
	if !s.requestMu.TryLock() {
		return Queued{}, &Refusal{Code: http.StatusConflict, Error: "busy"}
	}
	defer s.requestMu.Unlock()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opTimeout)
	defer cancel()
	for attempt := 0; attempt < saveAttempts; attempt++ {
		sn, err := s.read(ctx, true)
		if err != nil {
			s.cfg.Log.Warn("lab run request failed", "err", err)
			return Queued{}, &Refusal{Code: http.StatusServiceUnavailable, Error: "unavailable", Reason: "lab status unavailable"}
		}
		now := s.cfg.Now().UTC()
		ev := s.evaluate(sn.st, sn.markers, sn.vmRunning, now)
		if ref := refusal(ev); ref != nil {
			s.remember(ev)
			return Queued{}, ref
		}
		id, err := newID()
		if err != nil {
			return Queued{}, &Refusal{Code: http.StatusServiceUnavailable, Error: "unavailable"}
		}
		next := sn.st
		next.Request = &request{ID: id, RequestedAt: now}
		switch err := s.write(ctx, next, sn.version); {
		case err == nil:
			s.remember(s.evaluate(next, sn.markers, sn.vmRunning, now))
			return Queued{ID: id, State: StateQueued}, nil
		case !errors.Is(err, ErrConflict):
			s.cfg.Log.Warn("lab run request not stored", "err", err)
			return Queued{}, &Refusal{Code: http.StatusServiceUnavailable, Error: "unavailable"}
		}
	}
	return Queued{}, &Refusal{Code: http.StatusConflict, Error: "busy"}
}

// refusal maps a status that cannot start to POST's answer.
func refusal(ev Status) *Refusal {
	switch ev.State {
	case StateAvailable:
		return nil
	case StateClosed:
		return &Refusal{Code: http.StatusLocked, Error: "closed", NextAllowedAt: ev.NextAllowedAt}
	case StateQueued, StateStarting, StateRunning:
		return &Refusal{Code: http.StatusConflict, Error: "busy"}
	case StateCooldown:
		if ev.Reason == "daily limit" {
			return &Refusal{Code: http.StatusTooManyRequests, Error: "daily limit", NextAllowedAt: ev.NextAllowedAt}
		}
		return &Refusal{Code: http.StatusTooManyRequests, Error: "cooldown", NextAllowedAt: ev.NextAllowedAt}
	}
	return &Refusal{Code: http.StatusServiceUnavailable, Error: "unavailable", Reason: ev.Reason, NextAllowedAt: ev.NextAllowedAt}
}

// Claim is the agent's answer: Start once for a queued request, with its ID.
type Claim struct {
	Start bool   `json:"start"`
	ID    string `json:"id,omitempty"`
}

// Claim hands the queued request, if there is one, to the trigger agent - exactly once: the write
// that marks it claimed is conditional on the version it was read at, so of two concurrent claims
// one wins and the other re-reads a claimed request. The day's counter counts the claim. The
// markers are not needed: an unclaimed request's phase depends on the clock only.
func (s *Service) Claim(ctx context.Context) (Claim, error) {
	if !s.ClaimEnabled() {
		return Claim{}, errors.New("labrun: claim not configured")
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opTimeout)
	defer cancel()
	for attempt := 0; attempt < saveAttempts; attempt++ {
		sn, err := s.read(ctx, false)
		if err != nil {
			return Claim{}, err
		}
		now := s.cfg.Now().UTC()
		if ph, _ := s.phaseOf(sn.st.Request, nil, false, now); ph != phaseQueued {
			return Claim{Start: false}, nil
		}
		next := sn.st
		req := *next.Request
		req.ClaimedAt = &now
		next.Request = &req
		if day := now.Format(time.DateOnly); next.Day != day {
			next.Day, next.RunsToday = day, 0
		}
		next.RunsToday++
		switch err := s.write(ctx, next, sn.version); {
		case err == nil:
			s.invalidate()
			return Claim{Start: true, ID: req.ID}, nil
		case !errors.Is(err, ErrConflict):
			return Claim{}, err
		}
	}
	return Claim{Start: false}, nil
}

func newID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "req-" + hex.EncodeToString(b), nil
}
