// Package limits holds the abuse limits of the public API (ADR 0015).
//
// An attack run costs real cluster resources - a pod in `sandbox`, a Falco alert, a Talon action, a
// Kyverno signature verification - so the trigger is the one endpoint that has to be rationed:
//
//   - per visitor: 3 runs per 10 minutes (sliding window, keyed by client.Key);
//   - for everybody together: 30 runs per hour, so rotating addresses cannot run the node hot;
//   - one run at a time, cluster-wide, which is also what keeps the live feed readable.
//
// Every other endpoint is cheap but still not free, so Requests applies a coarse per-visitor
// request budget, and Conns caps concurrently open event streams, per visitor and in total.
//
// All state is in memory. A restart forgets the windows, which is accepted: it can only happen as
// often as the Deployment is rolled, and the sandbox ResourceQuota and the single concurrency slot
// still bound what a burst right after a restart can do.
package limits

import (
	"sync"
	"time"
)

// Outcome of an attack admission decision.
type Outcome int

const (
	Allowed Outcome = iota
	// RateLimited: the per-visitor or the global window is full. Answer 429 with Retry-After.
	RateLimited
	// Busy: a run is already in progress. Answer 409.
	Busy
)

// Decision is what Acquire decided, with RetryAfter set for RateLimited.
type Decision struct {
	Outcome    Outcome
	RetryAfter time.Duration
}

// AttackConfig sizes the attack limiter. The defaults are the contract's numbers.
type AttackConfig struct {
	PerKey       int
	PerKeyWindow time.Duration
	Global       int
	GlobalWindow time.Duration
	Concurrent   int
}

// DefaultAttackConfig: 3 per 10 min per visitor, 30 per hour in total, 1 at a time.
func DefaultAttackConfig() AttackConfig {
	return AttackConfig{PerKey: 3, PerKeyWindow: 10 * time.Minute, Global: 30, GlobalWindow: time.Hour, Concurrent: 1}
}

// Attacks is the attack admission limiter. Rate checks, the concurrency check and the bookkeeping
// happen under one lock, so two simultaneous requests can never both take the last slot.
type Attacks struct {
	mu     sync.Mutex
	cfg    AttackConfig
	now    func() time.Time
	perKey map[string][]time.Time
	global []time.Time
	active int
}

// NewAttacks returns a limiter; now may be nil (time.Now).
func NewAttacks(cfg AttackConfig, now func() time.Time) *Attacks {
	if now == nil {
		now = time.Now
	}
	return &Attacks{cfg: cfg, now: now, perKey: map[string][]time.Time{}}
}

// Acquire decides whether key may start a run now. On Allowed the run is counted against both
// windows and holds a concurrency slot until release is called (release is idempotent and must be
// called exactly when the run has ended, pod cleanup included). Rejected attempts are not counted:
// a visitor who hits 409 because someone else's run is in progress has not used up their quota.
//
// Rate limits are checked before the concurrency slot, so a visitor over their quota hears "429,
// come back in N seconds" rather than a 409 that invites an immediate retry.
func (a *Attacks) Acquire(key string) (Decision, func()) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()

	a.global = prune(a.global, now.Add(-a.cfg.GlobalWindow))
	for k, ts := range a.perKey {
		// Bounded: only accepted runs create entries, and the global window caps those.
		if ts = prune(ts, now.Add(-a.cfg.PerKeyWindow)); len(ts) == 0 {
			delete(a.perKey, k)
		} else {
			a.perKey[k] = ts
		}
	}

	if ts := a.perKey[key]; len(ts) >= a.cfg.PerKey {
		return Decision{Outcome: RateLimited, RetryAfter: ts[len(ts)-a.cfg.PerKey].Add(a.cfg.PerKeyWindow).Sub(now)}, noop
	}
	if len(a.global) >= a.cfg.Global {
		return Decision{Outcome: RateLimited, RetryAfter: a.global[len(a.global)-a.cfg.Global].Add(a.cfg.GlobalWindow).Sub(now)}, noop
	}
	if a.active >= a.cfg.Concurrent {
		return Decision{Outcome: Busy}, noop
	}

	a.perKey[key] = append(a.perKey[key], now)
	a.global = append(a.global, now)
	a.active++
	var once sync.Once
	return Decision{Outcome: Allowed}, func() {
		once.Do(func() {
			a.mu.Lock()
			a.active--
			a.mu.Unlock()
		})
	}
}

// AttackStatus is what GET /api/limits reports to one visitor: the attack budgets as they stand,
// without spending anything.
type AttackStatus struct {
	PerKeyLimit     int
	PerKeyWindow    time.Duration
	PerKeyRemaining int
	// PerKeyResetIn is when the visitor's oldest counted run leaves the window (one more attempt
	// becomes available); zero when nothing is counted.
	PerKeyResetIn   time.Duration
	GlobalLimit     int
	GlobalWindow    time.Duration
	GlobalRemaining int
	Active          bool
}

// Status reports key's budgets. Read-only: the windows are evaluated at now, not pruned.
func (a *Attacks) Status(key string) AttackStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	mine := inWindow(a.perKey[key], now.Add(-a.cfg.PerKeyWindow))
	all := inWindow(a.global, now.Add(-a.cfg.GlobalWindow))
	st := AttackStatus{
		PerKeyLimit: a.cfg.PerKey, PerKeyWindow: a.cfg.PerKeyWindow, PerKeyRemaining: max(0, a.cfg.PerKey-len(mine)),
		GlobalLimit: a.cfg.Global, GlobalWindow: a.cfg.GlobalWindow, GlobalRemaining: max(0, a.cfg.Global-len(all)),
		Active: a.active > 0,
	}
	if len(mine) > 0 {
		st.PerKeyResetIn = mine[0].Add(a.cfg.PerKeyWindow).Sub(now)
	}
	return st
}

// inWindow is the suffix of ts (ascending) after cutoff, without modifying ts.
func inWindow(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && !ts[i].After(cutoff) {
		i++
	}
	return ts[i:]
}

// Active is the number of runs holding a slot.
func (a *Attacks) Active() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.active
}

func noop() {}

// prune drops timestamps at or before cutoff; ts is in ascending order.
func prune(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && !ts[i].After(cutoff) {
		i++
	}
	if i == 0 {
		return ts
	}
	return append(ts[:0:0], ts[i:]...)
}

// Requests is a fixed-window request budget per visitor for every public endpoint. Coarse on
// purpose: it exists to stop a single client from hammering /api/posture or reconnecting the event
// stream in a tight loop, not to shape traffic. The number of tracked keys is capped; past the cap,
// unknown keys are refused until the window rolls over, so memory stays bounded however many
// addresses a flood rotates through.
type Requests struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	maxKeys int
	now     func() time.Time
	start   time.Time
	counts  map[string]int
}

// NewRequests allows limit requests per key per window, tracking at most maxKeys keys per window.
func NewRequests(limit int, window time.Duration, maxKeys int, now func() time.Time) *Requests {
	if now == nil {
		now = time.Now
	}
	return &Requests{limit: limit, window: window, maxKeys: maxKeys, now: now, counts: map[string]int{}}
}

// Allow counts one request for key and reports whether it is within budget, and if not, when the
// window resets.
func (r *Requests) Allow(key string) (bool, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if now.Sub(r.start) >= r.window {
		r.start = now
		clear(r.counts)
	}
	retry := r.start.Add(r.window).Sub(now)
	n, known := r.counts[key]
	if !known && len(r.counts) >= r.maxKeys {
		return false, retry
	}
	if n >= r.limit {
		return false, retry
	}
	r.counts[key] = n + 1
	return true, 0
}

// Conns caps concurrently open long-lived connections (the SSE stream), per key and in total.
type Conns struct {
	mu     sync.Mutex
	perKey int
	total  int
	open   map[string]int
	sum    int
}

// NewConns allows perKey connections per key and total connections overall.
func NewConns(perKey, total int) *Conns {
	return &Conns{perKey: perKey, total: total, open: map[string]int{}}
}

// Remaining is how many more connections key could open now.
func (c *Conns) Remaining(key string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return max(0, min(c.perKey-c.open[key], c.total-c.sum))
}

// Acquire reserves a connection for key; the returned release is idempotent.
func (c *Conns) Acquire(key string) (bool, func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sum >= c.total || c.open[key] >= c.perKey {
		return false, noop
	}
	c.open[key]++
	c.sum++
	var once sync.Once
	return true, func() {
		once.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.sum--
			if c.open[key]--; c.open[key] <= 0 {
				delete(c.open, key)
			}
		})
	}
}
