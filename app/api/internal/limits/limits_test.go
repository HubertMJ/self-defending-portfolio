package limits

import (
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newClock() *clock { return &clock{t: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)} }

func TestPerKeyWindow(t *testing.T) {
	c := newClock()
	a := NewAttacks(DefaultAttackConfig(), c.now)
	for i := range 3 {
		d, release := a.Acquire("1.2.3.4")
		if d.Outcome != Allowed {
			t.Fatalf("attempt %d: %v", i, d.Outcome)
		}
		release()
		c.add(time.Minute)
	}
	d, _ := a.Acquire("1.2.3.4")
	if d.Outcome != RateLimited {
		t.Fatalf("4th attempt: %v, want RateLimited", d.Outcome)
	}
	// The first run was at 12:00, it is now 12:03: the slot frees at 12:10.
	if d.RetryAfter != 7*time.Minute {
		t.Fatalf("RetryAfter = %v, want 7m", d.RetryAfter)
	}
	// Another visitor is unaffected.
	if d, release := a.Acquire("5.6.7.8"); d.Outcome != Allowed {
		t.Fatalf("other key: %v", d.Outcome)
	} else {
		release()
	}
	c.add(7 * time.Minute)
	if d, _ := a.Acquire("1.2.3.4"); d.Outcome != Allowed {
		t.Fatalf("after window: %v", d.Outcome)
	}
}

func TestGlobalWindow(t *testing.T) {
	c := newClock()
	cfg := DefaultAttackConfig()
	a := NewAttacks(cfg, c.now)
	for i := range cfg.Global {
		d, release := a.Acquire(string(rune('a' + i)))
		if d.Outcome != Allowed {
			t.Fatalf("attempt %d: %v", i, d.Outcome)
		}
		release()
		c.add(time.Minute)
	}
	d, _ := a.Acquire("fresh")
	if d.Outcome != RateLimited {
		t.Fatalf("31st attempt: %v, want RateLimited", d.Outcome)
	}
	if d.RetryAfter != 30*time.Minute {
		t.Fatalf("RetryAfter = %v, want 30m", d.RetryAfter)
	}
}

func TestConcurrencyAndRelease(t *testing.T) {
	a := NewAttacks(DefaultAttackConfig(), newClock().now)
	d, release := a.Acquire("a")
	if d.Outcome != Allowed {
		t.Fatal(d.Outcome)
	}
	if d, _ := a.Acquire("b"); d.Outcome != Busy {
		t.Fatalf("second concurrent: %v, want Busy", d.Outcome)
	}
	release()
	release() // idempotent: must not free a second slot
	if a.Active() != 0 {
		t.Fatalf("active = %d", a.Active())
	}
	d1, r1 := a.Acquire("b")
	if d1.Outcome != Allowed {
		t.Fatal(d1.Outcome)
	}
	if d, _ := a.Acquire("c"); d.Outcome != Busy {
		t.Fatalf("double release freed an extra slot: %v", d.Outcome)
	}
	r1()
}

func TestBusyDoesNotConsumeQuota(t *testing.T) {
	a := NewAttacks(DefaultAttackConfig(), newClock().now)
	_, release := a.Acquire("owner")
	for range 10 {
		if d, _ := a.Acquire("x"); d.Outcome != Busy {
			t.Fatalf("got %v, want Busy", d.Outcome)
		}
	}
	release()
	if d, r := a.Acquire("x"); d.Outcome != Allowed {
		t.Fatalf("x lost quota to 409s: %v", d.Outcome)
	} else {
		r()
	}
}

func TestRateLimitBeatsBusy(t *testing.T) {
	c := newClock()
	a := NewAttacks(AttackConfig{PerKey: 1, PerKeyWindow: time.Minute, Global: 10, GlobalWindow: time.Hour, Concurrent: 1}, c.now)
	_, release := a.Acquire("x")
	defer release()
	if d, _ := a.Acquire("x"); d.Outcome != RateLimited {
		t.Fatalf("got %v, want RateLimited while a run is active and quota is spent", d.Outcome)
	}
}

func TestConcurrentAcquireOnlyOneWins(t *testing.T) {
	a := NewAttacks(AttackConfig{PerKey: 100, PerKeyWindow: time.Minute, Global: 100, GlobalWindow: time.Hour, Concurrent: 1}, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if d, _ := a.Acquire("k"); d.Outcome == Allowed {
				mu.Lock()
				won++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if won != 1 {
		t.Fatalf("%d concurrent acquisitions succeeded, want 1", won)
	}
}

func TestRequests(t *testing.T) {
	c := newClock()
	r := NewRequests(2, time.Minute, 2, c.now)
	if ok, _ := r.Allow("a"); !ok {
		t.Fatal("1st")
	}
	if ok, _ := r.Allow("a"); !ok {
		t.Fatal("2nd")
	}
	c.add(15 * time.Second)
	ok, retry := r.Allow("a")
	if ok || retry != 45*time.Second {
		t.Fatalf("3rd: ok=%v retry=%v", ok, retry)
	}
	if ok, _ := r.Allow("b"); !ok {
		t.Fatal("b")
	}
	// Key cap reached: a third address is refused until the window rolls.
	if ok, _ := r.Allow("c"); ok {
		t.Fatal("c admitted past the key cap")
	}
	c.add(45 * time.Second)
	if ok, _ := r.Allow("c"); !ok {
		t.Fatal("c after rollover")
	}
}

func TestConns(t *testing.T) {
	c := NewConns(2, 3)
	_, r1 := c.Acquire("a")
	ok2, r2 := c.Acquire("a")
	if ok, _ := c.Acquire("a"); ok || !ok2 {
		t.Fatal("per-key cap")
	}
	_, r3 := c.Acquire("b")
	if ok, _ := c.Acquire("c"); ok {
		t.Fatal("total cap")
	}
	r1()
	r1()
	if ok, r := c.Acquire("c"); !ok {
		t.Fatal("after release")
	} else {
		r()
	}
	r2()
	r3()
	if c.sum != 0 || len(c.open) != 0 {
		t.Fatalf("leak: sum=%d open=%v", c.sum, c.open)
	}
}
