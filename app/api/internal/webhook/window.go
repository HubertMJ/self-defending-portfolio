package webhook

import (
	"sync"
	"time"
)

// Window counts events over a sliding period (24 h for the posture page) in fixed-size buckets,
// so memory is constant however many alerts arrive: 1440 one-minute buckets for a day.
//
// In memory only: the counters start at zero when the API restarts (ADR 0015, accepted: persisting
// them would need a volume or a store, for two numbers).
type Window struct {
	mu     sync.Mutex
	bucket time.Duration
	counts []int
	stamps []int64 // bucket index each slot currently holds
	now    func() time.Time
}

// NewWindow covers period with buckets of size bucket. now may be nil (time.Now).
func NewWindow(period, bucket time.Duration, now func() time.Time) *Window {
	if now == nil {
		now = time.Now
	}
	n := int(period / bucket)
	return &Window{bucket: bucket, counts: make([]int, n), stamps: make([]int64, n), now: now}
}

// NewDayWindow is a 24 h window with one-minute buckets.
func NewDayWindow(now func() time.Time) *Window { return NewWindow(24*time.Hour, time.Minute, now) }

// Add counts one event now.
func (w *Window) Add() {
	w.mu.Lock()
	defer w.mu.Unlock()
	idx := w.now().UnixNano() / int64(w.bucket)
	slot := int(idx % int64(len(w.counts)))
	if w.stamps[slot] != idx {
		w.stamps[slot], w.counts[slot] = idx, 0
	}
	w.counts[slot]++
}

// Count is the number of events in the window ending now.
func (w *Window) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	idx := w.now().UnixNano() / int64(w.bucket)
	oldest := idx - int64(len(w.counts)) + 1
	total := 0
	for i, s := range w.stamps {
		if s >= oldest && s <= idx {
			total += w.counts[i]
		}
	}
	return total
}
