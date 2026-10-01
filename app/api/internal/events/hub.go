// Package events is the fan-out behind GET /api/events: every run state change, every Falco alert
// and every Talon action from the sandbox is published here once and delivered to each connected
// Server-Sent Events client.
//
// The hub keeps the last N events in a ring buffer so a visitor who opens the page in the middle of a
// run sees how it started, and so a client that reconnects with Last-Event-ID gets exactly what it
// missed (if it is still in the buffer) instead of a gap or a duplicate. Snapshot and subscription
// happen under one lock, which is what makes "replay, then live" seamless.
//
// A subscriber that cannot keep up is dropped, not waited for: one stalled browser tab must never
// slow down publishing for everyone else (or block the webhook handler that published). EventSource
// reconnects on its own and resumes from Last-Event-ID.
package events

import (
	"encoding/json"
	"sync"
)

// Event is one SSE message. Data is pre-encoded JSON without newlines (encoding/json never emits
// them), so it can be written as a single `data:` line.
type Event struct {
	ID   uint64
	Type string
	Data []byte
}

// Subscription is one connected client. C is closed when the hub drops the subscriber.
type Subscription struct {
	C      chan Event
	closed bool
}

// Hub is safe for concurrent use.
type Hub struct {
	mu      sync.Mutex
	seq     uint64
	ring    []Event
	next    int
	full    bool
	subs    map[*Subscription]struct{}
	bufSize int
	tap     func(Event)
}

// subscriberBuffer is how far a client may fall behind before it is dropped. A run produces well under
// a dozen events, so 64 is only ever exceeded by a client that has stopped reading.
const subscriberBuffer = 64

// NewHub returns a hub that replays the last `replay` events to new subscribers.
func NewHub(replay int) *Hub {
	if replay < 1 {
		replay = 1
	}
	return &Hub{ring: make([]Event, replay), subs: map[*Subscription]struct{}{}, bufSize: subscriberBuffer}
}

// Tap registers fn to be called with every event as it is published, synchronously and in
// publication order (the run store records runs this way: unlike a subscriber, a tap is never
// dropped, so it never misses an event). fn runs under the hub's lock and must be quick and must
// not publish. Call Tap before the first Publish.
func (h *Hub) Tap(fn func(Event)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tap = fn
}

// Publish encodes v as JSON and delivers it to every subscriber. It never blocks on a subscriber.
func (h *Hub) Publish(typ string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seq++
	ev := Event{ID: h.seq, Type: typ, Data: data}
	h.ring[h.next] = ev
	h.next = (h.next + 1) % len(h.ring)
	if h.next == 0 {
		h.full = true
	}
	if h.tap != nil {
		h.tap(ev)
	}
	for s := range h.subs {
		select {
		case s.C <- ev:
		default:
			h.dropLocked(s)
		}
	}
	return nil
}

// Subscribe registers a subscriber and returns the buffered events with an ID greater than after
// (all of them for after == 0). Nothing published after the snapshot can be missed, and nothing in
// the snapshot is delivered twice.
//
// An after that is ahead of the hub's sequence (a Last-Event-ID from before an API restart) is
// treated as 0: the numbering started over, so the client gets the whole buffer.
func (h *Hub) Subscribe(after uint64) (*Subscription, []Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if after > h.seq {
		after = 0
	}
	replay := make([]Event, 0, len(h.ring))
	for _, ev := range h.bufferedLocked() {
		if ev.ID > after {
			replay = append(replay, ev)
		}
	}
	s := &Subscription{C: make(chan Event, h.bufSize)}
	h.subs[s] = struct{}{}
	return s, replay
}

// Unsubscribe removes s. Safe to call more than once and after the hub dropped s.
func (h *Hub) Unsubscribe(s *Subscription) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dropLocked(s)
}

// Subscribers is the number of connected clients.
func (h *Hub) Subscribers() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

func (h *Hub) dropLocked(s *Subscription) {
	if s.closed {
		return
	}
	s.closed = true
	delete(h.subs, s)
	close(s.C)
}

// bufferedLocked returns the ring's contents, oldest first.
func (h *Hub) bufferedLocked() []Event {
	if !h.full {
		return h.ring[:h.next]
	}
	out := make([]Event, 0, len(h.ring))
	out = append(out, h.ring[h.next:]...)
	return append(out, h.ring[:h.next]...)
}
