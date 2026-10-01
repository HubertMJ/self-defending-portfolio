package events

import (
	"fmt"
	"sync"
	"testing"
)

func ids(evs []Event) []uint64 {
	out := make([]uint64, len(evs))
	for i, e := range evs {
		out[i] = e.ID
	}
	return out
}

func TestReplayKeepsLastN(t *testing.T) {
	h := NewHub(3)
	for i := range 5 {
		if err := h.Publish("run", map[string]int{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	_, replay := h.Subscribe(0)
	if got := fmt.Sprint(ids(replay)); got != "[3 4 5]" {
		t.Fatalf("replay = %s, want [3 4 5]", got)
	}
	if string(replay[2].Data) != `{"i":4}` || replay[2].Type != "run" {
		t.Fatalf("last event = %s %s", replay[2].Type, replay[2].Data)
	}
}

func TestReplayAfterLastEventID(t *testing.T) {
	h := NewHub(50)
	for range 4 {
		_ = h.Publish("falco", struct{}{})
	}
	_, replay := h.Subscribe(2)
	if got := fmt.Sprint(ids(replay)); got != "[3 4]" {
		t.Fatalf("replay after 2 = %s", got)
	}
	// An ID from before a restart (ahead of the counter) gets the whole buffer.
	_, replay = h.Subscribe(99)
	if len(replay) != 4 {
		t.Fatalf("replay after future id = %d events, want 4", len(replay))
	}
}

func TestLiveDeliveryAfterSnapshot(t *testing.T) {
	h := NewHub(10)
	_ = h.Publish("run", 1)
	s, replay := h.Subscribe(0)
	_ = h.Publish("run", 2)
	if len(replay) != 1 || replay[0].ID != 1 {
		t.Fatalf("replay = %v", ids(replay))
	}
	ev := <-s.C
	if ev.ID != 2 {
		t.Fatalf("live event id = %d, want 2", ev.ID)
	}
	h.Unsubscribe(s)
	h.Unsubscribe(s) // idempotent
	if _, ok := <-s.C; ok {
		t.Fatal("channel still open after unsubscribe")
	}
}

func TestSlowSubscriberIsDropped(t *testing.T) {
	h := NewHub(1)
	slow, _ := h.Subscribe(0)
	fast, _ := h.Subscribe(0)
	var wg sync.WaitGroup
	wg.Add(1)
	got := 0
	go func() {
		defer wg.Done()
		for range fast.C {
			got++
			if got == subscriberBuffer+10 {
				h.Unsubscribe(fast)
			}
		}
	}()
	for range subscriberBuffer + 10 {
		_ = h.Publish("run", 0)
	}
	wg.Wait()
	// The slow one never read: it was dropped once its buffer filled, without blocking Publish.
	n := 0
	for range slow.C {
		n++
	}
	if n != subscriberBuffer {
		t.Fatalf("slow subscriber got %d buffered events, want %d", n, subscriberBuffer)
	}
	if h.Subscribers() != 0 {
		t.Fatalf("subscribers = %d, want 0", h.Subscribers())
	}
}

func TestConcurrentPublish(t *testing.T) {
	h := NewHub(50)
	s, _ := h.Subscribe(0)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 5 {
				_ = h.Publish("talon", 0)
			}
		}()
	}
	wg.Wait()
	h.Unsubscribe(s)
	var last uint64
	for ev := range s.C {
		if ev.ID <= last {
			t.Fatalf("out of order: %d after %d", ev.ID, last)
		}
		last = ev.ID
	}
	if last != 40 {
		t.Fatalf("last id = %d, want 40", last)
	}
}

func TestTapSeesEveryEventInOrder(t *testing.T) {
	h := NewHub(1)
	var got []uint64
	h.Tap(func(ev Event) { got = append(got, ev.ID) })
	for range 5 {
		if err := h.Publish("run", map[string]int{}); err != nil {
			t.Fatal(err)
		}
	}
	if len(got) != 5 || got[0] != 1 || got[4] != 5 {
		t.Fatalf("tap saw %v", got)
	}
}
