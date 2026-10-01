// Package runlog keeps the complete event history of the last runs, for GET /api/runs/{id}: the
// "verify it yourself" link on the page, which shows every event of one run as the API published
// it - run states, pod events, victim probes, and the Falco alerts and Talon actions about the run's
// pod - with the stream's own event ids.
//
// The SSE replay buffer cannot serve this: it holds the last few dozen events of any kind, so a run
// falls out of it as soon as the next one starts. The store is fed by a hub tap (events.Hub.Tap),
// so it records exactly what was published. It is bounded by count and by size, because the size of
// an event is not ours to choose (a Falco output line, a command line):
//
//   - the last 50 runs;
//   - per run, at most 500 events and 256 KiB of event data (a run produces a few dozen events of
//     well under 1 KiB; the caps are for a misbehaving rule that fires in a loop) - past either,
//     later events are not kept and the run is marked truncated;
//   - all runs together, 8 MiB: past it the oldest runs are dropped first, and a run that would
//     exceed it on its own is truncated.
//
// In memory only, like the rest of the API's state (ADR 0015).
package runlog

import (
	"encoding/json"
	"sync"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/events"
)

// Defaults: how many runs are kept, and how many events per run.
const (
	DefaultRuns       = 50
	DefaultRunEvents  = 500
	DefaultRunBytes   = 256 << 10
	DefaultTotalBytes = 8 << 20
)

// Event is one recorded event; Data is the published JSON object, unchanged.
type Event struct {
	ID   uint64          `json:"id"`
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// Run is the public GET /api/runs/{id} payload. Truncated is true when the run produced more than
// the per-run cap; the first events are kept.
type Run struct {
	RunID     string  `json:"run_id"`
	Scenario  string  `json:"scenario"`
	Events    []Event `json:"events"`
	Truncated bool    `json:"truncated"`

	bytes int // sum of len(Data) of Events
}

// Store is safe for concurrent use.
type Store struct {
	mu        sync.Mutex
	maxRuns   int
	maxEvents int
	maxBytes  int // per run
	maxTotal  int // all runs
	total     int
	order     []string // run ids, oldest first
	runs      map[string]*Run
	pods      map[string]string // pod name -> run id
}

// New keeps the last maxRuns runs, up to maxEvents events and maxBytes bytes of event data each,
// and maxTotal bytes over all runs (the defaults for values < 1).
func New(maxRuns, maxEvents, maxBytes, maxTotal int) *Store {
	if maxRuns < 1 {
		maxRuns = DefaultRuns
	}
	if maxEvents < 1 {
		maxEvents = DefaultRunEvents
	}
	if maxBytes < 1 {
		maxBytes = DefaultRunBytes
	}
	if maxTotal < 1 {
		maxTotal = DefaultTotalBytes
	}
	return &Store{maxRuns: maxRuns, maxEvents: maxEvents, maxBytes: maxBytes, maxTotal: maxTotal,
		runs: map[string]*Run{}, pods: map[string]string{}}
}

// Record files ev under its run: by run_id when the event has one (run, pod, victim), else by the
// pod it names (falco, talon - correlated the way the runner correlates them). Events about no
// known run (an alert for a pod no run created) are ignored.
func (s *Store) Record(ev events.Event) {
	var key struct {
		RunID    string `json:"run_id"`
		Scenario string `json:"scenario"`
		Pod      string `json:"pod"`
	}
	if json.Unmarshal(ev.Data, &key) != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := key.RunID
	if id == "" {
		id = s.pods[key.Pod]
	}
	if id == "" {
		return
	}
	run, ok := s.runs[id]
	if !ok {
		if key.RunID == "" {
			return
		}
		run = &Run{RunID: id, Events: []Event{}}
		s.runs[id] = run
		s.order = append(s.order, id)
		for len(s.order) > s.maxRuns {
			s.evictOldestLocked()
		}
	}
	if run.Scenario == "" && key.Scenario != "" {
		run.Scenario = key.Scenario
	}
	if key.RunID != "" && key.Pod != "" {
		s.pods[key.Pod] = id
	}
	size := len(ev.Data)
	if len(run.Events) >= s.maxEvents || run.bytes+size > s.maxBytes {
		run.Truncated = true
		return
	}
	// Over the total: older runs make room first; this run is truncated only if it is the oldest.
	for s.total+size > s.maxTotal && len(s.order) > 0 && s.order[0] != id {
		s.evictOldestLocked()
	}
	if s.total+size > s.maxTotal {
		run.Truncated = true
		return
	}
	run.Events = append(run.Events, Event{ID: ev.ID, Type: ev.Type, Data: json.RawMessage(ev.Data)})
	run.bytes += size
	s.total += size
}

func (s *Store) evictOldestLocked() {
	id := s.order[0]
	s.order = s.order[1:]
	if run, ok := s.runs[id]; ok {
		s.total -= run.bytes
	}
	delete(s.runs, id)
	for pod, rid := range s.pods {
		if rid == id {
			delete(s.pods, pod)
		}
	}
}

// Get returns a copy of the run's record.
func (s *Store) Get(id string) (Run, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return Run{}, false
	}
	out := *run
	out.Events = append([]Event(nil), run.Events...)
	return out, true
}
