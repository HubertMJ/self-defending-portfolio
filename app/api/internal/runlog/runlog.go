// Package runlog keeps the complete event history of the last runs, for GET /api/runs/{id}: the
// "verify it yourself" link on the page, which shows every event of one run as the API published
// it - run states, pod events, victim probes, and the Falco alerts and Talon actions about the run's
// pod - with the stream's own event ids.
//
// The SSE replay buffer cannot serve this: it holds the last few dozen events of any kind, so a run
// falls out of it as soon as the next one starts. The store is fed by a hub tap (events.Hub.Tap),
// so it records exactly what was published, and it is bounded twice: the last 50 runs, and at most
// 500 events per run (a run produces a few dozen; the cap is for a misbehaving Falco rule that fires
// in a loop). In memory only, like the rest of the API's state (ADR 0015).
package runlog

import (
	"encoding/json"
	"sync"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/events"
)

// Defaults: how many runs are kept, and how many events per run.
const (
	DefaultRuns      = 50
	DefaultRunEvents = 500
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
}

// Store is safe for concurrent use.
type Store struct {
	mu        sync.Mutex
	maxRuns   int
	maxEvents int
	order     []string // run ids, oldest first
	runs      map[string]*Run
	pods      map[string]string // pod name -> run id
}

// New keeps the last maxRuns runs, up to maxEvents events each (defaults for values < 1).
func New(maxRuns, maxEvents int) *Store {
	if maxRuns < 1 {
		maxRuns = DefaultRuns
	}
	if maxEvents < 1 {
		maxEvents = DefaultRunEvents
	}
	return &Store{maxRuns: maxRuns, maxEvents: maxEvents, runs: map[string]*Run{}, pods: map[string]string{}}
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
			s.evictLocked(s.order[0])
			s.order = s.order[1:]
		}
	}
	if run.Scenario == "" && key.Scenario != "" {
		run.Scenario = key.Scenario
	}
	if key.RunID != "" && key.Pod != "" {
		s.pods[key.Pod] = id
	}
	if len(run.Events) >= s.maxEvents {
		run.Truncated = true
		return
	}
	run.Events = append(run.Events, Event{ID: ev.ID, Type: ev.Type, Data: json.RawMessage(ev.Data)})
}

func (s *Store) evictLocked(id string) {
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
