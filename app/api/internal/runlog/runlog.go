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
//   - per run, at most 500 events and 256 KiB of event data (a scripted run produces a few dozen
//     events of well under 1 KiB, a terminal run at most a few hundred - its `output` events are
//     capped at 300 a run, ADR 0029; the caps are for a misbehaving rule that fires in a loop) - past
//     either, later events are not kept and the run is marked truncated;
//   - of those, a tenth of the events and an eighth of the bytes (50 events, 32 KiB) are reserved for
//     the run's terminal-state events: the final `run` event (finished, failed, timeout) and each
//     command's `exited`/`killed`. Other events stop at the rest, so however many alerts or output
//     chunks a run produced, its record still ends with how each command and the run itself ended
//     (a run accepts at most 30 commands, so 31 such events, a few KiB, fit the reserve);
//   - all runs together, 8 MiB: past it the oldest runs are dropped first, and a run that would
//     exceed it on its own is truncated.
//
// List (GET /api/runs, ADR 0035) is a summary of each kept run, newest first, maintained as events
// are recorded and evicted with its run, so the list and the store never disagree.
//
// In memory only, like the rest of the API's state (ADR 0015).
package runlog

import (
	"encoding/json"
	"sync"
	"time"

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
	sum   Summary
}

// Summary is one row of GET /api/runs: what the run's own `run` events say about it - its latest
// state, when it was queued and ended, whether it was detected and answered - and how many events
// it holds. No pod, no command, no output. StartedAt is the queued time (until it is seen, the first
// run event's), EndedAt the first terminal state's; either is null rather than a zero time.
type Summary struct {
	RunID     string     `json:"run_id"`
	Scenario  string     `json:"scenario"`
	State     string     `json:"state"`
	StartedAt *time.Time `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at"`
	Detected  bool       `json:"detected"`
	Responded bool       `json:"responded"`
	Events    int        `json:"events"`
	Truncated bool       `json:"truncated"`

	ended, queuedSeen bool
}

// Store is safe for concurrent use.
type Store struct {
	mu        sync.Mutex
	maxRuns   int
	maxEvents int
	maxBytes  int // per run
	maxTotal  int // all runs
	// reserveEvents/reserveBytes of the per-run caps are kept for terminal-state events.
	reserveEvents int
	reserveBytes  int
	total         int
	order         []string // run ids, oldest first
	runs          map[string]*Run
	pods          map[string]string // pod name -> run id
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
		reserveEvents: maxEvents / 10, reserveBytes: maxBytes / 8,
		runs: map[string]*Run{}, pods: map[string]string{}}
}

// terminalState reports whether an event records how a run or one of its commands ended - what the
// per-run reserve is kept for.
func terminalState(typ, state string) bool {
	switch typ {
	case "run":
		return state == "finished" || state == "failed" || state == "timeout"
	case "command":
		return state == "exited" || state == "killed"
	}
	return false
}

// Record files ev under its run: by run_id when the event has one (run, pod, victim), else by the
// pod it names (falco, talon - correlated the way the runner correlates them). Events about no
// known run (an alert for a pod no run created) are ignored.
func (s *Store) Record(ev events.Event) {
	var key struct {
		RunID    string    `json:"run_id"`
		Scenario string    `json:"scenario"`
		Pod      string    `json:"pod"`
		State    string    `json:"state"`
		At       time.Time `json:"at"`
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
	// The summary follows the run's own state events only: a command's or a pod's `state` is not the
	// run's. It is updated even when the event itself no longer fits the run's caps.
	if ev.Type == "run" && key.State != "" {
		summarise(&run.sum, key.State, key.At)
	}
	if key.RunID != "" && key.Pod != "" {
		s.pods[key.Pod] = id
	}
	size := len(ev.Data)
	maxEvents, maxBytes := s.maxEvents, s.maxBytes
	if !terminalState(ev.Type, key.State) {
		maxEvents, maxBytes = maxEvents-s.reserveEvents, maxBytes-s.reserveBytes
	}
	if len(run.Events) >= maxEvents || run.bytes+size > maxBytes {
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

// summarise files one of the run's state events. The first terminal state is final: a later event
// (a late `detected` after `finished`, a second terminal event) may still set Detected/Responded, but
// does not change State or EndedAt.
func summarise(sum *Summary, state string, at time.Time) {
	at = at.UTC()
	switch state {
	case "detected":
		sum.Detected = true
	case "responded":
		sum.Responded = true
	}
	if !at.IsZero() && !sum.queuedSeen && (state == "queued" || sum.StartedAt == nil) {
		sum.StartedAt = &at
		sum.queuedSeen = state == "queued"
	}
	if sum.ended {
		return
	}
	sum.State = state
	if terminalState("run", state) {
		sum.ended = true
		if !at.IsZero() {
			sum.EndedAt = &at
		}
	}
}

// List returns the summaries of the kept runs, newest first.
func (s *Store) List() []Summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Summary, 0, len(s.order))
	for i := len(s.order) - 1; i >= 0; i-- {
		run := s.runs[s.order[i]]
		sum := run.sum
		sum.RunID, sum.Scenario, sum.Events, sum.Truncated = run.RunID, run.Scenario, len(run.Events), run.Truncated
		out = append(out, sum)
	}
	return out
}

// Kept is how many runs the store keeps.
func (s *Store) Kept() int { return s.maxRuns }

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
