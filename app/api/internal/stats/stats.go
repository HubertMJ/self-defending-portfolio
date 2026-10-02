// Package stats keeps the counters behind GET /api/stats and the hero's live numbers (ADR 0030):
// how many attack runs there have been, how many were detected and answered, how fast the response
// was, which terminal commands visitors ran and which objectives they reached. It is fed by a hub
// tap (the same mechanism the run store uses), so it sees exactly what the live feed published and
// needs no extra reads or RBAC, and it carries counters only - no client address, no free text, no
// per-visitor record - so it is safe to persist.
//
// Persistence is a single ConfigMap in `portfolio-api` (configmap.go), read at start and written at
// most once a minute and on shutdown. A restart therefore keeps the running totals; the sandbox
// quota and the single run slot bound what a burst right after one could add.
package stats

import (
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/events"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/scenarios"
)

// sample ring sizes: enough for a stable median without unbounded memory or a large ConfigMap.
const (
	maxResponseSamples = 512
	maxSurvivalSamples = 512
)

// Snapshot is the GET /api/stats payload.
type Snapshot struct {
	Since      time.Time                `json:"since"`
	Runs       int                      `json:"runs"`
	ByScenario map[string]ScenarioStat  `json:"by_scenario"`
	ResponseMS ResponseMS               `json:"response_ms"`
	Unanswered int                      `json:"unanswered"`
	Commands   map[string]CommandStat   `json:"commands"`
	Objectives map[string]ObjectiveStat `json:"objectives"`
	Terminal   TerminalStat             `json:"terminal"`
}

// ScenarioStat is one scenario's run tally: how many runs, how many were detected, how many were
// answered by Talon.
type ScenarioStat struct {
	Runs      int `json:"runs"`
	Detected  int `json:"detected"`
	Responded int `json:"responded"`
}

// ResponseMS is the detection-to-response latency in milliseconds: the last one, the median over a
// recent sample, and the all-time min and max. Zero when nothing has been answered yet.
type ResponseMS struct {
	Last int64 `json:"last"`
	P50  int64 `json:"p50"`
	Min  int64 `json:"min"`
	Max  int64 `json:"max"`
}

// CommandStat is how often one terminal command was run and the outcome the catalogue gives it
// (allowed+prevented+detected == attempts; the outcome is fixed, and that it holds is the point).
type CommandStat struct {
	Attempts  int `json:"attempts"`
	Allowed   int `json:"allowed"`
	Prevented int `json:"prevented"`
	Detected  int `json:"detected"`
}

// ObjectiveStat is how often an objective was attempted (a command for it was run) and achieved (it
// exited 0).
type ObjectiveStat struct {
	Attempts int `json:"attempts"`
	Achieved int `json:"achieved"`
}

// TerminalStat summarises the terminal scenario: how many runs, the most objectives any one run
// reached, and the median seconds a run survived.
type TerminalStat struct {
	Runs            int `json:"runs"`
	BestObjectives  int `json:"best_objectives"`
	MedianSurvivalS int `json:"median_survival_s"`
}

// agg is the persisted aggregate: everything in Snapshot except what is computed from the sample
// rings at read time. Exported fields so encoding/json can round-trip it to the ConfigMap.
type agg struct {
	Since           time.Time
	Runs            int
	ByScenario      map[string]*ScenarioStat
	Unanswered      int
	Commands        map[string]*CommandStat
	Objectives      map[string]*ObjectiveStat
	TerminalRuns    int
	BestObjectives  int
	RespLast        int64
	RespMin         int64
	RespMax         int64
	RespSamples     []int64
	SurvivalSamples []int64
}

func newAgg(now time.Time) *agg {
	return &agg{Since: now, ByScenario: map[string]*ScenarioStat{},
		Commands: map[string]*CommandStat{}, Objectives: map[string]*ObjectiveStat{}}
}

// Collector accumulates the counters. Safe for concurrent use: Record is called from the hub (one
// goroutine, under the hub lock) and Snapshot/Marshal from request and persistence goroutines.
type Collector struct {
	scenarios *scenarios.Store
	now       func() time.Time

	mu     sync.Mutex
	a      *agg
	active map[string]*runState // by run id
	pods   map[string]string    // pod name -> run id (to attribute falco/talon by pod)
	dirty  bool
}

// runState is the in-flight view of one run, discarded when the run ends.
type runState struct {
	scenario    string
	interactive bool
	start       time.Time
	detectedAt  time.Time
	detected    bool
	responded   bool
	counted     bool            // counted into Runs/ByScenario already
	objectives  map[string]bool // objectives achieved in this run
}

// New returns a collector. sc is used to look up a scenario's interactive flag, command outcomes
// and objectives from an event that carries only ids; now may be nil (time.Now).
func New(sc *scenarios.Store, now func() time.Time) *Collector {
	if now == nil {
		now = time.Now
	}
	return &Collector{scenarios: sc, now: now, a: newAgg(now().UTC()),
		active: map[string]*runState{}, pods: map[string]string{}}
}

// Record files one published event (hub tap). It never blocks and never fails.
func (c *Collector) Record(ev events.Event) {
	switch ev.Type {
	case "run":
		c.recordRun(ev.Data)
	case "command":
		c.recordCommand(ev.Data)
	}
}

func (c *Collector) recordRun(data []byte) {
	var e struct {
		RunID    string    `json:"run_id"`
		Scenario string    `json:"scenario"`
		State    string    `json:"state"`
		At       time.Time `json:"at"`
		Pod      string    `json:"pod"`
	}
	if json.Unmarshal(data, &e) != nil || e.RunID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	rs := c.active[e.RunID]
	if rs == nil {
		interactive := false
		if sc, ok := c.scenarios.Get(e.Scenario); ok {
			interactive = sc.Interactive
		}
		rs = &runState{scenario: e.Scenario, interactive: interactive, start: e.At, objectives: map[string]bool{}}
		c.active[e.RunID] = rs
	}
	if e.Pod != "" {
		c.pods[e.Pod] = e.RunID
	}
	switch e.State {
	case "queued":
		if !rs.counted {
			rs.counted = true
			c.a.Runs++
			c.scenarioStat(rs.scenario).Runs++
			if rs.interactive {
				c.a.TerminalRuns++
			}
			c.dirty = true
		}
	case "detected":
		if !rs.detected {
			rs.detected = true
			rs.detectedAt = e.At
			c.scenarioStat(rs.scenario).Detected++
			c.dirty = true
		}
	case "responded":
		if !rs.responded {
			rs.responded = true
			c.scenarioStat(rs.scenario).Responded++
			if rs.detected && !e.At.Before(rs.detectedAt) {
				c.addResponse(e.At.Sub(rs.detectedAt).Milliseconds())
			}
			c.dirty = true
		}
	case "finished", "failed", "timeout":
		c.finishLocked(e.RunID, rs, e.At)
	}
}

func (c *Collector) finishLocked(runID string, rs *runState, at time.Time) {
	if rs.detected && !rs.responded {
		c.a.Unanswered++
	}
	if rs.interactive {
		if n := len(rs.objectives); n > c.a.BestObjectives {
			c.a.BestObjectives = n
		}
		if !at.Before(rs.start) {
			c.addSurvival(int64(at.Sub(rs.start).Seconds()))
		}
	}
	c.dirty = true
	delete(c.active, runID)
	for pod, id := range c.pods {
		if id == runID {
			delete(c.pods, pod)
		}
	}
}

func (c *Collector) recordCommand(data []byte) {
	var e struct {
		RunID    string `json:"run_id"`
		ID       string `json:"id"`
		State    string `json:"state"`
		Achieved bool   `json:"achieved"`
	}
	if json.Unmarshal(data, &e) != nil || e.RunID == "" || e.ID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	rs := c.active[e.RunID]
	if rs == nil {
		return
	}
	cmd, ok := c.command(rs.scenario, e.ID)
	if !ok {
		return
	}
	switch e.State {
	case "started":
		cs := c.commandStat(e.ID)
		cs.Attempts++
		switch cmd.Outcome {
		case "allowed":
			cs.Allowed++
		case "prevented":
			cs.Prevented++
		case "detected":
			cs.Detected++
		}
		if cmd.Objective != "" {
			c.objectiveStat(cmd.Objective).Attempts++
		}
		c.dirty = true
	case "exited":
		if e.Achieved && cmd.Objective != "" {
			c.objectiveStat(cmd.Objective).Achieved++
			rs.objectives[cmd.Objective] = true
			c.dirty = true
		}
	}
}

// Snapshot renders the current counters.
func (c *Collector) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Snapshot{
		Since:      c.a.Since,
		Runs:       c.a.Runs,
		ByScenario: map[string]ScenarioStat{},
		Unanswered: c.a.Unanswered,
		Commands:   map[string]CommandStat{},
		Objectives: map[string]ObjectiveStat{},
		Terminal: TerminalStat{Runs: c.a.TerminalRuns, BestObjectives: c.a.BestObjectives,
			MedianSurvivalS: int(median(c.a.SurvivalSamples))},
	}
	for id, v := range c.a.ByScenario {
		s.ByScenario[id] = *v
	}
	for id, v := range c.a.Commands {
		s.Commands[id] = *v
	}
	for id, v := range c.a.Objectives {
		s.Objectives[id] = *v
	}
	s.ResponseMS = ResponseMS{Last: c.a.RespLast, Min: c.a.RespMin, Max: c.a.RespMax, P50: median(c.a.RespSamples)}
	return s
}

func (c *Collector) scenarioStat(id string) *ScenarioStat {
	v := c.a.ByScenario[id]
	if v == nil {
		v = &ScenarioStat{}
		c.a.ByScenario[id] = v
	}
	return v
}

func (c *Collector) commandStat(id string) *CommandStat {
	v := c.a.Commands[id]
	if v == nil {
		v = &CommandStat{}
		c.a.Commands[id] = v
	}
	return v
}

func (c *Collector) objectiveStat(id string) *ObjectiveStat {
	v := c.a.Objectives[id]
	if v == nil {
		v = &ObjectiveStat{}
		c.a.Objectives[id] = v
	}
	return v
}

func (c *Collector) command(scenario, id string) (scenarios.Command, bool) {
	sc, ok := c.scenarios.Get(scenario)
	if !ok {
		return scenarios.Command{}, false
	}
	return sc.CommandByID(id)
}

func (c *Collector) addResponse(ms int64) {
	if ms < 0 {
		ms = 0
	}
	c.a.RespLast = ms
	if c.a.RespMin == 0 || ms < c.a.RespMin {
		c.a.RespMin = ms
	}
	if ms > c.a.RespMax {
		c.a.RespMax = ms
	}
	c.a.RespSamples = appendCapped(c.a.RespSamples, ms, maxResponseSamples)
}

func (c *Collector) addSurvival(s int64) {
	if s < 0 {
		s = 0
	}
	c.a.SurvivalSamples = appendCapped(c.a.SurvivalSamples, s, maxSurvivalSamples)
}

// appendCapped keeps the most recent n values (a simple ring by slice).
func appendCapped(xs []int64, v int64, n int) []int64 {
	xs = append(xs, v)
	if len(xs) > n {
		xs = xs[len(xs)-n:]
	}
	return xs
}

// median of a copy of xs; 0 for empty.
func median(xs []int64) int64 {
	if len(xs) == 0 {
		return 0
	}
	cp := append([]int64(nil), xs...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	return cp[len(cp)/2]
}

// Marshal serialises the aggregate counters for the ConfigMap. Only aggregates are written - no run
// is in it (the active map and the pod index are in-flight state, not persisted).
func (c *Collector) Marshal() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return json.Marshal(c.a)
}

// Load replaces the counters from a previous Marshal. A blank or unparseable blob leaves the fresh
// counters in place (a first start, or a corrupted ConfigMap). The since timestamp is kept so the
// page can say how long the totals have been collected.
func (c *Collector) Load(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	var a agg
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if a.ByScenario == nil {
		a.ByScenario = map[string]*ScenarioStat{}
	}
	if a.Commands == nil {
		a.Commands = map[string]*CommandStat{}
	}
	if a.Objectives == nil {
		a.Objectives = map[string]*ObjectiveStat{}
	}
	if a.Since.IsZero() {
		a.Since = c.now().UTC()
	}
	c.a = &a
	c.dirty = false
	return nil
}

// TakeDirty reports whether the counters changed since the last call and clears the flag, so the
// persistence loop writes the ConfigMap only when there is something new.
func (c *Collector) TakeDirty() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	d := c.dirty
	c.dirty = false
	return d
}
