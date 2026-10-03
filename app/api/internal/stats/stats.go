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
//
// The same aggregate carries the "last 24 h" numbers (ADR 0035): runs, detections and responses, and
// the Falco alerts and Talon actions the webhooks deliver, in one set of hourly buckets. The hero's
// numbers and the posture section's alerts_24h/actions_24h are therefore read from the same buckets
// and survive a restart together, so the page cannot show "7 detected" next to "0 alerts".
package stats

import (
	"encoding/json"
	"fmt"
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
	// LastRunAt is when the most recent run was queued (persisted, ADR 0035); null before any run.
	LastRunAt *time.Time `json:"last_run_at"`
	Last24h   Window     `json:"last_24h"`
}

// Window is the hourly window: the current hour and the 23 before it, so it covers between 23 and
// 24 h. Since says where it starts - the start of the oldest hour, or later when the counting itself
// started later (the first day after the window was introduced) - and the page labels the numbers
// with it rather than with a bare "24 h". A run's Runs, Detected and Responded are all counted in
// the hour it was queued, so runs >= detected >= responded holds in every window.
type Window struct {
	Since        time.Time `json:"since"`
	Runs         int       `json:"runs"`
	Detected     int       `json:"detected"`
	Responded    int       `json:"responded"`
	FalcoAlerts  int       `json:"falco_alerts"`
	TalonActions int       `json:"talon_actions"`
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
	RespCount       int // responses recorded, so RespMin is valid even when the min is 0
	RespMin         int64
	RespMax         int64
	RespSamples     []int64
	SurvivalSamples []int64
	// The hourly window (ADR 0035): at most windowHours buckets (plus one hour of clock slack after a
	// load), oldest first, pruned on every write. WindowSince is when this window's counting began;
	// LastRunAt is the queued time of the newest run.
	Hourly      []HourBucket
	WindowSince time.Time
	LastRunAt   time.Time
}

// HourBucket is one hour of the window. H is the hour as a Unix timestamp divided by 3600.
type HourBucket struct {
	H         int64
	Runs      int
	Detected  int
	Responded int
	Alerts    int
	Actions   int
}

// windowHours is the window's length in buckets: the current hour and the 23 before it.
const windowHours = 24

// maxHourly is the most buckets a persisted window may carry: windowHours plus the next hour, which
// a pod whose clock runs slightly ahead may have written.
const maxHourly = windowHours + 1

func newAgg(now time.Time) *agg {
	return &agg{Since: now, WindowSince: now, ByScenario: map[string]*ScenarioStat{},
		Commands: map[string]*CommandStat{}, Objectives: map[string]*ObjectiveStat{}}
}

func unixHour(t time.Time) int64 { return t.Unix() / 3600 }

// maxEndedTracked bounds the set of finished run ids kept to reject late events (ADR 0030).
const maxEndedTracked = 512

// Collector accumulates the counters. Safe for concurrent use: Record is called from the hub (one
// goroutine, under the hub lock) and Snapshot/Marshal from request and persistence goroutines.
type Collector struct {
	scenarios *scenarios.Store
	now       func() time.Time

	mu        sync.Mutex
	a         *agg
	active    map[string]*runState // by run id
	ended     map[string]bool      // finished run ids, so a late event cannot resurrect a run
	endedRing []string
	dirty     bool
}

// runState is the in-flight view of one run, discarded when the run ends. The scenario is resolved
// once, when the run is first seen, so Record does no catalogue I/O under the hub lock per event.
type runState struct {
	scenario    string
	sc          scenarios.Scenario
	interactive bool
	start       time.Time
	// hour is the window bucket of the run (ADR 0035): the hour of its queued event, or of the moment
	// it was recorded when that event carries no time. Detected and Responded go to this bucket too.
	hour int64
	// detectedAt is when each command of the run was first detected, keyed by command_seq (0: a
	// scripted run, or a terminal detection or response tied to no command); a response is measured
	// only against the detection of the same key. answered marks the keys a response was seen for.
	// Both are bounded by the commands a run accepts.
	detectedAt map[int]time.Time
	answered   map[int]bool
	detected   bool
	responded  bool
	// respPending: a response came before any detection (a terminal run's Talon-first path publishes
	// `responded` first). Its window count waits for the detection, so a window never holds a response
	// without its detection.
	respPending  bool
	counted      bool            // counted into Runs/ByScenario already
	objAttempted map[string]bool // objectives this run has tried (counted once per run)
	objAchieved  map[string]bool // objectives this run has reached (counted once per run)
}

// New returns a collector. sc is used to look up a scenario's interactive flag, command outcomes
// and objectives from an event that carries only ids; now may be nil (time.Now).
func New(sc *scenarios.Store, now func() time.Time) *Collector {
	if now == nil {
		now = time.Now
	}
	return &Collector{scenarios: sc, now: now, a: newAgg(now().UTC()),
		active: map[string]*runState{}, ended: map[string]bool{}}
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
		RunID      string    `json:"run_id"`
		Scenario   string    `json:"scenario"`
		State      string    `json:"state"`
		Detail     string    `json:"detail"`
		At         time.Time `json:"at"`
		CommandSeq int       `json:"command_seq"`
	}
	if json.Unmarshal(data, &e) != nil || e.RunID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	rs := c.active[e.RunID]
	if rs == nil {
		if c.ended[e.RunID] {
			return // a late event for a run that already finished: do not resurrect it
		}
		sc, _ := c.scenarios.Get(e.Scenario) // one lookup per run, not per event
		rs = &runState{scenario: e.Scenario, sc: sc, interactive: sc.Interactive, start: e.At,
			detectedAt: map[int]time.Time{}, answered: map[int]bool{},
			objAttempted: map[string]bool{}, objAchieved: map[string]bool{}}
		c.active[e.RunID] = rs
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
			// No time, or one ahead of this clock (a skewed publisher), is "now": a future hour would sit
			// outside the window until it arrives, and a future last run would read as one to come.
			at, now := e.At, c.now()
			if at.IsZero() || at.After(now) {
				at = now
			}
			at = at.UTC()
			rs.hour = unixHour(at)
			if at.After(c.a.LastRunAt) {
				c.a.LastRunAt = at
			}
			c.addHourLocked(rs.hour, func(b *HourBucket) { b.Runs++ })
			c.dirty = true
		}
	case "detected":
		if _, seen := rs.detectedAt[e.CommandSeq]; !seen {
			rs.detectedAt[e.CommandSeq] = e.At
		}
		if !rs.detected {
			rs.detected = true
			c.scenarioStat(rs.scenario).Detected++
			// In the run's own hour, not this event's: a run queued at 10:59:59 and detected at
			// 11:00:01 is one run and one detection of the 10:00 hour. A run never seen queued is
			// not in any hour's Runs, so it adds no detection to one either.
			if rs.counted {
				pending := rs.respPending
				rs.respPending = false
				c.addHourLocked(rs.hour, func(b *HourBucket) {
					b.Detected++
					if pending {
						b.Responded++
					}
				})
			}
			c.dirty = true
		}
	case "responded":
		if !rs.responded {
			rs.responded = true
			c.scenarioStat(rs.scenario).Responded++
			switch {
			case !rs.counted:
			case rs.detected:
				c.addHourLocked(rs.hour, func(b *HourBucket) { b.Responded++ })
			default:
				// Talon first: counted with the detection when it arrives. A run that ends without one
				// adds no response to the window (its action is still in the window's actions).
				rs.respPending = true
			}
			c.dirty = true
		}
		// The latency is the response to *this* detection: the one with the same command_seq (a
		// terminal run may detect several commands, and an unanswered one at 2 s followed by a
		// response to another at 102 s is not a 100 s response). No detection with that key - the
		// response could not be tied to one - and nothing is recorded.
		if !rs.answered[e.CommandSeq] {
			rs.answered[e.CommandSeq] = true
			if at, ok := rs.detectedAt[e.CommandSeq]; ok && !e.At.Before(at) {
				c.addResponse(e.At.Sub(at).Milliseconds())
				c.dirty = true
			}
		}
	case "finished", "failed", "timeout":
		c.finishLocked(e.RunID, rs, e.State, e.Detail, e.At)
	}
}

func (c *Collector) finishLocked(runID string, rs *runState, state, detail string, at time.Time) {
	// Unanswered is the honest "the defence missed it": detected, and no response before the
	// scenario's time ran out. A run that ended because the visitor left, went idle, was killed, or
	// the API shut down is not an escape (ADR 0030). A scripted run that ran out ends `timeout`; a
	// terminal run never does - it ends `finished` with detail `deadline` - and is unanswered when one
	// of its detections got no response by then. Responses and detections are matched by command_seq
	// only: the runner already pairs a response with the detection it answers and publishes it under
	// that seq, so a response tied to no command (seq 0) answers the detection tied to no command,
	// not any other - one published that way met no unanswered detection of its kind in the runner.
	switch {
	case state == "timeout" && rs.detected && !rs.responded:
		c.a.Unanswered++
	case rs.interactive && state == "finished" && detail == "deadline":
		for seq := range rs.detectedAt {
			if !rs.answered[seq] {
				c.a.Unanswered++
				break
			}
		}
	}
	if rs.interactive {
		if n := len(rs.objAchieved); n > c.a.BestObjectives {
			c.a.BestObjectives = n
		}
		if !at.Before(rs.start) {
			c.addSurvival(int64(at.Sub(rs.start).Seconds()))
		}
	}
	c.dirty = true
	delete(c.active, runID)
	c.markEndedLocked(runID)
}

func (c *Collector) markEndedLocked(id string) {
	if c.ended[id] {
		return
	}
	c.ended[id] = true
	c.endedRing = append(c.endedRing, id)
	if len(c.endedRing) > maxEndedTracked {
		delete(c.ended, c.endedRing[0])
		c.endedRing = c.endedRing[1:]
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
	cmd, ok := rs.sc.CommandByID(e.ID)
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
		// Objective attempts are per run, not per keystroke: "tried by X of N runs" (ADR 0030).
		if cmd.Objective != "" && !rs.objAttempted[cmd.Objective] {
			rs.objAttempted[cmd.Objective] = true
			c.objectiveStat(cmd.Objective).Attempts++
		}
		c.dirty = true
	case "exited":
		if e.Achieved && cmd.Objective != "" && !rs.objAchieved[cmd.Objective] {
			rs.objAchieved[cmd.Objective] = true
			c.objectiveStat(cmd.Objective).Achieved++
			c.dirty = true
		}
	}
}

// addHourLocked applies fn to the bucket of hour h, creating it, after pruning the hours that have
// left the window. An hour already out of the window (a run that outlived it) is not recreated.
func (c *Collector) addHourLocked(h int64, fn func(*HourBucket)) {
	nowH := unixHour(c.now())
	c.pruneLocked(nowH)
	if h < nowH-(windowHours-1) {
		return
	}
	i := sort.Search(len(c.a.Hourly), func(i int) bool { return c.a.Hourly[i].H >= h })
	if i == len(c.a.Hourly) || c.a.Hourly[i].H != h {
		c.a.Hourly = append(c.a.Hourly, HourBucket{})
		copy(c.a.Hourly[i+1:], c.a.Hourly[i:])
		c.a.Hourly[i] = HourBucket{H: h}
	}
	fn(&c.a.Hourly[i])
}

// pruneLocked drops the buckets older than the window ending in hour nowH.
func (c *Collector) pruneLocked(nowH int64) {
	oldest := nowH - (windowHours - 1)
	n := 0
	for n < len(c.a.Hourly) && c.a.Hourly[n].H < oldest {
		n++
	}
	if n > 0 {
		c.a.Hourly = append(c.a.Hourly[:0], c.a.Hourly[n:]...)
	}
}

// windowLocked sums the buckets of the window ending now and says where it starts.
func (c *Collector) windowLocked() Window {
	now := c.now().UTC()
	nowH := unixHour(now)
	oldest := nowH - (windowHours - 1)
	w := Window{Since: time.Unix(oldest*3600, 0).UTC()}
	if c.a.WindowSince.After(w.Since) {
		w.Since = c.a.WindowSince
	}
	for _, b := range c.a.Hourly {
		if b.H < oldest || b.H > nowH {
			continue
		}
		w.Runs += b.Runs
		w.Detected += b.Detected
		w.Responded += b.Responded
		w.FalcoAlerts += b.Alerts
		w.TalonActions += b.Actions
	}
	return w
}

// Since24h is where the hourly window starts now: posture's falco.counted_since, the same value as
// /api/stats last_24h.since (ADR 0035).
func (c *Collector) Since24h() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.windowLocked().Since
}

// WindowCounter counts one kind of webhook delivery (Falco alerts or Talon actions) into the hourly
// window, by the time it arrives. It is what the server's webhook handlers Add to and what posture's
// alerts_24h/actions_24h Count (ADR 0035), so both read the persisted buckets the hero reads.
type WindowCounter struct {
	c      *Collector
	action bool // Talon actions; Falco alerts otherwise
}

// AlertCounter counts Falco alerts (every namespace, as delivered).
func (c *Collector) AlertCounter() WindowCounter { return WindowCounter{c: c} }

// ActionCounter counts Talon actions (every notification, as delivered).
func (c *Collector) ActionCounter() WindowCounter { return WindowCounter{c: c, action: true} }

// Add counts one delivery now.
func (w WindowCounter) Add() {
	c := w.c
	c.mu.Lock()
	defer c.mu.Unlock()
	c.addHourLocked(unixHour(c.now()), func(b *HourBucket) {
		if w.action {
			b.Actions++
		} else {
			b.Alerts++
		}
	})
	c.dirty = true
}

// Count is the number of deliveries in the window ending now.
func (w WindowCounter) Count() int {
	w.c.mu.Lock()
	defer w.c.mu.Unlock()
	win := w.c.windowLocked()
	if w.action {
		return win.TalonActions
	}
	return win.FalcoAlerts
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
	if !c.a.LastRunAt.IsZero() {
		at := c.a.LastRunAt
		s.LastRunAt = &at
	}
	s.Last24h = c.windowLocked()
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

func (c *Collector) addResponse(ms int64) {
	if ms < 0 {
		ms = 0
	}
	c.a.RespLast = ms
	if c.a.RespCount == 0 || ms < c.a.RespMin { // RespCount, not "min == 0": a 0 ms response is real
		c.a.RespMin = ms
	}
	if ms > c.a.RespMax {
		c.a.RespMax = ms
	}
	c.a.RespCount++
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

// Marshal serialises the aggregate counters for the ConfigMap. Only aggregates are written - the
// active runs and the ended-id ring are in-flight state, not persisted.
func (c *Collector) Marshal() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return json.Marshal(c.a)
}

// Load adds the counters from a previous Marshal to what this collector has counted so far. At
// start-up that is nothing, so the persisted totals are installed as they are; when the first read
// only succeeds later (configmap.go retries it), the runs counted in the meantime are kept on top of
// the persisted totals rather than overwritten. A blank or unparseable or invalid blob changes
// nothing and returns an error for the caller to log - a corrupted ConfigMap must not panic or
// poison the counters. The persisted since timestamp is kept so the page can say how long the
// totals have been collected.
func (c *Collector) Load(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	var a agg
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	if err := validateAgg(&a, c.now()); err != nil {
		return err // keep the zero counters; do not install a bad aggregate
	}
	if a.Since.IsZero() {
		a.Since = c.now().UTC()
	}
	// A blob from before the hourly window (ADR 0035) has none: its window starts now, and the page
	// says "since" that time instead of passing off a few hours as a day.
	if a.WindowSince.IsZero() {
		a.WindowSince = c.now().UTC()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.a = mergeAgg(&a, c.a)
	return nil
}

// mergeAgg returns the persisted aggregate p with cur - counted since start-up, so more recent - added
// to it: counters summed, the best kept, the latency extremes combined, cur's samples appended
// after p's within the ring caps, the hourly buckets summed hour by hour, the earliest window start
// and the latest run time kept.
func mergeAgg(p, cur *agg) *agg {
	if cur.Since.Before(p.Since) {
		p.Since = cur.Since
	}
	if p.WindowSince.IsZero() || (!cur.WindowSince.IsZero() && cur.WindowSince.Before(p.WindowSince)) {
		p.WindowSince = cur.WindowSince
	}
	if cur.LastRunAt.After(p.LastRunAt) {
		p.LastRunAt = cur.LastRunAt
	}
	p.Hourly = sumHours(append(p.Hourly, cur.Hourly...))
	p.Runs += cur.Runs
	p.Unanswered += cur.Unanswered
	p.TerminalRuns += cur.TerminalRuns
	p.BestObjectives = max(p.BestObjectives, cur.BestObjectives)
	for k, v := range cur.ByScenario {
		if o := p.ByScenario[k]; o != nil {
			v = &ScenarioStat{Runs: o.Runs + v.Runs, Detected: o.Detected + v.Detected, Responded: o.Responded + v.Responded}
		}
		p.ByScenario[k] = v
	}
	for k, v := range cur.Commands {
		if o := p.Commands[k]; o != nil {
			v = &CommandStat{Attempts: o.Attempts + v.Attempts, Allowed: o.Allowed + v.Allowed,
				Prevented: o.Prevented + v.Prevented, Detected: o.Detected + v.Detected}
		}
		p.Commands[k] = v
	}
	for k, v := range cur.Objectives {
		if o := p.Objectives[k]; o != nil {
			v = &ObjectiveStat{Attempts: o.Attempts + v.Attempts, Achieved: o.Achieved + v.Achieved}
		}
		p.Objectives[k] = v
	}
	if cur.RespCount > 0 {
		if p.RespCount == 0 || cur.RespMin < p.RespMin {
			p.RespMin = cur.RespMin
		}
		p.RespMax = max(p.RespMax, cur.RespMax)
		p.RespLast = cur.RespLast
		p.RespCount += cur.RespCount
	}
	for _, v := range cur.RespSamples {
		p.RespSamples = appendCapped(p.RespSamples, v, maxResponseSamples)
	}
	for _, v := range cur.SurvivalSamples {
		p.SurvivalSamples = appendCapped(p.SurvivalSamples, v, maxSurvivalSamples)
	}
	return p
}

// sumHours merges buckets of the same hour (their counts added) and sorts them oldest first.
func sumHours(bs []HourBucket) []HourBucket {
	byH := map[int64]int{} // hour -> index in out
	out := make([]HourBucket, 0, len(bs))
	for _, b := range bs {
		if i, ok := byH[b.H]; ok {
			o := &out[i]
			o.Runs += b.Runs
			o.Detected += b.Detected
			o.Responded += b.Responded
			o.Alerts += b.Alerts
			o.Actions += b.Actions
			continue
		}
		byH[b.H] = len(out)
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].H < out[j].H })
	return out
}

// maxCounter bounds every persisted counter and latency. No real total comes near it (it is a
// trillion), and a blob carrying more is nonsense: a counter at MaxInt64 would overflow on the next
// increment and make the next load reject the blob and start everything over.
const maxCounter = 1 << 40

// validateAgg rejects a persisted aggregate that would break Snapshot or carry nonsense: a nil map
// value (Snapshot dereferences it), a counter, latency or sample that is negative or past maxCounter,
// a sample array past its cap, a `since` in the future, a best-objectives count no run could reach,
// or a min above the max. A blob written before RespCount existed has it at 0 although it has
// samples: the count is derived from them, so the old min is still a min (an old min of 200 and a
// later 900 ms response give 200, not 900).
//
// The hourly window (ADR 0035) is sanitised rather than rejected, because losing a day's buckets is
// no reason to lose the all-time totals beside them: buckets outside [now-23 h, now+1 h] are dropped,
// buckets of the same hour summed, and a window start or last run time in the future clamped to now.
// A window no writer produces - a count that is negative or past maxCounter (also after same-hour
// buckets are summed), or more than maxHourly buckets after the merge - is discarded as a whole and
// restarts now, and the all-time totals still load: only a malformed all-time section rejects the
// blob. A blob from before the window has none of these fields and loads unchanged.
func validateAgg(a *agg, now time.Time) error {
	if a.ByScenario == nil {
		a.ByScenario = map[string]*ScenarioStat{}
	}
	if a.Commands == nil {
		a.Commands = map[string]*CommandStat{}
	}
	if a.Objectives == nil {
		a.Objectives = map[string]*ObjectiveStat{}
	}
	ok := func(vs ...int64) bool {
		for _, v := range vs {
			if v < 0 || v > maxCounter {
				return false
			}
		}
		return true
	}
	for k, v := range a.ByScenario {
		if v == nil {
			return fmt.Errorf("by_scenario[%q] is null", k)
		}
		if !ok(int64(v.Runs), int64(v.Detected), int64(v.Responded)) {
			return fmt.Errorf("by_scenario[%q] has a counter out of range", k)
		}
	}
	for k, v := range a.Commands {
		if v == nil {
			return fmt.Errorf("commands[%q] is null", k)
		}
		if !ok(int64(v.Attempts), int64(v.Allowed), int64(v.Prevented), int64(v.Detected)) {
			return fmt.Errorf("commands[%q] has a counter out of range", k)
		}
	}
	for k, v := range a.Objectives {
		if v == nil {
			return fmt.Errorf("objectives[%q] is null", k)
		}
		if !ok(int64(v.Attempts), int64(v.Achieved)) {
			return fmt.Errorf("objectives[%q] has a counter out of range", k)
		}
	}
	if !ok(int64(a.Runs), int64(a.Unanswered), int64(a.TerminalRuns), int64(a.BestObjectives), int64(a.RespCount),
		a.RespLast, a.RespMin, a.RespMax) {
		return fmt.Errorf("a top-level counter or latency is out of range")
	}
	if len(a.RespSamples) > maxResponseSamples || len(a.SurvivalSamples) > maxSurvivalSamples {
		return fmt.Errorf("a sample array is over its cap")
	}
	if !ok(a.RespSamples...) || !ok(a.SurvivalSamples...) {
		return fmt.Errorf("a sample is out of range")
	}
	// An hour of slack for the clock of the pod that wrote it; a year-9999 since is not a clock skew.
	if a.Since.After(now.Add(time.Hour)) {
		return fmt.Errorf("since %s is in the future", a.Since.Format(time.RFC3339))
	}
	// Each objective is reached by a command, and a run cannot run more distinct catalogue commands
	// than the catalogue has; and no terminal run, no best.
	if a.BestObjectives > scenarios.MaxCommands || (a.BestObjectives > 0 && a.TerminalRuns == 0) {
		return fmt.Errorf("best_objectives %d is not reachable", a.BestObjectives)
	}
	if sanitiseWindow(a, now, ok) != nil {
		a.Hourly, a.WindowSince = nil, now.UTC()
	}
	if a.WindowSince.After(now) {
		a.WindowSince = now.UTC()
	}
	if a.LastRunAt.After(now) {
		a.LastRunAt = now.UTC()
	}
	if a.RespCount < len(a.RespSamples) {
		a.RespCount = len(a.RespSamples)
	}
	if a.RespCount > 0 && a.RespMin > a.RespMax {
		return fmt.Errorf("response min %d is above max %d", a.RespMin, a.RespMax)
	}
	return nil
}

// sanitiseWindow drops and merges a's buckets in place, or says the window is malformed (the caller
// then discards it).
func sanitiseWindow(a *agg, now time.Time, ok func(...int64) bool) error {
	nowH := unixHour(now)
	kept := a.Hourly[:0:0]
	for _, b := range a.Hourly {
		if !ok(int64(b.Runs), int64(b.Detected), int64(b.Responded), int64(b.Alerts), int64(b.Actions)) {
			return fmt.Errorf("hourly bucket %d has a counter out of range", b.H)
		}
		if b.H < nowH-(windowHours-1) || b.H > nowH+1 {
			continue
		}
		kept = append(kept, b)
	}
	a.Hourly = sumHours(kept)
	// After the merge the range filter above allows at most maxHourly distinct hours; the bound is the
	// contract's backstop should that filter ever be widened.
	if len(a.Hourly) > maxHourly {
		return fmt.Errorf("%d hourly buckets in range, at most %d", len(a.Hourly), maxHourly)
	}
	for _, b := range a.Hourly {
		if !ok(int64(b.Runs), int64(b.Detected), int64(b.Responded), int64(b.Alerts), int64(b.Actions)) {
			return fmt.Errorf("hourly bucket %d has a counter out of range", b.H)
		}
	}
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

// markDirty re-sets the dirty flag, used to re-queue a write that failed so it is retried on the
// next tick instead of lost (ADR 0030).
func (c *Collector) markDirty() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dirty = true
}
