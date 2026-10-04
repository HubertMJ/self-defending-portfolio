// Package siemlog writes the API's run and command events as slog lines for the SIEM (ADR 0034,
// "Ingest from k3s01: files only"). Fluent Bit tails the API container's stdout on k3s01 and ships
// only the lines whose `msg` is `siem.run` or `siem.command` to the `sdp-api` data stream, where the
// rules see a terminal command next to the Falco, Talon and Hubble evidence about the same pod.
//
// The lines are built field by field from a fixed allow-list (siem/fields/api.yaml), never by
// forwarding an event:
//
//	siem.run      run_id, scenario, state, arm, pod_ref, command_seq, at        (every run state)
//	siem.command  run_id, seq, command_id, state, exit_code, achieved,
//	              technique, objective, outcome, pod_ref, at                    (started|exited|killed)
//
// `output` command events are skipped entirely and the decoder has no field for their text, so a
// command's output - the run's flag after `read-flag` - never reaches a line (ADR 0017, ADR 0021).
// Nothing a visitor sends is in an event: no client IP, no token. A value that is not a short
// identifier (letters, digits, `.`, `_`, `-`) is written empty: Security Analytics never matches a
// value with a space (siem contract S0-#4), and free text has no business in these lines.
//
// pod_ref is `<namespace>_<pod>` (S0-#1: `/` breaks SA's correlation query, and `_` occurs in no
// namespace or pod name, so the API can split it back for publication), null while unknown. A
// compare run (ADR 0031) writes its states with arm `guarded`, and `started` and its final state
// once more with arm `unguarded` and the twin's ref in the unguarded namespace, so the twin's pod is
// tied to the run.
//
// Record runs inside the hub's tap, under the hub lock, so it never blocks: events go into a buffered
// channel drained by Run, and when the channel is full they are dropped and counted; the count is
// logged once a minute. The SIEM is evidence, not the demo (ADR 0034 "Degradation").
package siemlog

import (
	"context"
	"encoding/json"
	"log/slog"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/events"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/runner"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/scenarios"
)

// Line messages: the only two Fluent Bit keeps from the API's stdout.
const (
	MsgRun     = "siem.run"
	MsgCommand = "siem.command"
)

// Defaults: the channel between the hub and the writer, and how often drops are reported.
const (
	DefaultBuffer     = 1024
	DefaultDropReport = time.Minute
	// maxRuns bounds the run id -> pod map: entries go at the run's final state, so it holds the one
	// run in progress; the cap only matters if a final state was dropped.
	maxRuns = 64
)

// identifier is the shape every written string value must have; anything else is written empty.
var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

// Catalogue gives a command's technique, objective and outcome (*scenarios.Store).
type Catalogue interface {
	Get(id string) (scenarios.Scenario, bool)
}

// Config wires the recorder; Log is where the lines go (the API's stdout JSON logger).
type Config struct {
	Log                *slog.Logger
	Catalogue          Catalogue
	Namespace          string
	UnguardedNamespace string
	Buffer             int
	DropReport         time.Duration
}

// Recorder is safe for concurrent use: Record from the hub tap, Run in one goroutine.
type Recorder struct {
	cfg     Config
	ch      chan events.Event
	dropped atomic.Uint64
	// runs is touched by Run's goroutine only.
	runs map[string]runInfo
}

// runInfo is what a command event lacks and its run's events said: the scenario (for the catalogue
// lookup) and the pods.
type runInfo struct {
	scenario string
	pod      string
	twin     string
}

// New returns a recorder; nothing is written until Run is started.
func New(cfg Config) *Recorder {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Buffer <= 0 {
		cfg.Buffer = DefaultBuffer
	}
	if cfg.DropReport <= 0 {
		cfg.DropReport = DefaultDropReport
	}
	return &Recorder{cfg: cfg, ch: make(chan events.Event, cfg.Buffer), runs: map[string]runInfo{}}
}

// Record queues a run or command event and returns at once; other event types are ignored. A full
// queue drops the event and counts it.
func (r *Recorder) Record(ev events.Event) {
	if ev.Type != "run" && ev.Type != "command" {
		return
	}
	select {
	case r.ch <- ev:
	default:
		r.dropped.Add(1)
	}
}

// Dropped is the number of events dropped since start.
func (r *Recorder) Dropped() uint64 { return r.dropped.Load() }

// Run writes the queued events until ctx ends, then writes what is still queued and returns. Give it
// a context that ends after the runner's shutdown, so the runs' final states are written too.
func (r *Recorder) Run(ctx context.Context) {
	t := time.NewTicker(r.cfg.DropReport)
	defer t.Stop()
	var reported uint64
	report := func() {
		if n := r.dropped.Load(); n > reported {
			r.cfg.Log.Warn("siem events dropped", "dropped", n-reported, "dropped_total", n)
			reported = n
		}
	}
	for {
		select {
		case ev := <-r.ch:
			r.write(ev)
		case <-t.C:
			report()
		case <-ctx.Done():
			for {
				select {
				case ev := <-r.ch:
					r.write(ev)
				default:
					report()
					return
				}
			}
		}
	}
}

// runEvent and commandEvent decode only the fields a line may carry; in particular commandEvent has
// no field for an output chunk.
type runEvent struct {
	RunID      string            `json:"run_id"`
	Scenario   string            `json:"scenario"`
	State      string            `json:"state"`
	At         time.Time         `json:"at"`
	Pod        string            `json:"pod"`
	Pods       map[string]string `json:"pods"`
	CommandSeq int               `json:"command_seq"`
}

type commandEvent struct {
	RunID    string    `json:"run_id"`
	Seq      int       `json:"seq"`
	ID       string    `json:"id"`
	State    string    `json:"state"`
	At       time.Time `json:"at"`
	ExitCode *int      `json:"exit_code"`
	Achieved bool      `json:"achieved"`
	Arm      string    `json:"arm"`
}

var runStates = map[string]bool{
	runner.StateQueued: true, runner.StateStarted: true, runner.StatePodReady: true, runner.StateDetected: true,
	runner.StateResponded: true, runner.StateFinished: true, runner.StateFailed: true, runner.StateTimeout: true,
}

var finalStates = map[string]bool{runner.StateFinished: true, runner.StateFailed: true, runner.StateTimeout: true}

var commandStates = map[string]bool{runner.CommandStarted: true, runner.CommandExited: true, runner.CommandKilled: true}

func (r *Recorder) write(ev events.Event) {
	switch ev.Type {
	case "run":
		var e runEvent
		if json.Unmarshal(ev.Data, &e) != nil || !runStates[e.State] || !identifier.MatchString(e.RunID) {
			return
		}
		r.writeRun(e)
	case "command":
		var e commandEvent
		if json.Unmarshal(ev.Data, &e) != nil || !commandStates[e.State] || !identifier.MatchString(e.RunID) {
			return
		}
		r.writeCommand(e)
	}
}

func (r *Recorder) writeRun(e runEvent) {
	info, known := r.runs[e.RunID]
	if !known && len(r.runs) >= maxRuns {
		for id := range r.runs {
			delete(r.runs, id)
			break
		}
	}
	info.scenario = e.Scenario
	// The guarded pod is named from `started` on; before that the run has no pod to refer to. The
	// twin's name is in Pods from `queued` on and kept whenever present, so a compare run that fails
	// before its guarded pod shows still ties the twin, which may exist, to the run.
	if e.Pod != "" {
		info.pod = e.Pod
	}
	if twin := e.Pods["unguarded"]; twin != "" {
		info.twin = twin
	}
	if finalStates[e.State] {
		delete(r.runs, e.RunID)
	} else {
		r.runs[e.RunID] = info
	}

	if len(e.Pods) == 0 {
		r.runLine(e, "", r.podRef(r.cfg.Namespace, info.pod))
		return
	}
	r.runLine(e, "guarded", r.podRef(r.cfg.Namespace, info.pod))
	// The run's states are the guarded arm's (ADR 0031); only `started` (both pods are created
	// together) and the final state (published once both pods are gone) are true of the twin too.
	if e.State == runner.StateStarted || finalStates[e.State] {
		r.runLine(e, "unguarded", r.podRef(r.cfg.UnguardedNamespace, info.twin))
	}
}

func (r *Recorder) runLine(e runEvent, arm string, podRef any) {
	r.cfg.Log.LogAttrs(context.Background(), slog.LevelInfo, MsgRun,
		slog.String("run_id", e.RunID),
		slog.String("scenario", clean(e.Scenario)),
		slog.String("state", e.State),
		slog.String("arm", arm),
		slog.Any("pod_ref", podRef),
		slog.Any("command_seq", optional(e.CommandSeq)),
		slog.Time("at", e.At.UTC()),
	)
}

func (r *Recorder) writeCommand(e commandEvent) {
	info := r.runs[e.RunID]
	ns, pod := r.cfg.Namespace, info.pod
	if e.Arm == "unguarded" {
		ns, pod = r.cfg.UnguardedNamespace, info.twin
	}
	var cmd scenarios.Command
	if r.cfg.Catalogue != nil {
		if sc, ok := r.cfg.Catalogue.Get(info.scenario); ok {
			cmd, _ = sc.CommandByID(e.ID)
		}
	}
	var exit any
	if e.ExitCode != nil {
		exit = *e.ExitCode
	}
	r.cfg.Log.LogAttrs(context.Background(), slog.LevelInfo, MsgCommand,
		slog.String("run_id", e.RunID),
		slog.Int("seq", e.Seq),
		slog.String("command_id", clean(e.ID)),
		slog.String("state", e.State),
		slog.Any("exit_code", exit),
		slog.Bool("achieved", e.Achieved),
		slog.String("technique", clean(cmd.Technique)),
		slog.String("objective", clean(cmd.Objective)),
		slog.String("outcome", clean(cmd.Outcome)),
		slog.Any("pod_ref", r.podRef(ns, pod)),
		slog.Time("at", e.At.UTC()),
	)
}

// podRef is `<ns>_<pod>`, or null when either part is unknown or could make the split ambiguous:
// an absent ref is not indexed, where an empty string would be a value a query could match.
func (r *Recorder) podRef(ns, pod string) any {
	if !identifier.MatchString(ns) || !identifier.MatchString(pod) || strings.Contains(ns+pod, "_") {
		return nil
	}
	return ns + "_" + pod
}

func clean(s string) string {
	if !identifier.MatchString(s) {
		return ""
	}
	return s
}

// optional is n, or null for 0 (command sequence numbers start at 1).
func optional(n int) any {
	if n == 0 {
		return nil
	}
	return n
}
