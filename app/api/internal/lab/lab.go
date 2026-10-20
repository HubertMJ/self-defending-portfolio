// Package lab serves GET /api/lab/latest (ADR 0034 amendment 2026-10-18): the newest detection-lab
// run document from the `lab-runs` index - an isolated-VM run (variant B) when there is one, else the
// newest of any mode - with the last runs of its mode as a short history; and, from the lab's own
// stream `sdp-lab`, GET /api/lab/vm (the lab VM's state, derived from the run's lifecycle markers
// only) and GET /api/lab/raw (the newest VM run's records). All read-only, through the same
// internal/siem client the incidents tracker uses - never a cluster data stream.
//
// The lab's validator already sanitises every run document (no real host names, addresses or user
// names) and bounds it to 64 KiB before it is written to lab-runs. This package re-does that
// discipline as defence in depth: it projects the document into a fixed LabReplay shape through an
// allow-list of fields in code, drops anything unexpected (at the top level, inside each variant,
// and inside each event), and refuses a document over a size cap. A visitor's request is answered
// from a short in-process cache, so repeated hits do not query OpenSearch every time; the queries run
// detached from the visitor's request, and a failed one keeps the previous answer.
package lab

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/siem"
)

// Source is what this package needs from internal/siem: one bounded search of lab-runs or sdp-lab.
type Source interface {
	Search(ctx context.Context, indices []string, q siem.Query) (siem.SearchResult, error)
}

const (
	// defaultTTL is how long one fetched answer (a run, or "no run yet") is served before OpenSearch
	// is queried again: short enough that a fresh run shows within a few seconds, long enough that a
	// burst of requests makes at most one query.
	defaultTTL = 10 * time.Second
	// defaultLookback bounds the search's time range (siem.Query needs one, at most 31 days). A run is
	// expected daily, so 30 days finds the newest while staying inside the client's bound; a run older
	// than this is treated as none and the page falls back to its bundled sample.
	defaultLookback = 30 * 24 * time.Hour
	// failTTL is how long a failed fetch with no previous answer to fall back on is remembered: long
	// enough that an OpenSearch outage costs one query per answer every few seconds, short enough
	// that recovery shows at once.
	failTTL = 2 * time.Second
	// fetchTimeout bounds one fetch (up to three searches, each bounded by the client's own timeout).
	fetchTimeout = 8 * time.Second
	// defaultPreferVM is how recent an isolated-VM run must be for GET /api/lab/latest to prefer it
	// over a newer generated run: a VM run is daily, so one older than three days means variant B has
	// stopped, and the page shows the generated run instead of an ever older VM run.
	defaultPreferVM = 3 * 24 * time.Hour
	// maxDoc rejects an oversized _source outright (the validator caps a run at 64 KiB; this leaves
	// headroom and is the backstop if that cap were ever bypassed).
	maxDoc = 128 << 10
	// historySize is how many runs of the served run's mode the history lists (a week of daily runs).
	historySize = 7
	// modeVM is lab.mode / run.mode of an isolated-VM run (variant B).
	modeVM = "isolated-vm"
)

// source lists exactly the top-level fields the response may carry: a first allow-list enforced by
// OpenSearch's _source filtering, re-checked here by decoding into the typed Replay.
var source = []string{"schema", "sample", "run", "scenario", "artefact", "beacon", "risk_threshold",
	"rules", "variants", "lifecycle", "incident", "techniques", "counters"}

// eventFields is the allow-list of keys an event may keep (the data contract's sdp-lab fields that
// survive sanitisation). Anything else in an event is dropped.
var eventFields = map[string]bool{
	"@timestamp": true, "event.code": true, "event.action": true, "host.name": true,
	"process.name": true, "process.executable": true, "process.hash.sha256": true,
	"process.parent.name": true, "registry.path": true, "file.path": true,
	"destination.ip": true, "destination.port": true,
	// Variant B: the second from the run's start, and the pid/ppid the page's evidence shows.
	"offset_s": true, "process.pid": true, "process.parent.pid": true,
}

// Config wires a Reader. Zero values take the defaults; Source nil means the lab is unavailable and
// Latest, VM and Raw always answer false.
type Config struct {
	Source   Source
	Now      func() time.Time
	TTL      time.Duration
	Lookback time.Duration
	// DailyStart is when the scheduled VM run starts, as an offset from 00:00 UTC (GET /api/lab/vm's
	// next_run); zero takes 03:00, 24h means midnight.
	DailyStart time.Duration
	// RunningFor is how long after its newest lifecycle marker a VM run without a poweroff marker
	// still counts as running; zero takes 30 min.
	RunningFor time.Duration
	// PreferVM is how recent (by run.finished_at) an isolated-VM run must be for Latest to serve it
	// before a run of any mode; zero takes 3 days, and it never exceeds Lookback.
	PreferVM time.Duration
	// Log gets one warning per failed OpenSearch fetch; nil takes slog.Default().
	Log *slog.Logger
}

// Reader fetches, projects and caches the newest run, the VM's state and the newest VM run's records.
type Reader struct {
	src        Source
	now        func() time.Time
	ttl        time.Duration
	lookback   time.Duration
	dailyStart time.Duration
	runningFor time.Duration
	preferVM   time.Duration
	log        *slog.Logger

	latest, vm, raw cache
}

// errNoSource is Markers' answer when no SIEM source is configured.
var errNoSource = errors.New("lab: no SIEM source configured")

// fetchFunc makes one answer: its JSON, or nil when there is nothing to show. An error is an
// OpenSearch failure; with a non-nil answer it is a partial one (the history), served and logged.
type fetchFunc func(ctx context.Context) ([]byte, error)

// cache holds one fetched answer. At most one fetch per answer runs at a time, detached from the
// request that started it (its own timeout, never that visitor's cancellation), and every request
// waits for it only as long as its own context allows. A fetch that answers - even "nothing to show"
// - is served for the TTL; a failed one keeps the previous answer (stale on error) and is retried
// after failTTL.
type cache struct {
	name    string // the endpoint, for the log
	mu      sync.Mutex
	until   time.Time     // val is served without a fetch until then; zero means never fetched
	val     []byte        // the JSON answer, or nil when there is nothing to show
	pending chan struct{} // closed when the running fetch is done; nil when none runs
}

func (c *cache) get(ctx context.Context, r *Reader, fetch fetchFunc) ([]byte, bool) {
	if r.src == nil {
		return nil, false
	}
	c.mu.Lock()
	if !c.until.IsZero() && r.now().Before(c.until) {
		defer c.mu.Unlock()
		return c.val, c.val != nil
	}
	if c.pending == nil {
		c.pending = make(chan struct{})
		go c.refresh(context.WithoutCancel(ctx), r, fetch, c.pending)
	}
	wait := c.pending
	c.mu.Unlock()
	select {
	case <-wait:
	case <-ctx.Done(): // this visitor gave up; the fetch carries on for the next one
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.val, c.val != nil
}

func (c *cache) refresh(ctx context.Context, r *Reader, fetch fetchFunc, done chan struct{}) {
	defer close(done)
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	val, err := fetch(ctx)
	cancel()
	if err != nil {
		// The status says why (403 before roles.yml is applied, 5xx, 0 for a transport error); the
		// error carries the method and path or the transport's message, never a document.
		var se *siem.StatusError
		status := 0
		if errors.As(err, &se) {
			status = se.Code
		}
		r.log.Warn("lab query failed", "endpoint", c.name, "status", status, "err", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if val != nil || err == nil {
		c.val, c.until = val, r.now().Add(r.ttl)
	} else {
		c.until = r.now().Add(failTTL)
	}
	c.pending = nil
}

// New returns a Reader. A nil cfg.Source is allowed: Latest, VM and Raw then always answer false.
func New(cfg Config) *Reader {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.TTL <= 0 {
		cfg.TTL = defaultTTL
	}
	if cfg.Lookback <= 0 || cfg.Lookback > siem.MaxRange {
		cfg.Lookback = defaultLookback
	}
	if cfg.DailyStart <= 0 || cfg.DailyStart > 24*time.Hour {
		cfg.DailyStart = defaultDailyStart
	}
	if cfg.RunningFor <= 0 {
		cfg.RunningFor = defaultRunningFor
	}
	if cfg.PreferVM <= 0 {
		cfg.PreferVM = defaultPreferVM
	}
	cfg.PreferVM = min(cfg.PreferVM, cfg.Lookback)
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Reader{src: cfg.Source, now: cfg.Now, ttl: cfg.TTL, lookback: cfg.Lookback,
		dailyStart: cfg.DailyStart, runningFor: cfg.RunningFor, preferVM: cfg.PreferVM, log: cfg.Log,
		latest: cache{name: "latest"}, vm: cache{name: "vm"}, raw: cache{name: "raw"}}
}

// Enabled reports whether a SIEM source is configured.
func (r *Reader) Enabled() bool { return r.src != nil }

// Latest returns the newest run as projected JSON, or false when there is none to show (no source,
// an empty index, a query error, or a document that fails the size cap or the shape). The answer is
// cached for the TTL.
func (r *Reader) Latest(ctx context.Context) ([]byte, bool) {
	return r.latest.get(ctx, r, r.fetch)
}

// runsQuery is the fixed lab-runs search, newest by run.finished_at.
func (r *Reader) runsQuery(size int, src []string, filters ...map[string]any) siem.Query {
	now := r.now().UTC()
	return siem.Query{
		TimeField: "run.finished_at",
		Since:     now.Add(-r.lookback),
		// A small forward skew tolerates a run document whose clock is slightly ahead of the API's.
		Until:     now.Add(time.Hour),
		Filters:   filters,
		Size:      size,
		SortField: "run.finished_at",
		Source:    src,
	}
}

// fetch finds the newest isolated-VM run that finished within preferVM, or failing that the newest
// run of any mode, projects it and adds the history of its mode; nil for any no-run outcome.
func (r *Reader) fetch(ctx context.Context) ([]byte, error) {
	idx := []string{siem.LabRunsIndex}
	q := r.runsQuery(1, source, term("run.mode", modeVM))
	q.Since = r.now().UTC().Add(-r.preferVM)
	res, err := r.src.Search(ctx, idx, q)
	if err != nil {
		return nil, err
	}
	if len(res.Hits) == 0 {
		if res, err = r.src.Search(ctx, idx, r.runsQuery(1, source)); err != nil || len(res.Hits) == 0 {
			return nil, err
		}
	}
	rep := project(res.Hits[0].Source)
	if rep == nil {
		return nil, nil
	}
	rep.History, err = r.history(ctx, rep.Run.Mode)
	out, merr := json.Marshal(rep)
	if merr != nil {
		return nil, nil
	}
	return out, err
}

// history lists the newest runs of one mode, newest first; nil (omitted) when the query fails or
// finds nothing, so a history problem never hides the run itself.
func (r *Reader) history(ctx context.Context, mode string) ([]historyRun, error) {
	res, err := r.src.Search(ctx, []string{siem.LabRunsIndex},
		r.runsQuery(historySize, []string{"run", "incident"}, term("run.mode", mode)))
	if err != nil {
		return nil, err
	}
	var out []historyRun
	for _, h := range res.Hits {
		var doc struct {
			Run struct {
				ID         string   `json:"id"`
				FinishedAt string   `json:"finished_at"`
				DurationS  *float64 `json:"duration_s"`
				Complete   *bool    `json:"complete"`
			} `json:"run"`
			Incident struct {
				OpenedAtVariant *int `json:"opened_at_variant"`
			} `json:"incident"`
		}
		if !decode(h.Source, &doc) || doc.Run.ID == "" {
			continue
		}
		out = append(out, historyRun{ID: doc.Run.ID, FinishedAt: doc.Run.FinishedAt,
			DurationS: doc.Run.DurationS, Complete: doc.Run.Complete, OK: doc.Incident.OpenedAtVariant != nil})
	}
	return out, nil
}

// term is an exact-match filter on a keyword field.
func term(field, value string) map[string]any {
	return map[string]any{"term": map[string]any{field: value}}
}

// decode re-reads a hit's _source (a generic map) into a typed value; false when it does not fit.
func decode(src map[string]any, v any) bool {
	raw, err := json.Marshal(src)
	return err == nil && json.Unmarshal(raw, v) == nil
}

// Run is the run's own metadata. DurationS and Complete are variant B's: Complete is false when the
// validator timed out before the VM's poweroff or before every detection arrived.
type Run struct {
	ID         string   `json:"id"`
	Mode       string   `json:"mode"`
	StartedAt  string   `json:"started_at"`
	FinishedAt string   `json:"finished_at"`
	DurationS  *float64 `json:"duration_s,omitempty"`
	Complete   *bool    `json:"complete,omitempty"`
}

type scenario struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
}

type artefact struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type rule struct {
	ID        string  `json:"id"`
	Title     string  `json:"title"`
	Kind      string  `json:"kind"`
	Technique string  `json:"technique"`
	Score     float64 `json:"score"`
	Logic     string  `json:"logic"`
}

type finding struct {
	Rule      string   `json:"rule"`
	DelayS    float64  `json:"delay_s"`
	Only      string   `json:"only,omitempty"`
	AtOffsetS *float64 `json:"at_offset_s,omitempty"`
}

type groundTruth struct {
	Timestamp     string   `json:"@timestamp"`
	Host          string   `json:"host"`
	Techniques    []string `json:"techniques"`
	VariantSha256 string   `json:"variant_sha256"`
}

// event is one sanitised event, kept as raw values so a string stays a string and a number a number.
// Only allow-listed keys survive projection (see project).
type event map[string]json.RawMessage

type variant struct {
	N            int         `json:"n"`
	Host         string      `json:"host"`
	Sha256       string      `json:"sha256"`
	Renamed      string      `json:"renamed"`
	Events       []event     `json:"events"`
	GroundTruth  groundTruth `json:"ground_truth"`
	Findings     []finding   `json:"findings"`
	CaughtByHash bool        `json:"caught_by_hash"`
	Pid          *int        `json:"pid,omitempty"`
	Ppid         *int        `json:"ppid,omitempty"`
}

type incident struct {
	OpenedAtVariant *int     `json:"opened_at_variant"`
	DelayS          *float64 `json:"delay_s"`
	Key             string   `json:"key"`
	AtOffsetS       *float64 `json:"at_offset_s,omitempty"`
}

// marker is one step of a VM run's timeline (variant B), seconds from the rollback.
type marker struct {
	Marker  string  `json:"marker"`
	OffsetS float64 `json:"offset_s"`
	Label   string  `json:"label"`
}

type counters struct {
	Processes    int `json:"processes"`
	UniqueHashes int `json:"unique_hashes"`
	Events       int `json:"events"`
	Findings     int `json:"findings"`
	Incidents    int `json:"incidents"`
}

// historyRun is one entry of Replay.History: OK is whether the run opened its incident; Complete is
// the run's own run.complete, absent when the document has none.
type historyRun struct {
	ID         string   `json:"id"`
	FinishedAt string   `json:"finished_at"`
	DurationS  *float64 `json:"duration_s,omitempty"`
	Complete   *bool    `json:"complete,omitempty"`
	OK         bool     `json:"ok"`
}

type techniques struct {
	Expected []string `json:"expected"`
	Detected []string `json:"detected"`
}

// Replay is the fixed response shape: the LabReplay the /lab/ page consumes (schema 1), extended
// with run, incident, techniques and the per-variant findings/caught_by_hash the run document adds,
// variant B's lifecycle, counters and offsets/pids (absent from a generated run), and History - not
// part of the run document but the newest runs of its mode, newest first.
type Replay struct {
	Schema        int          `json:"schema"`
	Sample        bool         `json:"sample"`
	Run           Run          `json:"run"`
	Scenario      scenario     `json:"scenario"`
	Artefact      artefact     `json:"artefact"`
	Beacon        string       `json:"beacon"`
	RiskThreshold float64      `json:"risk_threshold"`
	Rules         []rule       `json:"rules"`
	Variants      []variant    `json:"variants"`
	Lifecycle     []marker     `json:"lifecycle,omitempty"`
	Incident      incident     `json:"incident"`
	Techniques    techniques   `json:"techniques"`
	Counters      *counters    `json:"counters,omitempty"`
	History       []historyRun `json:"history,omitempty"`
}

// project turns one hit's _source into the fixed response, or nil when it is too large, not valid
// JSON, or not a schema-1 run with at least one variant. Decoding into Replay drops every unexpected
// top-level and nested field; each event is then narrowed to the allow-listed keys. History is the
// caller's: a run document's own "history" field is dropped.
func project(src map[string]any) *Replay {
	raw, err := json.Marshal(src)
	if err != nil || len(raw) > maxDoc {
		return nil
	}
	var rep Replay
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil
	}
	if rep.Schema != 1 || len(rep.Variants) == 0 {
		return nil
	}
	rep.History = nil
	for i := range rep.Variants {
		for j, ev := range rep.Variants[i].Events {
			clean := make(event, len(ev))
			for k, v := range ev {
				if eventFields[k] {
					clean[k] = v
				}
			}
			rep.Variants[i].Events[j] = clean
		}
	}
	return &rep
}
