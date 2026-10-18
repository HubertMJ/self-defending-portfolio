// Package lab serves GET /api/lab/latest (ADR 0034 amendment 2026-10-18): the newest detection-lab
// run document from the `lab-runs` index, read-only, through the same internal/siem client the
// incidents tracker uses - never a cluster data stream.
//
// The lab's validator already sanitises every run document (no real host names, addresses or user
// names) and bounds it to 64 KiB before it is written to lab-runs. This package re-does that
// discipline as defence in depth: it projects the document into a fixed LabReplay shape through an
// allow-list of fields in code, drops anything unexpected (at the top level, inside each variant,
// and inside each event), and refuses a document over a size cap. A visitor's request is answered
// from a short in-process cache, so repeated hits do not query OpenSearch every time.
package lab

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/siem"
)

// Source is what this package needs from internal/siem: one bounded search of the lab-runs index.
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
	// maxDoc rejects an oversized _source outright (the validator caps a run at 64 KiB; this leaves
	// headroom and is the backstop if that cap were ever bypassed).
	maxDoc = 128 << 10
)

// source lists exactly the top-level fields the response may carry: a first allow-list enforced by
// OpenSearch's _source filtering, re-checked here by decoding into the typed Replay.
var source = []string{"schema", "sample", "run", "scenario", "artefact", "beacon", "risk_threshold",
	"rules", "variants", "incident", "techniques"}

// eventFields is the allow-list of keys an event may keep (the data contract's sdp-lab fields that
// survive sanitisation). Anything else in an event is dropped.
var eventFields = map[string]bool{
	"@timestamp": true, "event.code": true, "event.action": true, "host.name": true,
	"process.name": true, "process.executable": true, "process.hash.sha256": true,
	"process.parent.name": true, "registry.path": true, "file.path": true,
	"destination.ip": true, "destination.port": true,
}

// Config wires a Reader. Zero values take the defaults; Source nil means the lab is unavailable and
// Latest always answers false.
type Config struct {
	Source   Source
	Now      func() time.Time
	TTL      time.Duration
	Lookback time.Duration
}

// Reader fetches, projects and caches the newest run.
type Reader struct {
	src      Source
	now      func() time.Time
	ttl      time.Duration
	lookback time.Duration

	mu     sync.Mutex
	at     time.Time // when cached was set; zero means never fetched
	cached []byte    // the projected JSON, or nil when there is no run to show
}

// New returns a Reader. A nil cfg.Source is allowed: Latest then always answers false.
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
	return &Reader{src: cfg.Source, now: cfg.Now, ttl: cfg.TTL, lookback: cfg.Lookback}
}

// Enabled reports whether a SIEM source is configured.
func (r *Reader) Enabled() bool { return r.src != nil }

// Latest returns the newest run as projected JSON, or false when there is none to show (no source,
// an empty index, a query error, or a document that fails the size cap or the shape). The answer is
// cached for the TTL; one query at a time (the lock is held across the fetch), so a burst of
// requests makes at most one OpenSearch call.
func (r *Reader) Latest(ctx context.Context) ([]byte, bool) {
	if r.src == nil {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.at.IsZero() && r.now().Sub(r.at) < r.ttl {
		return r.cached, r.cached != nil
	}
	r.cached = r.fetch(ctx)
	r.at = r.now()
	return r.cached, r.cached != nil
}

// fetch runs the fixed query and projects the one hit; it returns nil for any no-run outcome.
func (r *Reader) fetch(ctx context.Context) []byte {
	now := r.now().UTC()
	res, err := r.src.Search(ctx, []string{siem.LabRunsIndex}, siem.Query{
		TimeField: "run.finished_at",
		Since:     now.Add(-r.lookback),
		// A small forward skew tolerates a run document whose clock is slightly ahead of the API's.
		Until:     now.Add(time.Hour),
		Size:      1,
		SortField: "run.finished_at",
		Source:    source,
	})
	if err != nil || len(res.Hits) == 0 {
		return nil
	}
	return project(res.Hits[0].Source)
}

// Run is the run's own metadata.
type Run struct {
	ID         string `json:"id"`
	Mode       string `json:"mode"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
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
	Rule  string  `json:"rule"`
	DelayS float64 `json:"delay_s"`
	Only   string  `json:"only,omitempty"`
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
}

type incident struct {
	OpenedAtVariant *int     `json:"opened_at_variant"`
	DelayS          *float64 `json:"delay_s"`
	Key             string   `json:"key"`
}

type techniques struct {
	Expected []string `json:"expected"`
	Detected []string `json:"detected"`
}

// Replay is the fixed response shape: the LabReplay the /lab/ page consumes (schema 1), extended
// with run, incident, techniques and the per-variant findings/caught_by_hash the run document adds.
type Replay struct {
	Schema        int        `json:"schema"`
	Sample        bool       `json:"sample"`
	Run           Run        `json:"run"`
	Scenario      scenario   `json:"scenario"`
	Artefact      artefact   `json:"artefact"`
	Beacon        string     `json:"beacon"`
	RiskThreshold float64    `json:"risk_threshold"`
	Rules         []rule     `json:"rules"`
	Variants      []variant  `json:"variants"`
	Incident      incident   `json:"incident"`
	Techniques    techniques `json:"techniques"`
}

// project turns one hit's _source into the fixed response, or nil when it is too large, not valid
// JSON, or not a schema-1 run with at least one variant. Decoding into Replay drops every unexpected
// top-level and nested field; each event is then narrowed to the allow-listed keys.
func project(src map[string]any) []byte {
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
	out, err := json.Marshal(rep)
	if err != nil {
		return nil
	}
	return out
}
