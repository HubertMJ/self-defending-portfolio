// Package incidents assembles the SIEM's evidence into the incidents the page's Correlation section
// shows (ADR 0036): it polls findings, correlations, Alerting alerts and a few bounded document
// searches through the read-only client (internal/siem), keeps 24 h of evidence in memory, and
// rebuilds every incident from it after each poll with one pure function. Joins are made here on the
// pod ref (siem contract S0-#13); an SA correlation is cited when it exists, never required.
//
// Everything published is built field by field from allow-listed fields and cleaned (publish.go):
// no user, address, pseudonym, node name, DNS query or flag ever reaches the View (ADR 0021).
//
// The tracker also holds the dns-exfil flag registrations: the runner hands it a terminal run's
// HMAC(process key, flag label) and the run's end (never the flag); a DNS finding's first label is
// HMAC'd and compared when the finding is first read, and only the result is kept.
package incidents

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/flagmac"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/siem"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/siemindex"
)

// Polling and retention (ADR 0036 section 2).
const (
	DefaultInterval = 15 * time.Second
	// overlap: each poll re-reads this much before the last successful one, so evidence that became
	// visible late (refresh, a slow detector run) is not missed; ids de-duplicate it.
	overlap = 2 * time.Minute
	// retention is how far back the evidence and the incidents go, and the start-up backfill.
	retention = 24 * time.Hour
	// pageSize: at most this many items per type and request (siem contract M16).
	pageSize = siem.MaxSize
	// maxPerSource bounds the evidence kept per source (Hubble: per kind, DNS findings and drops
	// apart, so a flood of drops never pushes a DNS finding out).
	maxPerSource = 2000
	// dropSettle: a Hubble drop older than this that no check uses is dropped from memory - by then
	// the command or Talon patch it could belong to has been read too.
	dropSettle = 10 * time.Minute
	// staleAfter: the section is available while the last fully successful poll is at most this old
	// (three polls), so a stopped SIEM hides it within a minute (L11) and one slow poll does not.
	staleAfter = 45 * time.Second
	// flagKeep: a DNS query up to this long after its run ended still matches the run's flag
	// (ADR 0034). Judged by the query's own time, so a finding read late (an outage, a slow detector)
	// matches as it would have on time; the registrations themselves (MACs only) are kept for the
	// evidence retention.
	flagKeep = 15 * time.Minute
	// lagWindow: the ingest lag is the median over documents the SIEM ingested this recently. Wider
	// than one poll window (2 min 15 s), which mostly holds no evidence at all: a sandbox source
	// writes only when someone attacks.
	lagWindow = 15 * time.Minute
	// maxFlags bounds the registrations (one run at a time; the cap only matters for a burst).
	maxFlags = 64
)

// Source is the read side of the SIEM (*siem.Client).
type Source interface {
	Findings(ctx context.Context, logType string, from, to time.Time, size int) ([]siem.Finding, error)
	Correlations(ctx context.Context, from, to time.Time) ([]siem.Correlation, error)
	MonitorAlerts(ctx context.Context, state string, size int) ([]siem.Alert, error)
	Search(ctx context.Context, indices []string, q siem.Query) (siem.SearchResult, error)
}

// Config wires the tracker. A nil Source means the SIEM is off: View answers available:false.
type Config struct {
	Source             Source
	MAC                *flagmac.Key
	Rules              *siemindex.Index
	Namespace          string
	UnguardedNamespace string
	Interval           time.Duration
	Log                *slog.Logger
	Now                func() time.Time
}

// Tracker is safe for concurrent use.
type Tracker struct {
	cfg   Config
	start time.Time

	mu      sync.Mutex
	records map[string]*record
	hosts   map[string]time.Time // host finding id -> time (counted only)
	lags    map[string]lagSample // per document read: its source and ingest lag
	corr    map[string]seenCorrelation
	alerts  []siem.Alert
	active  []siem.Alert // the ACTIVE alerts, for the health line
	rules   RulesView
	// recordAt is the newest sync record's applied_at; hb the sync's heartbeat, hbRead once it has
	// been read (found or not) at least once.
	recordAt time.Time
	hb       heartbeat
	hbRead   bool
	rewrite  bool
	lastOK   time.Time // start of the last fully successful poll: the next window starts 2 min before it
	lastEnd  time.Time // end of that poll: the staleness of the view is measured from here
	lastTry  time.Time
	failing  bool
	view     View
	// viewJSON is view marshalled once per poll; every request is served these bytes.
	viewJSON []byte
	// logged: notes already logged (a full page per read, a 404 per log type); Poll's goroutine only.
	logged map[string]bool

	fmu   sync.Mutex
	flags map[string]*flagEntry // by run id
}

type flagEntry struct {
	ref     string
	mac     []byte
	ended   time.Time // zero while the run lasts
	created time.Time
}

// New returns a tracker; nothing is read until Run.
func New(cfg Config) *Tracker {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "sandbox"
	}
	if cfg.MAC == nil {
		cfg.MAC = flagmac.New()
	}
	if cfg.Rules == nil {
		cfg.Rules, _ = siemindex.Load()
	}
	return &Tracker{cfg: cfg, start: cfg.Now(), records: map[string]*record{}, hosts: map[string]time.Time{},
		corr: map[string]seenCorrelation{}, rules: RulesView{Status: "unknown"}, flags: map[string]*flagEntry{}, logged: map[string]bool{}, lags: map[string]lagSample{}}
}

// Enabled reports whether a SIEM is configured.
func (t *Tracker) Enabled() bool { return t.cfg.Source != nil }

// Run polls until ctx ends: at once (the 24 h backfill), then every Interval. One goroutine, so polls
// never overlap, and nothing a visitor does starts one.
func (t *Tracker) Run(ctx context.Context) {
	if t.cfg.Source == nil {
		return
	}
	tick := time.NewTicker(t.cfg.Interval)
	defer tick.Stop()
	for {
		t.Poll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// View is the current answer of GET /api/correlation.
func (t *Tracker) View() View {
	t.mu.Lock()
	defer t.mu.Unlock()
	if v, down := t.down(); down {
		return v
	}
	return t.view
}

// JSON is View marshalled: the bytes made once per poll, or the small unavailable answer.
func (t *Tracker) JSON() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	if v, down := t.down(); down {
		b, _ := json.Marshal(v)
		return b
	}
	return t.viewJSON
}

// down is the unavailable answer when the SIEM is off or the last good poll is stale. t.mu held.
func (t *Tracker) down() (View, bool) {
	if t.cfg.Source == nil {
		return unavailable(nil), true
	}
	if t.lastEnd.IsZero() || t.cfg.Now().Sub(t.lastEnd) > staleAfter {
		var checked *time.Time
		if !t.lastTry.IsZero() {
			c := t.lastTry
			checked = &c
		}
		return unavailable(checked), true
	}
	return View{}, false
}

// Poll reads one window from the SIEM and rebuilds the incidents. Exported for tests; Run calls it.
func (t *Tracker) Poll(ctx context.Context) {
	now := t.cfg.Now().UTC()
	t.mu.Lock()
	from := now.Add(-retention)
	if !t.lastOK.IsZero() && t.lastOK.Add(-overlap).After(from) {
		from = t.lastOK.Add(-overlap)
	}
	t.lastTry = now
	t.mu.Unlock()

	src := t.cfg.Source
	var errs []error
	type found struct {
		r   record
		dns string
	}
	var news []found
	hosts := map[string]time.Time{}
	var lags []record // every document read, for the ingest lag
	for _, lt := range logTypes {
		fs, err := src.Findings(ctx, lt.logType, from, now, pageSize)
		if err != nil {
			// A log type without a detector yet answers 404: nothing to read, not an outage.
			var se *siem.StatusError
			if !errors.As(err, &se) || se.Code != 404 {
				errs = append(errs, err)
			} else {
				t.note("404 "+lt.logType, true, "siem: no detector for a log type yet", "log_type", lt.logType)
			}
			continue
		}
		t.note("404 "+lt.logType, false, "")
		t.note("full "+lt.logType, len(fs) >= pageSize, "siem: a findings page came back full; older items of the window are not read",
			"log_type", lt.logType, "size", pageSize)
		for _, f := range fs {
			r, q, ok := t.fromFinding(f, lt.source)
			lags = append(lags, r)
			if lt.source == "host" {
				// Host findings are counted, nothing else (ADR 0034 "counts only").
				if idPat.MatchString(f.ID) {
					hosts[f.ID] = time.UnixMilli(f.Timestamp).UTC()
				}
				continue
			}
			if ok {
				news = append(news, found{r, q})
			}
		}
	}
	// SA correlations are cited evidence, never a condition: a failed read keeps the pairs read
	// before and does not fail the poll.
	corr, corrErr := src.Correlations(ctx, from, now)
	t.note("correlations", corrErr != nil, "siem: correlations not read; the previous ones stand", "err", corrErr)
	alerts, alertsErr := src.MonitorAlerts(ctx, "ALL", pageSize)
	if alertsErr != nil {
		errs = append(errs, alertsErr)
	}
	// The health line reads the active alerts on their own: under a burst of incident alerts an ops
	// alarm can be older than the newest 500 of every state.
	active, activeErr := src.MonitorAlerts(ctx, "ACTIVE", pageSize)
	if activeErr != nil {
		errs = append(errs, activeErr)
	}
	for _, s := range t.searches(from, now) {
		res, err := src.Search(ctx, []string{s.index}, s.q)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		t.note("full "+s.index, len(res.Hits) >= pageSize, "siem: a search page came back full; older documents of the window are not read",
			"index", s.index, "size", pageSize)
		for _, h := range res.Hits {
			r, ok := t.fromHit(h, s.source)
			lags = append(lags, r)
			if ok {
				news = append(news, found{r, ""})
			}
		}
	}
	// The health reads are optional: a missing sync record or one failed count does not hide the
	// section; the previous value stands (rules: unknown until read once).
	rules, recordAt, rulesOK := t.readRules(ctx, now)
	hb, hbOK := t.readHeartbeat(ctx, now)
	rewrite, rewriteOK := t.readRewrite(ctx, now)

	unknown := 0
	for _, n := range news {
		if n.r.source == "hubble" && n.r.findingID != "" && n.r.unknownRule {
			unknown++
		}
	}
	t.note("unknown hubble rule", unknown > 0, "siem: Hubble findings under a rule title the embedded index does not know (rules synced before the API image?)",
		"findings", unknown)

	t.mu.Lock()
	defer t.mu.Unlock()
	for _, n := range news {
		if _, seen := t.records[n.r.key]; seen {
			continue
		}
		r := n.r
		if r.dns && r.findingID != "" {
			r.flag = t.flagMatch(r.ref, n.dns, r.at, now)
		}
		t.records[r.key] = &r
	}
	for id, at := range hosts {
		t.hosts[id] = at
	}
	for _, r := range lags {
		if r.key != "" && !r.at.IsZero() && !r.ingested.IsZero() {
			t.lags[r.key] = lagSample{source: r.source, ingested: r.ingested, lag: r.ingested.Sub(r.at)}
		}
	}
	for _, c := range corr {
		t.corr[c.Finding1+"|"+c.Finding2] = seenCorrelation{c, now}
	}
	if alertsErr == nil {
		t.alerts = alerts
	}
	if activeErr == nil {
		t.active = active
	}
	if rulesOK {
		if rules.Commit == "" {
			rules.Commit, rules.AppliedAt = t.rules.Commit, t.rules.AppliedAt
		}
		t.rules, t.recordAt = rules, recordAt
	}
	if hbOK {
		t.hb, t.hbRead = hb, true
	}
	if rewriteOK {
		t.rewrite = rewrite
	}
	t.prune(now)
	if len(errs) > 0 {
		if !t.failing {
			t.cfg.Log.Warn("siem poll failed", "err", errors.Join(errs...))
		}
		t.failing = true
		return
	}
	if t.failing {
		t.cfg.Log.Info("siem poll recovered")
	}
	t.failing = false
	t.lastOK, t.lastEnd = now, t.cfg.Now().UTC()
	t.view = t.buildView(now)
	t.viewJSON, _ = json.Marshal(t.view)
}

type search struct {
	index, source string
	q             siem.Query
}

// searches are the bounded document reads of one poll, by event.ingested so a document that arrived
// late is still read.
func (t *Tracker) searches(from, now time.Time) []search {
	q := func(filters []map[string]any, source ...string) siem.Query {
		return siem.Query{TimeField: "event.ingested", Since: from, Until: now, Filters: filters, Size: pageSize,
			SortField: "@timestamp", Source: append([]string{"@timestamp", "event.ingested", "k8s.pod.ref"}, source...)}
	}
	term := func(f string, v any) map[string]any { return map[string]any{"term": map[string]any{f: v}} }
	terms := func(f string, v ...string) map[string]any { return map[string]any{"terms": map[string]any{f: v}} }
	noSub := map[string]any{"bool": map[string]any{"must_not": []any{map[string]any{"exists": map[string]any{"field": "audit.object.subresource"}}}}}
	// Talon's responses on pods (TTI), and pod creates/deletes in the twin namespace (dwell).
	audit := []map[string]any{term("audit.object.resource", "pods"), noSub, {"bool": map[string]any{
		"minimum_should_match": 1,
		"should": []any{
			map[string]any{"bool": map[string]any{"filter": []any{term("user.name", talonUser), terms("audit.verb", "patch", "delete")}}},
			map[string]any{"bool": map[string]any{"filter": []any{term("k8s.ns.name", t.twinNamespace()), terms("audit.verb", "create", "delete")}}},
		},
	}}}
	return []search{
		{"sdp-api", "api", q([]map[string]any{terms("event.action", "siem.run", "siem.command")},
			"event.action", "api.run_id", "api.state", "api.arm", "api.seq", "api.command_seq", "api.command_id",
			"api.technique", "api.objective", "api.outcome", "api.exit_code")},
		{"sdp-k8s-audit", "k8s-audit", q(audit, "audit.verb", "audit.object.resource", "audit.object.subresource",
			"audit.response.code", "user.name")},
		{"sdp-hubble", "hubble", q([]map[string]any{term("hubble.verdict", "DROPPED")}, "hubble.verdict", "hubble.drop_reason",
			"hubble.traffic_direction", "hubble.l4.protocol", "hubble.l4.destination_port")},
	}
}

// twinNamespace never matches a real namespace when the twin is off.
func (t *Tracker) twinNamespace() string {
	if t.cfg.UnguardedNamespace == "" {
		return "-"
	}
	return t.cfg.UnguardedNamespace
}

var commitPat = regexp.MustCompile(`^[0-9a-f]{40}$`)

// readRules reads the newest sync records: the newest one's status, the newest applied one's commit
// and time. The sync writes a record only when it has something to do, so a quiet repository leaves
// the last record weeks old: the search looks back as far as a search may (31 d), and finding no
// record, or no applied one, keeps what was read before (ok false / the previous commit).
func (t *Tracker) readRules(ctx context.Context, now time.Time) (RulesView, time.Time, bool) {
	res, err := t.cfg.Source.Search(ctx, []string{siem.SyncIndex}, siem.Query{TimeField: "applied_at",
		Since: now.Add(-siem.MaxRange), Until: now, Size: 50, SortField: "applied_at",
		// The heartbeat document has no applied_at, so the range already leaves it out; the filter
		// and the check below say so twice.
		Filters: []map[string]any{{"bool": map[string]any{"must_not": []any{map[string]any{"term": map[string]any{"kind": "heartbeat"}}}}}},
		Source:  []string{"kind", "commit", "applied_at", "status"}})
	if err != nil {
		return RulesView{}, time.Time{}, false
	}
	type rec struct {
		at             time.Time
		commit, status string
	}
	var recs []rec
	for _, h := range res.Hits {
		at := timeOf(h.Source, "applied_at")
		if at.IsZero() || h.ID == heartbeatID || str(h.Source, "kind") == "heartbeat" {
			continue
		}
		recs = append(recs, rec{at, str(h.Source, "commit"), str(h.Source, "status")})
	}
	if len(recs) == 0 {
		return RulesView{}, time.Time{}, false
	}
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].at.After(recs[j].at) })
	out := RulesView{Status: "unknown"}
	if len(recs) > 0 {
		switch recs[0].status {
		case "applied", "refused", "failed":
			out.Status = recs[0].status
		}
	}
	for _, r := range recs {
		if r.status == "applied" && commitPat.MatchString(r.commit) {
			at := r.at
			out.Commit, out.AppliedAt = r.commit, &at
			break
		}
	}
	return out, recs[0].at, true
}

// heartbeatID is the sync's one heartbeat document in siem-sync, overwritten by every run.
const heartbeatID = "heartbeat"

// staleAfterSync: the sync runs every 5 minutes; no heartbeat for 30 minutes means it is not running
// (or cannot reach the SIEM), whatever the last record says.
const staleAfterSync = 30 * time.Minute

// heartbeat is the sync's liveness: when it last ran to an end, and how that run ended.
type heartbeat struct {
	found     bool
	checkedAt time.Time
	outcome   string // applied | unchanged | refused | failed, "" when unknown
}

// readHeartbeat reads the heartbeat document by a term query (the read-only allow-list has no GET on
// a document). A heartbeat whose checked_at is not an RFC 3339 time, or whose commit is neither empty
// nor 40 hex, is treated as missing; an unknown outcome is ignored.
func (t *Tracker) readHeartbeat(ctx context.Context, now time.Time) (heartbeat, bool) {
	res, err := t.cfg.Source.Search(ctx, []string{siem.SyncIndex}, siem.Query{TimeField: "checked_at",
		// Up to an hour ahead: siem01's clock may run ahead of this node's.
		Since: now.Add(-siem.MaxRange + time.Hour), Until: now.Add(time.Hour), Size: 1, SortField: "checked_at",
		Filters: []map[string]any{{"term": map[string]any{"kind": "heartbeat"}}},
		Source:  []string{"kind", "checked_at", "commit", "outcome"}})
	if err != nil {
		return heartbeat{}, false
	}
	for _, h := range res.Hits {
		if str(h.Source, "kind") != "heartbeat" {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, str(h.Source, "checked_at"))
		if c := str(h.Source, "commit"); err != nil || (c != "" && !commitPat.MatchString(c)) {
			return heartbeat{}, true
		}
		hb := heartbeat{found: true, checkedAt: at.UTC()}
		switch o := str(h.Source, "outcome"); o {
		case "applied", "unchanged", "refused", "failed":
			hb.outcome = o
		}
		return hb, true
	}
	return heartbeat{}, true
}

// rulesView is the published rules line: the records' status and last applied commit, then
//   - "stale" when the heartbeat is older than 30 minutes, or missing while records exist;
//   - otherwise the heartbeat's "refused" or "failed" when it is newer than the newest record: the
//     latest run's verdict (a run that refuses the same commit again writes no new record);
//
// the commit and applied_at stay the last applied ones either way. t.mu held.
func (t *Tracker) rulesView(now time.Time) RulesView {
	r := t.rules
	if !t.hbRead {
		return r
	}
	records := r.Status != "unknown" || r.Commit != ""
	hb := t.hb
	switch {
	case hb.found && now.Sub(hb.checkedAt) > staleAfterSync, !hb.found && records:
		r.Status = "stale"
	case hb.found && (hb.outcome == "refused" || hb.outcome == "failed") && hb.checkedAt.After(t.recordAt):
		r.Status = hb.outcome
	}
	return r
}

// readRewrite counts documents the sdp-final pipeline marked as written with a client id in the
// last 24 h (F1).
func (t *Tracker) readRewrite(ctx context.Context, now time.Time) (bool, bool) {
	res, err := t.cfg.Source.Search(ctx, siem.Streams, siem.Query{TimeField: "event.ingested", Since: now.Add(-retention),
		Until: now, Filters: []map[string]any{{"term": map[string]any{"event.overwrite": true}}}})
	if err != nil {
		return false, false
	}
	return res.Total > 0, true
}

// note logs msg once when cond becomes true, and forgets it when cond is false again.
func (t *Tracker) note(key string, cond bool, msg string, args ...any) {
	if !cond {
		delete(t.logged, key)
		return
	}
	if !t.logged[key] {
		t.logged[key] = true
		t.cfg.Log.Warn(msg, args...)
	}
}

// prune drops evidence older than the retention, settled Hubble documents no check uses and no
// finding names, and keeps at most maxPerSource records per source (Hubble DNS findings and drops
// counted apart).
func (t *Tracker) prune(now time.Time) {
	cut := now.Add(-retention)
	byRef := map[string][]*record{}
	cited := map[string]bool{} // documents a finding names
	for k, r := range t.records {
		if r.at.Before(cut) {
			delete(t.records, k)
			continue
		}
		byRef[r.ref] = append(byRef[r.ref], r)
		if !r.isDoc() {
			cited[r.docID] = true
		}
	}
	per := map[string][]*record{}
	for _, list := range byRef {
		sort.Slice(list, func(i, j int) bool { return list[i].at.Before(list[j].at) })
		used := usedDrops(list)
		for _, r := range list {
			bucket := r.source
			if r.source == "hubble" && !r.dns {
				if r.at.Before(now.Add(-dropSettle)) && !used[r] && !cited[r.docID] {
					delete(t.records, r.key)
					continue
				}
				bucket = "hubble-drop"
			}
			per[bucket] = append(per[bucket], r)
		}
	}
	for _, list := range per {
		if len(list) <= maxPerSource {
			continue
		}
		sort.Slice(list, func(i, j int) bool { return list[i].at.After(list[j].at) })
		for _, r := range list[maxPerSource:] {
			delete(t.records, r.key)
		}
	}
	for id, at := range t.hosts {
		if at.Before(cut) {
			delete(t.hosts, id)
		}
	}
	capOldest(t.hosts, func(at time.Time) time.Time { return at })
	for k, l := range t.lags {
		if l.ingested.Before(now.Add(-lagWindow)) {
			delete(t.lags, k)
		}
	}
	capOldest(t.lags, func(l lagSample) time.Time { return l.ingested })
	for k, c := range t.corr {
		if c.seen.Before(cut) {
			delete(t.corr, k)
		}
	}
	capOldest(t.corr, func(c seenCorrelation) time.Time { return c.seen })
}

// lagSample is one document's ingest lag: event.ingested (the SIEM's clock) - @timestamp (the event).
type lagSample struct {
	source   string
	ingested time.Time
	lag      time.Duration
}

// lagSources are the sources the API reads documents of; each is a key of metrics.ingest_lag_ms.
var lagSources = []string{"falco", "talon", "hubble", "k8s-audit", "api", "host"}

// ingestLag is the median ingest lag per source over the documents ingested in the last lagWindow,
// null for a source with none. t.mu held.
func (t *Tracker) ingestLag() map[string]*int64 {
	per := map[string][]int64{}
	for _, l := range t.lags {
		per[l.source] = append(per[l.source], l.lag.Milliseconds())
	}
	out := map[string]*int64{}
	for _, s := range lagSources {
		out[s] = median(per[s])
	}
	return out
}

// seenCorrelation is an SA correlation and when it was first read (the list carries no time).
type seenCorrelation struct {
	siem.Correlation
	seen time.Time
}

// capOldest keeps the maxPerSource newest entries of m.
func capOldest[V any](m map[string]V, at func(V) time.Time) {
	if len(m) <= maxPerSource {
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return at(m[keys[i]]).After(at(m[keys[j]])) })
	for _, k := range keys[maxPerSource:] {
		delete(m, k)
	}
}

// buildView assembles the answer from the evidence held. t.mu held.
func (t *Tracker) buildView(now time.Time) View {
	recs := make([]*record, 0, len(t.records))
	for _, r := range t.records {
		c := *r
		recs = append(recs, &c)
	}
	corr := make([]siem.Correlation, 0, len(t.corr))
	for _, c := range t.corr {
		corr = append(corr, c.Correlation)
	}
	incs, metrics := t.build(evidence{records: recs, correlations: corr, alerts: t.alerts, now: now})
	metrics.HostFindings = len(t.hosts)
	metrics.IngestLagMs = t.ingestLag()
	checked := now
	return View{Available: true, CheckedAt: &checked, Rules: t.rulesView(now), Health: t.health(), Metrics: metrics, Incidents: incs}
}

// health: ingest silent / disk high from the ops monitors' active alerts, evidence_rewritten from the
// count. t.mu held.
func (t *Tracker) health() HealthView {
	h := HealthView{Ingest: "ok", Disk: "ok", EvidenceRewritten: t.rewrite}
	for _, a := range t.active {
		if a.State != "ACTIVE" {
			continue
		}
		switch {
		case strings.HasPrefix(a.MonitorName, "ingest silent "):
			h.Ingest = "silent"
		case a.MonitorName == "disk watermark":
			h.Disk = "high"
		}
	}
	return h
}

var labelPat = regexp.MustCompile(`^sdp-[0-9a-f]{16}$`)

// RegisterFlag records a terminal run's flag MAC with its pod ref (runner.FlagSink).
func (t *Tracker) RegisterFlag(runID, podRef string, mac []byte) {
	t.fmu.Lock()
	defer t.fmu.Unlock()
	now := t.cfg.Now()
	t.expireFlags(now)
	if len(t.flags) >= maxFlags {
		var oldest string
		for id, e := range t.flags {
			if oldest == "" || e.created.Before(t.flags[oldest].created) {
				oldest = id
			}
		}
		delete(t.flags, oldest)
	}
	t.flags[runID] = &flagEntry{ref: podRef, mac: append([]byte(nil), mac...), created: now}
}

// EndFlag starts the run's 15 minutes after its end (runner.FlagSink).
func (t *Tracker) EndFlag(runID string, at time.Time) {
	t.fmu.Lock()
	defer t.fmu.Unlock()
	if e := t.flags[runID]; e != nil && e.ended.IsZero() {
		e.ended = at
	}
}

// FlagMAC is the key's MAC of a label: what the runner hands over (runner.Config.FlagMAC).
func (t *Tracker) FlagMAC(label string) []byte { return t.cfg.MAC.Sum(label) }

func (t *Tracker) expireFlags(now time.Time) {
	for id, e := range t.flags {
		end := e.ended
		if end.IsZero() {
			end = e.created
		}
		if now.After(end.Add(retention)) {
			delete(t.flags, id)
		}
	}
}

// flagMatch compares a DNS query's first label with the registrations for the same ref whose run
// was still going, or had ended at most flagKeep before, when the query happened: true on a match,
// false when the ref has a registration and none matches or when the query happened under this
// process with no registration for the ref, null when the query predates this process (its key went
// with the previous process).
func (t *Tracker) flagMatch(ref, query string, at, now time.Time) *bool {
	t.fmu.Lock()
	defer t.fmu.Unlock()
	t.expireFlags(now)
	label, _, _ := strings.Cut(strings.ToLower(query), ".")
	var sum []byte
	if labelPat.MatchString(label) {
		sum = t.cfg.MAC.Sum(label)
	}
	known, match := false, false
	for _, e := range t.flags {
		if e.ref != ref {
			continue
		}
		known = true
		inRun := e.ended.IsZero() || !at.After(e.ended.Add(flagKeep))
		if inRun && sum != nil && hmac.Equal(sum, e.mac) {
			match = true
		}
	}
	if !known && at.Before(t.start) {
		return nil
	}
	return &match
}
