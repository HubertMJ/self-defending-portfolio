package incidents

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/siem"
)

// Incident kinds (ADR 0036 section 4).
const (
	KindContainedIntrusion   = "contained-intrusion"
	KindDNSExfil             = "dns-exfil"
	KindStagedAttack         = "staged-attack"
	KindExecOutsideAPI       = "exec-outside-api"
	KindPolicyProbing        = "policy-probing"
	KindPreventedNotDetected = "prevented-not-detected"
	KindDetectionMissing     = "detection-missing"
	KindTwinDwell            = "twin-dwell"
)

// Caps (siem contract P4).
const (
	maxIncidents = 200
	maxSteps     = 50
	maxEvidence  = 50
	// maxExtraFindings: more finding ids kept for one document beyond its first.
	maxExtraFindings = 4
)

// Windows of the checks.
const (
	// dnsJoinWindow: a DNS finding belongs to the run's dns-exfil command started at most this long
	// before it - the terminal session's length (siem contract P3, the SA correlation's 300 000 ms).
	dnsJoinWindow = 300 * time.Second
	// falcoWindow: Falco findings within this of the dns-exfil command count as "Falco saw it".
	falcoWindow = 60 * time.Second
	// quarantineDropWindow: a quarantined pod's lookup is dropped at once; nslookup gives up within
	// the API's 5 s command bound.
	quarantineDropWindow = 10 * time.Second
	// enforceWindow: the first drop after Talon's quarantine label counts as "policy enforced" only
	// this soon after it (ADR 0032 measures isolation under 3 s).
	enforceWindow = 30 * time.Second
)

const monitorPrefix = "sdp-git: "

// evidence is everything one build reads; build is a pure function of it.
type evidence struct {
	records      []*record
	correlations []siem.Correlation
	alerts       []siem.Alert
	now          time.Time
}

// index is the evidence arranged for the checks.
type index struct {
	t       *Tracker
	now     time.Time
	byRef   map[string][]*record // time order
	runs    map[string][]*record // api records by run id, time order
	refRun  map[string]*record   // the first api record naming a ref: its run id and arm
	pairs   map[string]string    // "<finding>|<finding>" -> SA correlation rule id
	refList []string
	runList []string
}

func (t *Tracker) newIndex(ev evidence) *index {
	ix := &index{t: t, now: ev.now, byRef: map[string][]*record{}, runs: map[string][]*record{}, refRun: map[string]*record{}, pairs: map[string]string{}}
	// One document is one event: a finding on a document the searches also read (an sdp-api command
	// line, a Hubble drop), or several findings on one document (two rules matched it), make one
	// record - the document's, or else the finding with the lowest id - carrying the first finding's
	// rule, the flag match, and up to maxExtraFindings more finding ids as evidence.
	byDoc := map[string][]*record{}
	var recs []*record
	for _, r := range ev.records {
		if r.docID == "" {
			recs = append(recs, r)
			continue
		}
		byDoc[r.docID] = append(byDoc[r.docID], r)
	}
	for _, group := range byDoc {
		sort.Slice(group, func(i, j int) bool {
			if group[i].isDoc() != group[j].isDoc() {
				return group[i].isDoc()
			}
			return group[i].key < group[j].key
		})
		base := group[0]
		for _, r := range group[1:] {
			if r.isDoc() || r.findingID == "" {
				continue
			}
			if base.findingID == "" {
				base.findingID, base.rule, base.attack = r.findingID, r.rule, r.attack
			} else if len(base.extraFindings) < maxExtraFindings {
				base.extraFindings = append(base.extraFindings, r.findingID)
				for _, a := range r.attack {
					base.attack = appendUnique(base.attack, a)
				}
			}
			if r.dns {
				base.dns = true
			}
			if r.flag != nil && (base.flag == nil || *r.flag) {
				base.flag = r.flag
			}
		}
		recs = append(recs, base)
	}
	sort.SliceStable(recs, func(i, j int) bool {
		if !recs[i].at.Equal(recs[j].at) {
			return recs[i].at.Before(recs[j].at)
		}
		return recs[i].key < recs[j].key
	})
	for _, r := range recs {
		if _, ok := ix.byRef[r.ref]; !ok {
			ix.refList = append(ix.refList, r.ref)
		}
		ix.byRef[r.ref] = append(ix.byRef[r.ref], r)
		if r.source == "api" && r.runID != "" {
			if _, ok := ix.runs[r.runID]; !ok {
				ix.runList = append(ix.runList, r.runID)
			}
			ix.runs[r.runID] = append(ix.runs[r.runID], r)
			if _, ok := ix.refRun[r.ref]; !ok {
				ix.refRun[r.ref] = r
			}
		}
	}
	for _, c := range ev.correlations {
		if len(c.Rules) > 0 && idPat.MatchString(c.Rules[0]) {
			ix.pairs[c.Finding1+"|"+c.Finding2] = c.Rules[0]
			ix.pairs[c.Finding2+"|"+c.Finding1] = c.Rules[0]
		}
	}
	return ix
}

func (ix *index) on(ref string, keep func(*record) bool) []*record {
	var out []*record
	for _, r := range ix.byRef[ref] {
		if keep(r) {
			out = append(out, r)
		}
	}
	return out
}

func isFinding(source string) func(*record) bool {
	return func(r *record) bool { return r.source == source && r.findingID != "" }
}

func isCommandStart(r *record) bool {
	return r.source == "api" && r.apiAction == "siem.command" && r.state == "started"
}

// latest is the last record of list at or before t that keep accepts.
func latest(list []*record, t time.Time, keep func(*record) bool) *record {
	var out *record
	for _, r := range list {
		if r.at.After(t) {
			break
		}
		if keep(r) {
			out = r
		}
	}
	return out
}

// first is the first record of list at or after t that keep accepts.
func first(list []*record, t time.Time, keep func(*record) bool) *record {
	for _, r := range list {
		if !r.at.Before(t) && keep(r) {
			return r
		}
	}
	return nil
}

// draft collects one incident while it is assembled.
type draft struct {
	Incident
	key   string
	refs  []string
	recs  []*record
	extra []Step // steps that are not a record (monitor alerts, "policy enforced")
	ev    []Evidence
}

func (d *draft) add(rs ...*record) {
	for _, r := range rs {
		if r == nil {
			continue
		}
		dup := false
		for _, x := range d.recs {
			if x == r {
				dup = true
			}
		}
		if !dup {
			d.recs = append(d.recs, r)
		}
	}
}

// build assembles every incident from the evidence, newest first, and the metrics over them.
func (t *Tracker) build(ev evidence) ([]Incident, MetricsView) {
	ix := t.newIndex(ev)
	var drafts []*draft
	contained := map[string]*draft{}
	for _, ref := range ix.refList {
		if d := ix.containedIntrusion(ref); d != nil {
			contained[ref] = d
			drafts = append(drafts, d)
		}
		if d := ix.dnsExfil(ref); d != nil {
			drafts = append(drafts, d)
		}
		drafts = append(drafts, ix.execOutsideAPI(ref)...)
	}
	var dwells []int64
	for _, run := range ix.runList {
		if d := ix.stagedAttack(run); d != nil {
			drafts = append(drafts, d)
		}
		if d, dwell := ix.twinDwell(run, contained); d != nil {
			drafts = append(drafts, d)
			dwells = append(dwells, dwell)
		}
	}
	drafts = append(drafts, ix.monitorIncidents(ev.alerts, ev.now)...)

	out := make([]Incident, 0, len(drafts))
	for _, d := range drafts {
		out = append(out, ix.finish(d))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].FirstAt.Equal(out[j].FirstAt) {
			return out[i].FirstAt.After(out[j].FirstAt)
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > maxIncidents {
		out = out[:maxIncidents]
	}

	var ttds, ttis []int64
	for _, inc := range out {
		if inc.Kind != KindContainedIntrusion {
			continue
		}
		if inc.TTDMs != nil {
			ttds = append(ttds, *inc.TTDMs)
		}
		if inc.TTIMs != nil {
			ttis = append(ttis, *inc.TTIMs)
		}
	}
	since := ev.now.Add(-retention)
	return out, MetricsView{Since: &since, Incidents: len(out), MedianTTDMs: median(ttds), MedianTTIMs: median(ttis),
		MedianTwinDwellMs: median(dwells)}
}

func median(v []int64) *int64 {
	if len(v) == 0 {
		return nil
	}
	s := append([]int64(nil), v...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	m := s[len(s)/2]
	if len(s)%2 == 0 {
		m = (s[len(s)/2-1] + s[len(s)/2]) / 2
	}
	return &m
}

// containedIntrusion: a Falco finding and a Talon finding on the same ref, joined here (S0-#13); TTD
// from the anchoring command (or the run's pod_ready), TTI from Talon's audited patch or delete (M11).
func (ix *index) containedIntrusion(ref string) *draft {
	falcos := ix.on(ref, isFinding("falco"))
	talons := ix.on(ref, isFinding("talon"))
	if len(falcos) == 0 || len(talons) == 0 {
		return nil
	}
	all := ix.byRef[ref]
	f0 := falcos[0]
	d := &draft{key: ref, refs: []string{ref}}
	d.Kind, d.Severity = KindContainedIntrusion, "high"
	anchor := latest(all, f0.at, isCommandStart)
	if anchor == nil {
		anchor = latest(all, f0.at, func(r *record) bool {
			return r.source == "api" && r.apiAction == "siem.run" && r.state == "pod_ready"
		})
	}
	if anchor != nil {
		d.TTDMs = msPtr(f0.at.Sub(anchor.at))
	}
	resp := first(all, f0.at, isTalonResponse)
	d.add(anchor)
	d.add(falcos...)
	d.add(talons...)
	pod := ix.t.publicRef(ref)
	how := "isolated by Talon"
	if resp != nil {
		d.TTIMs = msPtr(resp.at.Sub(f0.at))
		d.add(resp)
		how = "quarantined by Talon in " + seconds(resp.at.Sub(f0.at))
		if resp.verb == "delete" {
			how = "terminated by Talon in " + seconds(resp.at.Sub(f0.at))
		}
		if resp.verb == "patch" {
			// The first drop after the label is the network policy taking effect: its own step,
			// "policy enforced +N ms", not part of TTI.
			if drop := enforcedDrop(all, resp); drop != nil {
				d.extra = append(d.extra, Step{At: drop.at, Source: "hubble", Rule: drop.rule,
					Detail: "policy enforced +" + fmt.Sprint(drop.at.Sub(resp.at).Milliseconds()) + " ms: " + ix.t.detail(drop)})
				d.ev = append(d.ev, evidenceOf(drop))
			}
		}
	}
	d.Title = "Contained intrusion: " + f0.falcoRule + " on " + pod + ", " + how
	return d
}

// dnsExfil: a DNS finding joined with the run's dns-exfil command on the ref; or, under quarantine,
// the command and a dropped lookup without any DNS finding (F7).
func (ix *index) dnsExfil(ref string) *draft {
	all := ix.byRef[ref]
	pod := ix.t.publicRef(ref)
	isExfilCmd := func(r *record) bool { return isCommandStart(r) && r.commandID == "dns-exfil" }
	dnsFindings := ix.on(ref, func(r *record) bool { return r.source == "hubble" && r.dns && r.findingID != "" })
	d := &draft{key: ref, refs: []string{ref}}
	d.Kind = KindDNSExfil
	if len(dnsFindings) == 0 {
		cmd := latest(all, ix.now, isExfilCmd)
		if cmd == nil {
			return nil
		}
		drop := lookupDrop(all, cmd)
		if drop == nil {
			return nil
		}
		d.Severity = "medium"
		d.Title = "DNS egress attempted under quarantine from " + pod + ", dropped"
		d.add(cmd, drop)
		d.FalcoEvents = len(ix.on(ref, func(r *record) bool {
			return isFinding("falco")(r) && !r.at.Before(cmd.at) && !r.at.After(cmd.at.Add(falcoWindow))
		}))
		return d
	}
	d0 := dnsFindings[0]
	cmd := latest(all, d0.at, func(r *record) bool { return isExfilCmd(r) && !r.at.Before(d0.at.Add(-dnsJoinWindow)) })
	anchor := d0.at
	if cmd != nil {
		anchor = cmd.at
		if rf := latest(all, cmd.at, func(r *record) bool {
			return isCommandStart(r) && r.commandID == "read-flag" && r.runID == cmd.runID
		}); rf != nil {
			d.add(rf)
		}
		d.add(cmd)
	}
	d.add(dnsFindings...)
	var match *bool
	for _, r := range dnsFindings {
		if r.flag != nil && (match == nil || *r.flag) {
			v := *r.flag
			match = &v
		}
	}
	d.FlagMatch = match
	from := anchor
	if cmd == nil {
		from = anchor.Add(-falcoWindow)
	}
	d.FalcoEvents = len(ix.on(ref, func(r *record) bool {
		return isFinding("falco")(r) && !r.at.Before(from) && !r.at.After(anchor.Add(falcoWindow))
	}))
	falco := "Falco: no event"
	if d.FalcoEvents > 0 {
		falco = fmt.Sprintf("Falco: %d event(s)", d.FalcoEvents)
	}
	switch {
	case match != nil && *match:
		d.Severity = "critical"
		d.Title = "Exfiltration over DNS: this run's secret left " + pod + " in a DNS query; " + falco
	case match != nil:
		d.Severity = "high"
		d.Title = "DNS query with an exfil label from " + pod + ", not this run's flag; " + falco
	default:
		d.Severity = "high"
		d.Title = "DNS query with an exfil label from " + pod + ", flag match unavailable; " + falco
	}
	return d
}

// execOutsideAPI: audited exec/attach/portforward sessions into a sandbox pod by anyone but the API,
// one incident per pod with each session a step. A session is audited once per stage
// (ResponseStarted, then ResponseComplete) under one audit id: the stages are one step, both
// findings cited.
func (ix *index) execOutsideAPI(ref string) []*draft {
	d := &draft{key: ref, refs: []string{ref}}
	d.Kind, d.Severity = KindExecOutsideAPI, "high"
	seen := map[string]bool{}
	var first *record
	for _, r := range ix.on(ref, isFinding("k8s-audit")) {
		if r.actor == actorAPI || (r.subresource != "exec" && r.subresource != "attach" && r.subresource != "portforward") {
			continue
		}
		key := r.auditID
		if key == "" {
			key = r.subresource + "@" + r.at.Format(time.RFC3339Nano)
		}
		if seen[key] {
			d.ev = append(d.ev, evidenceOf(r))
			continue
		}
		seen[key] = true
		if first == nil {
			first = r
		}
		d.add(r)
	}
	if first == nil {
		return nil
	}
	pod := ix.t.publicRef(ref)
	if len(d.recs) == 1 {
		verb := map[string]string{"exec": "Exec into", "attach": "Attach to", "portforward": "Port-forward to"}[first.subresource]
		d.Title = verb + " " + pod + " outside the API"
	} else {
		d.Title = fmt.Sprintf("%d exec/attach/port-forward sessions into %s outside the API", len(d.recs), pod)
	}
	return []*draft{d}
}

// stagedAttack: in one run, a recon step, then a credentials step, then an exfiltration attempt, by
// the @timestamp order of the run's command lines.
func (ix *index) stagedAttack(run string) *draft {
	var cmds []*record
	for _, r := range ix.runs[run] {
		if isCommandStart(r) && r.objective != "" {
			cmds = append(cmds, r)
		}
	}
	var recon, cred, exfil *record
	for _, r := range cmds {
		switch {
		case recon == nil && r.objective == "recon":
			recon = r
		case recon != nil && cred == nil && r.objective == "credentials" && r.at.After(recon.at):
			cred = r
		case cred != nil && exfil == nil && r.objective == "exfiltration" && r.at.After(cred.at):
			exfil = r
		}
	}
	if exfil == nil {
		return nil
	}
	d := &draft{key: run}
	d.Kind, d.Severity = KindStagedAttack, "high"
	d.add(cmds...)
	refs := map[string]bool{}
	for _, r := range ix.runs[run] {
		refs[r.ref] = true
	}
	for _, ref := range ix.refList {
		if refs[ref] {
			d.refs = append(d.refs, ref)
			d.add(ix.on(ref, isFinding("falco"))...)
		}
	}
	d.Title = fmt.Sprintf("Staged attack on %s: %s, then %s, then %s", ix.t.publicRef(exfil.ref), recon.commandID, cred.commandID, exfil.commandID)
	return d
}

// twinDwell: a compare run's twin pod lifetime from its audited create and delete, next to the
// guarded arm's TTD and TTI from the same run.
func (ix *index) twinDwell(run string, contained map[string]*draft) (*draft, int64) {
	var twin, guarded string
	var twinLine *record
	for _, r := range ix.runs[run] {
		if r.apiAction != "siem.run" {
			continue
		}
		ns, _, _ := ix.t.splitRef(r.ref)
		switch {
		case r.arm == "unguarded" && ns == ix.t.cfg.UnguardedNamespace && twin == "":
			twin, twinLine = r.ref, r
		case r.arm == "guarded" && ns == ix.t.cfg.Namespace && guarded == "":
			guarded = r.ref
		}
	}
	if twin == "" {
		return nil, 0
	}
	all := ix.byRef[twin]
	create := first(all, time.Time{}, func(r *record) bool {
		return r.source == "k8s-audit" && r.verb == "create" && r.resource == "pods" && r.subresource == "" && r.code < 300
	})
	if create == nil {
		return nil, 0
	}
	del := first(all, create.at, func(r *record) bool {
		return r.source == "k8s-audit" && r.verb == "delete" && r.resource == "pods" && r.subresource == ""
	})
	if del == nil {
		return nil, 0
	}
	dwell := del.at.Sub(create.at)
	d := &draft{key: run, refs: []string{twin}}
	d.Kind, d.Severity, d.Arm = KindTwinDwell, "medium", "unguarded"
	d.add(twinLine, create)
	d.add(ix.on(twin, isFinding("falco"))...)
	d.add(del)
	guard := "the guarded pod was not isolated"
	if g := contained[guarded]; g != nil {
		d.TTDMs, d.TTIMs = g.TTDMs, g.TTIMs
		if g.TTIMs != nil {
			guard = "the guarded pod was isolated in " + seconds(time.Duration(*g.TTIMs)*time.Millisecond)
		}
	}
	d.Title = "Unguarded twin " + ix.t.publicRef(twin) + " ran " + seconds(dwell) + "; " + guard
	d.extra = append(d.extra, Step{At: del.at, Source: "k8s-audit", Detail: "twin dwell " + fmt.Sprint(dwell.Milliseconds()) + " ms"})
	return d, dwell.Milliseconds()
}

var slugRun = regexp.MustCompile(`[^a-z0-9]+`)

// monitorIncidents: one incident per alert of a `sdp-git: ` monitor of a known kind.
func (ix *index) monitorIncidents(alerts []siem.Alert, now time.Time) []*draft {
	var out []*draft
	for _, a := range alerts {
		name, ok := strings.CutPrefix(a.MonitorName, monitorPrefix)
		if !ok || a.StartTime == nil || a.State == "ERROR" || a.State == "DELETED" || !idPat.MatchString(a.ID) {
			continue
		}
		start := time.UnixMilli(*a.StartTime).UTC()
		if start.Before(now.Add(-retention)) {
			continue
		}
		slug := strings.Trim(slugRun.ReplaceAllString(strings.ToLower(name), "-"), "-")
		d := &draft{key: a.ID}
		source := "api"
		switch {
		case strings.HasPrefix(slug, KindPolicyProbing):
			d.Kind, d.Severity, source = KindPolicyProbing, "medium", "k8s-audit"
			d.Title = "Policy probing: repeated admission denials by one principal, then an allowed create"
		case strings.HasPrefix(slug, KindPreventedNotDetected):
			d.Kind, d.Severity = KindPreventedNotDetected, "low"
			d.Title = "Prevented, not detected: a prevented command with no Falco event"
		case strings.HasPrefix(slug, KindDetectionMissing):
			d.Kind, d.Severity = KindDetectionMissing, "medium"
			d.Title = "Detection missing: a command the catalogue says is detected raised no Falco event"
		default:
			continue
		}
		detail := "monitor alert " + strings.ToLower(a.State)
		// A bucket key is published only when it is a pod ref in the sandboxes; policy probing's key
		// is a principal and never is.
		if a.Agg != nil && d.Kind != KindPolicyProbing {
			var pods []string
			for _, key := range a.Agg.BucketKeys {
				k, _ := key.(string)
				if p := ix.t.publicRef(k); p != "" {
					pods = append(pods, p)
					d.refs = append(d.refs, k)
					if d.RunID == "" {
						if r := ix.refRun[k]; r != nil {
							d.RunID, d.Arm = r.runID, r.arm
						}
					}
				}
			}
			if len(pods) > 0 {
				detail += " for " + strings.Join(pods, ", ")
				d.Title += " on " + strings.Join(pods, ", ")
			}
		}
		end := start
		if a.EndTime != nil && *a.EndTime > *a.StartTime {
			end = time.UnixMilli(*a.EndTime).UTC()
		}
		d.extra = append(d.extra, Step{At: start, Source: source, Rule: name, Detail: detail})
		if !end.Equal(start) {
			d.extra = append(d.extra, Step{At: end, Source: source, Rule: name, Detail: "monitor alert ended"})
		}
		d.ev = append(d.ev, Evidence{Type: "alert", ID: a.ID})
		out = append(out, d)
	}
	return out
}

// finish turns a draft into the published incident: steps in time order with their command
// sequence numbers, evidence, ATT&CK ids, run id and arm, the id, every string cleaned.
func (ix *index) finish(d *draft) Incident {
	inc := d.Incident
	sum := sha256.Sum256([]byte(d.Kind + "\x00" + d.key))
	inc.ID = hex.EncodeToString(sum[:8])
	inc.Title = clean(inc.Title, maxTitle)
	inc.Attack, inc.Steps, inc.Evidence = []string{}, []Step{}, []Evidence{}

	if inc.RunID == "" {
		for _, r := range d.recs {
			if r.runID != "" {
				inc.RunID = r.runID
				break
			}
		}
	}
	if inc.RunID == "" {
		for _, ref := range d.refs {
			if r := ix.refRun[ref]; r != nil {
				inc.RunID = r.runID
				break
			}
		}
	}
	if inc.Arm == "" {
		for _, ref := range d.refs {
			if r := ix.refRun[ref]; r != nil && (r.arm == "guarded" || r.arm == "unguarded") {
				inc.Arm = r.arm
				break
			}
		}
	}
	if !runIDPat.MatchString(inc.RunID) {
		inc.RunID = ""
	}

	var findings []string
	for _, r := range d.recs {
		st := Step{At: r.at, Source: r.source, Rule: clean(r.rule, maxRule), Detail: clean(ix.t.detail(r), maxDetail)}
		if r.rule != "" {
			st.RuleID = ix.t.cfg.Rules.RuleID(r.rule)
		}
		if seq := ix.commandSeq(r); seq > 0 {
			st.CommandSeq = &seq
		}
		inc.Steps = append(inc.Steps, st)
		for _, a := range r.attack {
			inc.Attack = appendUnique(inc.Attack, a)
		}
		if r.source == "api" && techPat.MatchString(r.technique) {
			inc.Attack = appendUnique(inc.Attack, r.technique)
		}
		if r.findingID != "" {
			findings = append(findings, r.findingID)
		}
		findings = append(findings, r.extraFindings...)
		inc.Evidence = append(inc.Evidence, evidenceOf(r))
		for _, id := range r.extraFindings {
			inc.Evidence = append(inc.Evidence, Evidence{Type: "finding", ID: id})
		}
		if r.source == "falco" && d.Kind != KindDNSExfil {
			inc.FalcoEvents++
		}
	}
	for _, st := range d.extra {
		st.Rule = clean(st.Rule, maxRule)
		st.Detail = clean(st.Detail, maxDetail)
		inc.Steps = append(inc.Steps, st)
	}
	inc.Evidence = append(inc.Evidence, d.ev...)
	for _, e := range d.ev {
		if e.Type == "finding" {
			findings = append(findings, e.ID)
		}
	}
	// An SA correlation that paired two of this incident's findings is cited first, so the evidence
	// cap never cuts it; it is never required.
	cited := map[string]bool{}
	var corr []Evidence
	for i := range findings {
		for j := i + 1; j < len(findings); j++ {
			if rule, ok := ix.pairs[findings[i]+"|"+findings[j]]; ok && !cited[rule] {
				cited[rule] = true
				corr = append(corr, Evidence{Type: "correlation", ID: rule})
			}
		}
	}
	inc.Evidence = append(corr, inc.Evidence...)
	if len(inc.Evidence) > maxEvidence {
		inc.Evidence = inc.Evidence[:maxEvidence]
	}
	sort.SliceStable(inc.Steps, func(i, j int) bool { return inc.Steps[i].At.Before(inc.Steps[j].At) })
	if len(inc.Steps) > maxSteps {
		inc.Steps = inc.Steps[:maxSteps]
	}
	if len(inc.Steps) > 0 {
		inc.FirstAt, inc.LastAt = inc.Steps[0].At, inc.Steps[0].At
		for _, st := range inc.Steps {
			if st.At.After(inc.LastAt) {
				inc.LastAt = st.At
			}
		}
	}
	return inc
}

func isDrop(r *record) bool { return r.source == "hubble" && r.verdict == "DROPPED" && !r.dns }

func isTalonResponse(r *record) bool {
	return r.source == "k8s-audit" && r.actor == actorTalon && r.resource == "pods" && r.subresource == "" &&
		(r.verb == "patch" || r.verb == "delete") && r.code < 300
}

// enforcedDrop is the first drop on the ref at or after Talon's quarantine patch, within
// enforceWindow; nil for a delete.
func enforcedDrop(all []*record, resp *record) *record {
	if resp.verb != "patch" {
		return nil
	}
	return first(all, resp.at, func(r *record) bool { return isDrop(r) && !r.at.After(resp.at.Add(enforceWindow)) })
}

// lookupDrop is a quarantined pod's dropped lookup: a drop to port 53 within quarantineDropWindow of
// the dns-exfil command.
func lookupDrop(all []*record, cmd *record) *record {
	return first(all, cmd.at, func(r *record) bool {
		return isDrop(r) && r.port == 53 && !r.at.After(cmd.at.Add(quarantineDropWindow))
	})
}

// usedDrops are the drops of one ref's time-ordered records that a check reads: the policy-enforced
// drop after each Talon patch and the dropped lookup after each dns-exfil command.
func usedDrops(list []*record) map[*record]bool {
	used := map[*record]bool{}
	for _, r := range list {
		var d *record
		switch {
		case isTalonResponse(r):
			d = enforcedDrop(list, r)
		case isCommandStart(r) && r.commandID == "dns-exfil":
			d = lookupDrop(list, r)
		}
		if d != nil {
			used[d] = true
		}
	}
	return used
}

// evidenceOf cites a record: its finding, or the document when no rule fired on it.
func evidenceOf(r *record) Evidence {
	if r.findingID != "" {
		return Evidence{Type: "finding", ID: r.findingID}
	}
	return Evidence{Type: "document", ID: r.docID}
}

// commandSeq is the terminal run's command in effect at r: its own seq for a command line, the
// command_seq of a run line, else the latest command started on the ref at or before r.
func (ix *index) commandSeq(r *record) int {
	if r.source == "api" {
		if r.apiAction == "siem.command" {
			return r.seq
		}
		return r.commandSeq
	}
	if c := latest(ix.byRef[r.ref], r.at, isCommandStart); c != nil {
		return c.seq
	}
	return 0
}
