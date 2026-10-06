package incidents

import (
	"encoding/json"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/siem"
)

// Identities in sdp-k8s-audit, kept verbatim inside the SIEM (siem contract F3) and used here only to
// classify an audit record; they are never published (ADR 0021).
const (
	apiUser   = "system:serviceaccount:portfolio-api:portfolio-api"
	talonUser = "system:serviceaccount:falco-response:falco-talon"
	// operatorUser: the k3s admin kubeconfig's client certificate, the live test suites' principal
	// (tests/scenarios/run.sh, tests/runtime/run.sh).
	operatorUser = "system:admin"
)

// operatorPod: the pods the live test suites create, matched whole - tests/scenarios/run.sh's
// sc-<scenario>-<6 hex> and sdp-probe-<6 hex>, tests/runtime/run.sh's rt-iso-<5 [a-z0-9]>, and l3probe.
var operatorPod = regexp.MustCompile(`^(sc-[a-z0-9]+(-[a-z0-9]+)*-[0-9a-f]{6}|sdp-probe-[0-9a-f]{6}|rt-iso-[a-z0-9]{5}|l3probe)$`)

// Who an audit record's request came from - the only thing kept of its user.
const (
	actorAPI   = "api"
	actorTalon = "talon"
	actorOther = "other"
)

// dnsExfilRule is the Sigma id of siem/rules/hubble-dns-exfil.yml ("Hubble - flag-shaped DNS lookup"),
// looked up by a finding's rule title in the embedded index: the one rule whose finding is a DNS lookup.
const dnsExfilRule = "fa0bd074-18fc-4827-834c-705c707a94f9"

// hubbleL7 is Hubble's event type of an L7 (DNS proxy) flow; 1 is a drop, 4 a trace.
const hubbleL7 = 129

// logTypes maps a detector log type (siem contract S0-#2) to its source. sdp_siem01 is not read: the
// API's role has no access to the SIEM host's own records (ADR 0034 amendment P1).
var logTypes = []struct{ logType, source string }{
	{"sdp_falco", "falco"}, {"sdp_talon", "talon"}, {"sdp_hubble", "hubble"},
	{"sdp_k8s_audit", "k8s-audit"}, {"sdp_api", "api"}, {"sdp_host", "host"},
}

// record is one piece of evidence: a finding (with its matched document's allow-listed fields) or a
// document read by a search. Only the fields below are kept - never a user, address, pseudonym or
// DNS query; a DNS finding keeps only whether its query was this run's flag.
type record struct {
	key       string // de-duplication key: "finding:<id>" or "doc:<index>/<id>"
	findingID string // SA finding id, "" for a document without a finding
	// extraFindings: further findings on the same document (another rule matched it)
	extraFindings []string
	docID         string // the document's _id (a finding's first matched document)
	source        string // falco | talon | hubble | k8s-audit | api
	at            time.Time
	ingested      time.Time // event.ingested, set by the sdp-final pipeline (for the ingest lag only)
	ref           string    // "<ns>_<pod>", only for the two sandbox namespaces
	synthetic     bool      // a P3 acceptance canary (pod ref or principal carries p3c-): never an incident

	rule   string   // the finding's Sigma rule title
	attack []string // ATT&CK ids from the finding's tags

	falcoRule, proc                     string
	talonAction, actionner, talonStatus string

	verdict, dropReason, direction, proto string
	port                                  int
	dns                                   bool  // a DNS lookup: an L7 DNS event the flag-shaped DNS rule fired on
	flag                                  *bool // DNS findings: the flag match when first read

	verb, resource, subresource, actor string
	auditID                            string // one request's id, shared by its stages
	code                               int
	operator                           bool // the request came from operatorUser, exactly

	apiAction, runID, state, arm, commandID, technique, objective, outcome string
	seq, commandSeq                                                        int
	exit                                                                   *int
}

var (
	podName  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	tagPat   = regexp.MustCompile(`^attack\.(t[0-9]{4}(\.[0-9]{3})?)$`)
	techPat  = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)
	runIDPat = regexp.MustCompile(`^[0-9a-f]{16}$`)
	idPat    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// splitRef reads a stored ref `<ns>_<pod>` (siem contract S0-#1), splitting at the first `_`: no
// namespace or pod name contains one. ok only for the guarded sandbox and the twin namespace and a
// pod name that is a DNS-1123 label; everything else is never published.
func (t *Tracker) splitRef(ref string) (ns, pod string, ok bool) {
	ns, pod, found := strings.Cut(ref, "_")
	if !found || (ns != t.cfg.Namespace && (t.cfg.UnguardedNamespace == "" || ns != t.cfg.UnguardedNamespace)) || !podName.MatchString(pod) {
		return "", "", false
	}
	return ns, pod, true
}

// publicRef is a kept ref as published: `<ns>/<pod>`.
func (t *Tracker) publicRef(ref string) string {
	ns, pod, ok := t.splitRef(ref)
	if !ok {
		return ""
	}
	return ns + "/" + pod
}

// lookup reads a dotted field from a document in either shape Fluent Bit may write: a flat key
// ("k8s.pod.ref") or nested objects ({"k8s":{"pod":{"ref":...}}}), or a mix (S0-b).
func lookup(m map[string]any, key string) any {
	if v, ok := m[key]; ok {
		return v
	}
	for i := 0; i < len(key); i++ {
		if key[i] != '.' {
			continue
		}
		if sub, ok := m[key[:i]].(map[string]any); ok {
			if v := lookup(sub, key[i+1:]); v != nil {
				return v
			}
		}
	}
	return nil
}

func str(m map[string]any, key string) string {
	s, _ := lookup(m, key).(string)
	return s
}

func num(m map[string]any, key string) (int, bool) {
	switch v := lookup(m, key).(type) {
	case float64:
		if v == math.Trunc(v) && math.Abs(v) < 1e9 {
			return int(v), true
		}
	case string:
		n, err := strconv.Atoi(v)
		return n, err == nil
	}
	return 0, false
}

func timeOf(m map[string]any, key string) time.Time {
	switch v := lookup(m, key).(type) {
	case string:
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			return t.UTC()
		}
	case float64:
		return time.UnixMilli(int64(v)).UTC()
	}
	return time.Time{}
}

// fill reads the allow-listed fields of one source from a document and returns the DNS query apart
// (it is used once, for the flag match, and never stored).
func (t *Tracker) fill(r *record, m map[string]any) (dnsQuery string) {
	if at := timeOf(m, "@timestamp"); !at.IsZero() {
		r.at = at
	}
	r.ingested = timeOf(m, "event.ingested")
	r.synthetic = syntheticRef.MatchString(str(m, "k8s.pod.ref")) || syntheticPrincipal.MatchString(str(m, "user.name"))
	if ref := str(m, "k8s.pod.ref"); ref != "" {
		if _, _, ok := t.splitRef(ref); ok {
			r.ref = ref
		}
	}
	switch r.source {
	case "falco":
		r.falcoRule, r.proc = str(m, "falco.rule"), str(m, "proc.name")
	case "talon":
		r.talonAction, r.actionner, r.talonStatus = str(m, "talon.action"), str(m, "talon.actionner"), str(m, "talon.status")
	case "hubble":
		r.verdict, r.dropReason, r.direction = str(m, "hubble.verdict"), str(m, "hubble.drop_reason"), str(m, "hubble.traffic_direction")
		r.proto = str(m, "hubble.l4.protocol")
		r.port, _ = num(m, "hubble.l4.destination_port")
		dnsQuery = str(m, "dns.query")
		// Only an L7 DNS event is a lookup: the exporter's field mask can leave a stale l7.dns.query on
		// an ordinary flow (a trace event, a drop to another port).
		eventType, _ := num(m, "hubble.event_type")
		r.dns = dnsQuery != "" && eventType == hubbleL7 && str(m, "hubble.l7.type") != ""
	case "k8s-audit":
		r.verb, r.resource, r.subresource = str(m, "audit.verb"), str(m, "audit.object.resource"), str(m, "audit.object.subresource")
		r.auditID = str(m, "audit.id")
		r.code, _ = num(m, "audit.response.code")
		r.operator = str(m, "user.name") == operatorUser
		switch str(m, "user.name") {
		case apiUser:
			r.actor = actorAPI
		case talonUser:
			r.actor = actorTalon
		default:
			r.actor = actorOther
		}
	case "api":
		r.apiAction, r.runID, r.state, r.arm = str(m, "event.action"), str(m, "api.run_id"), str(m, "api.state"), str(m, "api.arm")
		r.commandID, r.technique, r.objective, r.outcome = str(m, "api.command_id"), str(m, "api.technique"), str(m, "api.objective"), str(m, "api.outcome")
		r.seq, _ = num(m, "api.seq")
		r.commandSeq, _ = num(m, "api.command_seq")
		if n, ok := num(m, "api.exit_code"); ok {
			r.exit = &n
		}
		if !runIDPat.MatchString(r.runID) {
			r.runID = ""
		}
		if r.arm != "guarded" && r.arm != "unguarded" {
			r.arm = ""
		}
	}
	return dnsQuery
}

// fromFinding turns an SA finding into a record. ok is false when its document cannot be read or
// names no pod in the two sandbox namespaces.
func (t *Tracker) fromFinding(f siem.Finding, source string) (r record, dnsQuery string, ok bool) {
	if !idPat.MatchString(f.ID) {
		return record{}, "", false
	}
	r = record{key: "finding:" + f.ID, findingID: f.ID, source: source, at: time.UnixMilli(f.Timestamp).UTC()}
	if len(f.Queries) > 0 {
		r.rule = f.Queries[0].Name
	}
	dnsRule := false
	for _, q := range f.Queries {
		dnsRule = dnsRule || t.cfg.Rules.RuleID(q.Name) == dnsExfilRule
		for _, tag := range q.Tags {
			if m := tagPat.FindStringSubmatch(strings.ToLower(tag)); m != nil {
				r.attack = appendUnique(r.attack, strings.ToUpper(m[1]))
			}
		}
	}
	for _, d := range f.Documents {
		var m map[string]any
		if !d.Found || json.Unmarshal([]byte(d.Document), &m) != nil {
			continue
		}
		r.docID = d.ID
		dnsQuery = t.fill(&r, m)
		break
	}
	// A DNS lookup is a finding of the flag-shaped DNS rule on an L7 DNS event, nothing else.
	r.dns = r.dns && dnsRule
	if !r.dns {
		dnsQuery = ""
	}
	return r, dnsQuery, r.ref != "" && r.docID != "" && !r.synthetic
}

// fromHit turns a search hit into a record.
func (t *Tracker) fromHit(h siem.Hit, source string) (record, bool) {
	if !idPat.MatchString(h.ID) {
		return record{}, false
	}
	r := record{key: "doc:" + h.Index + "/" + h.ID, docID: h.ID, source: source}
	t.fill(&r, h.Source)
	r.dns = false // no rule fired on a document read by a search
	return r, r.ref != "" && !r.at.IsZero() && !r.synthetic
}

// The rules acceptance test's canary documents (P3) carry pod refs `sandbox_p3c-<tag>-*` and
// principals `system:p3c-<tag>`. They are written into the real streams to prove a rule fires; they are
// test data and must never become a public incident (ADR 0036). Both forms are matched whole and
// anchored, never as a substring: a ServiceAccount named p3c-y (system:serviceaccount:x:p3c-y) or a
// pod whose name merely contains p3c- must not be able to hide an exec or a probe from the page.
var (
	syntheticRef       = regexp.MustCompile(`^(sandbox|sandbox-unguarded)_p3c-[0-9a-z]+-`)
	syntheticPrincipal = regexp.MustCompile(`^system:p3c-[0-9a-z]+$`)
)

// isDoc: the record came from a search (it may carry a finding's rule once merged).
func (r *record) isDoc() bool { return strings.HasPrefix(r.key, "doc:") }

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
