package incidents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/siem"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/siemindex"
)

// The fixtures follow the shapes the SIEM really holds: siem/fields/*.yaml (allow-lists), the
// siemlog golden (app/api/internal/siemlog/testdata/lines.golden) for sdp-api, the F0 audit and
// Hubble fixtures (tests/siem/fixtures) and the S0 findings (findings-s0.json in internal/siem).
// Fields that must never be published are put in on purpose: the leak test reads the whole View.

var t0 = time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)

const (
	termRun   = "3755e65530aa11bb"
	termRef   = "sandbox_terminal-3755e65530"
	flagHex   = "0123456789abcdef"
	otherHex  = "fedcba9876543210"
	cmpRun    = "a1b2c3d4e5f60718"
	cmpRef    = "sandbox_shell-in-container-a1b2c3d4e5"
	twinRef   = "sandbox-unguarded_shell-in-container-a1b2c3d4e5-u"
	quarRun   = "b2c3d4e5f6071829"
	quarRef   = "sandbox_network-tool-b2c3d4e5f6"
	dnsRuleID = "9c41d2e7-8b3a-4f60-a1c5-0e7d6b2f9a48"
)

// fakeSource answers like the SIEM: findings by detection time, hits by event.ingested, each list cut
// to the requested size. It records every request.
type fakeSource struct {
	mu       sync.Mutex
	findings map[string][]siem.Finding
	corr     []siem.Correlation
	alerts   []siem.Alert
	hits     map[string][]siem.Hit
	sync     []siem.Hit
	rewrite  int
	fail     error
	calls    []call
}

type call struct {
	what     string
	from, to time.Time
	size     int
}

func newFake() *fakeSource {
	return &fakeSource{findings: map[string][]siem.Finding{}, hits: map[string][]siem.Hit{}}
}

func (f *fakeSource) Findings(_ context.Context, lt string, from, to time.Time, size int) ([]siem.Finding, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{"findings " + lt, from, to, size})
	if f.fail != nil {
		return nil, f.fail
	}
	var out []siem.Finding
	for _, x := range f.findings[lt] {
		at := time.UnixMilli(x.Timestamp)
		if !at.Before(from) && !at.After(to) {
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp > out[j].Timestamp })
	if len(out) > size {
		out = out[:size]
	}
	return out, nil
}

func (f *fakeSource) Correlations(_ context.Context, from, to time.Time) ([]siem.Correlation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{"correlations", from, to, 0})
	if f.fail != nil {
		return nil, f.fail
	}
	return f.corr, nil
}

func (f *fakeSource) MonitorAlerts(_ context.Context, state string, size int) ([]siem.Alert, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{"alerts " + state, time.Time{}, time.Time{}, size})
	if f.fail != nil {
		return nil, f.fail
	}
	var out []siem.Alert
	for _, a := range f.alerts {
		if state == "ALL" || a.State == state {
			out = append(out, a)
		}
	}
	if len(out) > size {
		out = out[:size]
	}
	return out, nil
}

func (f *fakeSource) Search(_ context.Context, indices []string, q siem.Query) (siem.SearchResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{fmt.Sprint("search ", indices), q.Since, q.Until, q.Size})
	if f.fail != nil {
		return siem.SearchResult{}, f.fail
	}
	if len(indices) == 1 && indices[0] == siem.SyncIndex {
		var out []siem.Hit
		for _, h := range f.sync {
			at := timeOf(h.Source, q.TimeField)
			if !at.Before(q.Since) && !at.After(q.Until) {
				out = append(out, h)
			}
		}
		return siem.SearchResult{Total: len(out), Hits: out}, nil
	}
	if q.Size == 0 {
		return siem.SearchResult{Total: f.rewrite}, nil
	}
	var out []siem.Hit
	for _, h := range f.hits[indices[0]] {
		at := timeOf(h.Source, "event.ingested")
		if !at.Before(q.Since) && !at.After(q.Until) {
			out = append(out, h)
		}
	}
	if len(out) > q.Size {
		out = out[:q.Size]
	}
	return siem.SearchResult{Total: len(out), Hits: out}, nil
}

func (f *fakeSource) callsOf(prefix string) []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []call
	for _, c := range f.calls {
		if len(c.what) >= len(prefix) && c.what[:len(prefix)] == prefix {
			out = append(out, c)
		}
	}
	return out
}

// clock is a settable time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func rulesIndex(t *testing.T) *siemindex.Index {
	t.Helper()
	ix, err := siemindex.Load()
	if err != nil {
		t.Fatal(err)
	}
	return ix
}

func newTracker(t *testing.T, src Source, clk *clock) *Tracker {
	t.Helper()
	return New(Config{Source: src, Rules: rulesIndex(t), Namespace: "sandbox", UnguardedNamespace: "sandbox-unguarded", Now: clk.Now})
}

var docSeq int

// finding builds an SA finding on one document, made 30 s after the event (a detector run); the document gets @timestamp at and the event
// fields, and is stored as SA stores it: a JSON string of the whole source.
func finding(id string, at time.Time, rule string, tags []string, doc map[string]any) siem.Finding {
	docSeq++
	doc["@timestamp"] = at.Format(time.RFC3339Nano)
	doc["event.ingested"] = at.Add(2 * time.Second).Format(time.RFC3339Nano)
	b, _ := json.Marshal(doc)
	return siem.Finding{ID: id, DetectorID: "det1", Timestamp: at.Add(30 * time.Second).UnixMilli(),
		Queries:   []siem.FindingQuery{{ID: "sa-" + id, Name: rule, Tags: append([]string{"high"}, tags...)}},
		Documents: []siem.FindingDoc{{ID: fmt.Sprintf("doc%04d", docSeq), Index: ".ds-sdp-x-000001", Found: true, Document: string(b)}}}
}

// hit builds a stream document read by a search; event.ingested is 3 s after the event.
func hit(index, id string, at time.Time, src map[string]any) siem.Hit {
	src["@timestamp"] = at.Format(time.RFC3339Nano)
	ev, _ := src["event"].(map[string]any)
	if ev == nil {
		ev = map[string]any{}
	}
	ev["ingested"], ev["overwrite"] = at.Add(3*time.Second).Format(time.RFC3339Nano), false
	src["event"] = ev
	// Through JSON, as the client decodes a search answer: numbers become float64.
	b, _ := json.Marshal(src)
	var decoded map[string]any
	_ = json.Unmarshal(b, &decoded)
	return siem.Hit{ID: id, Index: ".ds-" + index + "-000001", Source: decoded}
}

func apiCommand(id string, at time.Time, run, ref string, seq int, cmd, technique, objective, state string) siem.Hit {
	return hit("sdp-api", id, at, map[string]any{"event.action": "siem.command", "event.dataset": "api",
		"api": map[string]any{"run_id": run, "seq": seq, "command_id": cmd, "state": state, "technique": technique,
			"objective": objective, "outcome": "allowed"}, "k8s.pod.ref": ref})
}

func apiRun(id string, at time.Time, run, ref, state, arm string) siem.Hit {
	return hit("sdp-api", id, at, map[string]any{"event": map[string]any{"action": "siem.run"},
		"api.run_id": run, "api.state": state, "api.arm": arm, "api.scenario": "x", "k8s": map[string]any{"pod": map[string]any{"ref": ref}}})
}

func auditDoc(id string, at time.Time, ref, user, verb string, code int) siem.Hit {
	ns, pod, _ := cut(ref)
	return hit("sdp-k8s-audit", id, at, map[string]any{"audit": map[string]any{"verb": verb, "object": map[string]any{"resource": "pods", "name": pod},
		"response": map[string]any{"code": code}}, "k8s.ns.name": ns, "k8s.pod.name": pod, "k8s.pod.ref": ref,
		"user.name": user, "source.ip": "hm1:00aa11bb22cc33dd"})
}

func dropDoc(id string, at time.Time, ref string, port int) siem.Hit {
	return hit("sdp-hubble", id, at, map[string]any{"hubble": map[string]any{"verdict": "DROPPED", "drop_reason": "POLICY_DENIED",
		"traffic_direction": "EGRESS", "l4": map[string]any{"protocol": "udp", "destination_port": port}}, "k8s.pod.ref": ref})
}

func falcoFinding(id string, at time.Time, ref, rule string) siem.Finding {
	ns, pod, _ := cut(ref)
	return finding(id, at, "Falco "+rule, []string{"sdp_falco", "attack.t1552.001", "attack.credential_access"}, map[string]any{
		"falco": map[string]any{"rule": rule, "priority": "Warning"}, "proc.name": "cat", "proc.cmdline": "cat /srv/shop/.flag SDP{" + flagHex + "}",
		"k8s.ns.name": ns, "k8s.pod.name": pod, "k8s.pod.ref": ref, "hostname": "k3s01", "fd.name": "/etc/shadow"})
}

func talonFinding(id string, at time.Time, ref, action, actionner string) siem.Finding {
	return finding(id, at, "Talon action", []string{"sdp_talon"}, map[string]any{
		"talon": map[string]any{"action": action, "actionner": actionner, "status": "success", "rule": "Kill shell"}, "k8s.pod.ref": ref})
}

func dnsFinding(id string, at time.Time, ref, label string) siem.Finding {
	return finding(id, at, "DNS query carries an exfil label", []string{"sdp_hubble", "attack.t1048.003", "attack.t1071.004"}, map[string]any{
		"dns.query": label + ".x.exfil.sdp.test.", "dns.rcode": 3, "hubble.verdict": "FORWARDED", "hubble.traffic_direction": "EGRESS",
		"hubble.l4.protocol": "udp", "hubble.l4.destination_port": 53, "k8s.pod.ref": ref})
}

func cut(ref string) (string, string, bool) {
	for i := 0; i < len(ref); i++ {
		if ref[i] == '_' {
			return ref[:i], ref[i+1:], true
		}
	}
	return "", "", false
}

// terminalRun: whoami (recon), read-flag (credentials), dns-exfil (exfiltration) on the terminal pod,
// then the DNS finding with label (the run's flag or another).
func terminalRun(f *fakeSource, label string) {
	f.hits["sdp-api"] = append(f.hits["sdp-api"],
		apiRun("r1", t0, termRun, termRef, "started", ""),
		apiRun("r2", t0.Add(2400*time.Millisecond), termRun, termRef, "pod_ready", ""),
		apiCommand("c1", t0.Add(5*time.Second), termRun, termRef, 1, "whoami", "T1033", "recon", "started"),
		apiCommand("c2", t0.Add(9*time.Second), termRun, termRef, 2, "read-flag", "T1552.001", "credentials", "started"),
		apiCommand("c3", t0.Add(19*time.Second), termRun, termRef, 3, "dns-exfil", "T1048.003", "exfiltration", "started"),
		apiCommand("c4", t0.Add(19500*time.Millisecond), termRun, termRef, 3, "dns-exfil", "T1048.003", "exfiltration", "exited"),
	)
	f.findings["sdp_hubble"] = append(f.findings["sdp_hubble"], dnsFinding("f-dns-1", t0.Add(20101*time.Millisecond), termRef, label))
}

// compareRun: a one-click compare run of shell-in-container; the guarded pod is detected 800 ms after
// pod_ready and terminated by Talon 400 ms after the detection; the twin lives 14 s.
func compareRun(f *fakeSource) {
	f.hits["sdp-api"] = append(f.hits["sdp-api"],
		apiRun("p1", t0.Add(time.Hour), cmpRun, cmpRef, "started", "guarded"),
		apiRun("p2", t0.Add(time.Hour), cmpRun, twinRef, "started", "unguarded"),
		apiRun("p3", t0.Add(time.Hour+time.Second), cmpRun, cmpRef, "pod_ready", "guarded"),
	)
	f.findings["sdp_falco"] = append(f.findings["sdp_falco"],
		falcoFinding("f-falco-g", t0.Add(time.Hour+1800*time.Millisecond), cmpRef, "Terminal shell in container"),
		falcoFinding("f-falco-u", t0.Add(time.Hour+1900*time.Millisecond), twinRef, "Terminal shell in container"))
	f.findings["sdp_talon"] = append(f.findings["sdp_talon"],
		talonFinding("f-talon-g", t0.Add(time.Hour+2500*time.Millisecond), cmpRef, "Terminate Pod", "kubernetes:terminate"))
	f.hits["sdp-k8s-audit"] = append(f.hits["sdp-k8s-audit"],
		auditDoc("a1", t0.Add(time.Hour+2200*time.Millisecond), cmpRef, talonUser, "delete", 200),
		auditDoc("a2", t0.Add(time.Hour+100*time.Millisecond), twinRef, apiUser, "create", 201),
		auditDoc("a3", t0.Add(time.Hour+14100*time.Millisecond), twinRef, apiUser, "delete", 200))
}

// quarantineRun: network-tool, quarantined by Talon's label patch 300 ms after Falco; the first drop
// follows the patch by 300 ms.
func quarantineRun(f *fakeSource) {
	at := t0.Add(2 * time.Hour)
	f.hits["sdp-api"] = append(f.hits["sdp-api"],
		apiRun("q1", at, quarRun, quarRef, "started", ""),
		apiRun("q2", at.Add(time.Second), quarRun, quarRef, "pod_ready", ""))
	f.findings["sdp_falco"] = append(f.findings["sdp_falco"], falcoFinding("f-falco-q", at.Add(2*time.Second), quarRef, "SDP network tool in sandbox"))
	f.findings["sdp_talon"] = append(f.findings["sdp_talon"], talonFinding("f-talon-q", at.Add(2600*time.Millisecond), quarRef, "Quarantine Pod", "kubernetes:label"))
	f.hits["sdp-k8s-audit"] = append(f.hits["sdp-k8s-audit"], auditDoc("a4", at.Add(2300*time.Millisecond), quarRef, talonUser, "patch", 200))
	f.hits["sdp-hubble"] = append(f.hits["sdp-hubble"], dropDoc("h1", at.Add(2600*time.Millisecond), quarRef, 9))
}

func incidentsOf(v View, kind string) []Incident {
	var out []Incident
	for _, inc := range v.Incidents {
		if inc.Kind == kind {
			out = append(out, inc)
		}
	}
	return out
}

func one(t *testing.T, v View, kind string) Incident {
	t.Helper()
	list := incidentsOf(v, kind)
	if len(list) != 1 {
		b, _ := json.MarshalIndent(v.Incidents, "", " ")
		t.Fatalf("%d %s incidents, want 1: %s", len(list), kind, b)
	}
	return list[0]
}

var errDown = errors.New("connection refused")
