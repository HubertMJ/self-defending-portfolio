package incidents

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/siem"
)

func registerTerminalFlag(tr *Tracker, hex string) {
	tr.RegisterFlag(termRun, termRef, tr.FlagMAC("sdp-"+hex))
}

// S0-#1: refs are stored `<ns>_<pod>`, split at the first `_`, published `<ns>/<pod>`, and only for
// the two sandbox namespaces.
func TestPodRefMapping(t *testing.T) {
	tr := New(Config{Namespace: "sandbox", UnguardedNamespace: "sandbox-unguarded"})
	cases := map[string]string{
		"sandbox_shop-1":                          "sandbox/shop-1",
		"sandbox-unguarded_shop-1-u":              "sandbox-unguarded/shop-1-u",
		"kube-system_coredns-6d4b75cb6d-x2x9k":    "",
		"portfolio-api_portfolio-api-7c9d":        "",
		"sandboxx_shop-1":                         "",
		"sandbox_shop_1":                          "",
		"sandbox_":                                "",
		"sandbox":                                 "",
		"sandbox/shop-1":                          "",
		"_shop-1":                                 "",
		"sandbox_Shop-1":                          "",
		"sandbox_shop-1.svc":                      "",
		"sandbox_" + strings.Repeat("a", 64):      "",
		"sandbox_shop-1\u202e":                    "",
		"sandbox-unguarded_terminal-3755e65530-u": "sandbox-unguarded/terminal-3755e65530-u",
	}
	for in, want := range cases {
		if got := tr.publicRef(in); got != want {
			t.Errorf("publicRef(%q) = %q, want %q", in, got, want)
		}
	}
	// A finding on a pod outside the sandboxes is dropped as a whole.
	f := falcoFinding("f-x", t0, "kube-system_coredns-1", "Read sensitive file untrusted")
	if _, _, ok := tr.fromFinding(f, "falco"); ok {
		t.Fatal("a kube-system finding was kept")
	}
}

// Contained intrusion and dns-exfil are found from findings alone, without any SA correlation, and
// cite the correlation when SA made one (S0-#13, F17).
func TestJoinsWithoutAndWithSACorrelation(t *testing.T) {
	for _, withCorr := range []bool{false, true} {
		f := newFake()
		compareRun(f)
		terminalRun(f, "sdp-"+flagHex)
		// SA's api detector fired on the dns-exfil command line: its finding names that document.
		var apiDoc string
		for _, h := range f.hits["sdp-api"] {
			if h.ID == "c3" {
				apiDoc = h.ID
			}
		}
		af := finding("f-api-exfil", t0.Add(19*time.Second), "Terminal exfiltration command", []string{"sdp_api", "attack.t1048.003"}, map[string]any{"k8s.pod.ref": termRef})
		af.Documents[0].ID = apiDoc
		f.findings["sdp_api"] = []siem.Finding{af}
		if withCorr {
			f.corr = []siem.Correlation{
				{Finding1: "f-talon-g", Finding2: "f-falco-g", Rules: []string{"corr-contained"}},
				{Finding1: "f-dns-1", Finding2: "f-api-exfil", Rules: []string{"corr-dns"}},
			}
		}
		clk := &clock{t: t0.Add(2 * time.Hour)}
		tr := newTracker(t, f, clk)
		tr.Poll(context.Background())
		v := tr.View()
		ci := one(t, v, KindContainedIntrusion)
		dx := one(t, v, KindDNSExfil)
		for _, c := range []struct {
			inc  Incident
			corr string
		}{{ci, "corr-contained"}, {dx, "corr-dns"}} {
			cited := false
			for _, e := range c.inc.Evidence {
				if e.Type == "correlation" {
					if e.ID != c.corr {
						t.Errorf("%s cites correlation %q", c.inc.Kind, e.ID)
					}
					cited = true
				}
			}
			if cited != withCorr {
				t.Errorf("%s: correlation cited = %v, want %v", c.inc.Kind, cited, withCorr)
			}
		}
		// The api finding is the command line's finding, not a second step.
		var exfilSteps int
		for _, st := range dx.Steps {
			if strings.Contains(st.Detail, "command dns-exfil") {
				exfilSteps++
				if st.Rule != "Terminal exfiltration command" {
					t.Errorf("command step rule %q", st.Rule)
				}
			}
		}
		if exfilSteps != 1 {
			b, _ := json.MarshalIndent(dx, "", " ")
			t.Errorf("%d dns-exfil command steps: %s", exfilSteps, b)
		}
	}
}

func TestDNSExfilIncident(t *testing.T) {
	f := newFake()
	terminalRun(f, "sdp-"+flagHex)
	clk := &clock{t: t0}
	tr := newTracker(t, f, clk)
	registerTerminalFlag(tr, flagHex)
	clk.Set(t0.Add(70 * time.Second))
	tr.Poll(context.Background())
	v := tr.View()
	if !v.Available {
		t.Fatal("not available")
	}
	inc := one(t, v, KindDNSExfil)
	if inc.FlagMatch == nil || !*inc.FlagMatch || inc.Severity != "critical" || inc.FalcoEvents != 0 || inc.RunID != termRun {
		t.Fatalf("incident %+v", inc)
	}
	if !strings.Contains(inc.Title, "this run's secret left sandbox/terminal-3755e65530") || !strings.Contains(inc.Title, "Falco: no event") {
		t.Fatalf("title %q", inc.Title)
	}
	if len(inc.Steps) != 3 || inc.Steps[0].Detail != "command read-flag (T1552.001, credentials) started on sandbox/terminal-3755e65530" ||
		inc.Steps[2].Source != "hubble" || inc.Steps[2].CommandSeq == nil || *inc.Steps[2].CommandSeq != 3 {
		b, _ := json.MarshalIndent(inc.Steps, "", " ")
		t.Fatalf("steps %s", b)
	}
	if strings.Join(inc.Attack, ",") != "T1552.001,T1048.003,T1071.004" {
		t.Fatalf("attack %v", inc.Attack)
	}
	if inc.Evidence[len(inc.Evidence)-1] != (Evidence{Type: "finding", ID: "f-dns-1"}) {
		t.Fatalf("evidence %v", inc.Evidence)
	}
	if !inc.FirstAt.Equal(t0.Add(9*time.Second)) || !inc.LastAt.Equal(t0.Add(20101*time.Millisecond)) {
		t.Fatalf("times %v %v", inc.FirstAt, inc.LastAt)
	}
	// A Falco finding right after the command makes the claim "Falco: no event" false.
	f.findings["sdp_falco"] = append(f.findings["sdp_falco"], falcoFinding("f-falco-t", t0.Add(25*time.Second), termRef, "Terminal shell in container"))
	tr2 := newTracker(t, f, clk)
	tr2.Poll(context.Background())
	if inc := one(t, tr2.View(), KindDNSExfil); inc.FalcoEvents != 1 || strings.Contains(inc.Title, "no event") {
		t.Fatalf("with falco: %+v", inc)
	}
}

// F7: under quarantine the lookup carries no name; the command and the dropped packet to port 53
// make the incident, without a flag claim.
func TestDNSExfilUnderQuarantine(t *testing.T) {
	f := newFake()
	f.hits["sdp-api"] = append(f.hits["sdp-api"],
		apiRun("r1", t0, termRun, termRef, "started", ""),
		apiCommand("c3", t0.Add(19*time.Second), termRun, termRef, 3, "dns-exfil", "T1048.003", "exfiltration", "started"))
	f.hits["sdp-hubble"] = append(f.hits["sdp-hubble"], dropDoc("h1", t0.Add(19200*time.Millisecond), termRef, 53))
	tr := newTracker(t, f, &clock{t: t0.Add(time.Minute)})
	tr.Poll(context.Background())
	inc := one(t, tr.View(), KindDNSExfil)
	if inc.FlagMatch != nil || inc.Severity != "medium" || !strings.Contains(inc.Title, "under quarantine") || len(inc.Steps) != 2 {
		t.Fatalf("incident %+v", inc)
	}
	// A drop to another port, or one too late, is not the lookup.
	f.hits["sdp-hubble"] = []siem.Hit{dropDoc("h2", t0.Add(19200*time.Millisecond), termRef, 9), dropDoc("h3", t0.Add(40*time.Second), termRef, 53)}
	tr = newTracker(t, f, &clock{t: t0.Add(time.Minute)})
	tr.Poll(context.Background())
	if n := len(incidentsOf(tr.View(), KindDNSExfil)); n != 0 {
		t.Fatalf("%d dns-exfil incidents from unrelated drops", n)
	}
}

func TestFlagMatch(t *testing.T) {
	runEnd := t0.Add(30 * time.Second)
	// poll: the DNS query happens at dnsAt (its finding 30 s later), the tracker reads at readAt.
	poll := func(label string, register func(*Tracker), dnsAt, readAt time.Time) *bool {
		t.Helper()
		f := newFake()
		terminalRun(f, label)
		f.findings["sdp_hubble"] = []siem.Finding{dnsFinding("f-dns-1", dnsAt, termRef, label)}
		clk := &clock{t: t0}
		tr := newTracker(t, f, clk)
		register(tr)
		clk.Set(readAt)
		tr.Poll(context.Background())
		return one(t, tr.View(), KindDNSExfil).FlagMatch
	}
	reg := func(hex string) func(*Tracker) {
		return func(tr *Tracker) {
			registerTerminalFlag(tr, hex)
			tr.EndFlag(termRun, runEnd)
		}
	}
	check := func(name string, got *bool, want *bool) {
		t.Helper()
		switch {
		case (got == nil) != (want == nil):
			t.Errorf("%s: flag_match = %v, want %v", name, ptr(got), ptr(want))
		case got != nil && *got != *want:
			t.Errorf("%s: flag_match = %v, want %v", name, *got, *want)
		}
	}
	yes, no := true, false
	during := t0.Add(20 * time.Second)
	check("own flag", poll("sdp-"+flagHex, reg(flagHex), during, t0.Add(time.Minute)), &yes)
	check("upper-case query", poll("SDP-"+strings.ToUpper(flagHex), reg(flagHex), during, t0.Add(time.Minute)), &yes)
	check("another run's flag", poll("sdp-"+otherHex, reg(flagHex), during, t0.Add(time.Minute)), &no)
	// Leave right after the command: the run is over, the finding arrives 90 s later.
	check("finding read 90 s after the run", poll("sdp-"+flagHex, reg(flagHex), during, runEnd.Add(90*time.Second)), &yes)
	// The match is judged by the query's time, not by when the finding is read.
	check("query during the run, read 20 min after its end", poll("sdp-"+flagHex, reg(flagHex), during, runEnd.Add(20*time.Minute)), &yes)
	check("query during the run, read 23 h after its end", poll("sdp-"+flagHex, reg(flagHex), during, runEnd.Add(23*time.Hour)), &yes)
	// A query up to 15 min after the run's end still matches; later it does not.
	check("query 14:59 after the run", poll("sdp-"+flagHex, reg(flagHex), runEnd.Add(14*time.Minute+59*time.Second), runEnd.Add(16*time.Minute)), &yes)
	check("query 15:01 after the run", poll("sdp-"+flagHex, reg(flagHex), runEnd.Add(15*time.Minute+time.Second), runEnd.Add(16*time.Minute)), &no)
	// The same pod name in the twin namespace is another pod.
	twin := func(tr *Tracker) {
		tr.RegisterFlag(termRun, "sandbox-unguarded_terminal-3755e65530", tr.FlagMAC("sdp-"+flagHex))
	}
	check("same pod name in the twin namespace", poll("sdp-"+flagHex, twin, during, t0.Add(time.Minute)), &no)
	// Restart: the run registered with the previous process; this one started after the query.
	restart := func(tr *Tracker) { tr.start = t0.Add(40 * time.Second) }
	check("after a restart", poll("sdp-"+flagHex, restart, during, t0.Add(time.Minute)), nil)
	// The label must be exactly sdp-<16 hex>.
	check("malformed label", poll("sdp-"+flagHex+"aa", reg(flagHex), during, t0.Add(time.Minute)), &no)
}

// Registrations (MACs only) are kept for the evidence retention, then dropped.
func TestFlagRegistrationsExpire(t *testing.T) {
	clk := &clock{t: t0}
	tr := New(Config{Now: clk.Now})
	registerTerminalFlag(tr, flagHex)
	tr.EndFlag(termRun, t0)
	clk.Set(t0.Add(retention - time.Minute))
	tr.RegisterFlag("other", "sandbox_x", []byte{1})
	if len(tr.flags) != 2 {
		t.Fatalf("%d registrations before the retention ended", len(tr.flags))
	}
	clk.Set(t0.Add(retention + time.Minute))
	tr.RegisterFlag("third", "sandbox_y", []byte{1})
	if _, ok := tr.flags[termRun]; ok || len(tr.flags) != 2 {
		t.Fatalf("registrations after the retention: %d", len(tr.flags))
	}
}

func ptr(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

// The registration keeps only the MAC: the tracker never holds the flag.
func TestFlagRegistrationHoldsNoFlag(t *testing.T) {
	tr := New(Config{})
	registerTerminalFlag(tr, flagHex)
	b := fmt.Sprintf("%+v %x", *tr.flags[termRun], tr.flags[termRun].mac)
	if strings.Contains(b, flagHex) {
		t.Fatal("the flag is in the registration")
	}
}

func TestContainedIntrusionTTDAndTTI(t *testing.T) {
	f := newFake()
	compareRun(f)
	quarantineRun(f)
	tr := newTracker(t, f, &clock{t: t0.Add(3 * time.Hour)})
	tr.Poll(context.Background())
	v := tr.View()
	list := incidentsOf(v, KindContainedIntrusion)
	if len(list) != 2 {
		t.Fatalf("%d contained intrusions", len(list))
	}
	byRun := map[string]Incident{}
	for _, inc := range list {
		byRun[inc.RunID] = inc
	}
	// Terminate: TTD from pod_ready (a one-click run) to Falco, TTI from Falco to Talon's audited delete.
	del := byRun[cmpRun]
	if del.TTDMs == nil || *del.TTDMs != 800 || del.TTIMs == nil || *del.TTIMs != 400 || del.Arm != "guarded" {
		t.Fatalf("terminate: %+v", del)
	}
	if !strings.Contains(del.Title, "terminated by Talon in 400 ms") {
		t.Fatalf("title %q", del.Title)
	}
	// Quarantine: TTI from Talon's audited label patch, not from Talon's own log line (600 ms) or the
	// first drop (600 ms); the drop is its own step.
	q := byRun[quarRun]
	if q.TTIMs == nil || *q.TTIMs != 300 || !strings.Contains(q.Title, "quarantined by Talon in 300 ms") {
		t.Fatalf("quarantine: %+v", q)
	}
	var enforced *Step
	for i, st := range q.Steps {
		if strings.HasPrefix(st.Detail, "policy enforced +300 ms") {
			enforced = &q.Steps[i]
		}
	}
	if enforced == nil || enforced.Source != "hubble" {
		b, _ := json.MarshalIndent(q.Steps, "", " ")
		t.Fatalf("no policy-enforced step: %s", b)
	}
	if q.FalcoEvents != 1 {
		t.Fatalf("falco events %d", q.FalcoEvents)
	}
	if v.Metrics.MedianTTIMs == nil || *v.Metrics.MedianTTIMs != 350 || v.Metrics.MedianTTDMs == nil || *v.Metrics.MedianTTDMs != 900 {
		t.Fatalf("metrics %+v ttd=%v tti=%v", v.Metrics, v.Metrics.MedianTTDMs, v.Metrics.MedianTTIMs)
	}
	// Without Talon's audit record there is no TTI: Talon's log line is not the anchor.
	f.hits["sdp-k8s-audit"] = nil
	tr = newTracker(t, f, &clock{t: t0.Add(3 * time.Hour)})
	tr.Poll(context.Background())
	for _, inc := range incidentsOf(tr.View(), KindContainedIntrusion) {
		if inc.TTIMs != nil {
			t.Fatalf("TTI without an audited response: %+v", inc)
		}
	}
}

func TestContainedIntrusionNeedsTalon(t *testing.T) {
	f := newFake()
	compareRun(f)
	f.findings["sdp_talon"] = nil
	tr := newTracker(t, f, &clock{t: t0.Add(2 * time.Hour)})
	tr.Poll(context.Background())
	if n := len(incidentsOf(tr.View(), KindContainedIntrusion)); n != 0 {
		t.Fatalf("%d contained intrusions without Talon", n)
	}
}

func TestTwinDwell(t *testing.T) {
	f := newFake()
	compareRun(f)
	tr := newTracker(t, f, &clock{t: t0.Add(2 * time.Hour)})
	tr.Poll(context.Background())
	v := tr.View()
	inc := one(t, v, KindTwinDwell)
	if inc.Arm != "unguarded" || inc.RunID != cmpRun || inc.TTIMs == nil || *inc.TTIMs != 400 || inc.FalcoEvents != 1 {
		t.Fatalf("twin dwell %+v", inc)
	}
	if !strings.Contains(inc.Title, "sandbox-unguarded/shell-in-container-a1b2c3d4e5-u ran 14.0 s") || !strings.Contains(inc.Title, "isolated in 400 ms") {
		t.Fatalf("title %q", inc.Title)
	}
	if v.Metrics.MedianTwinDwellMs == nil || *v.Metrics.MedianTwinDwellMs != 14000 {
		t.Fatalf("dwell metric %v", v.Metrics.MedianTwinDwellMs)
	}
}

func TestStagedAttack(t *testing.T) {
	f := newFake()
	terminalRun(f, "sdp-"+flagHex)
	tr := newTracker(t, f, &clock{t: t0.Add(time.Minute)})
	tr.Poll(context.Background())
	inc := one(t, tr.View(), KindStagedAttack)
	if inc.RunID != termRun || inc.Severity != "high" || len(inc.Steps) != 3 || !strings.Contains(inc.Title, "whoami, then read-flag, then dns-exfil") {
		t.Fatalf("staged attack %+v", inc)
	}
	// Order violated: credentials before any recon - no staged attack.
	f = newFake()
	f.hits["sdp-api"] = []siem.Hit{
		apiCommand("c1", t0.Add(5*time.Second), termRun, termRef, 1, "read-flag", "T1552.001", "credentials", "started"),
		apiCommand("c2", t0.Add(9*time.Second), termRun, termRef, 2, "whoami", "T1033", "recon", "started"),
		apiCommand("c3", t0.Add(19*time.Second), termRun, termRef, 3, "dns-exfil", "T1048.003", "exfiltration", "started"),
	}
	tr = newTracker(t, f, &clock{t: t0.Add(time.Minute)})
	tr.Poll(context.Background())
	if n := len(incidentsOf(tr.View(), KindStagedAttack)); n != 0 {
		t.Fatalf("%d staged attacks out of order", n)
	}
	// Same timestamp is not "then".
	f.hits["sdp-api"] = []siem.Hit{
		apiCommand("c1", t0.Add(5*time.Second), termRun, termRef, 1, "whoami", "T1033", "recon", "started"),
		apiCommand("c2", t0.Add(5*time.Second), termRun, termRef, 2, "read-flag", "T1552.001", "credentials", "started"),
		apiCommand("c3", t0.Add(19*time.Second), termRun, termRef, 3, "dns-exfil", "T1048.003", "exfiltration", "started"),
	}
	tr = newTracker(t, f, &clock{t: t0.Add(time.Minute)})
	tr.Poll(context.Background())
	if n := len(incidentsOf(tr.View(), KindStagedAttack)); n != 0 {
		t.Fatalf("%d staged attacks with simultaneous steps", n)
	}
}

func TestExecOutsideAPI(t *testing.T) {
	f := newFake()
	exec := func(id string, at time.Time, ref, sub, user, auditID, stage string) siem.Finding {
		return finding(id, at, "Exec into a sandbox pod not by the API", []string{"sdp_k8s_audit", "attack.t1609"}, map[string]any{
			"audit.id": auditID, "audit.stage": stage, "audit.verb": "create", "audit.object.resource": "pods",
			"audit.object.subresource": sub, "audit.response.code": 101, "k8s.pod.ref": ref, "user.name": user, "source.ip": "hm1:0011223344556677"})
	}
	f.findings["sdp_k8s_audit"] = []siem.Finding{
		// One kubectl exec, audited at ResponseStarted and at ResponseComplete under one audit id.
		exec("f-exec-1a", t0, quarRef, "exec", "system:admin", "aud-1", "ResponseStarted"),
		exec("f-exec-1b", t0, quarRef, "exec", "system:admin", "aud-1", "ResponseComplete"),
		// The API's own exec is not one.
		exec("f-exec-api", t0.Add(time.Second), quarRef, "exec", apiUser, "aud-2", "ResponseComplete"),
		// A second session on the same pod, by a person (pseudonymised).
		exec("f-exec-3", t0.Add(5*time.Second), quarRef, "exec", "hm1:8899aabbccddeeff", "aud-3", "ResponseComplete"),
		// Attach and port-forward on other pods.
		exec("f-attach", t0, cmpRef, "attach", "system:admin", "aud-4", "ResponseComplete"),
		exec("f-pf", t0, termRef, "portforward", "system:admin", "aud-5", "ResponseComplete"),
		// Not a session: a log read.
		exec("f-log", t0, twinRef, "log", "system:admin", "aud-6", "ResponseComplete"),
	}
	tr := newTracker(t, f, &clock{t: t0.Add(time.Minute)})
	tr.Poll(context.Background())
	byTitle := map[string]Incident{}
	for _, inc := range incidentsOf(tr.View(), KindExecOutsideAPI) {
		byTitle[inc.Title] = inc
	}
	if len(byTitle) != 3 {
		t.Fatalf("%d exec-outside-api incidents, want 3 (one per pod): %v", len(byTitle), byTitle)
	}
	two := byTitle["2 exec/attach/port-forward sessions into sandbox/network-tool-b2c3d4e5f6 outside the API"]
	// The two sessions publish the same evidence (the principal never is): one step, counted twice,
	// at the first session's time; last_at is the second's.
	if len(two.Steps) != 1 || two.Steps[0].Detail != "create pods/exec on sandbox/network-tool-b2c3d4e5f6 not by the API, response 101" ||
		two.Steps[0].Count != 2 || !two.Steps[0].At.Equal(t0) || !two.LastAt.Equal(t0.Add(5*time.Second)) || len(two.Evidence) != 3 {
		t.Fatalf("two sessions: %+v", two)
	}
	if _, ok := byTitle["Attach to sandbox/shell-in-container-a1b2c3d4e5 outside the API"]; !ok {
		t.Errorf("no attach incident: %v", byTitle)
	}
	if _, ok := byTitle["Port-forward to sandbox/terminal-3755e65530 outside the API"]; !ok {
		t.Errorf("no port-forward incident: %v", byTitle)
	}
}

func TestMonitorIncidentsAndHealth(t *testing.T) {
	f := newFake()
	terminalRun(f, "sdp-"+flagHex)
	st := t0.Add(30 * time.Second).UnixMilli()
	end := t0.Add(90 * time.Second).UnixMilli()
	old := t0.Add(-25 * time.Hour).UnixMilli()
	f.alerts = []siem.Alert{
		{ID: "al-probe", MonitorName: "sdp-git: policy probing", State: "COMPLETED", StartTime: &st, EndTime: &end,
			Agg: &siem.AlertAgg{BucketKeys: []any{"hm1:0011223344556677"}}},
		{ID: "al-prev", MonitorName: "sdp-git: prevented-not-detected", State: "ACTIVE", StartTime: &st,
			Agg: &siem.AlertAgg{BucketKeys: []any{termRef, "kube-system_x"}}},
		{ID: "al-miss", MonitorName: "sdp-git: detection-missing", State: "ERROR", StartTime: &st},
		{ID: "al-old", MonitorName: "sdp-git: detection-missing", State: "COMPLETED", StartTime: &old},
		{ID: "al-other", MonitorName: "sdp-git: something else", State: "ACTIVE", StartTime: &st},
		{ID: "al-ops", MonitorName: "ingest silent falco", State: "ACTIVE", StartTime: &st},
	}
	f.sync = []siem.Hit{
		{ID: "s1", Source: map[string]any{"commit": strings.Repeat("a", 40), "applied_at": t0.Add(-time.Hour).Format(time.RFC3339), "status": "applied"}},
		{ID: "s2", Source: map[string]any{"commit": strings.Repeat("b", 40), "applied_at": t0.Format(time.RFC3339), "status": "refused"}},
	}
	f.sync = append(f.sync, hbHit(t0.Add(time.Minute), "unchanged", strings.Repeat("a", 40)))
	f.rewrite = 1
	tr := newTracker(t, f, &clock{t: t0.Add(2 * time.Minute)})
	tr.Poll(context.Background())
	v := tr.View()
	probe := one(t, v, KindPolicyProbing)
	if probe.Severity != "medium" || len(probe.Steps) != 2 || probe.Steps[0].Source != "k8s-audit" || probe.Steps[0].Rule != "policy probing" ||
		probe.Evidence[0] != (Evidence{Type: "alert", ID: "al-probe"}) || probe.RunID != "" {
		t.Fatalf("policy probing %+v", probe)
	}
	prev := one(t, v, KindPreventedNotDetected)
	if prev.RunID != termRun || !strings.HasSuffix(prev.Title, "on sandbox/terminal-3755e65530") || strings.Contains(prev.Title, "kube-system") {
		t.Fatalf("prevented %+v", prev)
	}
	if n := len(incidentsOf(v, KindDetectionMissing)); n != 0 {
		t.Fatalf("%d detection-missing incidents from an ERROR and a 25 h old alert", n)
	}
	if v.Health != (HealthView{Ingest: "silent", EvidenceRewritten: true, Disk: "ok"}) {
		t.Fatalf("health %+v", v.Health)
	}
	if v.Rules.Status != "refused" || v.Rules.Commit != strings.Repeat("a", 40) || v.Rules.AppliedAt == nil || !v.Rules.AppliedAt.Equal(t0.Add(-time.Hour)) {
		t.Fatalf("rules %+v", v.Rules)
	}
	f.alerts = []siem.Alert{{ID: "al-disk", MonitorName: "disk watermark", State: "ACTIVE", StartTime: &st},
		{ID: "al-ops2", MonitorName: "ingest silent api", State: "COMPLETED", StartTime: &st}}
	tr.Poll(context.Background())
	if h := tr.View().Health; h.Ingest != "ok" || h.Disk != "high" {
		t.Fatalf("health %+v", h)
	}
}

// The window: a 24 h backfill with at most 500 items per type first, then [last success - 2 min,
// now]; evidence read twice is kept once.
func TestPollWindowBackfillAndDedup(t *testing.T) {
	f := newFake()
	terminalRun(f, "sdp-"+flagHex)
	for i := 0; i < 700; i++ {
		at := t0.Add(-time.Duration(i) * time.Minute)
		f.findings["sdp_host"] = append(f.findings["sdp_host"], siem.Finding{ID: fmt.Sprintf("host-%d", i), Timestamp: at.UnixMilli()})
	}
	clk := &clock{t: t0.Add(time.Minute)}
	tr := newTracker(t, f, clk)
	tr.Poll(context.Background())
	for _, c := range f.callsOf("findings") {
		if !c.from.Equal(t0.Add(time.Minute-24*time.Hour)) || c.size != 500 {
			t.Fatalf("backfill call %+v", c)
		}
	}
	for _, c := range f.callsOf("search [sdp-") {
		if c.size > 500 || c.to.Sub(c.from) > 24*time.Hour {
			t.Fatalf("search call %+v", c)
		}
	}
	if v := tr.View(); v.Metrics.HostFindings != 500 {
		t.Fatalf("host findings %d, want the 500 cap", v.Metrics.HostFindings)
	}
	before := len(tr.records)
	f.calls = nil
	clk.Set(t0.Add(time.Minute + 15*time.Second))
	tr.Poll(context.Background())
	for _, c := range f.callsOf("findings") {
		if !c.from.Equal(t0.Add(time.Minute-2*time.Minute)) || !c.to.Equal(t0.Add(time.Minute+15*time.Second)) {
			t.Fatalf("window call %+v", c)
		}
	}
	if len(tr.records) != before {
		t.Fatalf("records %d -> %d after re-reading the overlap", before, len(tr.records))
	}
	if n := len(incidentsOf(tr.View(), KindDNSExfil)); n != 1 {
		t.Fatalf("%d dns-exfil incidents after two polls", n)
	}
	// Evidence older than 24 h goes.
	clk.Set(t0.Add(25 * time.Hour))
	tr.Poll(context.Background())
	if len(tr.records) != 0 || len(tr.View().Incidents) != 0 {
		t.Fatalf("%d records, %d incidents after 25 h", len(tr.records), len(tr.View().Incidents))
	}
}

func TestCaps(t *testing.T) {
	f := newFake()
	for i := 0; i < 260; i++ {
		f.findings["sdp_k8s_audit"] = append(f.findings["sdp_k8s_audit"], finding(fmt.Sprintf("ex-%d", i), t0.Add(time.Duration(i)*time.Second),
			"Exec", nil, map[string]any{"audit.object.subresource": "exec", "audit.object.resource": "pods", "k8s.pod.ref": fmt.Sprintf("sandbox_p-%d", i), "user.name": "system:admin"}))
	}
	// 70 different Falco rules: steps that are not the same evidence, so none collapses.
	for i := 0; i < 70; i++ {
		f.findings["sdp_falco"] = append(f.findings["sdp_falco"], falcoFinding(fmt.Sprintf("fa-%d", i), t0.Add(time.Duration(i)*time.Second), cmpRef, fmt.Sprintf("Terminal shell %d", i)))
	}
	f.findings["sdp_talon"] = []siem.Finding{talonFinding("ta", t0.Add(time.Second), cmpRef, "Terminate Pod", "kubernetes:terminate")}
	tr := newTracker(t, f, &clock{t: t0.Add(time.Hour)})
	tr.Poll(context.Background())
	v := tr.View()
	if len(v.Incidents) != maxIncidents || v.Metrics.Incidents != maxIncidents {
		t.Fatalf("%d incidents, want %d", len(v.Incidents), maxIncidents)
	}
	// Newest first.
	for i := 1; i < len(v.Incidents); i++ {
		if v.Incidents[i].FirstAt.After(v.Incidents[i-1].FirstAt) {
			t.Fatal("not newest first")
		}
	}
	tr2 := newTracker(t, &fakeSource{findings: map[string][]siem.Finding{"sdp_falco": f.findings["sdp_falco"], "sdp_talon": f.findings["sdp_talon"]}, hits: map[string][]siem.Hit{}}, &clock{t: t0.Add(time.Hour)})
	tr2.Poll(context.Background())
	ci := one(t, tr2.View(), KindContainedIntrusion)
	if len(ci.Steps) != maxSteps || len(ci.Evidence) > maxEvidence {
		t.Fatalf("%d steps, %d evidence", len(ci.Steps), len(ci.Evidence))
	}
}

func TestAvailability(t *testing.T) {
	// Unconfigured: available:false, checked_at null, everything empty.
	v := New(Config{}).View()
	b, _ := json.Marshal(v)
	want := `{"available":false,"checked_at":null,"rules":{"commit":"","applied_at":null,"status":"unknown"},"health":{"ingest":"unknown","evidence_rewritten":false,"disk":"unknown"},"metrics":{"since":null,"incidents":0,"median_ttd_ms":null,"median_tti_ms":null,"median_twin_dwell_ms":null,"host_findings":0,"ingest_lag_ms":null},"incidents":[]}`
	if string(b) != want {
		t.Fatalf("unconfigured:\n%s\nwant\n%s", b, want)
	}
	f := newFake()
	terminalRun(f, "sdp-"+flagHex)
	clk := &clock{t: t0.Add(time.Minute)}
	tr := newTracker(t, f, clk)
	if tr.View().Available {
		t.Fatal("available before the first poll")
	}
	tr.Poll(context.Background())
	if !tr.View().Available {
		t.Fatal("not available after a poll")
	}
	// The SIEM stops: still available for 45 s (one slow poll does not hide the section), then not.
	f.fail = errDown
	clk.Set(t0.Add(time.Minute + 30*time.Second))
	tr.Poll(context.Background())
	if !tr.View().Available {
		t.Fatal("hidden after one failed poll")
	}
	clk.Set(t0.Add(time.Minute + 46*time.Second))
	tr.Poll(context.Background())
	v = tr.View()
	if v.Available || len(v.Incidents) != 0 || v.Rules.Status != "unknown" || v.CheckedAt == nil || !v.CheckedAt.Equal(t0.Add(time.Minute+46*time.Second)) {
		t.Fatalf("down: %+v", v)
	}
	// It comes back.
	f.fail = nil
	clk.Set(t0.Add(2 * time.Minute))
	tr.Poll(context.Background())
	if v := tr.View(); !v.Available || len(v.Incidents) == 0 {
		t.Fatalf("back: %+v", v)
	}
	// A log type without a detector (404) is not an outage; a 403 is.
	f.fail = nil
	src := &statusSource{fakeSource: f, code: 404}
	tr = newTracker(t, src, clk)
	tr.Poll(context.Background())
	if !tr.View().Available {
		t.Fatal("a 404 for one log type hid the section")
	}
	src.code = 403
	tr = newTracker(t, src, clk)
	tr.Poll(context.Background())
	if tr.View().Available {
		t.Fatal("a 403 counted as success")
	}
}

type statusSource struct {
	*fakeSource
	code int
}

func (s *statusSource) Findings(ctx context.Context, lt string, from, to time.Time, size int) ([]siem.Finding, error) {
	if lt == "sdp_host" {
		return nil, &siem.StatusError{Method: "GET", Path: siem.PathFindings, Code: s.code}
	}
	return s.fakeSource.Findings(ctx, lt, from, to, size)
}

// Run polls at once and then on its interval, and stops with its context.
func TestRunPollsAndStops(t *testing.T) {
	f := newFake()
	tr := New(Config{Source: f, Interval: 10 * time.Millisecond, Rules: rulesIndex(t)})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { tr.Run(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for len(f.callsOf("correlations")) < 3 {
		if time.Now().After(deadline) {
			t.Fatal("Run did not poll repeatedly")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	New(Config{}).Run(context.Background()) // no SIEM: returns at once
}

// The leak test (siem contract P4, M9): the whole View, built from fixtures that carry every kind of
// value ADR 0021 never publishes - in fields outside the allow-lists and inside allowed ones.
func TestViewLeaksNothing(t *testing.T) {
	f := newFake()
	compareRun(f)
	quarantineRun(f)
	terminalRun(f, "sdp-"+flagHex)
	poison := "k3s01 siem01 10.4.2.10 10.42.0.77 fd00::1 coredns.kube-system.svc.cluster.local kubernetes.default.svc " +
		"SDP{" + flagHex + "} sdp-" + flagHex + " hm1:0011223344556677 system:serviceaccount:portfolio-api:portfolio-api ServiceAccount " +
		"https://10.43.0.1:443/api node_k3s01 siem01-data service-account service_account"
	f.findings["sdp_falco"] = append(f.findings["sdp_falco"], finding("f-poison", t0.Add(25*time.Second), "Falco "+poison, []string{"attack.t1059"},
		map[string]any{"falco.rule": poison, "proc.name": poison, "k8s.pod.ref": termRef, "user.name": "operator", "source.ip": "10.1.1.250",
			"hostname": "k3s01", "dns.query": "sdp-" + flagHex + ".x.exfil.sdp.test."}))
	f.findings["sdp_talon"] = append(f.findings["sdp_talon"], talonFinding("f-talon-p", t0.Add(26*time.Second), termRef, poison, poison))
	f.hits["sdp-k8s-audit"] = append(f.hits["sdp-k8s-audit"], hit("sdp-k8s-audit", "a9", t0.Add(27*time.Second), map[string]any{
		"audit.verb": "patch " + poison, "audit.object.resource": "pods", "k8s.pod.ref": termRef, "user.name": talonUser, "source.ip": "hm1:aabbccddeeff0011"}))
	f.hits["sdp-hubble"] = append(f.hits["sdp-hubble"], hit("sdp-hubble", "h9", t0.Add(28*time.Second), map[string]any{
		"hubble.verdict": "DROPPED", "hubble.drop_reason": poison, "k8s.pod.ref": termRef, "dns.query": "sdp-" + flagHex + ".x.exfil.sdp.test."}))
	// A second lookup of the run's DNS query, its direction poisoned: one step with f-dns-1, whose
	// detail lists both directions.
	f.findings["sdp_hubble"] = append(f.findings["sdp_hubble"], finding("f-dns-p", t0.Add(20200*time.Millisecond), "DNS query carries an exfil label", nil,
		map[string]any{"dns.query": "sdp-" + flagHex + ".x.exfil.sdp.test.", "hubble.verdict": "FORWARDED", "hubble.traffic_direction": poison,
			"hubble.l4.protocol": "udp", "hubble.l4.destination_port": 53, "k8s.pod.ref": termRef}))
	f.alerts = []siem.Alert{{ID: "al-p", MonitorName: "sdp-git: policy probing " + poison, State: "ACTIVE", StartTime: ptrInt(t0.UnixMilli()),
		Agg: &siem.AlertAgg{BucketKeys: []any{"hm1:0011223344556677", "system:serviceaccount:x:y"}}}}
	clk := &clock{t: t0}
	tr := newTracker(t, f, clk)
	registerTerminalFlag(tr, flagHex)
	clk.Set(t0.Add(3 * time.Hour))
	tr.Poll(context.Background())
	v := tr.View()
	if len(v.Incidents) < 6 {
		t.Fatalf("only %d incidents: the leak test must see every kind", len(v.Incidents))
	}
	if dx := one(t, v, KindDNSExfil); !hasStep(dx, "DNS query under the exfil zone") || dx.Steps[len(dx.Steps)-1].Count != 2 {
		t.Fatalf("the leak test must see a collapsed step: %+v", dx.Steps)
	}
	b, _ := json.Marshal(v)
	for _, ip := range ipv4.FindAllString(string(b), -1) {
		if !strings.HasPrefix(ip, "127.") {
			t.Errorf("published IPv4 %q", ip)
		}
	}
	for _, re := range leakPatterns {
		if m := re.FindString(string(b)); m != "" {
			t.Errorf("published %q (pattern %s)", m, re)
		}
	}
	for _, s := range []string{"operator", "10.1.1.250", "/etc/shadow", "/srv/shop/.flag", "exfil.sdp.test"} {
		if strings.Contains(string(b), s) {
			t.Errorf("published %q", s)
		}
	}
}

var ipv4 = regexp.MustCompile(`\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b`)

// leakPatterns: ADR 0021's never-publish list as the contract's P4 leak test states it.
var leakPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\.svc\b`),
	regexp.MustCompile(`cluster\.local`),
	regexp.MustCompile(`(?i)k3s01|siem01`),
	regexp.MustCompile(`(?i)system:serviceaccount`),
	regexp.MustCompile(`(?i)service[\s_-]?account`),
	regexp.MustCompile(`(?i)hm1:`),
	regexp.MustCompile(`(?i)sdp-[0-9a-f]{16}`),
	regexp.MustCompile(`SDP\{`),
	regexp.MustCompile(`(?i)fd00::1`),
}

func ptrInt(v int64) *int64 { return &v }

// A flag match is made once, when the finding is first read: a later re-read of the same finding
// (a window widened by an outage) does not turn it false after the registration expired.
func TestFlagMatchIsKept(t *testing.T) {
	f := newFake()
	terminalRun(f, "sdp-"+flagHex)
	clk := &clock{t: t0}
	tr := newTracker(t, f, clk)
	registerTerminalFlag(tr, flagHex)
	tr.EndFlag(termRun, t0.Add(30*time.Second))
	clk.Set(t0.Add(time.Minute))
	tr.Poll(context.Background())
	f.fail = errDown
	clk.Set(t0.Add(10 * time.Minute))
	tr.Poll(context.Background())
	f.fail = nil
	clk.Set(t0.Add(30 * time.Minute))
	tr.Poll(context.Background())
	if c := f.callsOf("findings sdp_hubble"); !c[len(c)-1].from.Equal(t0.Add(-time.Minute)) {
		t.Fatalf("the window after the outage starts at %v", c[len(c)-1].from)
	}
	if m := one(t, tr.View(), KindDNSExfil).FlagMatch; m == nil || !*m {
		t.Fatalf("flag match after a re-read: %v", ptr(m))
	}
}

// The sync writes a record only when it has work: an applied record 8 days old is still the rules in
// effect, and a poll that finds no record keeps what was read before.
func TestRulesHealthSurvivesQuietWeeks(t *testing.T) {
	f := newFake()
	commit := strings.Repeat("c", 40)
	f.sync = []siem.Hit{{ID: "s1", Source: map[string]any{"commit": commit, "applied_at": t0.Add(-8 * 24 * time.Hour).Format(time.RFC3339), "status": "applied"}},
		hbHit(t0.Add(-time.Minute), "unchanged", commit)}
	clk := &clock{t: t0}
	tr := newTracker(t, f, clk)
	tr.Poll(context.Background())
	if r := tr.View().Rules; r.Status != "applied" || r.Commit != commit {
		t.Fatalf("8-day-old record: %+v", r)
	}
	// 40 days later the record is past any search range: the last known state stands.
	clk.Set(t0.Add(40 * 24 * time.Hour))
	f.sync[1] = hbHit(clk.Now().Add(-time.Minute), "unchanged", commit)
	tr.Poll(context.Background())
	if r := tr.View().Rules; r.Status != "applied" || r.Commit != commit {
		t.Fatalf("no record in range: %+v", r)
	}
	// A newer refused record changes the status, the applied commit stays.
	f.sync = append(f.sync, siem.Hit{ID: "s2", Source: map[string]any{"commit": strings.Repeat("d", 40), "applied_at": clk.Now().Add(-time.Minute).Format(time.RFC3339), "status": "refused"}})
	tr.Poll(context.Background())
	if r := tr.View().Rules; r.Status != "refused" || r.Commit != commit {
		t.Fatalf("refused after applied: %+v", r)
	}
}

// Hubble drops are capped apart from DNS findings, and a settled drop no check reads is not kept: a
// quarantined pod's drop flood never pushes a DNS finding or the policy-enforced drop out.
func TestHubbleDropsCappedApart(t *testing.T) {
	f := newFake()
	quarantineRun(f) // Talon patch at t0+2h+2.3 s, first drop at +2.6 s
	terminalRun(f, "sdp-"+flagHex)
	clk := &clock{t: t0.Add(2*time.Hour + time.Minute)}
	tr := newTracker(t, f, clk)
	tr.Poll(context.Background())
	// A flood of later drops on the quarantined pod, past the cap.
	tr.mu.Lock()
	for i := 0; i < maxPerSource+500; i++ {
		r := &record{key: fmt.Sprintf("doc:flood/%d", i), docID: fmt.Sprintf("fl%d", i), source: "hubble", ref: quarRef,
			at: t0.Add(2*time.Hour + 3*time.Second + time.Duration(i)*time.Millisecond), verdict: "DROPPED", port: 9}
		tr.records[r.key] = r
	}
	tr.prune(clk.Now())
	n := len(tr.records)
	tr.mu.Unlock()
	if n > maxPerSource+50 {
		t.Fatalf("%d records kept", n)
	}
	clk.Set(t0.Add(2*time.Hour + 15*time.Minute))
	tr.Poll(context.Background())
	tr.mu.Lock()
	drops := 0
	for _, r := range tr.records {
		if r.source == "hubble" && !r.dns {
			drops++
		}
	}
	tr.mu.Unlock()
	if drops != 1 {
		t.Fatalf("%d settled drops kept, want only the policy-enforced one", drops)
	}
	v := tr.View()
	if inc := one(t, v, KindDNSExfil); inc.Evidence[len(inc.Evidence)-1].ID != "f-dns-1" {
		t.Fatalf("dns finding lost: %+v", inc)
	}
	for _, inc := range incidentsOf(v, KindContainedIntrusion) {
		if inc.RunID != quarRun {
			continue
		}
		found := false
		for _, st := range inc.Steps {
			found = found || strings.HasPrefix(st.Detail, "policy enforced +300 ms")
		}
		if !found {
			t.Fatalf("policy-enforced drop pruned: %+v", inc.Steps)
		}
	}
}

// A page that comes back full and a log type without a detector are logged once each, not every poll.
func TestPollNotesLoggedOnce(t *testing.T) {
	f := newFake()
	for i := 0; i < pageSize; i++ {
		f.hits["sdp-hubble"] = append(f.hits["sdp-hubble"], dropDoc(fmt.Sprintf("hd%d", i), t0.Add(time.Duration(i)*time.Millisecond), quarRef, 9))
	}
	var buf strings.Builder
	var mu sync.Mutex
	log := slog.New(slog.NewTextHandler(&lockedWriter{w: &buf, mu: &mu}, nil))
	clk := &clock{t: t0.Add(time.Minute)}
	tr := New(Config{Source: &statusSource{fakeSource: f, code: 404}, Rules: rulesIndex(t), Namespace: "sandbox",
		UnguardedNamespace: "sandbox-unguarded", Now: clk.Now, Log: log})
	tr.Poll(context.Background())
	clk.Set(t0.Add(time.Minute + 15*time.Second))
	tr.Poll(context.Background())
	mu.Lock()
	out := buf.String()
	mu.Unlock()
	if strings.Count(out, "search page came back full") != 1 || !strings.Contains(out, "index=sdp-hubble") {
		t.Fatalf("full page logged %d times: %s", strings.Count(out, "search page came back full"), out)
	}
	if strings.Count(out, "no detector for a log type yet") != 1 || !strings.Contains(out, "log_type=sdp_host") {
		t.Fatalf("404 logged %d times: %s", strings.Count(out, "no detector for a log type yet"), out)
	}
}

type lockedWriter struct {
	w  *strings.Builder
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// A terminal run's contained intrusion: TTD from the command's `started` (300 ms), not from the pod's
// readiness; TTI from Talon's audited delete (200 ms).
func TestTerminalContainedIntrusion(t *testing.T) {
	f := newFake()
	f.hits["sdp-api"] = []siem.Hit{
		apiRun("r1", t0, termRun, termRef, "started", ""),
		apiRun("r2", t0.Add(2400*time.Millisecond), termRun, termRef, "pod_ready", ""),
		apiCommand("c1", t0.Add(5*time.Second), termRun, termRef, 1, "whoami", "T1033", "recon", "started"),
		apiCommand("c4", t0.Add(15*time.Second), termRun, termRef, 4, "read-shadow", "T1003.008", "credentials", "started"),
	}
	f.findings["sdp_falco"] = []siem.Finding{falcoFinding("f-falco-t", t0.Add(15300*time.Millisecond), termRef, "Read sensitive file untrusted")}
	f.findings["sdp_talon"] = []siem.Finding{talonFinding("f-talon-t", t0.Add(15600*time.Millisecond), termRef, "Terminate Pod", "kubernetes:terminate")}
	f.hits["sdp-k8s-audit"] = []siem.Hit{auditDoc("a1", t0.Add(15500*time.Millisecond), termRef, talonUser, "delete", 200)}
	tr := newTracker(t, f, &clock{t: t0.Add(2 * time.Minute)})
	tr.Poll(context.Background())
	inc := one(t, tr.View(), KindContainedIntrusion)
	if inc.TTDMs == nil || *inc.TTDMs != 300 || inc.TTIMs == nil || *inc.TTIMs != 200 || inc.RunID != termRun {
		t.Fatalf("terminal contained intrusion: %+v ttd=%v tti=%v", inc, inc.TTDMs, inc.TTIMs)
	}
	for _, st := range inc.Steps {
		if st.Source == "falco" && (st.CommandSeq == nil || *st.CommandSeq != 4) {
			t.Fatalf("falco step command_seq %v", st.CommandSeq)
		}
	}
}

// detection-missing from an ACTIVE alert whose bucket key is a sandbox pod ref.
func TestDetectionMissing(t *testing.T) {
	f := newFake()
	terminalRun(f, "sdp-"+flagHex)
	st := t0.Add(40 * time.Second).UnixMilli()
	f.alerts = []siem.Alert{{ID: "al-miss", MonitorName: "sdp-git: detection-missing", State: "ACTIVE", StartTime: &st,
		Agg: &siem.AlertAgg{BucketKeys: []any{termRef}}}}
	tr := newTracker(t, f, &clock{t: t0.Add(2 * time.Minute)})
	tr.Poll(context.Background())
	inc := one(t, tr.View(), KindDetectionMissing)
	if inc.Severity != "medium" || inc.RunID != termRun ||
		inc.Title != "Detection missing: a command the catalogue says is detected raised no Falco event on sandbox/terminal-3755e65530" ||
		len(inc.Steps) != 1 || inc.Steps[0].Source != "api" || inc.Evidence[0] != (Evidence{Type: "alert", ID: "al-miss"}) {
		t.Fatalf("detection missing: %+v", inc)
	}
}

// Fixtures for the edges of each check, so that loosening any of them changes an answer.
func TestCheckEdges(t *testing.T) {
	t.Run("TTI only from Talon's own successful response", func(t *testing.T) {
		f := newFake()
		compareRun(f) // Falco +1.8 s, Talon's audited delete +2.2 s
		f.hits["sdp-k8s-audit"] = append(f.hits["sdp-k8s-audit"],
			auditDoc("a-other", t0.Add(time.Hour+1900*time.Millisecond), cmpRef, "system:admin", "patch", 200),
			auditDoc("a-refused", t0.Add(time.Hour+2000*time.Millisecond), cmpRef, talonUser, "delete", 409))
		tr := newTracker(t, f, &clock{t: t0.Add(2 * time.Hour)})
		tr.Poll(context.Background())
		if inc := one(t, tr.View(), KindContainedIntrusion); inc.TTIMs == nil || *inc.TTIMs != 400 {
			t.Fatalf("TTI %v, want 400 (Talon's successful delete)", inc.TTIMs)
		}
	})
	t.Run("policy enforced: the first drop after the label, within 30 s", func(t *testing.T) {
		f := newFake()
		quarantineRun(f) // Falco +2 s, patch +2.3 s, drop +2.6 s
		at := t0.Add(2 * time.Hour)
		f.hits["sdp-hubble"] = append(f.hits["sdp-hubble"], dropDoc("h-before", at.Add(2100*time.Millisecond), quarRef, 9))
		tr := newTracker(t, f, &clock{t: at.Add(time.Minute)})
		tr.Poll(context.Background())
		if !hasStep(one(t, tr.View(), KindContainedIntrusion), "policy enforced +300 ms") {
			t.Fatal("the drop before the label was taken")
		}
		f.hits["sdp-hubble"] = []siem.Hit{dropDoc("h-late", at.Add(2300*time.Millisecond+31*time.Second), quarRef, 9)}
		tr = newTracker(t, f, &clock{t: at.Add(2 * time.Minute)})
		tr.Poll(context.Background())
		if hasStep(one(t, tr.View(), KindContainedIntrusion), "policy enforced") {
			t.Fatal("a drop 31 s after the label counted as enforcement")
		}
	})
	t.Run("twin dwell from the successful create to the delete after it", func(t *testing.T) {
		f := newFake()
		compareRun(f) // create +0.1 s (201), delete +14.1 s
		f.hits["sdp-k8s-audit"] = append(f.hits["sdp-k8s-audit"],
			auditDoc("a-old-del", t0.Add(time.Hour-time.Second), twinRef, apiUser, "delete", 404),
			auditDoc("a-denied", t0.Add(time.Hour+50*time.Millisecond), twinRef, apiUser, "create", 400))
		tr := newTracker(t, f, &clock{t: t0.Add(2 * time.Hour)})
		tr.Poll(context.Background())
		if v := tr.View(); v.Metrics.MedianTwinDwellMs == nil || *v.Metrics.MedianTwinDwellMs != 14000 {
			t.Fatalf("dwell %v, want 14000", v.Metrics.MedianTwinDwellMs)
		}
	})
	t.Run("dns-exfil joins a command at most 300 s before the query", func(t *testing.T) {
		f := newFake()
		f.hits["sdp-api"] = []siem.Hit{apiCommand("c3", t0, termRun, termRef, 3, "dns-exfil", "T1048.003", "exfiltration", "started")}
		f.findings["sdp_hubble"] = []siem.Finding{dnsFinding("f-dns-1", t0.Add(301*time.Second), termRef, "sdp-"+flagHex)}
		tr := newTracker(t, f, &clock{t: t0.Add(10 * time.Minute)})
		tr.Poll(context.Background())
		if inc := one(t, tr.View(), KindDNSExfil); len(inc.Steps) != 1 {
			t.Fatalf("a command 301 s before was joined: %+v", inc.Steps)
		}
	})
	t.Run("dns-exfil counts Falco only from the command to 60 s after", func(t *testing.T) {
		f := newFake()
		terminalRun(f, "sdp-"+flagHex) // dns-exfil started at +19 s
		f.findings["sdp_falco"] = []siem.Finding{
			falcoFinding("f-before", t0.Add(18*time.Second), termRef, "Terminal shell in container"),
			falcoFinding("f-after", t0.Add(80*time.Second), termRef, "Terminal shell in container")}
		tr := newTracker(t, f, &clock{t: t0.Add(5 * time.Minute)})
		tr.Poll(context.Background())
		if inc := one(t, tr.View(), KindDNSExfil); inc.FalcoEvents != 0 {
			t.Fatalf("falco_events %d, want 0 (both outside the window)", inc.FalcoEvents)
		}
		f.findings["sdp_falco"] = append(f.findings["sdp_falco"], falcoFinding("f-in", t0.Add(78*time.Second), termRef, "Terminal shell in container"))
		tr = newTracker(t, f, &clock{t: t0.Add(5 * time.Minute)})
		tr.Poll(context.Background())
		if inc := one(t, tr.View(), KindDNSExfil); inc.FalcoEvents != 1 {
			t.Fatalf("falco_events %d, want 1", inc.FalcoEvents)
		}
	})
}

func hasStep(inc Incident, prefix string) bool {
	for _, st := range inc.Steps {
		if strings.HasPrefix(st.Detail, prefix) {
			return true
		}
	}
	return false
}

// The health line reads ACTIVE alerts on their own: an active ops alarm older than the newest 500
// alerts of every state still shows.
func TestHealthReadsActiveAlertsApart(t *testing.T) {
	f := newFake()
	for i := 0; i < pageSize; i++ {
		st := t0.Add(time.Duration(i) * time.Second).UnixMilli()
		f.alerts = append(f.alerts, siem.Alert{ID: fmt.Sprintf("al%d", i), MonitorName: "sdp-git: policy probing", State: "COMPLETED", StartTime: &st})
	}
	old := t0.Add(-time.Hour).UnixMilli()
	f.alerts = append(f.alerts, siem.Alert{ID: "al-disk", MonitorName: "disk watermark", State: "ACTIVE", StartTime: &old})
	tr := newTracker(t, f, &clock{t: t0.Add(time.Hour)})
	tr.Poll(context.Background())
	if h := tr.View().Health; h.Disk != "high" {
		t.Fatalf("health %+v", h)
	}
}

// One document is one event: two rules on one Falco document make one step citing both findings; a
// DNS finding on a document the Hubble search also read keeps its flag match; a correlation is cited
// first, so the evidence cap never cuts it.
func TestOneDocumentOneEvent(t *testing.T) {
	f := newFake()
	compareRun(f)
	second := falcoFinding("f-falco-g2", t0.Add(time.Hour+1800*time.Millisecond), cmpRef, "Terminal shell in container")
	second.Documents = f.findings["sdp_falco"][0].Documents
	second.Queries[0].Name = "Falco shell second rule"
	f.findings["sdp_falco"] = append(f.findings["sdp_falco"], second)
	for i := 0; i < 60; i++ {
		f.findings["sdp_falco"] = append(f.findings["sdp_falco"], falcoFinding(fmt.Sprintf("fz-%02d", i), t0.Add(time.Hour+3*time.Second+time.Duration(i)*time.Second), cmpRef, "Terminal shell in container"))
	}
	f.corr = []siem.Correlation{{Finding1: "fz-59", Finding2: "f-talon-g", Rules: []string{"corr-late"}}}
	terminalRun(f, "sdp-"+flagHex)
	dns := f.findings["sdp_hubble"][0]
	f.hits["sdp-hubble"] = append(f.hits["sdp-hubble"], hit("sdp-hubble", dns.Documents[0].ID, t0.Add(20101*time.Millisecond),
		map[string]any{"hubble.verdict": "FORWARDED", "k8s.pod.ref": termRef}))
	clk := &clock{t: t0}
	tr := newTracker(t, f, clk)
	registerTerminalFlag(tr, flagHex)
	clk.Set(t0.Add(2 * time.Hour))
	tr.Poll(context.Background())
	v := tr.View()
	ci := one(t, v, KindContainedIntrusion)
	if ci.Evidence[0] != (Evidence{Type: "correlation", ID: "corr-late"}) {
		t.Fatalf("correlation not first: %v", ci.Evidence[:3])
	}
	steps, cites := 0, 0
	for _, st := range ci.Steps {
		if st.At.Equal(t0.Add(time.Hour+1800*time.Millisecond)) && st.Source == "falco" {
			steps++
		}
	}
	for _, e := range ci.Evidence {
		if e.ID == "f-falco-g" || e.ID == "f-falco-g2" {
			cites++
		}
	}
	if steps != 1 || cites != 2 {
		t.Fatalf("one document: %d steps, %d citations", steps, cites)
	}
	dx := one(t, v, KindDNSExfil)
	if dx.FlagMatch == nil || !*dx.FlagMatch || dx.Evidence[len(dx.Evidence)-1].ID != "f-dns-1" {
		t.Fatalf("dns on a searched document: %+v", dx)
	}
}

// Records that are the same evidence (source, rule, pod, command, kind) are one step with a count:
// a DNS lookup's request and response, both directions, at the earliest record's time, citing the
// earliest maxStepEvidence ids; another rule, another verdict or another command is a step of its own.
func TestSameEvidenceOneStep(t *testing.T) {
	f := newFake()
	terminalRun(f, "sdp-"+flagHex) // f-dns-1: FORWARDED EGRESS at 20.101 s, under command 3
	lookup := func(id string, at time.Time, rule, verdict, dir string) siem.Finding {
		return finding(id, at, rule, []string{"sdp_hubble", "attack.t1048.003"}, map[string]any{
			"dns.query": "sdp-" + flagHex + ".x.exfil.sdp.test.", "hubble.verdict": verdict, "hubble.traffic_direction": dir,
			"hubble.l4.protocol": "udp", "hubble.l4.destination_port": 53, "k8s.pod.ref": termRef})
	}
	const rule = "DNS query carries an exfil label"
	// The earliest record is a response (INGRESS): the directions are listed sorted, not first seen.
	f.findings["sdp_hubble"] = append(f.findings["sdp_hubble"], lookup("f-dns-0", t0.Add(20050*time.Millisecond), rule, "FORWARDED", "INGRESS"))
	for i := 2; i <= 11; i++ {
		dir := "EGRESS"
		if i%2 == 0 {
			dir = "INGRESS"
		}
		f.findings["sdp_hubble"] = append(f.findings["sdp_hubble"], lookup(fmt.Sprintf("f-dns-%d", i), t0.Add(20*time.Second+time.Duration(i)*100*time.Millisecond), rule, "FORWARDED", dir))
	}
	f.findings["sdp_hubble"] = append(f.findings["sdp_hubble"],
		lookup("f-dns-rule", t0.Add(20250*time.Millisecond), "Hubble - flag-shaped DNS lookup", "FORWARDED", "EGRESS"),
		lookup("f-dns-drop", t0.Add(20350*time.Millisecond), rule, "DROPPED", "EGRESS"),
		lookup("f-dns-late", t0.Add(41*time.Second), rule, "FORWARDED", "EGRESS"))
	f.hits["sdp-api"] = append(f.hits["sdp-api"], apiCommand("c5", t0.Add(40*time.Second), termRun, termRef, 4, "dns-exfil", "T1048.003", "exfiltration", "started"))
	compareRun(f)
	quarantineRun(f)
	clk := &clock{t: t0}
	tr := newTracker(t, f, clk)
	registerTerminalFlag(tr, flagHex)
	clk.Set(t0.Add(3 * time.Hour))
	tr.Poll(context.Background())
	v := tr.View()
	// Every kind's steps stay in time order (a check adds its records in its own order).
	for _, inc := range v.Incidents {
		for i := 1; i < len(inc.Steps); i++ {
			if inc.Steps[i].At.Before(inc.Steps[i-1].At) {
				t.Errorf("%s: step %d before step %d", inc.Kind, i, i-1)
			}
		}
	}
	inc := one(t, v, KindDNSExfil)
	b, _ := json.MarshalIndent(inc.Steps, "", " ")
	type want struct {
		at     time.Duration
		source string
		seq    int
		count  int
		detail string
	}
	pod := "sandbox/terminal-3755e65530"
	wants := []want{
		{9 * time.Second, "api", 2, 0, "command read-flag (T1552.001, credentials) started on " + pod},
		{19 * time.Second, "api", 3, 0, "command dns-exfil (T1048.003, exfiltration) started on " + pod},
		{20050 * time.Millisecond, "hubble", 3, 12, "DNS query under the exfil zone from " + pod + ", FORWARDED egress+ingress udp/53"},
		{20250 * time.Millisecond, "hubble", 3, 0, "DNS query under the exfil zone from " + pod + ", FORWARDED egress udp/53"},
		{20350 * time.Millisecond, "hubble", 3, 0, "DNS query under the exfil zone from " + pod + ", DROPPED egress udp/53"},
		{41 * time.Second, "hubble", 4, 0, "DNS query under the exfil zone from " + pod + ", FORWARDED egress udp/53"},
	}
	if len(inc.Steps) != len(wants) {
		t.Fatalf("%d steps, want %d: %s", len(inc.Steps), len(wants), b)
	}
	for i, w := range wants {
		st := inc.Steps[i]
		if !st.At.Equal(t0.Add(w.at)) || st.Source != w.source || st.CommandSeq == nil || *st.CommandSeq != w.seq || st.Count != w.count || st.Detail != w.detail {
			t.Errorf("step %d: %+v, want %+v", i, st, w)
		}
	}
	if inc.Steps[3].Rule != "Hubble - flag-shaped DNS lookup" {
		t.Errorf("rule step: %+v", inc.Steps[3])
	}
	// "count" is published for a collapsed step only.
	if one, _ := json.Marshal(inc.Steps[2]); !strings.Contains(string(one), `"count":12`) {
		t.Errorf("collapsed step JSON %s", one)
	}
	if single, _ := json.Marshal(inc.Steps[3]); strings.Contains(string(single), `"count"`) {
		t.Errorf("single step JSON %s", single)
	}
	var ids []string
	for _, e := range inc.Evidence {
		ids = append(ids, e.ID)
	}
	if got := strings.Join(ids, ","); got != "c2,c3,f-dns-0,f-dns-1,f-dns-2,f-dns-3,f-dns-4,f-dns-rule,f-dns-drop,f-dns-late" {
		t.Errorf("evidence %s", got)
	}
	if !inc.FirstAt.Equal(t0.Add(9*time.Second)) || !inc.LastAt.Equal(t0.Add(41*time.Second)) {
		t.Errorf("times %v %v", inc.FirstAt, inc.LastAt)
	}
}

// hookSource runs a hook inside the correlations read (a slow SIEM) or fails that read alone.
type hookSource struct {
	*fakeSource
	hook    func()
	corrErr error
}

func (h *hookSource) Correlations(ctx context.Context, from, to time.Time) ([]siem.Correlation, error) {
	if h.hook != nil {
		h.hook()
	}
	if h.corrErr != nil {
		return nil, h.corrErr
	}
	return h.fakeSource.Correlations(ctx, from, to)
}

// Staleness is measured from the end of the last successful poll: a poll that took 40 s leaves the
// view available 30 s later.
func TestStalenessFromPollEnd(t *testing.T) {
	f := newFake()
	clk := &clock{t: t0}
	src := &hookSource{fakeSource: f, hook: func() { clk.Set(clk.Now().Add(40 * time.Second)) }}
	tr := newTracker(t, src, clk)
	tr.Poll(context.Background())
	clk.Set(clk.Now().Add(30 * time.Second))
	if !tr.View().Available {
		t.Fatal("hidden 30 s after a slow poll ended")
	}
	clk.Set(clk.Now().Add(16 * time.Second))
	if tr.View().Available {
		t.Fatal("still available 46 s after the poll ended")
	}
}

// A failed correlations read keeps the pairs read before and does not hide the section.
func TestCorrelationsReadFailureIsSoft(t *testing.T) {
	f := newFake()
	compareRun(f)
	f.corr = []siem.Correlation{{Finding1: "f-falco-g", Finding2: "f-talon-g", Rules: []string{"corr-1"}}}
	clk := &clock{t: t0.Add(2 * time.Hour)}
	src := &hookSource{fakeSource: f}
	tr := newTracker(t, src, clk)
	tr.Poll(context.Background())
	src.corrErr = errDown
	clk.Set(clk.Now().Add(15 * time.Second))
	tr.Poll(context.Background())
	v := tr.View()
	if !v.Available {
		t.Fatal("a failed correlations read hid the section")
	}
	if inc := one(t, v, KindContainedIntrusion); inc.Evidence[0] != (Evidence{Type: "correlation", ID: "corr-1"}) {
		t.Fatalf("the earlier correlation was lost: %v", inc.Evidence)
	}
	if !v.CheckedAt.Equal(clk.Now()) {
		t.Fatalf("checked_at %v: the poll did not count", v.CheckedAt)
	}
	// Correlations age out with the evidence retention; host finding ids are capped.
	src.corrErr = nil
	f.corr = nil
	clk.Set(clk.Now().Add(25 * time.Hour))
	tr.Poll(context.Background())
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.corr) != 0 {
		t.Fatalf("%d correlations after 25 h", len(tr.corr))
	}
	for i := 0; i < maxPerSource+300; i++ {
		tr.hosts[fmt.Sprintf("h%d", i)] = clk.Now().Add(-time.Duration(i) * time.Second)
	}
	tr.prune(clk.Now())
	if len(tr.hosts) != maxPerSource {
		t.Fatalf("%d host findings kept", len(tr.hosts))
	}
}

// An arm is published only as guarded or unguarded, whatever the document says.
func TestArmValidated(t *testing.T) {
	f := newFake()
	f.hits["sdp-api"] = []siem.Hit{apiRun("r1", t0, termRun, termRef, "started", "k3s01-arm")}
	st := t0.Add(time.Minute).UnixMilli()
	f.alerts = []siem.Alert{{ID: "al-prev", MonitorName: "sdp-git: prevented-not-detected", State: "ACTIVE", StartTime: &st,
		Agg: &siem.AlertAgg{BucketKeys: []any{termRef}}}}
	tr := newTracker(t, f, &clock{t: t0.Add(2 * time.Minute)})
	tr.Poll(context.Background())
	if inc := one(t, tr.View(), KindPreventedNotDetected); inc.RunID != termRun || inc.Arm != "" {
		t.Fatalf("run %q arm %q", inc.RunID, inc.Arm)
	}
}

// The view is marshalled once per poll and served as those bytes.
func TestJSONMarshalledOncePerPoll(t *testing.T) {
	f := newFake()
	terminalRun(f, "sdp-"+flagHex)
	clk := &clock{t: t0.Add(time.Minute)}
	tr := newTracker(t, f, clk)
	tr.Poll(context.Background())
	a, b := tr.JSON(), tr.JSON()
	want, _ := json.Marshal(tr.View())
	if string(a) != string(want) || &a[0] != &b[0] {
		t.Fatal("JSON is not the poll's one marshalled view")
	}
	clk.Set(clk.Now().Add(time.Minute))
	if got := string(tr.JSON()); !strings.HasPrefix(got, `{"available":false`) {
		t.Fatalf("stale JSON %s", got)
	}
	if got := string(New(Config{}).JSON()); !strings.HasPrefix(got, `{"available":false,"checked_at":null`) {
		t.Fatalf("unconfigured JSON %s", got)
	}
}

// metrics.ingest_lag_ms: per source, the median of event.ingested - @timestamp over the documents
// read that were ingested in the last 15 min; null for a source with none.
func TestIngestLag(t *testing.T) {
	f := newFake()
	terminalRun(f, "sdp-"+flagHex) // api lines ingested 3 s after the event, the DNS finding's document 2 s
	f.findings["sdp_host"] = []siem.Finding{finding("h1", t0.Add(10*time.Second), "ssh", nil, map[string]any{"ssh.event": "accepted"})}
	clk := &clock{t: t0.Add(time.Minute)}
	tr := newTracker(t, f, clk)
	tr.Poll(context.Background())
	lag := tr.View().Metrics.IngestLagMs
	want := map[string]any{"api": int64(3000), "hubble": int64(2000), "host": int64(2000), "falco": nil, "talon": nil, "k8s-audit": nil}
	if len(lag) != len(want) {
		t.Fatalf("lag %v", lag)
	}
	for k, w := range want {
		got := lag[k]
		if (got == nil) != (w == nil) || (got != nil && *got != w.(int64)) {
			t.Errorf("%s lag %v, want %v", k, ptr64(got), w)
		}
	}
	clk.Set(t0.Add(20 * time.Minute))
	tr.Poll(context.Background())
	for k, v := range tr.View().Metrics.IngestLagMs {
		if v != nil {
			t.Errorf("%s lag %d 20 min later, want null", k, *v)
		}
	}
}

func ptr64(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

// P3's acceptance canaries (pod refs sandbox_p3c-<tag>-*, principals system:p3c-<tag>) never become
// an incident, whatever rule they fire.
func TestSyntheticCanariesDropped(t *testing.T) {
	f := newFake()
	ref := "sandbox_p3c-a1b2-shell"
	f.findings["sdp_falco"] = []siem.Finding{falcoFinding("f-c1", t0, ref, "Terminal shell in container")}
	f.findings["sdp_talon"] = []siem.Finding{talonFinding("f-c2", t0.Add(time.Second), ref, "Terminate Pod", "kubernetes:terminate")}
	f.findings["sdp_hubble"] = []siem.Finding{dnsFinding("f-c3", t0, "sandbox_p3c-a1b2-dns", "sdp-"+flagHex)}
	// P3's exec canary: its own canary pod, its own principal.
	f.findings["sdp_k8s_audit"] = []siem.Finding{finding("f-c4", t0, "Exec", nil, map[string]any{"audit.object.subresource": "exec",
		"audit.object.resource": "pods", "k8s.pod.ref": "sandbox-unguarded_p3c-a1b2-exec", "user.name": "system:p3c-a1b2"})}
	f.hits["sdp-api"] = []siem.Hit{
		apiCommand("c1", t0, termRun, "sandbox_p3c-a1b2-term", 1, "whoami", "T1033", "recon", "started"),
		apiCommand("c2", t0.Add(time.Second), termRun, "sandbox_p3c-a1b2-term", 2, "read-flag", "T1552.001", "credentials", "started"),
		apiCommand("c3", t0.Add(2*time.Second), termRun, "sandbox_p3c-a1b2-term", 3, "dns-exfil", "T1048.003", "exfiltration", "started")}
	st := t0.UnixMilli()
	f.alerts = []siem.Alert{
		{ID: "al-c1", MonitorName: "sdp-git: prevented-not-detected", State: "ACTIVE", StartTime: &st, Agg: &siem.AlertAgg{BucketKeys: []any{"sandbox_p3c-a1b2-x"}}},
		{ID: "al-c2", MonitorName: "sdp-git: policy-probing", State: "ACTIVE", StartTime: &st, Agg: &siem.AlertAgg{BucketKeys: []any{"system:p3c-a1b2"}}},
		{ID: "al-real", MonitorName: "sdp-git: policy-probing", State: "ACTIVE", StartTime: &st, Agg: &siem.AlertAgg{BucketKeys: []any{"hm1:0011223344556677"}}},
	}
	tr := newTracker(t, f, &clock{t: t0.Add(time.Minute)})
	tr.Poll(context.Background())
	v := tr.View()
	if len(v.Incidents) != 1 || v.Incidents[0].Evidence[0].ID != "al-real" {
		b, _ := json.Marshal(v.Incidents)
		t.Fatalf("synthetic canaries became incidents: %s", b)
	}
	if b, _ := json.Marshal(v); strings.Contains(string(b), "p3c-") {
		t.Fatalf("the marker was published: %s", b)
	}
}

// The canary marker is matched whole and anchored: a ServiceAccount named p3c-y, or a pod whose name
// merely contains p3c-, cannot hide an exec or a probe from the page. Only P3's exact canary
// principal (system:p3c-<tag>, a user only a cluster admin can mint) is dropped on a real pod.
func TestSyntheticMarkerAnchored(t *testing.T) {
	f := newFake()
	exec := func(id, ref, user string) siem.Finding {
		return finding(id, t0, "Exec", nil, map[string]any{"audit.object.subresource": "exec", "audit.object.resource": "pods",
			"k8s.pod.ref": ref, "user.name": user})
	}
	f.findings["sdp_k8s_audit"] = []siem.Finding{
		exec("f-sa", quarRef, "system:serviceaccount:x:p3c-y"), // a ServiceAccount named p3c-y
		exec("f-pod", "sandbox_shop-p3c-1", "system:admin"),    // p3c- inside a pod name
		exec("f-pod2", "sandbox_p3c-x", "system:admin"),        // a tag but no canary name after it
		exec("f-user", cmpRef, "system:p3c-a1b2:extra"),        // not the whole principal
		exec("f-canary", termRef, "system:p3c-a1b2"),           // P3's canary principal: dropped
	}
	st := t0.UnixMilli()
	f.alerts = []siem.Alert{
		{ID: "al-sa", MonitorName: "sdp-git: policy-probing", State: "ACTIVE", StartTime: &st, Agg: &siem.AlertAgg{BucketKeys: []any{"system:serviceaccount:x:p3c-y"}}},
		{ID: "al-pod", MonitorName: "sdp-git: prevented-not-detected", State: "ACTIVE", StartTime: &st, Agg: &siem.AlertAgg{BucketKeys: []any{"sandbox_shop-p3c-1"}}},
	}
	tr := newTracker(t, f, &clock{t: t0.Add(time.Minute)})
	tr.Poll(context.Background())
	v := tr.View()
	execs := map[string]bool{}
	for _, inc := range incidentsOf(v, KindExecOutsideAPI) {
		execs[inc.Title] = true
	}
	for _, want := range []string{
		"Exec into sandbox/network-tool-b2c3d4e5f6 outside the API",
		"Exec into sandbox/shop-p3c-1 outside the API",
		"Exec into sandbox/p3c-x outside the API",
		"Exec into sandbox/shell-in-container-a1b2c3d4e5 outside the API",
	} {
		if !execs[want] {
			t.Errorf("missing %q in %v", want, execs)
		}
	}
	if execs["Exec into sandbox/terminal-3755e65530 outside the API"] || len(execs) != 4 {
		t.Errorf("exec incidents %v", execs)
	}
	one(t, v, KindPolicyProbing)
	one(t, v, KindPreventedNotDetected)
}

// hbHit is the sync's heartbeat document as P3 writes it (siem-sync, _id heartbeat).
func hbHit(checked time.Time, outcome, commit string) siem.Hit {
	return siem.Hit{ID: "heartbeat", Index: "siem-sync", Source: map[string]any{"kind": "heartbeat",
		"checked_at": checked.Format("2006-01-02T15:04:05.000Z07:00"), "commit": commit, "outcome": outcome,
		"lint_sha256": strings.Repeat("e", 64)}}
}

// The sync's liveness: "stale" when its heartbeat is older than 30 min or missing while records
// exist; a newer refused/failed heartbeat is the latest run's verdict; the applied commit stays.
func TestRulesStaleFromHeartbeat(t *testing.T) {
	commit := strings.Repeat("c", 40)
	applied := siem.Hit{ID: "s1", Source: map[string]any{"commit": commit, "applied_at": t0.Add(-2 * time.Hour).Format(time.RFC3339),
		"status": "applied", "reason": "free text k3s01 10.4.2.10 never published", "changed": map[string]any{"rules": 1}, "lint_sha256": "x"}}
	rules := func(t *testing.T, hits ...siem.Hit) RulesView {
		t.Helper()
		f := newFake()
		f.sync = hits
		tr := newTracker(t, f, &clock{t: t0})
		tr.Poll(context.Background())
		v := tr.View()
		if b, _ := json.Marshal(v); strings.Contains(string(b), "free text") {
			t.Fatalf("a record's reason was published: %s", b)
		}
		return v.Rules
	}
	check := func(name string, got RulesView, status string) {
		t.Helper()
		if got.Status != status || got.Commit != commit || got.AppliedAt == nil {
			t.Errorf("%s: %+v, want status %s with commit %s", name, got, status, commit)
		}
	}
	check("fresh heartbeat", rules(t, applied, hbHit(t0.Add(-5*time.Minute), "unchanged", commit)), "applied")
	check("heartbeat 29:59 old", rules(t, applied, hbHit(t0.Add(-30*time.Minute+time.Second), "unchanged", commit)), "applied")
	check("heartbeat 30:01 old", rules(t, applied, hbHit(t0.Add(-30*time.Minute-time.Second), "unchanged", commit)), "stale")
	check("heartbeat missing", rules(t, applied), "stale")
	check("checked_at not RFC 3339", rules(t, applied, siem.Hit{ID: "heartbeat", Source: map[string]any{"kind": "heartbeat",
		"checked_at": "04/10/2026 10:00", "outcome": "unchanged"}}), "stale")
	check("heartbeat commit not 40 hex", rules(t, applied, hbHit(t0.Add(-time.Minute), "unchanged", "abc")), "stale")
	check("newer refused run", rules(t, applied, hbHit(t0.Add(-time.Minute), "refused", commit)), "refused")
	check("newer failed run", rules(t, applied, hbHit(t0.Add(-time.Minute), "failed", commit)), "failed")
	check("unknown outcome", rules(t, applied, hbHit(t0.Add(-time.Minute), "exploded", commit)), "applied")
	refusedRec := siem.Hit{ID: "s2", Source: map[string]any{"commit": strings.Repeat("d", 40), "applied_at": t0.Add(-time.Minute).Format(time.RFC3339), "status": "refused"}}
	check("heartbeat older than the newest record", rules(t, applied, refusedRec, hbHit(t0.Add(-2*time.Minute), "failed", commit)), "refused")
	// No records and no heartbeat: nothing known yet.
	f := newFake()
	tr := newTracker(t, f, &clock{t: t0})
	tr.Poll(context.Background())
	if r := tr.View().Rules; r.Status != "unknown" {
		t.Fatalf("empty siem-sync: %+v", r)
	}
	// A malformed heartbeat is a missing one: with no records, still nothing known.
	f.sync = []siem.Hit{{ID: "heartbeat", Source: map[string]any{"kind": "heartbeat", "checked_at": "yesterday", "outcome": "refused"}}}
	tr.Poll(context.Background())
	if r := tr.View().Rules; r.Status != "unknown" {
		t.Fatalf("malformed heartbeat, no records: %+v", r)
	}
	// The heartbeat is never counted as a record, even if a search returned it with an applied_at.
	stray := hbHit(t0.Add(-time.Minute), "applied", commit)
	stray.Source["applied_at"] = t0.Add(-time.Minute).Format(time.RFC3339)
	stray.Source["status"] = "failed"
	check("heartbeat in the records search", rules(t, applied, stray), "applied")
}
