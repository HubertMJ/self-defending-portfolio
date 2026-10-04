package incidents

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
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
	poll := func(label string, register func(*Tracker, *clock), readAt time.Duration) *bool {
		t.Helper()
		f := newFake()
		terminalRun(f, label)
		clk := &clock{t: t0}
		tr := newTracker(t, f, clk)
		register(tr, clk)
		clk.Set(t0.Add(readAt))
		tr.Poll(context.Background())
		return one(t, tr.View(), KindDNSExfil).FlagMatch
	}
	runEnd := 30 * time.Second
	reg := func(hex string) func(*Tracker, *clock) {
		return func(tr *Tracker, clk *clock) {
			registerTerminalFlag(tr, hex)
			tr.EndFlag(termRun, t0.Add(runEnd))
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
	check("own flag", poll("sdp-"+flagHex, reg(flagHex), time.Minute), &yes)
	check("upper-case query", poll("SDP-"+strings.ToUpper(flagHex), reg(flagHex), time.Minute), &yes)
	check("another run's flag", poll("sdp-"+otherHex, reg(flagHex), time.Minute), &no)
	// Leave right after the command: the run is over, the finding arrives 90 s later.
	check("finding 90 s after the run", poll("sdp-"+flagHex, reg(flagHex), runEnd+90*time.Second), &yes)
	// Retention: kept 15 min after the run's end.
	check("14:59 after the run", poll("sdp-"+flagHex, reg(flagHex), runEnd+14*time.Minute+59*time.Second), &yes)
	check("15:01 after the run", poll("sdp-"+flagHex, reg(flagHex), runEnd+15*time.Minute+time.Second), &no)
	// The same pod name in the twin namespace is another pod.
	twin := func(tr *Tracker, _ *clock) {
		tr.RegisterFlag(termRun, "sandbox-unguarded_terminal-3755e65530", tr.FlagMAC("sdp-"+flagHex))
	}
	check("same pod name in the twin namespace", poll("sdp-"+flagHex, twin, time.Minute), &no)
	// Restart: the run registered with the previous process; this one started after the query.
	restart := func(tr *Tracker, _ *clock) { tr.start = t0.Add(40 * time.Second) }
	check("after a restart", poll("sdp-"+flagHex, restart, time.Minute), nil)
	// The label must be exactly sdp-<16 hex>.
	check("malformed label", poll("sdp-"+flagHex+"aa", reg(flagHex), time.Minute), &no)
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
	exec := func(id, user string) siem.Finding {
		return finding(id, t0, "Exec into a sandbox pod not by the API", []string{"sdp_k8s_audit", "attack.t1609"}, map[string]any{
			"audit.verb": "create", "audit.object.resource": "pods", "audit.object.subresource": "exec", "audit.response.code": 101,
			"k8s.pod.ref": quarRef, "user.name": user, "source.ip": "hm1:0011223344556677"})
	}
	f.findings["sdp_k8s_audit"] = []siem.Finding{exec("f-exec-admin", "system:admin"), exec("f-exec-api", apiUser), exec("f-exec-op", "hm1:8899aabbccddeeff")}
	tr := newTracker(t, f, &clock{t: t0.Add(time.Minute)})
	tr.Poll(context.Background())
	list := incidentsOf(tr.View(), KindExecOutsideAPI)
	if len(list) != 2 {
		t.Fatalf("%d exec-outside-api incidents, want 2 (the API's own exec is not one)", len(list))
	}
	if list[0].Title != "Exec into sandbox/network-tool-b2c3d4e5f6 outside the API" || list[0].Steps[0].Detail != "create pods/exec on sandbox/network-tool-b2c3d4e5f6 not by the API, response 101" {
		t.Fatalf("incident %+v", list[0])
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
			Agg: &struct {
				BucketKeys []string `json:"bucket_keys"`
			}{BucketKeys: []string{"hm1:0011223344556677"}}},
		{ID: "al-prev", MonitorName: "sdp-git: prevented-not-detected", State: "ACTIVE", StartTime: &st,
			Agg: &struct {
				BucketKeys []string `json:"bucket_keys"`
			}{BucketKeys: []string{termRef, "kube-system_x"}}},
		{ID: "al-miss", MonitorName: "sdp-git: detection-missing", State: "ERROR", StartTime: &st},
		{ID: "al-old", MonitorName: "sdp-git: detection-missing", State: "COMPLETED", StartTime: &old},
		{ID: "al-other", MonitorName: "sdp-git: something else", State: "ACTIVE", StartTime: &st},
		{ID: "al-ops", MonitorName: "ingest silent falco", State: "ACTIVE", StartTime: &st},
	}
	f.sync = []siem.Hit{
		{ID: "s1", Source: map[string]any{"commit": strings.Repeat("a", 40), "applied_at": t0.Add(-time.Hour).Format(time.RFC3339), "status": "applied"}},
		{ID: "s2", Source: map[string]any{"commit": strings.Repeat("b", 40), "applied_at": t0.Format(time.RFC3339), "status": "refused"}},
	}
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
			"Exec", nil, map[string]any{"audit.object.subresource": "exec", "audit.object.resource": "pods", "k8s.pod.ref": quarRef, "user.name": "system:admin"}))
	}
	for i := 0; i < 70; i++ {
		f.findings["sdp_falco"] = append(f.findings["sdp_falco"], falcoFinding(fmt.Sprintf("fa-%d", i), t0.Add(time.Duration(i)*time.Second), cmpRef, "Terminal shell in container"))
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
	want := `{"available":false,"checked_at":null,"rules":{"commit":"","applied_at":null,"status":"unknown"},"health":{"ingest":"unknown","evidence_rewritten":false,"disk":"unknown"},"metrics":{"since":null,"incidents":0,"median_ttd_ms":null,"median_tti_ms":null,"median_twin_dwell_ms":null,"host_findings":0},"incidents":[]}`
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
		"https://10.43.0.1:443/api"
	f.findings["sdp_falco"] = append(f.findings["sdp_falco"], finding("f-poison", t0.Add(25*time.Second), "Falco "+poison, []string{"attack.t1059"},
		map[string]any{"falco.rule": poison, "proc.name": poison, "k8s.pod.ref": termRef, "user.name": "operator", "source.ip": "10.1.1.250",
			"hostname": "k3s01", "dns.query": "sdp-" + flagHex + ".x.exfil.sdp.test."}))
	f.findings["sdp_talon"] = append(f.findings["sdp_talon"], talonFinding("f-talon-p", t0.Add(26*time.Second), termRef, poison, poison))
	f.hits["sdp-k8s-audit"] = append(f.hits["sdp-k8s-audit"], hit("sdp-k8s-audit", "a9", t0.Add(27*time.Second), map[string]any{
		"audit.verb": "patch " + poison, "audit.object.resource": "pods", "k8s.pod.ref": termRef, "user.name": talonUser, "source.ip": "hm1:aabbccddeeff0011"}))
	f.hits["sdp-hubble"] = append(f.hits["sdp-hubble"], hit("sdp-hubble", "h9", t0.Add(28*time.Second), map[string]any{
		"hubble.verdict": "DROPPED", "hubble.drop_reason": poison, "k8s.pod.ref": termRef, "dns.query": "sdp-" + flagHex + ".x.exfil.sdp.test."}))
	f.alerts = []siem.Alert{{ID: "al-p", MonitorName: "sdp-git: policy probing " + poison, State: "ACTIVE", StartTime: ptrInt(t0.UnixMilli()),
		Agg: &struct {
			BucketKeys []string `json:"bucket_keys"`
		}{BucketKeys: []string{"hm1:0011223344556677", "system:serviceaccount:x:y"}}}}
	clk := &clock{t: t0}
	tr := newTracker(t, f, clk)
	registerTerminalFlag(tr, flagHex)
	clk.Set(t0.Add(3 * time.Hour))
	tr.Poll(context.Background())
	v := tr.View()
	if len(v.Incidents) < 6 {
		t.Fatalf("only %d incidents: the leak test must see every kind", len(v.Incidents))
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
	regexp.MustCompile(`(?i)serviceaccount`),
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
	f.sync = []siem.Hit{{ID: "s1", Source: map[string]any{"commit": commit, "applied_at": t0.Add(-8 * 24 * time.Hour).Format(time.RFC3339), "status": "applied"}}}
	clk := &clock{t: t0}
	tr := newTracker(t, f, clk)
	tr.Poll(context.Background())
	if r := tr.View().Rules; r.Status != "applied" || r.Commit != commit {
		t.Fatalf("8-day-old record: %+v", r)
	}
	// 40 days later the record is past any search range: the last known state stands.
	clk.Set(t0.Add(40 * 24 * time.Hour))
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
