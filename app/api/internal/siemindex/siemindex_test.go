package siemindex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestLoadEmbeddedIndex(t *testing.T) {
	ix, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(ix)
	for _, k := range []string{`"rules":[`, `"monitors":[`, `"correlations":[`} {
		if !strings.Contains(string(b), k) {
			t.Fatalf("%s missing or null in %s", k, b)
		}
	}
	uuid := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	tech := regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)
	root := repoRoot()
	for _, r := range ix.Rules {
		if !uuid.MatchString(r.ID) || r.Title == "" || !strings.HasPrefix(r.File, "siem/rules/") || r.Line < 1 || r.Canary == "" {
			t.Errorf("rule %+v", r)
		}
		for _, a := range r.Attack {
			if !tech.MatchString(a) {
				t.Errorf("rule %s technique %q", r.ID, a)
			}
		}
		if root != "" {
			if _, err := os.Stat(filepath.Join(root, r.File)); err != nil {
				t.Errorf("rule %s: %v", r.ID, err)
			}
		}
	}
	for _, m := range ix.Monitors {
		if !strings.HasPrefix(m.Name, "sdp-git: ") || m.Canary == "" {
			t.Errorf("monitor %+v", m)
		}
	}
}

// TestDetectionLabExcluded proves the published /cluster/ index carries only the cluster project: the
// detection lab's content (source `lab`, log type sdp_lab, stream sdp-lab) syncs to siem01 but is kept
// out of the index by scripts/gen-siem-index.sh, while the cluster sources are untouched.
func TestDetectionLabExcluded(t *testing.T) {
	ix, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// The three lab Sigma rules (ADR 0034 amendment): a known hash, a Run key from Temp, a user unit
	// or crontab from /tmp. None may appear on the cluster page.
	labRuleIDs := map[string]bool{
		"daefd3d6-c180-41f1-96be-a9ecdc66b67e": true,
		"1ee26ef6-5232-4036-9134-f5cb465a2b9a": true,
		"1c34da41-643f-4979-9d33-be68ab49cdc0": true,
	}
	for _, r := range ix.Rules {
		if r.Source == "lab" {
			t.Errorf("rule %s (%q) has source lab in the published index", r.ID, r.Title)
		}
		if labRuleIDs[r.ID] {
			t.Errorf("lab rule %s (%q) present in the published index", r.ID, r.Title)
		}
	}
	for _, m := range ix.Monitors {
		if m.Name == "sdp-git: lab-polymorphic-beacon" {
			t.Errorf("lab monitor %q present in the published index", m.Name)
		}
	}
	// The cluster sources are unaffected: exactly these remain, lab is gone.
	wantSources := map[string]bool{
		"api": true, "falco": true, "host": true, "hubble": true,
		"k8s-audit": true, "siem-host": true, "talon": true,
	}
	got := map[string]bool{}
	for _, r := range ix.Rules {
		got[r.Source] = true
	}
	for s := range wantSources {
		if !got[s] {
			t.Errorf("cluster source %q missing from the published index", s)
		}
	}
	for s := range got {
		if !wantSources[s] {
			t.Errorf("unexpected source %q in the published index", s)
		}
	}
}

func TestRuleIDByTitle(t *testing.T) {
	ix, err := parse([]byte(`{"rules":[{"id":"9c41d2e7-8b3a-4f60-a1c5-0e7d6b2f9a48","title":"DNS query carries an exfil label"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := ix.RuleID("DNS query carries an exfil label"); got != "9c41d2e7-8b3a-4f60-a1c5-0e7d6b2f9a48" {
		t.Fatalf("RuleID = %q", got)
	}
	if ix.RuleID("nope") != "" || (*Index)(nil).RuleID("x") != "" {
		t.Fatal("unknown title has an id")
	}
	if ix.Rules[0].Attack == nil || ix.Monitors == nil || ix.Correlations == nil {
		t.Fatal("nil list would marshal null")
	}
}

// repoRoot finds the checkout this package sits in; "" inside the image build (app/api only).
func repoRoot() string {
	dir, _ := os.Getwd()
	for range 6 {
		if fi, err := os.Stat(filepath.Join(dir, "siem", "fields")); err == nil && fi.IsDir() {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	return ""
}
