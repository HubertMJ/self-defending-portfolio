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
