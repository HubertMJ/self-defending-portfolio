package ruleindex

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLookups(t *testing.T) {
	ix, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if r := ix.FalcoRule("SDP network tool in sandbox"); r.File == "" || r.Line == 0 {
		t.Fatalf("custom rule: %+v", r)
	}
	if r := ix.FalcoRule("Terminal shell in container"); r.Name != "Terminal shell in container" || r.File != "" {
		t.Fatalf("stock rule: %+v", r)
	}
	if r := ix.TalonRule("Terminal shell in container"); r.Name != "Kill terminal shell in sandbox" || r.Line == 0 {
		t.Fatalf("talon rule: %+v", r)
	}
	if r := ix.TalonRule("nope"); r != (Rule{}) {
		t.Fatalf("unknown: %+v", r)
	}
	if len(ix.Policies) == 0 {
		t.Fatal("no policies")
	}
}

// repoRoot finds the checkout this package sits in; "" inside the image build, where only app/api
// is present.
func repoRoot() string {
	dir, _ := os.Getwd()
	for range 6 {
		if fi, err := os.Stat(filepath.Join(dir, "cluster", "infra")); err == nil && fi.IsDir() {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	return ""
}

func lineOf(t *testing.T, root, file string, n int) string {
	t.Helper()
	f, err := os.Open(filepath.Join(root, file))
	if err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for i := 1; sc.Scan(); i++ {
		if i == n {
			return sc.Text()
		}
	}
	t.Fatalf("%s has no line %d", file, n)
	return ""
}

// TestIndexMatchesRepository is the guard against a stale index: every file and line must still say
// what the index claims. Rerun scripts/gen-rule-index.sh when it fails.
func TestIndexMatchesRepository(t *testing.T) {
	root := repoRoot()
	if root == "" {
		t.Skip("not inside a full checkout")
	}
	ix, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for name, l := range ix.Falco {
		if got := strings.TrimSpace(lineOf(t, root, l.File, l.Line)); got != "- rule: "+name {
			t.Errorf("falco %q: %s:%d is %q", name, l.File, l.Line, got)
		}
	}
	for falco, l := range ix.Talon {
		if got := lineOf(t, root, l.File, l.Line); got != "- rule: "+l.Name {
			t.Errorf("talon rule for %q: %s:%d is %q", falco, l.File, l.Line, got)
		}
	}
	for _, p := range ix.Policies {
		data, err := os.ReadFile(filepath.Join(root, p.File))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "kind: "+p.Kind+"\n") || !strings.Contains(string(data), "  name: "+p.Name+"\n") {
			t.Errorf("policy %s/%s not in %s", p.Kind, p.Name, p.File)
		}
	}
}
