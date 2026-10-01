package scenarios

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const img = "ghcr.io/hubertmj/self-defending-portfolio/scenario:main@sha256:0000000000000000000000000000000000000000000000000000000000000000"

const sample = `
- id: shell-in-container
  title: Terminal shell in container
  summary: Opens an interactive shell.
  technique: T1059.004
  detection: Terminal shell in container
  response: terminate
  timeout_seconds: 90
  pod:
    containers:
      - name: victim
        image: ` + img + `
  exec:
    command: ["sh", "-c", "id"]
    tty: true
- id: network-tool
  title: Network tool
  summary: Runs wget.
  technique: T1105
  detection: SDP network tool in sandbox
  response: quarantine
  victim: true
  pod:
    metadata:
      labels:
        extra: "yes"
    spec:
      containers:
        - name: victim
          image: ` + img + `
  exec: null
`

func TestParseBothPodForms(t *testing.T) {
	list, errs := Parse([]byte(sample))
	if len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	if len(list) != 2 {
		t.Fatalf("got %d scenarios", len(list))
	}
	if list[0].Template.Spec.Containers[0].Image != img || list[0].Timeout() != 90*time.Second {
		t.Fatalf("first: %+v", list[0])
	}
	if !list[0].Exec.TTY || list[0].Container() != "victim" {
		t.Fatalf("exec: %+v", list[0].Exec)
	}
	if list[0].Victim || list[0].Public().Victim || !list[1].Victim || !list[1].Public().Victim {
		t.Fatalf("victim flag: %v %v", list[0].Victim, list[1].Victim)
	}
	if list[1].Template.Labels["extra"] != "yes" || list[1].Exec != nil || list[1].Timeout() != DefaultTimeout {
		t.Fatalf("second: %+v", list[1])
	}
	if p := list[1].Public(); p.Response != "quarantine" || p.Detection != "SDP network tool in sandbox" {
		t.Fatalf("public: %+v", p)
	}
}

func TestParseWrappedForm(t *testing.T) {
	list, errs := Parse([]byte("scenarios:\n" + indent(sample)))
	if len(errs) != 0 || len(list) != 2 {
		t.Fatalf("wrapped: %d scenarios, errs %v", len(list), errs)
	}
}

func indent(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = "  " + l
		}
	}
	return strings.Join(lines, "\n")
}

func TestTimeoutCapped(t *testing.T) {
	if (Scenario{TimeoutSeconds: 600}).Timeout() != MaxTimeout {
		t.Fatal("timeout not capped at 120 s")
	}
}

func TestInvalidEntriesAreSkipped(t *testing.T) {
	bad := []struct{ name, yaml string }{
		{"foreign image", `- {id: a, title: A, response: terminate, pod: {containers: [{name: c, image: "docker.io/library/alpine:3@sha256:00"}]}}`},
		{"tag only", `- {id: a, title: A, response: terminate, pod: {containers: [{name: c, image: "` + strings.Split(img, "@")[0] + `"}]}}`},
		{"foreign init image", `- {id: a, title: A, response: terminate, pod: {initContainers: [{name: i, image: "busybox"}], containers: [{name: c, image: "` + img + `"}]}}`},
		{"bad response", `- {id: a, title: A, response: explode, pod: {containers: [{name: c, image: "` + img + `"}]}}`},
		{"bad id", `- {id: "A_B", title: A, response: terminate, pod: {containers: [{name: c, image: "` + img + `"}]}}`},
		{"no pod", `- {id: a, title: A, response: terminate}`},
		{"no containers", `- {id: a, title: A, response: terminate, pod: {containers: []}}`},
		{"unknown field", `- {id: a, title: A, response: terminate, pod: {containers: [{name: c, image: "` + img + `"}], hostPID2: true}}`},
		{"exec bad container", `- {id: a, title: A, response: terminate, pod: {containers: [{name: c, image: "` + img + `"}]}, exec: {command: [sh], container: nope}}`},
		{"exec empty", `- {id: a, title: A, response: terminate, pod: {containers: [{name: c, image: "` + img + `"}]}, exec: {command: []}}`},
		{"ephemeral", `- {id: a, title: A, response: terminate, pod: {containers: [{name: c, image: "` + img + `"}], ephemeralContainers: [{name: e, image: "` + img + `"}]}}`},
	}
	good := `- {id: ok, title: OK, response: terminate, pod: {containers: [{name: c, image: "` + img + `"}]}}`
	for _, b := range bad {
		list, errs := Parse([]byte(b.yaml + "\n" + good))
		if len(errs) != 1 || len(list) != 1 || list[0].ID != "ok" {
			t.Errorf("%s: list=%d errs=%v", b.name, len(list), errs)
		}
	}
	list, errs := Parse([]byte(good + "\n" + good))
	if len(list) != 1 || len(errs) != 1 {
		t.Errorf("duplicate id: list=%d errs=%v", len(list), errs)
	}
}

func TestStoreReloadsOnChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scenarios.yaml")
	s := NewStore(path, nil)
	if len(s.List()) != 0 {
		t.Fatal("missing file should be an empty catalogue")
	}
	if err := os.WriteFile(path, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	if len(s.List()) != 2 {
		t.Fatal("not loaded after the file appeared")
	}
	if _, ok := s.Get("network-tool"); !ok {
		t.Fatal("Get network-tool")
	}
	one := strings.SplitN(sample, "- id: network-tool", 2)[0]
	if err := os.WriteFile(path, []byte(one), 0o600); err != nil {
		t.Fatal(err)
	}
	// Size changed, so this is picked up even within the file system's mtime granularity.
	if len(s.List()) != 1 {
		t.Fatalf("not reloaded: %d", len(s.List()))
	}
	if _, ok := s.Get("network-tool"); ok {
		t.Fatal("removed scenario still served")
	}
}
