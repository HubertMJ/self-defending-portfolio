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
  pre_exec:
    command: ["sh", "-c", "deface"]
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
	if list[0].PreExec == nil || strings.Join(list[0].PreExec.Command, " ") != "sh -c deface" || list[0].PreExec.TTY ||
		list[1].PreExec != nil {
		t.Fatalf("pre_exec: %+v %+v", list[0].PreExec, list[1].PreExec)
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
		{"pre_exec with tty", `- {id: a, title: A, response: terminate, pod: {containers: [{name: c, image: "` + img + `"}]}, pre_exec: {command: [sh], tty: true}, exec: {command: [sh]}}`},
		{"pre_exec without exec", `- {id: a, title: A, response: terminate, pod: {containers: [{name: c, image: "` + img + `"}]}, pre_exec: {command: [sh]}}`},
		{"pre_exec empty", `- {id: a, title: A, response: terminate, pod: {containers: [{name: c, image: "` + img + `"}]}, pre_exec: {command: []}, exec: {command: [sh]}}`},
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

// terminalSample is a valid interactive scenario the way CLUSTER will write it: a `target`
// container, objectives in kill-chain order, and one command of each outcome.
const terminalSample = `
- id: terminal
  title: Attacker's terminal
  summary: Type commands into a hardened pod.
  interactive: true
  timeout_seconds: 120
  idle_seconds: 30
  victim: true
  objectives:
    - {id: recon, title: "Look around"}
    - {id: credentials, title: "Find credentials"}
  commands:
    - id: whoami
      input: "id"
      aliases: ["whoami"]
      objective: recon
      technique: T1033
      command: ["id"]
      tty: false
      outcome: allowed
      layer: runtime
      control: "Nothing: id is a normal process"
      explain: "You are a non-root user in a hardened pod."
    - id: write-bin
      input: "touch /bin/backdoor"
      command: ["touch", "/bin/backdoor"]
      outcome: prevented
      layer: pod-security
      control: "read-only root filesystem"
      explain: "The root filesystem is read-only, so the write fails."
    - id: read-shadow
      input: "cat /etc/shadow"
      objective: credentials
      technique: T1003.008
      command: ["cat", "/etc/shadow"]
      outcome: detected
      layer: runtime
      control: "Falco rule Read sensitive file untrusted"
      detection: Read sensitive file untrusted
      response: terminate
      explain: "Falco sees the read; Talon deletes the pod."
  pod:
    securityContext: {runAsNonRoot: true, runAsUser: 10001, seccompProfile: {type: RuntimeDefault}}
    containers:
      - name: target
        image: ` + img + `
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities: {drop: [ALL]}
        resources: {requests: {cpu: 10m, memory: 16Mi}, limits: {cpu: 100m, memory: 32Mi}}
`

func TestParseTerminal(t *testing.T) {
	list, errs := Parse([]byte(terminalSample))
	if len(errs) != 0 || len(list) != 1 {
		t.Fatalf("list=%d errs=%v", len(list), errs)
	}
	sc := list[0]
	if !sc.Interactive || sc.Idle() != 30*time.Second || sc.Timeout() != 120*time.Second {
		t.Fatalf("flags: interactive=%v idle=%v timeout=%v", sc.Interactive, sc.Idle(), sc.Timeout())
	}
	if !sc.Public().Interactive {
		t.Fatal("Public().Interactive is false")
	}
	if len(sc.Objectives) != 2 || sc.Objectives[0].ID != "recon" {
		t.Fatalf("objectives: %+v", sc.Objectives)
	}
	c, ok := sc.CommandByID("read-shadow")
	if !ok || c.Outcome != "detected" || c.Response != "terminate" || c.Objective != "credentials" {
		t.Fatalf("read-shadow: %+v ok=%v", c, ok)
	}
	if _, ok := sc.CommandByID("no-such"); ok {
		t.Fatal("CommandByID returned an unknown id")
	}
	if sc.Container() != "target" { // no exec, so the first (only) container
		t.Fatalf("container = %q", sc.Container())
	}
}

func TestTerminalValidation(t *testing.T) {
	base := func(mut func(*Scenario)) string {
		// Start from the valid terminal scenario and mutate the decoded form into YAML-ish by
		// editing the source string; simpler here to assert on hand-written bad snippets.
		return ""
	}
	_ = base
	bad := []struct {
		name, yaml string
	}{
		{"interactive with exec", `
- id: terminal
  title: t
  interactive: true
  commands: [{id: a, input: "id", command: [id], outcome: allowed, layer: runtime}]
  exec: {command: [sh], tty: false}
  pod: {containers: [{name: target, image: ` + img + `}]}`},
		{"interactive with response", `
- id: terminal
  title: t
  interactive: true
  response: terminate
  commands: [{id: a, input: "id", command: [id], outcome: allowed, layer: runtime}]
  pod: {containers: [{name: target, image: ` + img + `}]}`},
		{"no target container", `
- id: terminal
  title: t
  interactive: true
  commands: [{id: a, input: "id", command: [id], outcome: allowed, layer: runtime}]
  pod: {containers: [{name: victim, image: ` + img + `}]}`},
		{"no commands", `
- id: terminal
  title: t
  interactive: true
  pod: {containers: [{name: target, image: ` + img + `}]}`},
		{"bad outcome", `
- id: terminal
  title: t
  interactive: true
  commands: [{id: a, input: "id", command: [id], outcome: nope, layer: runtime}]
  pod: {containers: [{name: target, image: ` + img + `}]}`},
		{"bad layer", `
- id: terminal
  title: t
  interactive: true
  commands: [{id: a, input: "id", command: [id], outcome: allowed, layer: moon}]
  pod: {containers: [{name: target, image: ` + img + `}]}`},
		{"detected without detection", `
- id: terminal
  title: t
  interactive: true
  commands: [{id: a, input: "id", command: [id], outcome: detected, layer: runtime, response: terminate}]
  pod: {containers: [{name: target, image: ` + img + `}]}`},
		{"allowed with response", `
- id: terminal
  title: t
  interactive: true
  commands: [{id: a, input: "id", command: [id], outcome: allowed, layer: runtime, response: terminate}]
  pod: {containers: [{name: target, image: ` + img + `}]}`},
		{"duplicate command id", `
- id: terminal
  title: t
  interactive: true
  commands:
    - {id: a, input: "id", command: [id], outcome: allowed, layer: runtime}
    - {id: a, input: "ls", command: [ls], outcome: allowed, layer: runtime}
  pod: {containers: [{name: target, image: ` + img + `}]}`},
		{"ambiguous input", `
- id: terminal
  title: t
  interactive: true
  commands:
    - {id: a, input: "id", command: [id], outcome: allowed, layer: runtime}
    - {id: b, input: "id", command: [ls], outcome: allowed, layer: runtime}
  pod: {containers: [{name: target, image: ` + img + `}]}`},
		{"objective not declared", `
- id: terminal
  title: t
  interactive: true
  commands: [{id: a, input: "id", command: [id], objective: ghost, outcome: allowed, layer: runtime}]
  pod: {containers: [{name: target, image: ` + img + `}]}`},
		{"commands on non-interactive", `
- id: x
  title: t
  response: terminate
  commands: [{id: a, input: "id", command: [id], outcome: allowed, layer: runtime}]
  pod: {containers: [{name: target, image: ` + img + `}]}`},
	}
	for _, b := range bad {
		list, errs := Parse([]byte(b.yaml))
		if len(errs) != 1 || len(list) != 0 {
			t.Errorf("%s: expected one error, got list=%d errs=%v", b.name, len(list), errs)
		}
	}
}

// A catalogue shaped like the real cluster-branch `terminal` entry: a tty:true detected command, a
// prevented command with no objective, a multi-line deface, SDP_FLAG not declared. It must validate.
const realisticTerminal = `
- id: terminal
  title: Attacker's terminal
  summary: Type commands into a hardened pod.
  interactive: true
  timeout_seconds: 120
  idle_seconds: 30
  victim: true
  objectives:
    - {id: recon, title: "Look around"}
    - {id: execution, title: "Run your own code"}
    - {id: exfiltration, title: "Phone home"}
  commands:
    - {id: whoami, input: "id", aliases: ["whoami"], objective: recon, technique: T1033, command: [id], tty: false, outcome: allowed, layer: runtime, control: "Falco watching", explain: "unprivileged"}
    - {id: caps, input: "grep Cap /proc/self/status", command: [grep, Cap, /proc/self/status], outcome: allowed, layer: pod-security, control: "all caps dropped", explain: "CapEff zero"}
    - {id: touch-bin, input: "touch /bin/backdoor", technique: T1543, command: [touch, /bin/backdoor], outcome: prevented, layer: pod-security, control: "read-only root", explain: "read-only fs"}
    - {id: beacon, input: "wget -q -T 2 -O- http://127.0.0.1:9/", aliases: ["wget"], objective: exfiltration, command: [wget, -q, -T, "2", -O-, "http://127.0.0.1:9/"], outcome: detected, layer: network, control: "SDP network tool", detection: SDP network tool in sandbox, response: quarantine, explain: "beacon"}
    - {id: shell, input: "sh -i", aliases: ["bash -i"], objective: execution, command: [sh, -i], tty: true, outcome: detected, layer: runtime, control: "Terminal shell", detection: Terminal shell in container, response: terminate, explain: "second shell"}
    - id: drop-run
      input: "cp /bin/busybox /srv/shop/busybox && /srv/shop/busybox echo"
      aliases: ["drop and execute"]
      objective: execution
      command: [sh, -c, "cp /bin/busybox /srv/shop/busybox && exec /srv/shop/busybox echo ran"]
      outcome: detected
      layer: runtime
      control: "SDP execution from shop volume"
      detection: SDP execution from shop volume
      response: terminate
      explain: "drop and run"
  pod:
    securityContext: {runAsNonRoot: true, runAsUser: 10001, supplementalGroups: [42], seccompProfile: {type: RuntimeDefault}}
    containers:
      - name: target
        image: ` + img + `
        securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
        resources: {requests: {cpu: 10m, memory: 16Mi}, limits: {cpu: 100m, memory: 32Mi}}
`

func TestParseRealisticTerminal(t *testing.T) {
	list, errs := Parse([]byte(realisticTerminal))
	if len(errs) != 0 || len(list) != 1 {
		t.Fatalf("list=%d errs=%v", len(list), errs)
	}
	sc := list[0]
	if len(sc.Commands) != 6 {
		t.Fatalf("commands=%d", len(sc.Commands))
	}
	if sc.Container() != "target" {
		t.Fatalf("container=%q", sc.Container())
	}
	// A command with no objective serialises without the field; aliases never null.
	for _, c := range sc.Commands {
		if c.Aliases == nil {
			t.Fatalf("command %q has nil aliases", c.ID)
		}
	}
}

func TestTerminalCommandValidationExtra(t *testing.T) {
	bad := []struct{ name, yaml string }{
		{"empty argv element", `
- id: terminal
  title: t
  interactive: true
  commands: [{id: a, input: "x", command: ["", "y"], outcome: allowed, layer: runtime}]
  pod: {containers: [{name: target, image: ` + img + `}]}`},
		{"tty on allowed", `
- id: terminal
  title: t
  interactive: true
  commands: [{id: a, input: "x", command: [sh], tty: true, outcome: allowed, layer: runtime}]
  pod: {containers: [{name: target, image: ` + img + `}]}`},
		{"SDP_FLAG predeclared", `
- id: terminal
  title: t
  interactive: true
  commands: [{id: a, input: "x", command: [id], outcome: allowed, layer: runtime}]
  pod: {containers: [{name: target, image: ` + img + `, env: [{name: SDP_FLAG, value: fixed}]}]}`},
	}
	for _, b := range bad {
		list, errs := Parse([]byte(b.yaml))
		if len(errs) != 1 || len(list) != 0 {
			t.Errorf("%s: expected one error, got list=%d errs=%v", b.name, len(list), errs)
		}
	}
}
