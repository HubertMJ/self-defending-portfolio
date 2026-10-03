// Package scenarios loads the attack catalogue: the `scenarios` ConfigMap (key scenarios.yaml),
// mounted into the API pod as a file. The API never hardcodes a scenario id; what can be triggered is
// exactly what that ConfigMap lists and this package accepts.
//
// Mounted rather than read through the API server: no RBAC on ConfigMaps is needed, and the kubelet
// refreshes the file in place when the ConfigMap changes (a whole-directory mount, not subPath), so
// a new scenario is live without a restart. The file is re-read when its modification time or size
// changes.
//
// Every scenario is validated before it can run, and an invalid one is skipped (and logged), not
// fatal: one bad entry must not take the other three down with it. Validation is defence in depth
// only - the pod still goes through Pod Security admission and the Kyverno image policies in
// `sandbox` - but failing here gives a clear log line instead of a cryptic admission error mid-run.
package scenarios

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

const (
	// ImagePrefix is the only registry path a scenario image may come from; the same prefix
	// restrict-image-registries enforces in `sandbox`.
	ImagePrefix = "ghcr.io/hubertmj/self-defending-portfolio/"
	// MaxTimeout is the contract's ceiling for a scenario pod's lifetime: the same bound the
	// cluster enforces on every sandbox pod's activeDeadlineSeconds (require-sandbox-deadline). It
	// was 120 s until the terminal's session went to 300 s so a visitor has time to read between
	// commands (ADR 0017 amendment of 2026-10-03). A catalogue entry over it is refused, not capped.
	MaxTimeout = 300 * time.Second
	// DefaultTimeout applies when a scenario sets no timeout_seconds.
	DefaultTimeout = 60 * time.Second
	// DefaultIdle ends an interactive run that goes this long without a command (ADR 0029). The
	// catalogue sets idle_seconds; this is the fallback when it does not.
	DefaultIdle = 30 * time.Second
	// MaxCommandInput caps the printable-ASCII `input` (and each alias) a terminal command may
	// show: these are display strings for the web terminal, never sent to the cluster.
	MaxCommandInput = 80
	// MaxCommands is the catalogue ceiling on a terminal scenario's command list; the per-run cap
	// on how many a visitor may send is a separate, smaller limit enforced by the server.
	MaxCommands = 64
	// Generous caps on the human-readable command and objective fields: enough for the real
	// catalogue (a sentence or two), tight enough that a malformed entry cannot carry a wall of
	// text into the page. Every one of these is shown to the visitor.
	maxTechnique      = 40
	maxControl        = 200
	maxExplain        = 2000
	maxObjectiveTitle = 120
	// The scenario title and a detection (a Falco rule name, on the scenario or a command) are shown
	// on the page as well; the real ones are under 50 characters.
	maxTitle     = 120
	maxDetection = 120
)

// flagEnv is the environment variable the runner sets per terminal run; the catalogue must not
// declare it (the API owns its value).
const flagEnv = "SDP_FLAG"

// An id ends up in a pod name and a label value: DNS-1123 label, short enough to leave room for
// the run suffix.
var idPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,38}[a-z0-9])?$`)

// A terminal command id or objective id: [a-z0-9-]{1,32}, the only thing POST
// /api/runs/{id}/commands accepts (the contract's hard rule: no visitor free text reaches the
// cluster, command ids only).
var shortIDPattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// TerminalContainer is the container a terminal scenario's commands run in.
const TerminalContainer = "target"

// Command outcomes and the defence-map layers a command may report (ADR 0029). The API only
// records what the catalogue states; it does not infer either from the Falco/Talon events.
var (
	commandOutcomes = map[string]bool{"allowed": true, "prevented": true, "detected": true}
	commandLayers   = map[string]bool{
		"edge": true, "host": true, "network": true, "supply-chain": true,
		"admission": true, "pod-security": true, "runtime": true,
	}
)

// Exec is the command run in the scenario pod once it is Ready.
type Exec struct {
	Command   []string `json:"command"`
	TTY       bool     `json:"tty"`
	Container string   `json:"container,omitempty"`
}

// Scenario is one entry of scenarios.yaml.
type Scenario struct {
	ID             string          `json:"id"`
	Title          string          `json:"title"`
	Summary        string          `json:"summary"`
	Technique      string          `json:"technique"`
	Detection      string          `json:"detection"`
	Response       string          `json:"response"`
	TimeoutSeconds int             `json:"timeout_seconds"`
	Pod            json.RawMessage `json:"pod"`
	Exec           *Exec           `json:"exec"`
	// PreExec, if set, runs to completion before Exec, in the same container and never with a
	// TTY. It is the visible half of an attack whose detected half fires the moment it starts
	// (shell-in-container: the interactive shell *is* the detection, so the victim must be defaced
	// by an earlier, undetected step for the visitor to see it before the kill; ADR 0022). Without
	// a TTY a shell does not match "Terminal shell in container"; validate refuses tty: true.
	PreExec *Exec `json:"pre_exec,omitempty"`
	// Victim marks a scenario whose image serves the victim app (state.json on :8080). Optional,
	// false when absent: only then does the runner probe the pod (runner/victim.go, ADR 0021), so a
	// scenario image without the app never shows a spurious "unreachable".
	Victim bool `json:"victim"`

	// Interactive marks a terminal scenario (ADR 0029): the pod is created and kept alive, and the
	// visitor runs catalogue commands into it one at a time, instead of a single scripted exec. An
	// interactive scenario has no exec/pre_exec and its own detection/response are empty; each
	// command carries its own. Validation enforces that split.
	Interactive bool `json:"interactive"`
	// IdleSeconds ends an interactive run after this long without a command (0: DefaultIdle). Only
	// meaningful when Interactive.
	IdleSeconds int `json:"idle_seconds"`
	// Objectives are what the visitor tries to reach, in kill-chain order; a command may count
	// towards one by its id. Only meaningful when Interactive.
	Objectives []Objective `json:"objectives"`
	// Commands is the terminal catalogue: every command the visitor may run, by stable id. Only
	// meaningful when Interactive; the one thing POST /api/runs/{id}/commands accepts is a
	// command's id.
	Commands []Command `json:"commands"`

	// Template is Pod decoded: either a PodTemplateSpec ({metadata, spec}) or a bare PodSpec.
	Template corev1.PodTemplateSpec `json:"-"`
}

// Objective is one goal a terminal visitor works towards, shown in kill-chain order.
type Objective struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// Command is one entry of a terminal scenario's catalogue (ADR 0029). The visitor sends its ID and
// nothing else; Input and Aliases are the spellings the web terminal offers for completion and are
// never matched by the API. Command is the argv run in container `target`.
type Command struct {
	ID        string   `json:"id"`
	Input     string   `json:"input"`
	Aliases   []string `json:"aliases"`
	Objective string   `json:"objective,omitempty"`
	Technique string   `json:"technique"`
	Command   []string `json:"command"`
	TTY       bool     `json:"tty"`
	// Outcome is allowed | prevented | detected: what the command does against the cluster, as the
	// catalogue states it (not inferred from events).
	Outcome string `json:"outcome"`
	// Layer is the defence-map layer this command exercises (edge, host, network, supply-chain,
	// admission, pod-security, runtime).
	Layer string `json:"layer"`
	// Control is the one-line name of what answers (a Falco rule, a kernel refusal, nothing).
	Control string `json:"control"`
	// Detection and Response are set only when Outcome == detected: the Falco rule that fires and
	// what Talon does (terminate | quarantine).
	Detection string `json:"detection"`
	Response  string `json:"response"`
	// Explain is the one or two sentences shown after the command ran.
	Explain string `json:"explain"`
}

// Public is the shape GET /api/scenarios returns: no pod spec, no command.
type Public struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Summary     string `json:"summary"`
	Technique   string `json:"technique"`
	Detection   string `json:"detection"`
	Response    string `json:"response"`
	Victim      bool   `json:"victim"`
	Interactive bool   `json:"interactive"`
}

// Public returns the visitor-facing fields.
func (s Scenario) Public() Public {
	return Public{ID: s.ID, Title: s.Title, Summary: s.Summary, Technique: s.Technique, Detection: s.Detection,
		Response: s.Response, Victim: s.Victim, Interactive: s.Interactive}
}

// Idle is an interactive scenario's idle timeout, defaulted; zero for a non-interactive one.
func (s Scenario) Idle() time.Duration {
	if !s.Interactive {
		return 0
	}
	if s.IdleSeconds <= 0 {
		return DefaultIdle
	}
	return time.Duration(s.IdleSeconds) * time.Second
}

// CommandByID returns the catalogue command with the given id. The API matches by id only; a
// visitor's typed text never reaches here.
func (s Scenario) CommandByID(id string) (Command, bool) {
	for _, c := range s.Commands {
		if c.ID == id {
			return c, true
		}
	}
	return Command{}, false
}

// Timeout is the scenario's run time limit, defaulted and capped.
func (s Scenario) Timeout() time.Duration {
	d := time.Duration(s.TimeoutSeconds) * time.Second
	switch {
	case d <= 0:
		return DefaultTimeout
	case d > MaxTimeout:
		return MaxTimeout
	}
	return d
}

// Container is the container exec (or a terminal command) runs in: the one the exec names, the
// fixed `target` for an interactive scenario, or the first container.
func (s Scenario) Container() string {
	if s.Interactive {
		return TerminalContainer
	}
	if s.Exec != nil && s.Exec.Container != "" {
		return s.Exec.Container
	}
	return s.Template.Spec.Containers[0].Name
}

// Parse decodes and validates scenarios.yaml. It accepts a top-level list (the contract's form) or
// an object with a `scenarios` list. Invalid entries are returned as errors next to the valid ones.
func Parse(data []byte) ([]Scenario, []error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil
	}
	var list []Scenario
	if err := yaml.Unmarshal(data, &list); err != nil {
		var wrapped struct {
			Scenarios []Scenario `json:"scenarios"`
		}
		if err2 := yaml.Unmarshal(data, &wrapped); err2 != nil {
			return nil, []error{fmt.Errorf("scenarios.yaml: %w", err)}
		}
		list = wrapped.Scenarios
	}
	var (
		valid []Scenario
		errs  []error
		seen  = map[string]bool{}
	)
	for i, s := range list {
		if err := s.validate(); err != nil {
			errs = append(errs, fmt.Errorf("scenario #%d (%q): %w", i, s.ID, err))
			continue
		}
		if seen[s.ID] {
			errs = append(errs, fmt.Errorf("scenario #%d: duplicate id %q", i, s.ID))
			continue
		}
		seen[s.ID] = true
		valid = append(valid, s)
	}
	return valid, errs
}

func (s *Scenario) validate() error {
	if !idPattern.MatchString(s.ID) {
		return errors.New("id must be a DNS-1123 label of at most 40 characters")
	}
	if strings.TrimSpace(s.Title) == "" {
		return errors.New("title is empty")
	}
	if !printableText(s.Title, maxTitle) {
		return fmt.Errorf("title is not printable or is over %d characters", maxTitle)
	}
	if s.Detection != "" && !printableText(s.Detection, maxDetection) {
		return fmt.Errorf("detection is not printable or is over %d characters", maxDetection)
	}
	if s.Interactive {
		// A terminal scenario carries no scripted attack of its own: its detection/response are
		// empty (each command has its own), and it runs no exec/pre_exec.
		if s.Response != "" || s.Detection != "" {
			return errors.New("an interactive scenario's detection and response must be empty (each command carries its own)")
		}
		if s.Exec != nil || s.PreExec != nil {
			return errors.New("an interactive scenario must not declare exec or pre_exec (commands are run on request)")
		}
	} else {
		if s.Response != "terminate" && s.Response != "quarantine" {
			return fmt.Errorf("response %q is not terminate or quarantine", s.Response)
		}
		if len(s.Commands) > 0 || len(s.Objectives) > 0 || s.IdleSeconds != 0 {
			return errors.New("commands, objectives and idle_seconds are for interactive scenarios only")
		}
	}
	if s.TimeoutSeconds < 0 {
		return errors.New("timeout_seconds is negative")
	}
	// Refused rather than silently capped by Timeout(): the cluster refuses such a pod anyway
	// (require-sandbox-deadline), and a clear log line here beats an admission error mid-run.
	// Compared in seconds, so an absurd value cannot overflow time.Duration into a small one.
	if s.TimeoutSeconds > int(MaxTimeout/time.Second) {
		return fmt.Errorf("timeout_seconds %d is over the %d s bound", s.TimeoutSeconds, int(MaxTimeout/time.Second))
	}
	if s.IdleSeconds < 0 {
		return errors.New("idle_seconds is negative")
	}
	// An idle timeout at or past the deadline never fires: the run would always end as `deadline`
	// and the visitor would never be told they went quiet. Compared on the defaulted values, so an
	// entry that sets neither (60 s and 30 s) passes and one that sets only a short timeout does not;
	// in seconds, as above.
	if s.Interactive {
		idle, timeout := int(DefaultIdle/time.Second), int(s.Timeout()/time.Second)
		if s.IdleSeconds > 0 {
			idle = s.IdleSeconds
		}
		if idle >= timeout {
			return fmt.Errorf("idle_seconds %d must be below timeout_seconds %d", idle, timeout)
		}
	}
	if len(s.Pod) == 0 || string(s.Pod) == "null" {
		return errors.New("pod is missing")
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(s.Pod, &probe); err != nil {
		return fmt.Errorf("pod: %w", err)
	}
	if _, ok := probe["spec"]; ok {
		if err := strictUnmarshal(s.Pod, &s.Template); err != nil {
			return fmt.Errorf("pod (template): %w", err)
		}
	} else if err := strictUnmarshal(s.Pod, &s.Template.Spec); err != nil {
		return fmt.Errorf("pod (spec): %w", err)
	}
	spec := &s.Template.Spec
	if len(spec.Containers) == 0 {
		return errors.New("pod has no containers")
	}
	if len(spec.EphemeralContainers) > 0 {
		return errors.New("pod must not declare ephemeral containers")
	}
	for _, c := range append(append([]corev1.Container{}, spec.InitContainers...), spec.Containers...) {
		if !strings.HasPrefix(c.Image, ImagePrefix) || !strings.Contains(c.Image, "@sha256:") {
			return fmt.Errorf("container %q: image must be %s<name>[:tag]@sha256:<digest>", c.Name, ImagePrefix)
		}
	}
	if s.PreExec != nil {
		switch {
		case s.Exec == nil:
			return errors.New("pre_exec needs an exec to precede")
		case len(s.PreExec.Command) == 0:
			return errors.New("pre_exec.command is empty")
		case s.PreExec.TTY:
			return errors.New("pre_exec must not have a TTY (it would be detected as a terminal shell itself)")
		case s.PreExec.Container != "" && s.PreExec.Container != s.Container():
			return errors.New("pre_exec runs in exec's container")
		}
	}
	if s.Exec != nil {
		if len(s.Exec.Command) == 0 {
			return errors.New("exec.command is empty")
		}
		found := false
		for _, c := range spec.Containers {
			found = found || c.Name == s.Container()
		}
		if !found {
			return fmt.Errorf("exec.container %q is not a container of the pod", s.Container())
		}
	}
	if s.Interactive {
		if err := s.validateInteractive(spec); err != nil {
			return err
		}
	}
	return nil
}

// validateInteractive checks the terminal-only shape: a container named `target` for the commands
// to run in, well-formed objectives, and a command catalogue whose ids, inputs and detected-outcome
// fields are all consistent. The visitor only ever sends a command id, so the ids must be unique;
// inputs and aliases are display text and are kept short printable ASCII, not because the API
// matches them but so the catalogue cannot smuggle control characters into the terminal.
func (s *Scenario) validateInteractive(spec *corev1.PodSpec) error {
	hasTarget := false
	for _, c := range spec.Containers {
		if c.Name != TerminalContainer {
			continue
		}
		hasTarget = true
		for _, e := range c.Env {
			if e.Name == flagEnv {
				return fmt.Errorf("the catalogue must not set %s on %q; the API sets it per run", flagEnv, TerminalContainer)
			}
		}
	}
	if !hasTarget {
		return fmt.Errorf("an interactive scenario needs a container named %q for its commands", TerminalContainer)
	}
	objIDs := map[string]bool{}
	for i, o := range s.Objectives {
		if !shortIDPattern.MatchString(o.ID) {
			return fmt.Errorf("objective #%d: id must match [a-z0-9-]{1,32}", i)
		}
		if objIDs[o.ID] {
			return fmt.Errorf("objective #%d: duplicate id %q", i, o.ID)
		}
		if !printableText(o.Title, maxObjectiveTitle) {
			return fmt.Errorf("objective %q: title is empty or over %d printable characters", o.ID, maxObjectiveTitle)
		}
		objIDs[o.ID] = true
	}
	if len(s.Commands) == 0 {
		return errors.New("an interactive scenario has no commands")
	}
	if len(s.Commands) > MaxCommands {
		return fmt.Errorf("an interactive scenario has %d commands, more than %d", len(s.Commands), MaxCommands)
	}
	ids := map[string]bool{}
	inputs := map[string]bool{}
	for i := range s.Commands {
		c := &s.Commands[i]
		if c.Aliases == nil {
			c.Aliases = []string{} // so details serialises [] not null
		}
		if !shortIDPattern.MatchString(c.ID) {
			return fmt.Errorf("command #%d: id must match [a-z0-9-]{1,32}", i)
		}
		if ids[c.ID] {
			return fmt.Errorf("command #%d: duplicate id %q", i, c.ID)
		}
		ids[c.ID] = true
		if err := c.validate(objIDs, inputs); err != nil {
			return fmt.Errorf("command %q: %w", c.ID, err)
		}
	}
	return nil
}

// validate checks one catalogue command. inputs accumulates the inputs and aliases already seen, so
// a spelling is never ambiguous across the catalogue.
func (c Command) validate(objectives, inputs map[string]bool) error {
	if len(c.Command) == 0 {
		return errors.New("command argv is empty")
	}
	for _, a := range c.Command {
		if a == "" {
			return errors.New("command argv has an empty element")
		}
	}
	for _, spelling := range append([]string{c.Input}, c.Aliases...) {
		if !printableASCII(spelling, MaxCommandInput) {
			return fmt.Errorf("input/alias %q must be 1-%d printable ASCII characters", spelling, MaxCommandInput)
		}
		if inputs[spelling] {
			return fmt.Errorf("input/alias %q is used by more than one command", spelling)
		}
		inputs[spelling] = true
	}
	if c.Objective != "" && !objectives[c.Objective] {
		return fmt.Errorf("objective %q is not one of the scenario's objectives", c.Objective)
	}
	if !commandOutcomes[c.Outcome] {
		return fmt.Errorf("outcome %q is not allowed, prevented or detected", c.Outcome)
	}
	if !commandLayers[c.Layer] {
		return fmt.Errorf("layer %q is not a defence-map layer", c.Layer)
	}
	// The human-readable fields are shown to the visitor: bound them and forbid control/invisible
	// characters (the Falco "Terminal shell" rule only fires on a TTY, so a TTY command must be a
	// detected one - otherwise a catalogue typo would make an "allowed" command get the pod killed).
	if c.Technique != "" && !printableText(c.Technique, maxTechnique) {
		return fmt.Errorf("technique %q is not printable or is over %d characters", c.Technique, maxTechnique)
	}
	if c.Control != "" && !printableText(c.Control, maxControl) {
		return errors.New("control is not printable or is too long")
	}
	if c.Explain != "" && !printableText(c.Explain, maxExplain) {
		return errors.New("explain is not printable or is too long")
	}
	if c.TTY && c.Outcome != "detected" {
		return errors.New("tty: true is only for a detected command (a TTY shell is what Falco detects)")
	}
	if c.Outcome == "detected" {
		if strings.TrimSpace(c.Detection) == "" {
			return errors.New("a detected command needs a detection (the Falco rule)")
		}
		if !printableText(c.Detection, maxDetection) {
			return fmt.Errorf("detection is not printable or is over %d characters", maxDetection)
		}
		if c.Response != "terminate" && c.Response != "quarantine" {
			return fmt.Errorf("a detected command's response %q is not terminate or quarantine", c.Response)
		}
	} else if c.Detection != "" || c.Response != "" {
		return errors.New("detection and response are set only for a detected command")
	}
	return nil
}

// printableText reports whether s is 1..n runes with no control or invisible-format characters
// (tabs and other whitespace within a line are allowed). Used for the command/objective text the
// page shows; the API never acts on these, but they must not carry control characters.
func printableText(s string, n int) bool {
	count := 0
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
		count++
		if count > n {
			return false
		}
	}
	return count > 0
}

// printableASCII reports whether s is 1..n characters, each a printable ASCII byte (0x20-0x7e). A
// terminal command's display text is held to this so the catalogue cannot put control characters,
// invisible format characters or multi-byte runes into what the terminal echoes.
func printableASCII(s string, n int) bool {
	if len(s) == 0 || len(s) > n {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// strictUnmarshal rejects unknown fields: a typo in a PodSpec should fail here, loudly, rather than
// silently drop a security setting.
func strictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// Store serves the parsed catalogue from a file, reloading it when the file changes.
type Store struct {
	path string
	log  *slog.Logger

	mu      sync.Mutex
	modTime time.Time
	size    int64
	loaded  bool
	list    []Scenario
}

// NewStore returns a store for path. A missing file is an empty catalogue (the ConfigMap volume is
// optional, so the API starts before the scenarios exist).
func NewStore(path string, log *slog.Logger) *Store {
	if log == nil {
		log = slog.Default()
	}
	return &Store{path: path, log: log}
}

// List returns the valid scenarios, in file order.
func (s *Store) List() []Scenario {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	return s.list
}

// Get returns the scenario with the given id.
func (s *Store) Get(id string) (Scenario, bool) {
	for _, sc := range s.List() {
		if sc.ID == id {
			return sc, true
		}
	}
	return Scenario{}, false
}

func (s *Store) refreshLocked() {
	fi, err := os.Stat(s.path)
	if err != nil {
		if s.loaded || !errors.Is(err, os.ErrNotExist) {
			s.log.Warn("scenarios file unavailable", "path", s.path, "err", err)
		}
		s.list, s.loaded, s.modTime, s.size = nil, false, time.Time{}, 0
		return
	}
	if s.loaded && fi.ModTime().Equal(s.modTime) && fi.Size() == s.size {
		return
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		s.log.Warn("scenarios file unreadable", "path", s.path, "err", err)
		return
	}
	list, errs := Parse(data)
	for _, e := range errs {
		s.log.Warn("scenario skipped", "err", e)
	}
	s.list, s.loaded, s.modTime, s.size = list, true, fi.ModTime(), fi.Size()
	s.log.Info("scenarios loaded", "count", len(list), "skipped", len(errs))
}
