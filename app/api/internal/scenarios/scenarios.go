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

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

const (
	// ImagePrefix is the only registry path a scenario image may come from; the same prefix
	// restrict-image-registries enforces in `sandbox`.
	ImagePrefix = "ghcr.io/hubertmj/self-defending-portfolio/"
	// MaxTimeout is the contract's ceiling for a scenario pod's lifetime.
	MaxTimeout = 120 * time.Second
	// DefaultTimeout applies when a scenario sets no timeout_seconds.
	DefaultTimeout = 60 * time.Second
)

// An id ends up in a pod name and a label value: DNS-1123 label, short enough to leave room for
// the run suffix.
var idPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,38}[a-z0-9])?$`)

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

	// Template is Pod decoded: either a PodTemplateSpec ({metadata, spec}) or a bare PodSpec.
	Template corev1.PodTemplateSpec `json:"-"`
}

// Public is the shape GET /api/scenarios returns: no pod spec, no command.
type Public struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Summary   string `json:"summary"`
	Technique string `json:"technique"`
	Detection string `json:"detection"`
	Response  string `json:"response"`
}

// Public returns the visitor-facing fields.
func (s Scenario) Public() Public {
	return Public{ID: s.ID, Title: s.Title, Summary: s.Summary, Technique: s.Technique, Detection: s.Detection, Response: s.Response}
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

// Container is the container exec runs in: the one named, or the first.
func (s Scenario) Container() string {
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
	if s.Response != "terminate" && s.Response != "quarantine" {
		return fmt.Errorf("response %q is not terminate or quarantine", s.Response)
	}
	if s.TimeoutSeconds < 0 {
		return errors.New("timeout_seconds is negative")
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
	return nil
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
