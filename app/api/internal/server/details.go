package server

// The three read-only endpoints behind the page's technical mode and its "verify it yourself" panel
// (ADR 0021): what a scenario actually is (details), everything one run published (runs), and where
// the visitor stands against the limits (limits). All three are GET, JSON, under the same request
// budget as everything else, and expose nothing the catalogue, the public repository or the event
// stream do not already show.

import (
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/clientip"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/ruleindex"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/scenarios"
)

// commitPattern: the build's commit, as GitHub Actions passes it (github.sha), or a short form.
// Anything else (unset, "unknown") is published as "", and the page links to the default branch.
var commitPattern = regexp.MustCompile(`^[0-9a-f]{7,40}$`)

// runIDPattern is newRunID's format.
var runIDPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

// Details is the GET /api/scenarios/{id}/details payload.
type Details struct {
	ID          string   `json:"id"`
	ExecCommand []string `json:"exec_command"`
	ExecTTY     bool     `json:"exec_tty"`
	// PreExecCommand runs before ExecCommand, without a TTY; [] when the scenario has none.
	PreExecCommand []string           `json:"pre_exec_command"`
	PodSecurity    PodSecurity        `json:"pod_security"`
	Resources      Resources          `json:"resources"`
	Image          Image              `json:"image"`
	FalcoRule      ruleindex.Rule     `json:"falco_rule"`
	TalonRule      ruleindex.Rule     `json:"talon_rule"`
	Policies       []ruleindex.Policy `json:"policies"`
	Commit         string             `json:"commit"`
	Victim         bool               `json:"victim"`
}

// PodSecurity is the effective security context of the container the command runs in: a container
// setting wins over the pod's, as in the kubelet; null where neither sets it. The field names are
// the Kubernetes ones, so they can be searched for in the catalogue as they are.
//
// automountServiceAccountToken is always false: the runner forces it off whatever the catalogue
// says (runner.buildPod), and this reports what the pod gets.
type PodSecurity struct {
	RunAsUser                    *int64   `json:"runAsUser"`
	RunAsNonRoot                 *bool    `json:"runAsNonRoot"`
	ReadOnlyRootFilesystem       *bool    `json:"readOnlyRootFilesystem"`
	AllowPrivilegeEscalation     *bool    `json:"allowPrivilegeEscalation"`
	CapabilitiesDrop             []string `json:"capabilities_drop"`
	Seccomp                      string   `json:"seccomp"`
	AutomountServiceAccountToken bool     `json:"automountServiceAccountToken"`
}

// Resources are the container's requests and limits as written ("10m", "32Mi").
type Resources struct {
	Requests map[string]string `json:"requests"`
	Limits   map[string]string `json:"limits"`
}

// Image is the container image: the reference as the catalogue pins it, and its digest.
type Image struct {
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
}

func (s *Server) details(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.cfg.Scenarios.Get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "unknown scenario")
		return
	}
	writeJSON(w, http.StatusOK, buildDetails(sc, s.cfg.Rules, s.cfg.Commit))
}

func buildDetails(sc scenarios.Scenario, rules *ruleindex.Index, commit string) Details {
	d := Details{ID: sc.ID, ExecCommand: []string{}, PreExecCommand: []string{}, Commit: commit, Victim: sc.Victim,
		Policies: []ruleindex.Policy{}, FalcoRule: ruleindex.Rule{Name: sc.Detection}}
	if sc.Exec != nil {
		d.ExecCommand = append(d.ExecCommand, sc.Exec.Command...)
		d.ExecTTY = sc.Exec.TTY
	}
	if sc.PreExec != nil {
		d.PreExecCommand = append(d.PreExecCommand, sc.PreExec.Command...)
	}
	if rules != nil {
		d.FalcoRule = rules.FalcoRule(sc.Detection)
		d.TalonRule = rules.TalonRule(sc.Detection)
		d.Policies = append(d.Policies, rules.Policies...)
	}

	spec := sc.Template.Spec
	var c corev1.Container
	for _, ct := range spec.Containers {
		if ct.Name == sc.Container() {
			c = ct
		}
	}
	d.Image.Ref = c.Image
	if i := strings.Index(c.Image, "@"); i >= 0 {
		d.Image.Digest = c.Image[i+1:]
	}
	d.Resources = Resources{Requests: quantities(c.Resources.Requests), Limits: quantities(c.Resources.Limits)}

	ps := PodSecurity{CapabilitiesDrop: []string{}}
	if p := spec.SecurityContext; p != nil {
		ps.RunAsUser, ps.RunAsNonRoot = p.RunAsUser, p.RunAsNonRoot
		if p.SeccompProfile != nil {
			ps.Seccomp = string(p.SeccompProfile.Type)
		}
	}
	if cs := c.SecurityContext; cs != nil {
		if cs.RunAsUser != nil {
			ps.RunAsUser = cs.RunAsUser
		}
		if cs.RunAsNonRoot != nil {
			ps.RunAsNonRoot = cs.RunAsNonRoot
		}
		if cs.SeccompProfile != nil {
			ps.Seccomp = string(cs.SeccompProfile.Type)
		}
		ps.ReadOnlyRootFilesystem, ps.AllowPrivilegeEscalation = cs.ReadOnlyRootFilesystem, cs.AllowPrivilegeEscalation
		if cs.Capabilities != nil {
			for _, dc := range cs.Capabilities.Drop {
				ps.CapabilitiesDrop = append(ps.CapabilitiesDrop, string(dc))
			}
		}
	}
	d.PodSecurity = ps
	return d
}

func quantities(rl corev1.ResourceList) map[string]string {
	out := make(map[string]string, len(rl))
	for k, q := range rl {
		out[string(k)] = q.String()
	}
	return out
}

func (s *Server) run(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.cfg.Runs == nil || !runIDPattern.MatchString(id) {
		writeError(w, http.StatusNotFound, "unknown run")
		return
	}
	run, ok := s.cfg.Runs.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "unknown run (only the last 50 runs are kept)")
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// Limits is the GET /api/limits payload.
type Limits struct {
	PerVisitor           VisitorLimit `json:"per_visitor"`
	Global               GlobalLimit  `json:"global"`
	ActiveRun            bool         `json:"active_run"`
	StreamSlotsRemaining int          `json:"stream_slots_remaining"`
}

// VisitorLimit is the attack budget of the visitor asking (keyed as the limiter keys it: the
// network address, a /64 for IPv6 - shared behind NAT).
type VisitorLimit struct {
	Limit     int `json:"limit"`
	WindowS   int `json:"window_s"`
	Remaining int `json:"remaining"`
	ResetInS  int `json:"reset_in_s"`
}

// GlobalLimit is everybody's attack budget together.
type GlobalLimit struct {
	Limit     int `json:"limit"`
	WindowS   int `json:"window_s"`
	Remaining int `json:"remaining"`
}

func (s *Server) limits(w http.ResponseWriter, r *http.Request) {
	key := clientip.Key(r)
	st := s.cfg.Attacks.Status(key)
	writeJSON(w, http.StatusOK, Limits{
		PerVisitor: VisitorLimit{Limit: st.PerKeyLimit, WindowS: seconds(st.PerKeyWindow),
			Remaining: st.PerKeyRemaining, ResetInS: seconds(st.PerKeyResetIn)},
		Global:               GlobalLimit{Limit: st.GlobalLimit, WindowS: seconds(st.GlobalWindow), Remaining: st.GlobalRemaining},
		ActiveRun:            st.Active,
		StreamSlotsRemaining: s.cfg.Streams.Remaining(key),
	})
}

// seconds rounds up, so "0" only ever means "now".
func seconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int(math.Ceil(d.Seconds()))
}
