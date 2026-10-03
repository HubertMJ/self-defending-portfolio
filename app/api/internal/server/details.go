package server

// The read-only endpoints behind the page's technical mode and its "verify it yourself" panel
// (ADR 0021, 0035): what a scenario actually is (details), everything one run published (runs/{id})
// and the list of kept runs (runs), where the visitor stands against the limits (limits), and what
// the running images were built from (provenance). All are GET, JSON, under the same request budget
// as everything else, and expose nothing the catalogue, the public repository, the registry's
// signatures or the event stream do not already show.

import (
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/clientip"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/ruleindex"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/runlog"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/scenarios"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/stats"
)

// commitPattern: the build's commit, as GitHub Actions passes it (github.sha), or a short form.
// Anything else (unset, "unknown") is published as "", and the page links to the default branch.
var commitPattern = regexp.MustCompile(`^[0-9a-f]{7,40}$`)

// ciRunIDPattern: a GitHub Actions run id (github.run_id) as the Dockerfile passes it in CI_RUN_ID.
var ciRunIDPattern = regexp.MustCompile(`^[0-9]{1,20}$`)

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
	// Terminal fields (ADR 0029), present for an interactive scenario; absent otherwise. Commands
	// carries every catalogue field, the argv included - it is public in the repository anyway, and
	// the web terminal needs the spellings for completion.
	Interactive    bool                  `json:"interactive"`
	TimeoutSeconds int                   `json:"timeout_seconds,omitempty"`
	IdleSeconds    int                   `json:"idle_seconds,omitempty"`
	Objectives     []scenarios.Objective `json:"objectives,omitempty"`
	Commands       []scenarios.Command   `json:"commands,omitempty"`
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
		Policies: []ruleindex.Policy{}, FalcoRule: ruleindex.Rule{Name: sc.Detection}, Interactive: sc.Interactive}
	if sc.Interactive {
		d.TimeoutSeconds = int(sc.Timeout().Seconds())
		d.IdleSeconds = int(sc.Idle().Seconds())
		d.Objectives = sc.Objectives
		d.Commands = sc.Commands
		if d.Objectives == nil {
			d.Objectives = []scenarios.Objective{}
		}
		if d.Commands == nil {
			d.Commands = []scenarios.Command{}
		}
	}
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

// stats returns the cross-visitor counters (ADR 0030). A nil collector (not wired, e.g. in a test)
// is an empty-but-well-formed snapshot, so the page never has to special-case a missing field.
func (s *Server) stats(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.Stats == nil {
		writeJSON(w, http.StatusOK, stats.Snapshot{
			Since: s.cfg.Now().UTC(), ByScenario: map[string]stats.ScenarioStat{},
			Commands: map[string]stats.CommandStat{}, Objectives: map[string]stats.ObjectiveStat{},
			Last24h: stats.Window{Since: s.cfg.Now().UTC()}})
		return
	}
	writeJSON(w, http.StatusOK, s.cfg.Stats.Snapshot())
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

// RunList is the GET /api/runs payload (ADR 0035): the kept runs, newest first, and how many are
// kept. Each row says only what the run's own state events say; the events are at /api/runs/{id}.
type RunList struct {
	Runs []runlog.Summary `json:"runs"`
	Kept int              `json:"kept"`
}

func (s *Server) runs(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.Runs == nil {
		writeJSON(w, http.StatusOK, RunList{Runs: []runlog.Summary{}})
		return
	}
	writeJSON(w, http.StatusOK, RunList{Runs: s.cfg.Runs.List(), Kept: s.cfg.Runs.Kept()})
}

// Provenance is the GET /api/provenance payload (ADR 0035): what this API was built from (commit and
// CI run, from the image's environment), when it started, and the api and web image digests the
// cluster's Running pods run, from posture's pod list - so a visitor can check each digest's
// signature and find its Rekor entry. Never a pod name or a namespace.
type Provenance struct {
	GeneratedAt      time.Time     `json:"generated_at"`
	API              ProvenanceAPI `json:"api"`
	Web              ProvenanceWeb `json:"web"`
	ImagesObservedAt *time.Time    `json:"images_observed_at"`
}

// ProvenanceAPI is the API's own build and its running images.
type ProvenanceAPI struct {
	Commit    string    `json:"commit"`
	CIRunID   string    `json:"ci_run_id"`
	StartedAt time.Time `json:"started_at"`
	Images    []string  `json:"images"`
}

// ProvenanceWeb is the web's running images; its commit and run are in the web image's /build.json.
type ProvenanceWeb struct {
	Images []string `json:"images"`
}

func (s *Server) provenance(w http.ResponseWriter, r *http.Request) {
	p := Provenance{GeneratedAt: s.cfg.Now().UTC(),
		API: ProvenanceAPI{Commit: s.cfg.Commit, CIRunID: s.cfg.CIRunID, StartedAt: s.cfg.StartedAt, Images: []string{}},
		Web: ProvenanceWeb{Images: []string{}}}
	if s.cfg.Posture != nil {
		d := s.cfg.Posture.Get(r.Context()).Deployed
		p.API.Images = append(p.API.Images, d.API...)
		p.Web.Images = append(p.Web.Images, d.Web...)
		p.ImagesObservedAt = d.ObservedAt
	}
	writeJSON(w, http.StatusOK, p)
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
