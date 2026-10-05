package incidents

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/webhook"
)

// View is the GET /api/correlation payload (ADR 0036 "Endpoints"). Every list marshals as [].
type View struct {
	Available bool        `json:"available"`
	CheckedAt *time.Time  `json:"checked_at"`
	Rules     RulesView   `json:"rules"`
	Health    HealthView  `json:"health"`
	Metrics   MetricsView `json:"metrics"`
	Incidents []Incident  `json:"incidents"`
}

// RulesView is what the rules sync last did (siem-sync).
type RulesView struct {
	Commit    string     `json:"commit"`
	AppliedAt *time.Time `json:"applied_at"`
	Status    string     `json:"status"`
}

// HealthView is the SIEM's own alarms as the page's health line (D1).
type HealthView struct {
	Ingest            string `json:"ingest"`
	EvidenceRewritten bool   `json:"evidence_rewritten"`
	Disk              string `json:"disk"`
}

// MetricsView: the SOC numbers over the last 24 h.
type MetricsView struct {
	Since             *time.Time `json:"since"`
	Incidents         int        `json:"incidents"`
	MedianTTDMs       *int64     `json:"median_ttd_ms"`
	MedianTTIMs       *int64     `json:"median_tti_ms"`
	MedianTwinDwellMs *int64     `json:"median_twin_dwell_ms"`
	HostFindings      int        `json:"host_findings"`
}

// Incident is one assembled incident; FlagMatch is set for dns-exfil only.
type Incident struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"`
	Severity    string     `json:"severity"`
	Title       string     `json:"title"`
	RunID       string     `json:"run_id"`
	Arm         string     `json:"arm"`
	FirstAt     time.Time  `json:"first_at"`
	LastAt      time.Time  `json:"last_at"`
	Attack      []string   `json:"attack"`
	FalcoEvents int        `json:"falco_events"`
	FlagMatch   *bool      `json:"flag_match"`
	TTDMs       *int64     `json:"ttd_ms"`
	TTIMs       *int64     `json:"tti_ms"`
	Steps       []Step     `json:"steps"`
	Evidence    []Evidence `json:"evidence"`
}

// Step is one piece of an incident's evidence in time order.
type Step struct {
	At         time.Time `json:"at"`
	Source     string    `json:"source"`
	Rule       string    `json:"rule"`
	RuleID     string    `json:"rule_id"`
	CommandSeq *int      `json:"command_seq"`
	Detail     string    `json:"detail"`
}

// Evidence is an id in the SIEM an incident is built from.
type Evidence struct {
	Type string `json:"type"` // finding | alert | correlation | document
	ID   string `json:"id"`
}

// Unavailable is the answer without a SIEM configured.
func Unavailable() View { return unavailable(nil) }

// unavailable is the answer when the SIEM is off or not reachable: everything empty or null.
func unavailable(checkedAt *time.Time) View {
	return View{
		CheckedAt: checkedAt,
		Rules:     RulesView{Status: "unknown"},
		Health:    HealthView{Ingest: "unknown", Disk: "unknown"},
		Incidents: []Incident{},
	}
}

// What webhook.Scrub does not know about, redacted from every published string as a backstop: the
// allow-lists below never put any of it there (ADR 0021, siem contract M9).
var redactions = []*regexp.Regexp{
	regexp.MustCompile(`(?i)k3s01|siem01`), // no word boundary: "node_k3s01" is a node name too
	regexp.MustCompile(`(?i)system:serviceaccount:\S*`),
	regexp.MustCompile(`(?i)service[\s_-]?account`),
	regexp.MustCompile(`(?i)hm1:[0-9a-f]*`),
	regexp.MustCompile(`(?i)SDP\{[^}\s]*\}?`),
	regexp.MustCompile(`(?i)sdp-[0-9a-f]{16}`),
	regexp.MustCompile(`(?i)\S*\.svc\b\S*|\S*cluster\.local\S*`),
}

// clean is the last step of every string published from SIEM data.
func clean(s string, n int) string {
	s = webhook.Scrub(s)
	for _, re := range redactions {
		s = re.ReplaceAllString(s, "[redacted]")
	}
	return webhook.Truncate(strings.TrimSpace(s), n)
}

const (
	maxTitle  = 160
	maxRule   = 120
	maxDetail = 200
)

// detail describes a record from its source's allow-listed fields only.
func (t *Tracker) detail(r *record) string {
	pod := t.publicRef(r.ref)
	switch r.source {
	case "falco":
		d := "Falco: " + r.falcoRule + " on " + pod
		if r.proc != "" {
			d += ", process " + r.proc
		}
		return d
	case "talon":
		return fmt.Sprintf("Talon: %s (%s) %s on %s", r.talonAction, r.actionner, r.talonStatus, pod)
	case "hubble":
		l4 := r.proto
		if r.port > 0 {
			l4 += "/" + strconv.Itoa(r.port)
		}
		if r.dns {
			return fmt.Sprintf("DNS query under the exfil zone from %s, %s %s %s", pod, r.verdict, strings.ToLower(r.direction), l4)
		}
		d := fmt.Sprintf("Hubble: %s %s %s", r.verdict, strings.ToLower(r.direction), l4)
		if r.dropReason != "" {
			d += " (" + r.dropReason + ")"
		}
		return d + " on " + pod
	case "k8s-audit":
		res := r.resource
		if r.subresource != "" {
			res += "/" + r.subresource
		}
		by := map[string]string{actorAPI: "by the API", actorTalon: "by Talon", actorOther: "not by the API"}[r.actor]
		return fmt.Sprintf("%s %s on %s %s, response %d", r.verb, res, pod, by, r.code)
	case "api":
		if r.apiAction == "siem.command" {
			d := "command " + r.commandID
			if r.technique != "" || r.objective != "" {
				d += " (" + strings.Trim(r.technique+", "+r.objective, ", ") + ")"
			}
			d += " " + r.state + " on " + pod
			if r.exit != nil {
				d += ", exit " + strconv.Itoa(*r.exit)
			}
			return d
		}
		return "run " + r.state + " on " + pod
	}
	return ""
}

func msPtr(d time.Duration) *int64 {
	v := d.Milliseconds()
	return &v
}

// seconds renders a duration for a title: "41.2 s", "850 ms".
func seconds(d time.Duration) string {
	if d < time.Second {
		return strconv.FormatInt(d.Milliseconds(), 10) + " ms"
	}
	return strconv.FormatFloat(d.Seconds(), 'f', 1, 64) + " s"
}
