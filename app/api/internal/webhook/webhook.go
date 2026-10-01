// Package webhook decodes what Falcosidekick and Falco Talon POST to the API's internal port
// (8081, reachable from those two only - cluster/infra/portfolio-api/ciliumnetworkpolicy.yaml) and
// turns it into the public `falco` and `talon` event shapes.
//
// Both senders are unauthenticated, as Falcosidekick -> Talon already is (ADR 0013): the network
// policy is the authentication. The decoders are therefore strict about size (the handler caps the
// body) and lenient about shape: an unknown or missing field yields an empty string, never a 500,
// because a Falcosidekick or Talon upgrade that adds a field must not blind the live feed.
package webhook

import (
	"encoding/json"
	"net"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Output caps, in runes. A Falco output line is the evidence a visitor reads in technical mode, so it
// gets room (1024); Talon's result text is one sentence (300); a single output field value is never
// longer than a command line needs to be recognisable (256).
const (
	MaxOutput      = 1024
	MaxTalonOutput = 300
	MaxFieldValue  = 256
)

// FalcoFields is the allow-list of Falco output fields that are published, and the only ones:
// enough to show *what* ran, *as whom* and *where* (pod, namespace, image), and nothing that
// describes the node it ran on - no hostname, no node name, no host or pod address (contract hard
// rule). Falco puts more into output_fields (evt.time, container.name, k8s.pod.uid, whatever
// suggested_output adds for a rule); anything not named here is dropped, so a Falco upgrade that
// adds a field cannot leak it.
var FalcoFields = []string{
	"evt.type", "proc.name", "proc.cmdline", "proc.pname", "user.name", "user.uid",
	"container.id", "container.image.repository", "k8s.pod.name", "k8s.ns.name", "fd.name",
}

// FalcoEvent is the public `event: falco` payload.
//
// At is Falco's own timestamp (the syscall), APIReceivedAt the moment Falcosidekick's POST reached
// the API: the difference is the alert pipeline's latency, which the page shows as measured, not
// claimed.
type FalcoEvent struct {
	At            time.Time      `json:"at"`
	Rule          string         `json:"rule"`
	Priority      string         `json:"priority"`
	Namespace     string         `json:"namespace"`
	Pod           string         `json:"pod"`
	Output        string         `json:"output"`
	Fields        map[string]any `json:"fields"`
	APIReceivedAt time.Time      `json:"api_received_at"`
}

// TalonEvent is the public `event: talon` payload. Talon's notification carries no timestamp of its
// own, so At and APIReceivedAt are both the moment it arrived; both exist so the two event kinds
// have the same shape for the page's timing maths.
type TalonEvent struct {
	At            time.Time `json:"at"`
	Action        string    `json:"action"`
	Actionner     string    `json:"actionner"`
	Namespace     string    `json:"namespace"`
	Pod           string    `json:"pod"`
	Status        string    `json:"status"`
	Output        string    `json:"output"`
	APIReceivedAt time.Time `json:"api_received_at"`
}

// falcoPayload is Falcosidekick's webhook body: the Falco alert as Falco emitted it
// (json_output: true), with output_fields carrying k8s.ns.name and k8s.pod.name
// (cluster/infra/falco/kustomization.yaml appends both to every rule's output).
type falcoPayload struct {
	Output       string         `json:"output"`
	Priority     string         `json:"priority"`
	Rule         string         `json:"rule"`
	Time         time.Time      `json:"time"`
	OutputFields map[string]any `json:"output_fields"`
}

// ParseFalco decodes a Falcosidekick webhook body. now is used when the alert has no time.
func ParseFalco(body []byte, now time.Time) (FalcoEvent, error) {
	var p falcoPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return FalcoEvent{}, err
	}
	at := p.Time
	if at.IsZero() {
		at = now
	}
	return FalcoEvent{
		At:            at.UTC(),
		Rule:          p.Rule,
		Priority:      p.Priority,
		Namespace:     str(p.OutputFields["k8s.ns.name"]),
		Pod:           str(p.OutputFields["k8s.pod.name"]),
		Output:        Truncate(Scrub(p.Output), MaxOutput),
		Fields:        allowedFields(p.OutputFields),
		APIReceivedAt: now.UTC(),
	}, nil
}

// allowedFields copies the allow-listed output fields. Strings are scrubbed and capped, numbers and
// booleans pass as they are (user.uid is a number), anything else (null, objects) is dropped.
// container.id is cut to the 12 characters Falco and crictl show, which is also what the `pod`
// event's container_id carries, so the two can be matched by eye.
func allowedFields(in map[string]any) map[string]any {
	out := make(map[string]any, len(FalcoFields))
	for _, k := range FalcoFields {
		switch v := in[k].(type) {
		case string:
			if k == "container.id" && len(v) > 12 {
				v = v[:12]
			}
			out[k] = Truncate(Scrub(v), MaxFieldValue)
		case float64, bool:
			out[k] = v
		}
	}
	return out
}

// ParseTalon decodes a Falco Talon webhook notifier body. Talon 0.3.0 posts the action's
// utils.LogLine (notifiers/webhook, notifiers.Notify): `action` (the rule file's action name),
// `actionner`, `status` ("success" / "failure") and `objects`, whose keys Notify title-cases
// ("Pod", "Namespace") while the actionners themselves use lower case. Keys are therefore matched
// case-insensitively, and the actionner stands in when there is no action name.
func ParseTalon(body []byte, now time.Time) (TalonEvent, error) {
	var p map[string]any
	if err := json.Unmarshal(body, &p); err != nil {
		return TalonEvent{}, err
	}
	ev := TalonEvent{At: now.UTC(), APIReceivedAt: now.UTC(), Status: str(get(p, "status"))}
	ev.Actionner = str(get(p, "actionner"))
	ev.Action = str(get(p, "action"))
	if ev.Action == "" {
		ev.Action = ev.Actionner
	}
	// What the actionner reported doing ("the pod ... has been terminated") or, on failure, why not.
	// The first non-empty of the fields Talon's LogLine uses for it; never `event`, which is the
	// whole Falco alert again.
	for _, k := range []string{"result", "output", "message", "error"} {
		if v := str(get(p, k)); v != "" {
			ev.Output = Truncate(Scrub(v), MaxTalonOutput)
			break
		}
	}
	if objs, ok := get(p, "objects").(map[string]any); ok {
		ev.Pod = str(get(objs, "pod"))
		ev.Namespace = str(get(objs, "namespace"))
	}
	return ev, nil
}

// get looks a key up case-insensitively, exact match first.
func get(m map[string]any, key string) any {
	if v, ok := m[key]; ok {
		return v
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

var (
	// Anywhere, not between word boundaries: "pod10.42.0.7" or "ip=10.42.0.7x" must not slip past.
	ipv4 = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	// Candidates only; net.ParseIP decides (so "12:00:00" in a timestamp is left alone).
	ipv6 = regexp.MustCompile(`(?i)[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}`)
	// <name>.<namespace>.svc, ...svc.cluster.local, or anything ending in .cluster.local.
	svcHost = regexp.MustCompile(`(?i)\b[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\.(svc(\.cluster\.local)?|cluster\.local)\b`)
	anyURL  = regexp.MustCompile(`(?i)https?://[^\s"']+`)
)

// Scrub removes what the contract says is never published from free text that the API passes
// through: URLs (an API server address in a Talon error), in-cluster service hostnames, and IPv4
// and IPv6 addresses other than loopback. It also drops invisible format characters (bidi
// overrides, zero-width spaces), which could make a published command line read differently from
// what ran. Loopback stays because it is the evidence of the network-tool
// scenario ("wget http://127.0.0.1:9/": nothing left the pod). Falco and Talon do not normally put
// any of these into the fields published, which is the point: this is the backstop for the
// abnormal case (an error message, a new field in a new release), not the policy.
//
// HTML is deliberately not escaped: the evidence is published verbatim (a scenario's command line
// may contain markup it writes into the victim's page), and the page renders every string as text,
// never as HTML (ADR 0019, 0021). Escaping here would only corrupt what the visitor is meant to see.
func Scrub(s string) string {
	s = Printable(s)
	s = anyURL.ReplaceAllStringFunc(s, func(u string) string {
		if strings.HasPrefix(u, "http://127.") || strings.HasPrefix(u, "http://localhost") {
			return u
		}
		return "[url]"
	})
	s = svcHost.ReplaceAllString(s, "[service]")
	s = ipv4.ReplaceAllStringFunc(s, func(ip string) string {
		if strings.HasPrefix(ip, "127.") {
			return ip
		}
		return "[ip]"
	})
	return scrubIPv6(s)
}

// scrubIPv6 replaces IPv6 addresses (not loopback, not unspecified). A candidate counts only as a
// whole token: "std::string" contains "d::", which parses as an address but is not one.
func scrubIPv6(s string) string {
	var b strings.Builder
	last := 0
	for _, m := range ipv6.FindAllStringIndex(s, -1) {
		start, end := m[0], m[1]
		if (start > 0 && wordByte(s[start-1])) || (end < len(s) && wordByte(s[end])) {
			continue
		}
		ip := net.ParseIP(s[start:end])
		if ip == nil || ip.To4() != nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		b.WriteString(s[last:start])
		b.WriteString("[ip]")
		last = end
	}
	b.WriteString(s[last:])
	return b.String()
}

func wordByte(c byte) bool {
	return c == '_' || c == '.' || c == ':' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// Printable drops every rune that is neither printable nor white space: control characters and
// the invisible format characters (Unicode Cf: bidi overrides, zero-width joiners and spaces).
func Printable(s string) string {
	return strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

// Truncate shortens s to at most n runes, marking the cut with an ellipsis, and never splits a
// UTF-8 sequence. Non-printable characters are dropped first (Printable).
func Truncate(s string, n int) string {
	s = Printable(s)
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}
