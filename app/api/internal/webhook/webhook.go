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
	"strings"
	"time"
	"unicode/utf8"
)

// MaxOutput is how much of a Falco alert's output line is published (contract: 300 characters).
const MaxOutput = 300

// FalcoEvent is the public `event: falco` payload.
type FalcoEvent struct {
	At        time.Time `json:"at"`
	Rule      string    `json:"rule"`
	Priority  string    `json:"priority"`
	Namespace string    `json:"namespace"`
	Pod       string    `json:"pod"`
	Output    string    `json:"output"`
}

// TalonEvent is the public `event: talon` payload.
type TalonEvent struct {
	At        time.Time `json:"at"`
	Action    string    `json:"action"`
	Namespace string    `json:"namespace"`
	Pod       string    `json:"pod"`
	Status    string    `json:"status"`
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
		At:        at.UTC(),
		Rule:      p.Rule,
		Priority:  p.Priority,
		Namespace: str(p.OutputFields["k8s.ns.name"]),
		Pod:       str(p.OutputFields["k8s.pod.name"]),
		Output:    Truncate(p.Output, MaxOutput),
	}, nil
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
	ev := TalonEvent{At: now.UTC(), Status: str(get(p, "status"))}
	ev.Action = str(get(p, "action"))
	if ev.Action == "" {
		ev.Action = str(get(p, "actionner"))
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

// Truncate shortens s to at most n runes, marking the cut with an ellipsis, and never splits a
// UTF-8 sequence.
func Truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}
