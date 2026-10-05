// Package siemindex is the SIEM's detection content as the page lists it (ADR 0036, GET
// /api/correlation/rules): every Sigma rule, Alerting monitor and correlation rule in `siem/`, with
// the file and line it is defined at and the canary that proves it fires. The page links each one to
// github.com/HubertMJ/self-defending-portfolio/blob/<commit>/<file>#L<line> at the commit the rules
// sync last applied, and builds its ATT&CK matrix from the rules' techniques.
//
// The data is index.json, generated from siem/ by scripts/gen-siem-index.sh and embedded at build
// time, the pattern of internal/ruleindex: the API image is built from app/api alone. It is git
// content, not SIEM state, so it is served whether or not the SIEM is reachable. The incidents use it
// to turn a finding's rule title (all SA hands back) into the rule's Sigma id.
package siemindex

import (
	_ "embed"
	"encoding/json"
)

//go:embed index.json
var indexJSON []byte

// Rule is one Sigma rule: Source is the siem/fields source (falco, hubble, ...), Attack its ATT&CK
// technique ids, Canary the scenario or test that must make it fire (`api:<id>` or `exec:<step>`).
type Rule struct {
	ID     string   `json:"id"`
	Title  string   `json:"title"`
	Level  string   `json:"level"`
	Status string   `json:"status"`
	Source string   `json:"source"`
	Attack []string `json:"attack"`
	File   string   `json:"file"`
	Line   int      `json:"line"`
	Canary string   `json:"canary"`
}

// Monitor is one `sdp-git: ` Alerting monitor.
type Monitor struct {
	Name   string `json:"name"`
	File   string `json:"file"`
	Canary string `json:"canary"`
}

// Correlation is one Security Analytics correlation rule.
type Correlation struct {
	Name   string `json:"name"`
	File   string `json:"file"`
	Canary string `json:"canary"`
}

// Index is the parsed index.json; every list marshals as [] when empty.
type Index struct {
	Rules        []Rule        `json:"rules"`
	Monitors     []Monitor     `json:"monitors"`
	Correlations []Correlation `json:"correlations"`

	byTitle map[string]string
}

// Load parses the embedded index.
func Load() (*Index, error) { return parse(indexJSON) }

func parse(b []byte) (*Index, error) {
	var ix Index
	if err := json.Unmarshal(b, &ix); err != nil {
		return nil, err
	}
	if ix.Rules == nil {
		ix.Rules = []Rule{}
	}
	if ix.Monitors == nil {
		ix.Monitors = []Monitor{}
	}
	if ix.Correlations == nil {
		ix.Correlations = []Correlation{}
	}
	ix.byTitle = map[string]string{}
	for i := range ix.Rules {
		if ix.Rules[i].Attack == nil {
			ix.Rules[i].Attack = []string{}
		}
		ix.byTitle[ix.Rules[i].Title] = ix.Rules[i].ID
	}
	return &ix, nil
}

// RuleID is the Sigma id of the rule titled title, or "" (titles are unique, the rules lint says so).
func (ix *Index) RuleID(title string) string {
	if ix == nil {
		return ""
	}
	return ix.byTitle[title]
}
