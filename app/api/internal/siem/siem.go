// Package siem is the API's client for the SIEM on siem01 (ADR 0034, ADR 0036 "The SIEM client"): a
// read-only client by construction, not only by its certificate's role.
//
// Every request goes through one function that first checks the method and path against an
// allow-list in code - three GET paths of Security Analytics and Alerting, and POST `_search` on the
// named streams the API's role may read - and refuses anything else before a byte is sent. There is
// no way to ask this package for a write: no method builds one, and a programming error that tried
// would get ErrNotAllowed (the unit test proves no such request reaches the server). Search bodies
// are built here from a typed Query: a bounded size, a mandatory time range, an explicit field list.
//
// The client authenticates with the certificate of the optional KSOPS Secret and trusts only the
// Secret's CA. When SIEM_URL or any of the files is missing the caller runs without the SIEM: the
// demo never depends on it (ADR 0034 "Degradation").
package siem

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The GET paths the client may call (ADR 0036). Security Analytics' own alerts are not read: the
// incidents are built from findings, correlations and Alerting alerts.
const (
	PathFindings      = "/_plugins/_security_analytics/findings/_search"
	PathCorrelations  = "/_plugins/_security_analytics/correlations"
	PathMonitorAlerts = "/_plugins/_alerting/monitors/alerts"
)

// SyncIndex is the rules sync's record of what it applied (ADR 0034 amendment, F6).
const SyncIndex = "siem-sync"

// Streams are k3s01's data streams, the ones the API's role `sdp_api_read` names. Never `sdp-*` (the
// role refuses a pattern) and never `sdp-siem01` (the SIEM host's own records are not the page's).
var Streams = []string{"sdp-falco", "sdp-talon", "sdp-hubble", "sdp-k8s-audit", "sdp-api", "sdp-host"}

// readable is every index a search may name.
var readable = func() map[string]bool {
	m := map[string]bool{SyncIndex: true}
	for _, s := range Streams {
		m[s] = true
	}
	return m
}()

// Limits of every request.
const (
	DefaultTimeout = 5 * time.Second
	// MaxSize is the most items one request may ask for (findings, alerts, search hits).
	MaxSize = 500
	// MaxRange bounds a search's time range: the incidents look back 24 h, the sync record a week.
	MaxRange = 31 * 24 * time.Hour
	// maxBody bounds a response: 500 findings with their source documents are about 1 MiB.
	maxBody = 16 << 20
)

// ErrNotAllowed is a request outside the allow-list: always a programming error.
var ErrNotAllowed = errors.New("siem: request outside the read-only allow-list")

// StatusError is an answer other than 200 (a redirect is one too: it is never followed).
type StatusError struct {
	Method, Path string
	Code         int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("siem: %s %s: HTTP %d", e.Method, e.Path, e.Code)
}

var logTypePattern = regexp.MustCompile(`^sdp_[a-z0-9_]{1,40}$`)

// Config: URL is SIEM_URL (https://10.4.2.10:9200), CertDir holds tls.crt, tls.key and ca.crt.
type Config struct {
	URL     string
	CertDir string
	Timeout time.Duration
}

// Client is safe for concurrent use.
type Client struct {
	base    *url.URL
	http    *http.Client
	timeout time.Duration
}

// New checks the configuration and loads the certificate; any error means "run without the SIEM".
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return nil, fmt.Errorf("siem: SIEM_URL must be https://host:port, got %q", cfg.URL)
	}
	u.Path = ""
	tlsCfg, err := loadTLS(cfg.CertDir)
	if err != nil {
		return nil, err
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	tr := &http.Transport{
		TLSClientConfig:       tlsCfg,
		Proxy:                 nil, // siem01 is reached directly; no environment proxy in between
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   cfg.Timeout,
		ResponseHeaderTimeout: cfg.Timeout,
	}
	return &Client{base: u, timeout: cfg.Timeout, http: &http.Client{
		Transport: tr,
		// A redirect could point at another path; the answer is then a non-200 and an error.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func loadTLS(dir string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err != nil {
		return nil, fmt.Errorf("siem: client certificate: %w", err)
	}
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("siem: CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("siem: CA: no certificate in ca.crt")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{cert}}, nil
}

// allowed is the allow-list: exactly these methods and paths, nothing else.
func allowed(method, path string) bool {
	switch method {
	case http.MethodGet:
		return path == PathFindings || path == PathCorrelations || path == PathMonitorAlerts
	case http.MethodPost:
		rest, ok := strings.CutPrefix(path, "/")
		if !ok {
			return false
		}
		list, ok := strings.CutSuffix(rest, "/_search")
		if !ok || list == "" {
			return false
		}
		for _, idx := range strings.Split(list, ",") {
			if !readable[idx] {
				return false
			}
		}
		return true
	}
	return false
}

// do sends one allowed request and decodes a 200 JSON answer into out.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	if !allowed(method, path) {
		return fmt.Errorf("%w: %s %s", ErrNotAllowed, method, path)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	u := *c.base
	u.Path = path
	u.RawQuery = query.Encode()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return &StatusError{Method: method, Path: path, Code: resp.StatusCode}
	}
	if len(data) > maxBody {
		return fmt.Errorf("siem: %s %s: response over %d bytes", method, path, maxBody)
	}
	return json.Unmarshal(data, out)
}

// Finding is one Security Analytics finding, as findings/_search returns it. Document holds the
// source document as SA stores it - the whole document, so callers read only allow-listed fields.
type Finding struct {
	ID         string         `json:"id"`
	DetectorID string         `json:"detectorId"`
	Timestamp  int64          `json:"timestamp"` // epoch ms, when SA made the finding
	Queries    []FindingQuery `json:"queries"`
	Documents  []FindingDoc   `json:"document_list"`
}

// FindingQuery is a rule that matched: Name is the Sigma rule's title, ID SA's rule id, Tags the
// rule's level, log type and ATT&CK tags.
type FindingQuery struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

// FindingDoc is a matched document; Document is its JSON source as a string.
type FindingDoc struct {
	ID       string `json:"id"`
	Index    string `json:"index"`
	Found    bool   `json:"found"`
	Document string `json:"document"`
}

// Findings reads the findings of one detector log type made in [from, to], newest first.
func (c *Client) Findings(ctx context.Context, logType string, from, to time.Time, size int) ([]Finding, error) {
	if !logTypePattern.MatchString(logType) {
		return nil, fmt.Errorf("siem: log type %q", logType)
	}
	if err := checkRange(from, to); err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("detectorType", logType)
	q.Set("startTime", ms(from))
	q.Set("endTime", ms(to))
	q.Set("size", strconv.Itoa(clampSize(size)))
	q.Set("startIndex", "0")
	q.Set("sortOrder", "desc")
	var out struct {
		Findings []Finding `json:"findings"`
	}
	if err := c.do(ctx, http.MethodGet, PathFindings, q, nil, &out); err != nil {
		return nil, err
	}
	return out.Findings, nil
}

// Correlation is one entry of SA's correlations list: two findings an SA correlation rule paired.
// The list carries no id of its own, and its log-type names are truncated at a hyphen (S0-e), so
// only the finding ids and the rule ids are used.
type Correlation struct {
	Finding1 string   `json:"finding1"`
	Finding2 string   `json:"finding2"`
	Rules    []string `json:"rules"`
}

// Correlations reads the correlations recorded in [from, to].
func (c *Client) Correlations(ctx context.Context, from, to time.Time) ([]Correlation, error) {
	if err := checkRange(from, to); err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("start_timestamp", ms(from))
	q.Set("end_timestamp", ms(to))
	var out struct {
		Findings []Correlation `json:"findings"`
	}
	if err := c.do(ctx, http.MethodGet, PathCorrelations, q, nil, &out); err != nil {
		return nil, err
	}
	if len(out.Findings) > MaxSize {
		out.Findings = out.Findings[:MaxSize]
	}
	return out.Findings, nil
}

// Alert is one Alerting alert. StartTime/EndTime are epoch ms (EndTime nil while active); BucketKeys
// are a bucket-level monitor's composite key values.
type Alert struct {
	ID          string `json:"id"`
	MonitorID   string `json:"monitor_id"`
	MonitorName string `json:"monitor_name"`
	TriggerName string `json:"trigger_name"`
	State       string `json:"state"`
	Severity    string `json:"severity"`
	StartTime   *int64 `json:"start_time"`
	EndTime     *int64 `json:"end_time"`
	Agg         *struct {
		BucketKeys []string `json:"bucket_keys"`
	} `json:"agg_alert_content"`
}

// MonitorAlerts reads the newest Alerting alerts of every state. The Alerting API has no time filter;
// callers drop what is older than they look.
func (c *Client) MonitorAlerts(ctx context.Context, size int) ([]Alert, error) {
	q := url.Values{}
	q.Set("size", strconv.Itoa(clampSize(size)))
	q.Set("startIndex", "0")
	q.Set("sortString", "start_time")
	q.Set("sortOrder", "desc")
	q.Set("alertState", "ALL")
	var out struct {
		Alerts []Alert `json:"alerts"`
	}
	if err := c.do(ctx, http.MethodGet, PathMonitorAlerts, q, nil, &out); err != nil {
		return nil, err
	}
	return out.Alerts, nil
}

// Query is a search, built in code: documents whose TimeField is in [Since, Until] and that match
// every filter (OpenSearch query clauses), at most Size hits sorted by SortField descending, only the
// Source fields returned. Size 0 counts.
type Query struct {
	TimeField    string
	Since, Until time.Time
	Filters      []map[string]any
	Size         int
	SortField    string
	Source       []string
}

// SearchResult is the hit count and the hits.
type SearchResult struct {
	Total int
	Hits  []Hit
}

// Hit is a document id, its backing index and its (field-limited) source.
type Hit struct {
	ID     string         `json:"_id"`
	Index  string         `json:"_index"`
	Source map[string]any `json:"_source"`
}

func (q Query) body() (map[string]any, error) {
	if q.TimeField == "" {
		return nil, errors.New("siem: a search needs a time field")
	}
	if err := checkRange(q.Since, q.Until); err != nil {
		return nil, err
	}
	if q.Size < 0 || q.Size > MaxSize {
		return nil, fmt.Errorf("siem: search size %d outside 0..%d", q.Size, MaxSize)
	}
	filters := []any{map[string]any{"range": map[string]any{q.TimeField: map[string]any{
		"gte": q.Since.UnixMilli(), "lte": q.Until.UnixMilli(), "format": "epoch_millis"}}}}
	for _, f := range q.Filters {
		filters = append(filters, f)
	}
	b := map[string]any{
		"size":             q.Size,
		"track_total_hits": true,
		"query":            map[string]any{"bool": map[string]any{"filter": filters}},
	}
	if q.Size > 0 {
		if len(q.Source) > 0 {
			b["_source"] = q.Source
		} else {
			b["_source"] = false
		}
		if q.SortField != "" {
			b["sort"] = []any{map[string]any{q.SortField: map[string]any{"order": "desc", "unmapped_type": "date"}}}
		}
	}
	return b, nil
}

// Search runs q on the named indices (each one the API's role names).
func (c *Client) Search(ctx context.Context, indices []string, q Query) (SearchResult, error) {
	body, err := q.body()
	if err != nil {
		return SearchResult{}, err
	}
	var out struct {
		Hits struct {
			Total json.RawMessage `json:"total"`
			Hits  []Hit           `json:"hits"`
		} `json:"hits"`
	}
	if err := c.do(ctx, http.MethodPost, "/"+strings.Join(indices, ",")+"/_search", nil, body, &out); err != nil {
		return SearchResult{}, err
	}
	return SearchResult{Total: total(out.Hits.Total), Hits: out.Hits.Hits}, nil
}

// total reads hits.total in either form: {"value": n} or a bare number.
func total(raw json.RawMessage) int {
	var obj struct {
		Value int `json:"value"`
	}
	if json.Unmarshal(raw, &obj) == nil && obj.Value > 0 {
		return obj.Value
	}
	var n int
	_ = json.Unmarshal(raw, &n)
	return n
}

func checkRange(from, to time.Time) error {
	if from.IsZero() || to.IsZero() || !from.Before(to) || to.Sub(from) > MaxRange {
		return fmt.Errorf("siem: time range [%s, %s] is not bounded", from.Format(time.RFC3339), to.Format(time.RFC3339))
	}
	return nil
}

func clampSize(n int) int {
	if n < 1 {
		return 1
	}
	if n > MaxSize {
		return MaxSize
	}
	return n
}

func ms(t time.Time) string { return strconv.FormatInt(t.UnixMilli(), 10) }
