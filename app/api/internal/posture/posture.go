// Package posture aggregates GET /api/posture: the cluster's security posture as the phase 4 tools
// already record it, reduced to a handful of numbers a visitor can read.
//
//	kyverno    PolicyReports + ClusterPolicyReports (wgpolicyk8s.io/v1alpha2), results whose
//	           source is "kyverno", counted per policy
//	trivy      VulnerabilityReports (aquasecurity.github.io/v1alpha1), severity totals per distinct
//	           image (one image in three workloads is one image, not three)
//	kube_bench the newest successful kube-bench Job's log, which is the benchmark's JSON (ADR 0014)
//	falco      alerts Falcosidekick delivered in the last 24 h  } counted by this API as the webhooks
//	talon      actions Talon reported in the last 24 h         } arrive (internal/webhook.Window)
//
// The result is cached for 60 s (contract): the page may be opened by many visitors at once, and
// every refresh lists every report in the cluster. One refresh runs at a time; callers during a
// refresh wait for it rather than starting their own. A source that fails keeps its previous value
// (zeros before the first success) and is logged; the endpoint still answers, because a partly stale
// posture page is better than none.
//
// Only reads, and only what the RBAC in cluster/infra/portfolio-api allows: list on the two report
// kinds cluster-wide (they live in every namespace), list pods and get pods/log in kube-bench.
package posture

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var (
	PolicyReports        = schema.GroupVersionResource{Group: "wgpolicyk8s.io", Version: "v1alpha2", Resource: "policyreports"}
	ClusterPolicyReports = schema.GroupVersionResource{Group: "wgpolicyk8s.io", Version: "v1alpha2", Resource: "clusterpolicyreports"}
	VulnerabilityReports = schema.GroupVersionResource{Group: "aquasecurity.github.io", Version: "v1alpha1", Resource: "vulnerabilityreports"}
)

// Snapshot is the contract's posture document.
type Snapshot struct {
	GeneratedAt time.Time `json:"generated_at"`
	Kyverno     Kyverno   `json:"kyverno"`
	Trivy       Trivy     `json:"trivy"`
	KubeBench   KubeBench `json:"kube_bench"`
	Falco       Falco     `json:"falco"`
	Talon       Talon     `json:"talon"`
}

type Kyverno struct {
	Policies []PolicyCount `json:"policies"`
}

type PolicyCount struct {
	Name string `json:"name"`
	Pass int    `json:"pass"`
	Fail int    `json:"fail"`
	Warn int    `json:"warn"`
}

// Trivy is the image vulnerability summary. The top-level counts are every distinct running image,
// unchanged from the first version of this document, so the total stays visible and older clients
// keep working. Two splits make it honest to read (ADR 0020):
//
//   - ours / third_party: images built by this repository (OurImagePrefix) against everything else.
//     A visitor should see that "236 critical + high" is upstream software we run, not what we ship;
//   - fixable_*: findings for which a fixed version exists. Severity totals come from each report's
//     summary; fixable counts from its vulnerability list (fixedVersion set), which the operator
//     writes in full.
type Trivy struct {
	TrivyGroup
	Ours       TrivyGroup `json:"ours"`
	ThirdParty TrivyGroup `json:"third_party"`
}

// TrivyGroup is one set of distinct images and their findings.
type TrivyGroup struct {
	Images          int `json:"images"`
	Critical        int `json:"critical"`
	High            int `json:"high"`
	Medium          int `json:"medium"`
	Low             int `json:"low"`
	FixableCritical int `json:"fixable_critical"`
	FixableHigh     int `json:"fixable_high"`
}

// OurImagePrefix is where this repository's images live (registry server + repository).
const OurImagePrefix = "ghcr.io/hubertmj/self-defending-portfolio/"

func (g *TrivyGroup) add(s imageFindings) {
	g.Images++
	g.Critical += s.critical
	g.High += s.high
	g.Medium += s.medium
	g.Low += s.low
	g.FixableCritical += s.fixableCritical
	g.FixableHigh += s.fixableHigh
}

type imageFindings struct {
	ours                                                      bool
	critical, high, medium, low, fixableCritical, fixableHigh int
}

type KubeBench struct {
	// LastRun is null until a kube-bench Job has completed.
	LastRun *time.Time `json:"last_run"`
	Pass    int        `json:"pass"`
	Fail    int        `json:"fail"`
	Warn    int        `json:"warn"`
	Info    int        `json:"info"`
}

type Falco struct {
	Alerts24h int `json:"alerts_24h"`
}

type Talon struct {
	Actions24h int `json:"actions_24h"`
}

// Counter is a 24 h event count (internal/webhook.Window).
type Counter interface{ Count() int }

// Config wires the aggregator.
type Config struct {
	Dynamic        dynamic.Interface
	Kube           kubernetes.Interface
	KubeBenchNS    string
	FalcoAlerts    Counter
	TalonActions   Counter
	TTL            time.Duration
	RefreshTimeout time.Duration
	Log            *slog.Logger
	Now            func() time.Time
}

// Aggregator computes and caches the snapshot.
type Aggregator struct {
	cfg Config

	mu     sync.Mutex
	cached Snapshot
	at     time.Time
	valid  bool
}

// New returns an aggregator with defaults filled in.
func New(cfg Config) *Aggregator {
	if cfg.KubeBenchNS == "" {
		cfg.KubeBenchNS = "kube-bench"
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 60 * time.Second
	}
	if cfg.RefreshTimeout <= 0 {
		cfg.RefreshTimeout = 15 * time.Second
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Aggregator{cfg: cfg, cached: Snapshot{Kyverno: Kyverno{Policies: []PolicyCount{}}}}
}

// Get returns the cached snapshot, refreshing it first when it is older than the TTL.
func (a *Aggregator) Get(ctx context.Context) Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.cfg.Now()
	if a.valid && now.Sub(a.at) < a.cfg.TTL {
		return a.cached
	}
	// Detached from the request: a visitor closing the tab must not abort a refresh that every
	// other waiting caller is about to use.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.cfg.RefreshTimeout)
	defer cancel()

	next := a.cached
	if p, err := a.kyverno(rctx); err != nil {
		a.cfg.Log.Warn("posture: kyverno reports", "err", err)
	} else {
		next.Kyverno = p
	}
	if t, err := a.trivy(rctx); err != nil {
		a.cfg.Log.Warn("posture: trivy reports", "err", err)
	} else {
		next.Trivy = t
	}
	if kb, err := a.kubeBench(rctx); err != nil {
		a.cfg.Log.Warn("posture: kube-bench", "err", err)
	} else if kb != nil {
		next.KubeBench = *kb
	}
	if a.cfg.FalcoAlerts != nil {
		next.Falco.Alerts24h = a.cfg.FalcoAlerts.Count()
	}
	if a.cfg.TalonActions != nil {
		next.Talon.Actions24h = a.cfg.TalonActions.Count()
	}
	next.GeneratedAt = now.UTC()
	a.cached, a.at, a.valid = next, now, true
	return next
}

// list pages through a resource across all namespaces.
func (a *Aggregator) list(ctx context.Context, gvr schema.GroupVersionResource, fn func(u *unstructured.Unstructured)) error {
	opts := metav1.ListOptions{Limit: 250}
	for {
		l, err := a.cfg.Dynamic.Resource(gvr).List(ctx, opts)
		if err != nil {
			return err
		}
		for i := range l.Items {
			fn(&l.Items[i])
		}
		if opts.Continue = l.GetContinue(); opts.Continue == "" {
			return nil
		}
	}
}

func (a *Aggregator) kyverno(ctx context.Context) (Kyverno, error) {
	counts := map[string]*PolicyCount{}
	collect := func(u *unstructured.Unstructured) {
		results, _, _ := unstructured.NestedSlice(u.Object, "results")
		for _, r := range results {
			m, ok := r.(map[string]any)
			if !ok {
				continue
			}
			// The Trivy adapter writes PolicyReports too; only Kyverno's own results count here.
			if src, _ := m["source"].(string); src != "kyverno" {
				continue
			}
			name, _ := m["policy"].(string)
			if name == "" {
				continue
			}
			c := counts[name]
			if c == nil {
				c = &PolicyCount{Name: name}
				counts[name] = c
			}
			switch res, _ := m["result"].(string); res {
			case "pass":
				c.Pass++
			case "fail", "error":
				c.Fail++
			case "warn":
				c.Warn++
			}
		}
	}
	if err := a.list(ctx, PolicyReports, collect); err != nil {
		return Kyverno{}, err
	}
	if err := a.list(ctx, ClusterPolicyReports, collect); err != nil {
		return Kyverno{}, err
	}
	out := Kyverno{Policies: make([]PolicyCount, 0, len(counts))}
	for _, c := range counts {
		out.Policies = append(out.Policies, *c)
	}
	sort.Slice(out.Policies, func(i, j int) bool { return out.Policies[i].Name < out.Policies[j].Name })
	return out, nil
}

func (a *Aggregator) trivy(ctx context.Context) (Trivy, error) {
	images := map[string]imageFindings{}
	err := a.list(ctx, VulnerabilityReports, func(u *unstructured.Unstructured) {
		server, _, _ := unstructured.NestedString(u.Object, "report", "registry", "server")
		repo, _, _ := unstructured.NestedString(u.Object, "report", "artifact", "repository")
		digest, _, _ := unstructured.NestedString(u.Object, "report", "artifact", "digest")
		tag, _, _ := unstructured.NestedString(u.Object, "report", "artifact", "tag")
		name := server + "/" + repo
		key := name
		if digest != "" {
			key += "@" + digest
		} else {
			key += ":" + tag
		}
		if repo == "" {
			key = u.GetNamespace() + "/" + u.GetName()
		}
		f := imageFindings{ours: repo != "" && strings.HasPrefix(name+"/", OurImagePrefix)}
		f.critical = summaryCount(u, "criticalCount")
		f.high = summaryCount(u, "highCount")
		f.medium = summaryCount(u, "mediumCount")
		f.low = summaryCount(u, "lowCount")
		vulns, _, _ := unstructured.NestedSlice(u.Object, "report", "vulnerabilities")
		for _, v := range vulns {
			m, ok := v.(map[string]any)
			if !ok {
				continue
			}
			if fixed, _ := m["fixedVersion"].(string); strings.TrimSpace(fixed) == "" {
				continue
			}
			switch sev, _ := m["severity"].(string); sev {
			case "CRITICAL":
				f.fixableCritical++
			case "HIGH":
				f.fixableHigh++
			}
		}
		images[key] = f
	})
	if err != nil {
		return Trivy{}, err
	}
	var out Trivy
	for _, f := range images {
		out.add(f)
		if f.ours {
			out.Ours.add(f)
		} else {
			out.ThirdParty.add(f)
		}
	}
	return out, nil
}

func summaryCount(u *unstructured.Unstructured, field string) int {
	n, _, _ := unstructured.NestedInt64(u.Object, "report", "summary", field)
	return int(n)
}

// maxBenchLog bounds what is read from the Job log; the k3s benchmark's JSON is ~150 KiB.
const maxBenchLog = 4 << 20

// kubeBench returns nil, nil when no run has completed yet.
func (a *Aggregator) kubeBench(ctx context.Context) (*KubeBench, error) {
	pods, err := a.cfg.Kube.CoreV1().Pods(a.cfg.KubeBenchNS).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/name=kube-bench",
	})
	if err != nil {
		return nil, err
	}
	newest, newestAt := newestSucceeded(pods.Items)
	if newest == nil {
		return nil, nil
	}
	limit := int64(maxBenchLog)
	rc, err := a.cfg.Kube.CoreV1().Pods(a.cfg.KubeBenchNS).GetLogs(newest.Name, &corev1.PodLogOptions{LimitBytes: &limit}).Stream(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, maxBenchLog))
	if err != nil {
		return nil, err
	}
	kb, err := ParseKubeBench(data)
	if err != nil {
		return nil, err
	}
	at := newestAt.UTC()
	kb.LastRun = &at
	return &kb, nil
}

// newestSucceeded picks the most recently finished successful kube-bench pod. Failed runs are
// skipped: their log is an error, not a benchmark, and the previous good run is the better answer.
func newestSucceeded(pods []corev1.Pod) (*corev1.Pod, time.Time) {
	var newest *corev1.Pod
	var newestAt time.Time
	for i := range pods {
		p := &pods[i]
		if p.Status.Phase != corev1.PodSucceeded {
			continue
		}
		at := p.CreationTimestamp.Time
		for _, cs := range p.Status.ContainerStatuses {
			if t := cs.State.Terminated; t != nil && t.FinishedAt.After(at) {
				at = t.FinishedAt.Time
			}
		}
		if newest == nil || at.After(newestAt) {
			newest, newestAt = p, at
		}
	}
	return newest, newestAt
}

type benchTotals struct {
	Pass int `json:"total_pass"`
	Fail int `json:"total_fail"`
	Warn int `json:"total_warn"`
	Info int `json:"total_info"`
}

type benchDoc struct {
	Totals   *benchTotals  `json:"Totals"`
	Controls []benchTotals `json:"Controls"`
}

// ErrNoBenchJSON is returned for a log without a kube-bench JSON document.
var ErrNoBenchJSON = errors.New("no kube-bench JSON document in the log")

// ParseKubeBench reads kube-bench's --json output from a Job log. The log may carry stderr lines
// (glog warnings) around the document, and kube-bench versions differ between one document with
// Totals and one document per target, so every line that starts a JSON object is tried, and the
// totals of every document found are added up (from Totals, or summed over Controls).
func ParseKubeBench(log []byte) (KubeBench, error) {
	var kb KubeBench
	found := false
	sc := bufio.NewScanner(bytes.NewReader(log))
	sc.Buffer(make([]byte, 0, 64<<10), maxBenchLog)
	offset := 0
	for sc.Scan() {
		line := sc.Bytes()
		start := offset
		offset += len(line) + 1
		if !bytes.HasPrefix(bytes.TrimLeft(line, " \t"), []byte("{")) {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(log[start:]))
		var doc benchDoc
		if err := dec.Decode(&doc); err != nil {
			continue
		}
		switch {
		case doc.Totals != nil:
			kb.Pass += doc.Totals.Pass
			kb.Fail += doc.Totals.Fail
			kb.Warn += doc.Totals.Warn
			kb.Info += doc.Totals.Info
		case len(doc.Controls) > 0:
			for _, c := range doc.Controls {
				kb.Pass += c.Pass
				kb.Fail += c.Fail
				kb.Warn += c.Warn
				kb.Info += c.Info
			}
		default:
			continue
		}
		found = true
		// Skip the lines the decoded document spanned.
		consumed := int(dec.InputOffset())
		for offset < start+consumed && sc.Scan() {
			offset += len(sc.Bytes()) + 1
		}
	}
	if !found {
		return KubeBench{}, ErrNoBenchJSON
	}
	return kb, nil
}
