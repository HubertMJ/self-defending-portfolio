// Package posture aggregates GET /api/posture: the cluster's security posture as the phase 4 tools
// already record it, reduced to a handful of numbers a visitor can read.
//
//	kyverno    PolicyReports + ClusterPolicyReports (wgpolicyk8s.io/v1alpha2), results whose
//	           source is "kyverno", counted per policy
//	trivy      VulnerabilityReports (aquasecurity.github.io/v1alpha1) of the images pods run now,
//	           severity totals per distinct image (one image in three workloads is one image, not
//	           three), the same totals split into this project's own images and third-party ones,
//	           and a per-image breakdown
//	kube_bench the newest successful kube-bench Job's log, which is the benchmark's JSON (ADR 0014)
//	falco      alerts Falcosidekick delivered in the last 24 h  } counted by this API as the webhooks
//	talon      actions Talon reported in the last 24 h         } arrive, in the persisted hourly
//	                                                             window of internal/stats (ADR 0035)
//
// The result is cached for 60 s (contract): the page may be opened by many visitors at once, and
// every refresh lists every report in the cluster. One refresh runs at a time; callers during a
// refresh wait for it rather than starting their own. A source that fails keeps its previous value
// (zeros before the first success) and is logged; the endpoint still answers, because a partly stale
// posture page is better than none.
//
// Only reads, and only what the RBAC in cluster/infra/portfolio-api allows: list on the report kinds
// and on pods cluster-wide (they live in every namespace), get pods/log in kube-bench.
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

// Trivy is the image-scanning section. The five top-level counts are the original contract and stay
// the true totals over every distinct running image: no finding of an image a pod runs is filtered,
// ignored or suppressed here, ever (ADR 0023). What is left out is reports of images nothing runs -
// a Deployment's old ReplicaSets keep their reports while scaled to 0 (ADR 0015, amendment). Own, ThirdParty and ByImage were added later to say *whose* findings those are;
// they partition the same set of reports, so Own + ThirdParty always add up to the totals and the
// ByImage rows always add up to Own + ThirdParty. An older page that reads only the five counts
// renders exactly what it rendered before.
type Trivy struct {
	Images   int `json:"images"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`

	Own        TrivyGroup   `json:"own"`
	ThirdParty TrivyGroup   `json:"third_party"`
	ByImage    []ImageVulns `json:"by_image"`
}

// TrivyGroup is one side of the own/third-party split. Images counts distinct images (digests) like
// Trivy.Images does; Fixable is the CRITICAL+HIGH findings that name a fixed version upstream.
type TrivyGroup struct {
	Images   int `json:"images"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Fixable  int `json:"fixable"`
}

// ImageVulns is one row of the per-image breakdown. Image is registry/repository:tag as the scanner
// recorded it (several digests of one tag - both sides of a rollout in progress, or a DaemonSet not
// yet updated on every node - are one row, their counts added, exactly as the totals add them). Own is true for the images this
// repository builds and signs (OwnImagePrefix). Fixable counts the row's CRITICAL+HIGH findings that
// have a fixedVersion, i.e. the ones a version bump of that image would remove.
type ImageVulns struct {
	Image    string `json:"image"`
	Own      bool   `json:"own"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Fixable  int    `json:"fixable"`
}

// OwnImagePrefix is where .github/workflows/build-images.yml publishes every image this repository
// builds (ADR 0016). Everything else in the cluster is third-party.
const OwnImagePrefix = "ghcr.io/hubertmj/self-defending-portfolio/"

type KubeBench struct {
	// LastRun is null until a kube-bench Job has completed.
	LastRun *time.Time `json:"last_run"`
	Pass    int        `json:"pass"`
	Fail    int        `json:"fail"`
	Warn    int        `json:"warn"`
	Info    int        `json:"info"`
}

// Falco's Alerts24h keeps its name, but counts the hourly window (ADR 0035): between 23 and 24 h,
// starting at CountedSince, the same buckets and start as /api/stats last_24h.
type Falco struct {
	Alerts24h    int        `json:"alerts_24h"`
	CountedSince *time.Time `json:"counted_since,omitempty"`
}

type Talon struct {
	Actions24h int `json:"actions_24h"`
}

// Counter is a webhook delivery count over the hourly window (stats.WindowCounter, ADR 0035).
type Counter interface{ Count() int }

// Config wires the aggregator.
type Config struct {
	Dynamic      dynamic.Interface
	Kube         kubernetes.Interface
	KubeBenchNS  string
	FalcoAlerts  Counter
	TalonActions Counter
	// CountedSince is where the counters' window starts (stats.Collector.Since24h); nil omits it.
	CountedSince   func() time.Time
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
	return &Aggregator{cfg: cfg, cached: Snapshot{
		Kyverno: Kyverno{Policies: []PolicyCount{}},
		Trivy:   Trivy{ByImage: []ImageVulns{}},
	}}
}

// Get returns the cached snapshot, refreshing it first when it is older than the TTL. The webhook
// counts are read on every call, cache hit or not (ADR 0035): reading them is a sum over 25 buckets,
// and /api/stats reads the same buckets live, so the two are never a TTL apart.
func (a *Aggregator) Get(ctx context.Context) Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.cfg.Now()
	if !a.valid || now.Sub(a.at) >= a.cfg.TTL {
		a.refreshLocked(ctx, now)
	}
	out := a.cached
	if a.cfg.FalcoAlerts != nil {
		out.Falco.Alerts24h = a.cfg.FalcoAlerts.Count()
	}
	if a.cfg.TalonActions != nil {
		out.Talon.Actions24h = a.cfg.TalonActions.Count()
	}
	if a.cfg.CountedSince != nil {
		since := a.cfg.CountedSince().UTC()
		out.Falco.CountedSince = &since
	}
	return out
}

func (a *Aggregator) refreshLocked(ctx context.Context, now time.Time) {
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
	next.GeneratedAt = now.UTC()
	a.cached, a.at, a.valid = next, now, true
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
	type sev struct {
		image             string
		own               bool
		c, h, m, l, fixed int
	}
	running, err := a.runningImages(ctx)
	if err != nil {
		return Trivy{}, err
	}
	// Keyed by digest, so one image in three workloads (three reports) is counted once.
	images := map[string]sev{}
	err = a.list(ctx, VulnerabilityReports, func(u *unstructured.Unstructured) {
		server, _, _ := unstructured.NestedString(u.Object, "report", "registry", "server")
		repo, _, _ := unstructured.NestedString(u.Object, "report", "artifact", "repository")
		digest, _, _ := unstructured.NestedString(u.Object, "report", "artifact", "digest")
		tag, _, _ := unstructured.NestedString(u.Object, "report", "artifact", "tag")
		if !running.has(server, repo, tag, digest) {
			return
		}
		key := server + "/" + repo
		if digest != "" {
			key += "@" + digest
		} else {
			key += ":" + tag
		}
		var s sev
		s.image, s.own = imageName(server, repo, tag, digest)
		if repo == "" {
			key = u.GetNamespace() + "/" + u.GetName()
			s.image, s.own = key, false
		}
		s.c = summaryCount(u, "criticalCount")
		s.h = summaryCount(u, "highCount")
		s.m = summaryCount(u, "mediumCount")
		s.l = summaryCount(u, "lowCount")
		s.fixed = fixableCount(u)
		images[key] = s
	})
	if err != nil {
		return Trivy{}, err
	}
	out := Trivy{Images: len(images), ByImage: []ImageVulns{}}
	rows := map[string]*ImageVulns{}
	for _, s := range images {
		out.Critical += s.c
		out.High += s.h
		out.Medium += s.m
		out.Low += s.l
		g := &out.ThirdParty
		if s.own {
			g = &out.Own
		}
		g.Images++
		g.Critical += s.c
		g.High += s.h
		g.Fixable += s.fixed
		r := rows[s.image]
		if r == nil {
			r = &ImageVulns{Image: s.image, Own: s.own}
			rows[s.image] = r
		}
		r.Critical += s.c
		r.High += s.h
		r.Fixable += s.fixed
	}
	for _, r := range rows {
		out.ByImage = append(out.ByImage, *r)
	}
	// Worst first: most CRITICAL+HIGH, then most CRITICAL, then by name so the order is stable
	// between refreshes.
	sort.Slice(out.ByImage, func(i, j int) bool {
		a, b := out.ByImage[i], out.ByImage[j]
		if a.Critical+a.High != b.Critical+b.High {
			return a.Critical+a.High > b.Critical+b.High
		}
		if a.Critical != b.Critical {
			return a.Critical > b.Critical
		}
		return a.Image < b.Image
	})
	return out, nil
}

// running is what the cluster's pods run: the digests their container runtimes resolved, and, for
// containers not started yet (no imageID while the image is pulled), the references they asked for.
type running struct {
	digests map[string]bool // "sha256:..."
	pending map[string]bool // normalised registry/repository:tag
}

// runningImages lists every pod in the cluster, in any phase: a pod object exists while its
// workload wants it, so a scaled-to-0 ReplicaSet has none, while a CronJob's last completed run
// (kube-bench) still does and keeps its image in the totals between runs. Containers, init
// containers and ephemeral containers all count: each is an image the node ran.
func (a *Aggregator) runningImages(ctx context.Context) (running, error) {
	r := running{digests: map[string]bool{}, pending: map[string]bool{}}
	opts := metav1.ListOptions{Limit: 250}
	for {
		l, err := a.cfg.Kube.CoreV1().Pods("").List(ctx, opts)
		if err != nil {
			return running{}, err
		}
		for i := range l.Items {
			st := &l.Items[i].Status
			for _, list := range [][]corev1.ContainerStatus{st.InitContainerStatuses, st.ContainerStatuses, st.EphemeralContainerStatuses} {
				for _, cs := range list {
					// The runtime's imageID is repo@sha256:... (containerd); the digest alone is
					// compared, so registry spelling (docker.io vs index.docker.io) never matters.
					if d := digestOf(cs.ImageID); d != "" {
						r.digests[d] = true
						continue
					}
					if d := digestOf(cs.Image); d != "" {
						r.digests[d] = true
					} else if cs.Image != "" {
						r.pending[normalizeRef(cs.Image)] = true
					}
				}
			}
			// A container that has no status yet (just scheduled) is known only by its spec.
			sp := &l.Items[i].Spec
			for _, list := range [][]corev1.Container{sp.InitContainers, sp.Containers} {
				for _, c := range list {
					if d := digestOf(c.Image); d != "" {
						r.digests[d] = true
					} else if !hasStatus(st, c.Name) {
						r.pending[normalizeRef(c.Image)] = true
					}
				}
			}
		}
		if opts.Continue = l.GetContinue(); opts.Continue == "" {
			return r, nil
		}
	}
}

// has says whether a report's image is one a pod runs. A report that names no repository cannot
// be matched and is kept: dropping it could hide something that runs.
func (r running) has(server, repo, tag, digest string) bool {
	if repo == "" || r.digests[digest] {
		return true
	}
	if i := strings.LastIndex(tag, ":"); i >= 0 {
		tag = tag[i+1:]
	}
	if tag == "" {
		return false
	}
	return r.pending[normalizeRef(server+"/"+repo+":"+tag)]
}

func hasStatus(st *corev1.PodStatus, name string) bool {
	for _, list := range [][]corev1.ContainerStatus{st.InitContainerStatuses, st.ContainerStatuses} {
		for _, cs := range list {
			if cs.Name == name {
				return true
			}
		}
	}
	return false
}

// digestOf returns the sha256:... part of a repo@sha256:... reference, or "".
func digestOf(ref string) string {
	if i := strings.LastIndex(ref, "@"); i >= 0 && strings.HasPrefix(ref[i+1:], "sha256:") {
		return ref[i+1:]
	}
	return ""
}

// normalizeRef spells a registry/repository:tag reference the way containerd does: Docker Hub as
// docker.io (with library/ for official images), and :latest when no tag is given.
func normalizeRef(ref string) string {
	name, tag := ref, "latest"
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		name, tag = ref[:i], ref[i+1:]
	}
	first, rest, found := strings.Cut(name, "/")
	if !found || (!strings.ContainsAny(first, ".:") && first != "localhost") {
		first, rest = "docker.io", name
	}
	if first == "index.docker.io" {
		first = "docker.io"
	}
	if first == "docker.io" && !strings.Contains(rest, "/") {
		rest = "library/" + rest
	}
	return first + "/" + rest + ":" + tag
}

func summaryCount(u *unstructured.Unstructured, field string) int {
	n, _, _ := unstructured.NestedInt64(u.Object, "report", "summary", field)
	return int(n)
}

// fixableCount counts the report's CRITICAL and HIGH findings that name a fixed version. The list is
// read as Trivy wrote it; a finding without a fixedVersion is still in the totals, it just is not
// something a version bump can remove today.
func fixableCount(u *unstructured.Unstructured) int {
	vulns, _, _ := unstructured.NestedSlice(u.Object, "report", "vulnerabilities")
	n := 0
	for _, v := range vulns {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if sev, _ := m["severity"].(string); sev != "CRITICAL" && sev != "HIGH" {
			continue
		}
		if fixed, _ := m["fixedVersion"].(string); fixed != "" {
			n++
		}
	}
	return n
}

// imageName turns a report's registry/artifact fields into the reference a reader recognises, and
// says whether it is one of this repository's images.
//
// Trivy Operator records the tag of a reference it was given as `repo:tag@digest` oddly for some
// registries: for docker.io images the artifact tag comes back as the whole reference
// ("docker.io/falcosecurity/falco:0.45.0"), so only what follows the last colon is the tag. It also
// writes Docker Hub as index.docker.io, which is shortened to the docker.io everyone types.
func imageName(server, repo, tag, digest string) (string, bool) {
	if i := strings.LastIndex(tag, ":"); i >= 0 {
		tag = tag[i+1:]
	}
	if server == "index.docker.io" {
		server = "docker.io"
	}
	name := server + "/" + repo
	own := strings.HasPrefix(name, OwnImagePrefix)
	switch {
	case tag != "":
		name += ":" + tag
	case len(digest) > len("sha256:")+12:
		name += "@" + digest[:len("sha256:")+12]
	case digest != "":
		name += "@" + digest
	}
	return name, own
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
