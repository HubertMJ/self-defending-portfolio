// Package posture aggregates GET /api/posture: the cluster's security posture as the phase 4 tools
// already record it, reduced to a handful of numbers a visitor can read.
//
//	kyverno    PolicyReports + ClusterPolicyReports (wgpolicyk8s.io/v1alpha2), results whose
//	           source is "kyverno", counted per policy, and the failing ones grouped by policy,
//	           rule, kind and namespace, with whether the object still runs anything (ADR 0035)
//	trivy      VulnerabilityReports (aquasecurity.github.io/v1alpha1) of the images pods run now,
//	           severity totals per distinct image (one image in three workloads is one image, not
//	           three), the same totals split into this project's own images and third-party ones,
//	           and a per-image breakdown
//	kube_bench the newest successful kube-bench Job's log, which is the benchmark's JSON (ADR 0014):
//	           the totals, the failing and warning checks by id, title and remediation (ADR 0035),
//	           and the checks the benchmark configuration marks not applicable, with its reason,
//	           counted apart from INFO (ADR 0025, amendment 2026-10-10)
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
// Pods are listed once per refresh and that one list serves three readers: trivy (which images run),
// kyverno (does a violating object still run a pod) and the provenance endpoint (which api and web
// digests run, ADR 0035).
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
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/webhook"
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

	// Deployed is not part of /api/posture: GET /api/provenance publishes it (ADR 0035). It rides on
	// the snapshot because it comes from the same pod list and the same 60 s cache.
	Deployed Deployed `json:"-"`
}

// Deployed is this repository's api and web images that Running pods run, as
// repository@sha256:<digest>, distinct and sorted. ObservedAt is when the pods were last listed
// successfully; a failed list keeps the previous images and their time. Never a pod name or a
// namespace.
type Deployed struct {
	API        []string
	Web        []string
	ObservedAt *time.Time
}

type Kyverno struct {
	Policies []PolicyCount `json:"policies"`
	// Violations names what the failing results are about (ADR 0035), so "7 violations" is not a
	// bare red number: one row per policy, rule, kind of object, namespace and running state, with
	// how many results it covers. A violation is a `fail` or `error` result - the set PolicyCount.Fail
	// counts - so the counts add up to the policies' Fail unless ViolationsTruncated (more than
	// maxViolations rows). Never an object's name and never Kyverno's message.
	Violations          []Violation `json:"violations"`
	ViolationsTruncated bool        `json:"violations_truncated"`
}

// Violation is one group of failing results. Running is true when a Pending or Running pod is the
// object or is owned by it (Pod, ReplicaSet, Job, StatefulSet, DaemonSet, matched by uid), false
// when no such pod exists - an old ReplicaSet kept at 0 replicas - and null for any other kind, an
// object without a uid, or when the pod list failed this refresh. File is where the policy is
// defined in the repository (the server fills it from the rule index), "" when unknown.
type Violation struct {
	Policy    string `json:"policy"`
	Rule      string `json:"rule"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Count     int    `json:"count"`
	Running   *bool  `json:"running"`
	File      string `json:"file"`
}

// maxViolations bounds the violation rows; the counts per policy stay complete.
const maxViolations = 50

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
	// LastScan is the newest updateTimestamp among the reports counted here (running images only),
	// null when there is none (ADR 0035).
	LastScan *time.Time `json:"last_scan"`
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
	// Info is kube-bench's INFO count less the not-applicable checks, which kube-bench also reports
	// as INFO: pass + fail + warn + info + not_applicable is every check that ran.
	Info int `json:"info"`
	// NotApplicable counts the checks the benchmark configuration marks as not applicable to this
	// cluster (kube-bench `type: skip`: upstream's own k3s skips and this repository's, ADR 0025
	// amendment 2026-10-10). They are neither passed nor failed; the page shows them as such.
	NotApplicable int `json:"not_applicable"`
	// Failing names the FAIL checks (ADR 0035): id, title and kube-bench's own remediation text,
	// scrubbed and capped, in benchmark order. Nothing else from a result is read - not the audit
	// command, its output, the expected value or the reason, which describe this node.
	Failing []BenchCheck `json:"failing"`
	// Warning names the WARN checks the same way: manual checks, and unscored ones that did not pass.
	Warning []BenchCheck `json:"warning"`
	// NotApplicableChecks names the not-applicable checks with the reason the configuration gives,
	// which is the check's remediation text ("Not Applicable." and why; the prefix is dropped). The
	// reason has one source, the benchmark configuration (app/kube-bench/k3s-cis-1.9.patch).
	NotApplicableChecks []BenchNA `json:"not_applicable_checks"`
}

// BenchCheck is one failing CIS check. Remediation may name k3s's default file paths; those describe
// k3s, not this host (ADR 0035).
type BenchCheck struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Remediation string `json:"remediation"`
}

// BenchNA is one check the benchmark configuration marks as not applicable, and why.
type BenchNA struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Reason string `json:"reason"`
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
		Kyverno:   Kyverno{Policies: []PolicyCount{}, Violations: []Violation{}},
		Trivy:     Trivy{ByImage: []ImageVulns{}},
		KubeBench: KubeBench{Failing: []BenchCheck{}, Warning: []BenchCheck{}, NotApplicableChecks: []BenchNA{}},
		Deployed:  Deployed{API: []string{}, Web: []string{}},
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
	// One pod list for the three readers. When it fails, trivy keeps its previous value (counting
	// without it would drop every running image, ADR 0015 amendment), kyverno says "unknown" for
	// running, and provenance keeps the images and the time it last saw them.
	pods, err := a.listPods(rctx)
	if err != nil {
		a.cfg.Log.Warn("posture: pods", "err", err)
		pods = nil
	} else {
		at := now.UTC()
		next.Deployed = Deployed{API: pods.api.sorted(), Web: pods.web.sorted(), ObservedAt: &at}
	}
	if p, err := a.kyverno(rctx, pods); err != nil {
		a.cfg.Log.Warn("posture: kyverno reports", "err", err)
	} else {
		next.Kyverno = p
	}
	if t, err := a.trivy(rctx, pods); err != nil {
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

// violationKey groups failing results; running is -1 unknown, 0 no, 1 yes.
type violationKey struct {
	policy, rule, kind, namespace string
	running                       int8
}

// ownerKinds are the kinds whose pods carry an ownerReference to them, so "does it still run
// anything" can be answered from the pod list.
var ownerKinds = map[string]bool{"Pod": true, "ReplicaSet": true, "Job": true, "StatefulSet": true, "DaemonSet": true}

// kyverno counts results per policy and groups the failing ones. pods is this refresh's pod list,
// nil when it failed.
func (a *Aggregator) kyverno(ctx context.Context, pods *podView) (Kyverno, error) {
	counts := map[string]*PolicyCount{}
	groups := map[violationKey]int{}
	collect := func(u *unstructured.Unstructured) {
		results, _, _ := unstructured.NestedSlice(u.Object, "results")
		// The object a report is about is its scope (Kyverno writes one report per object); older
		// reports list it per result instead. Only kind, namespace and uid are read - never the name.
		scope, _, _ := unstructured.NestedMap(u.Object, "scope")
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
				ref := scope
				if s, _ := ref["kind"].(string); s == "" {
					if rs, _ := m["resources"].([]any); len(rs) > 0 {
						ref, _ = rs[0].(map[string]any)
					}
				}
				kind, _ := ref["kind"].(string)
				ns, _ := ref["namespace"].(string)
				uid, _ := ref["uid"].(string)
				if ns == "" {
					ns = u.GetNamespace()
				}
				rule, _ := m["rule"].(string)
				groups[violationKey{
					policy: field(name, 128), rule: field(rule, 128), kind: field(kind, 64), namespace: field(ns, 63),
					running: pods.runs(kind, uid),
				}]++
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
	out := Kyverno{Policies: make([]PolicyCount, 0, len(counts)), Violations: make([]Violation, 0, min(len(groups), maxViolations))}
	for _, c := range counts {
		out.Policies = append(out.Policies, *c)
	}
	sort.Slice(out.Policies, func(i, j int) bool { return out.Policies[i].Name < out.Policies[j].Name })
	keys := make([]violationKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		switch {
		case groups[a] != groups[b]:
			return groups[a] > groups[b]
		case a.policy != b.policy:
			return a.policy < b.policy
		case a.rule != b.rule:
			return a.rule < b.rule
		case a.kind != b.kind:
			return a.kind < b.kind
		case a.namespace != b.namespace:
			return a.namespace < b.namespace
		}
		return a.running < b.running
	})
	if len(keys) > maxViolations {
		keys, out.ViolationsTruncated = keys[:maxViolations], true
	}
	for _, k := range keys {
		v := Violation{Policy: k.policy, Rule: k.rule, Kind: k.kind, Namespace: k.namespace, Count: groups[k]}
		if k.running >= 0 {
			r := k.running == 1
			v.Running = &r
		}
		out.Violations = append(out.Violations, v)
	}
	return out, nil
}

// field is a cluster-supplied string made safe to publish: the scrubber's backstop (ADR 0021) and a
// length cap.
func field(s string, n int) string { return webhook.Truncate(webhook.Scrub(s), n) }

// errNoPods is trivy's answer when this refresh has no pod list: without it every report would be
// "not running" and the totals would drop to zero.
var errNoPods = errors.New("pods could not be listed")

func (a *Aggregator) trivy(ctx context.Context, pods *podView) (Trivy, error) {
	type sev struct {
		image             string
		own               bool
		c, h, m, l, fixed int
	}
	if pods == nil {
		return Trivy{}, errNoPods
	}
	running := pods.images
	var lastScan time.Time
	// Keyed by digest, so one image in three workloads (three reports) is counted once.
	images := map[string]sev{}
	err := a.list(ctx, VulnerabilityReports, func(u *unstructured.Unstructured) {
		server, _, _ := unstructured.NestedString(u.Object, "report", "registry", "server")
		repo, _, _ := unstructured.NestedString(u.Object, "report", "artifact", "repository")
		digest, _, _ := unstructured.NestedString(u.Object, "report", "artifact", "digest")
		tag, _, _ := unstructured.NestedString(u.Object, "report", "artifact", "tag")
		if !running.has(server, repo, tag, digest) {
			return
		}
		if ts, _, _ := unstructured.NestedString(u.Object, "report", "updateTimestamp"); ts != "" {
			if t, err := time.Parse(time.RFC3339, ts); err == nil && t.After(lastScan) {
				lastScan = t
			}
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
	if !lastScan.IsZero() {
		t := lastScan.UTC()
		out.LastScan = &t
	}
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

// podView is what one refresh's pod list says, for its three readers.
type podView struct {
	images running
	// live holds the uid of every Pending or Running pod and the uids of its owners: a violating
	// ReplicaSet whose uid is not here runs nothing.
	live map[string]bool
	// api and web are this repository's images run by Running pods (provenance).
	api, web imageSet
}

// runs says whether a policy report's object still runs a pod: 1 yes, 0 no, -1 not knowable (a kind
// that owns no pods, no uid, or no pod list this refresh).
func (p *podView) runs(kind, uid string) int8 {
	if p == nil || uid == "" || !ownerKinds[kind] {
		return -1
	}
	if p.live[uid] {
		return 1
	}
	return 0
}

type imageSet map[string]bool

func (s imageSet) sorted() []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ownImageID matches a runtime imageID of this repository's api or web image, exactly: a
// repository that only starts with .../api (api-x) is not the api.
var ownImageID = regexp.MustCompile(`^` + regexp.QuoteMeta(OwnImagePrefix) + `(api|web)@(sha256:[0-9a-f]{64})$`)

// listPods lists every pod in the cluster, in any phase: a pod object exists while its workload
// wants it, so a scaled-to-0 ReplicaSet has none, while a CronJob's last completed run (kube-bench)
// still does and keeps its image in the Trivy totals between runs. For Trivy, containers, init
// containers and ephemeral containers all count: each is an image the node ran.
func (a *Aggregator) listPods(ctx context.Context) (*podView, error) {
	r := running{digests: map[string]bool{}, pending: map[string]bool{}}
	pv := &podView{images: r, live: map[string]bool{}, api: imageSet{}, web: imageSet{}}
	opts := metav1.ListOptions{Limit: 250}
	for {
		l, err := a.cfg.Kube.CoreV1().Pods("").List(ctx, opts)
		if err != nil {
			return nil, err
		}
		for i := range l.Items {
			pod := &l.Items[i]
			if ph := pod.Status.Phase; ph == corev1.PodPending || ph == corev1.PodRunning {
				pv.live[string(pod.UID)] = true
				for _, o := range pod.OwnerReferences {
					pv.live[string(o.UID)] = true
				}
			}
			if pod.Status.Phase == corev1.PodRunning {
				for _, cs := range pod.Status.ContainerStatuses {
					if m := ownImageID.FindStringSubmatch(cs.ImageID); m != nil {
						set := pv.api
						if m[1] == "web" {
							set = pv.web
						}
						set[cs.ImageID] = true
					}
				}
			}
			st := &pod.Status
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
			return pv, nil
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
	kb, err := parseKubeBench(data, newest.Spec.NodeName)
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

// benchControl is one control section: its totals, and of its results only the five fields read.
type benchControl struct {
	benchTotals
	Tests []struct {
		Results []benchResult `json:"results"`
	} `json:"tests"`
}

type benchResult struct {
	TestNumber  string `json:"test_number"`
	TestDesc    string `json:"test_desc"`
	Remediation string `json:"remediation"`
	Status      string `json:"status"`
	Type        string `json:"type"`
}

type benchDoc struct {
	Totals   *benchTotals   `json:"Totals"`
	Controls []benchControl `json:"Controls"`
}

// benchID is a CIS check number (1.1.9, 1.2.26); a result with anything else is dropped.
var benchID = regexp.MustCompile(`^[0-9]+(\.[0-9]+){1,3}$`)

// Caps on the failing, warning and not-applicable lists: rows, and runes of each text (ADR 0035).
const (
	maxFailing     = 50
	maxBenchTitle  = 200
	maxBenchRemedy = 300
)

// benchCut shortens a kube-bench text to at most n runes, the ellipsis included, never inside a
// word: after the last sentence end (a period and white space) if that keeps at least 60% of n,
// else at the last white space, else (one token longer than the cap) hard. Non-printable
// characters are dropped first, as webhook.Truncate does (ADR 0035).
func benchCut(s string, n int) string {
	s = webhook.Printable(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	for i := n - 3; 5*(i+1) >= 3*n; i-- { // r[:i+1] ends with the period, " …" follows
		if r[i] == '.' && unicode.IsSpace(r[i+1]) {
			return string(r[:i+1]) + " …"
		}
	}
	for i := n - 1; i > 0; i-- { // r[:i] ends before a space, "…" follows
		if unicode.IsSpace(r[i]) {
			if w := strings.TrimRightFunc(string(r[:i]), unicode.IsSpace); w != "" {
				return w + "…"
			}
			break
		}
	}
	return string(r[:n-1]) + "…"
}

// naPrefix is how kube-bench's k3s configuration opens the remediation of a skipped check.
var naPrefix = regexp.MustCompile(`(?i)^\s*not applicable\.?\s*`)

// ErrNoBenchJSON is returned for a log without a kube-bench JSON document.
var ErrNoBenchJSON = errors.New("no kube-bench JSON document in the log")

// ParseKubeBench reads kube-bench's --json output from a Job log. The log may carry stderr lines
// (glog warnings) around the document, and kube-bench versions differ between one document with
// Totals and one document per target, so every line that starts a JSON object is tried, and the
// totals of every document found are added up (from Totals, or summed over Controls). The FAIL
// and WARN results are listed in Failing and Warning, in the order the benchmark gives them, capped
// at maxFailing each. Skipped checks (type "skip", reported INFO) are counted in NotApplicable and
// taken out of Info, and listed with their reason, capped the same way.
func ParseKubeBench(log []byte) (KubeBench, error) { return parseKubeBench(log, "") }

// parseKubeBench is ParseKubeBench for a run on the node called node: its name is replaced in the
// published texts, after the scrubber and before the cap (ADR 0021 never publishes node names, and
// kube-bench may quote the host it ran on). "" redacts nothing.
func parseKubeBench(log []byte, node string) (KubeBench, error) {
	text := func(s string, n int) string {
		s = webhook.Scrub(s)
		if node != "" {
			s = strings.ReplaceAll(s, node, "[node]")
		}
		return benchCut(s, n)
	}
	kb := KubeBench{Failing: []BenchCheck{}, Warning: []BenchCheck{}, NotApplicableChecks: []BenchNA{}}
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
		for _, c := range doc.Controls {
			for _, t := range c.Tests {
				for _, r := range t.Results {
					if !benchID.MatchString(r.TestNumber) {
						continue
					}
					switch {
					case r.Status == "INFO" && r.Type == "skip":
						kb.NotApplicable++
						if len(kb.NotApplicableChecks) < maxFailing {
							reason := strings.Join(strings.Fields(naPrefix.ReplaceAllString(r.Remediation, "")), " ")
							kb.NotApplicableChecks = append(kb.NotApplicableChecks, BenchNA{ID: r.TestNumber,
								Title: text(r.TestDesc, maxBenchTitle), Reason: text(reason, maxBenchRemedy)})
						}
					case r.Status == "FAIL" && len(kb.Failing) < maxFailing:
						kb.Failing = append(kb.Failing, BenchCheck{ID: r.TestNumber,
							Title: text(r.TestDesc, maxBenchTitle), Remediation: text(r.Remediation, maxBenchRemedy)})
					case r.Status == "WARN" && len(kb.Warning) < maxFailing:
						kb.Warning = append(kb.Warning, BenchCheck{ID: r.TestNumber,
							Title: text(r.TestDesc, maxBenchTitle), Remediation: text(r.Remediation, maxBenchRemedy)})
					}
				}
			}
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
	// Every skipped result is one of kube-bench's INFO; a log whose totals say otherwise is
	// malformed, and the INFO count is not driven below zero by it.
	kb.NotApplicable = min(kb.NotApplicable, kb.Info)
	kb.Info -= kb.NotApplicable
	return kb, nil
}
