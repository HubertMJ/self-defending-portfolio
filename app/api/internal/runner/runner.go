// Package runner executes one attack scenario end to end (ADR 0015):
//
//	queued     POST /api/attack/{id} accepted; the concurrency slot is held from here
//	started    the API server accepted the scenario pod in `sandbox` (admission passed)
//	pod_ready  the pod is Running and Ready; the exec, if any, is sent right after this
//	detected   Falcosidekick delivered a Falco alert for that pod
//	responded  Talon reported a successful action on that pod
//	finished   the pod is gone and the slot is free
//
// or one of two terminal failures: `timeout` (nothing responded within the scenario's
// timeout_seconds, at most 120 s) and `failed` (the pod could not be created or never became
// Ready). Every terminal state, success or not, ends with the pod deleted and the slot released;
// activeDeadlineSeconds on the pod is the backstop should the API die mid-run, and orphans from such
// a crash are deleted at the next start-up (CleanupOrphans).
//
// Correlation is by pod name, which is unique per run (scenario id + run id): Falco reports
// k8s.pod.name, Talon reports the pod it acted on. Nothing else ties an alert to a run, and nothing
// else needs to. Every `run` event from `started` on names the pod, so the page can show it before
// anything has been detected.
//
// Alongside the states, a run publishes evidence (ADR 0021): `pod` events from a watch on its one
// pod (podwatch.go), and for a victim scenario `victim` events from probing the app in it
// (victim.go).
package runner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/scenarios"
)

// Labels set on every scenario pod. The quarantine label must exist as "false" from the start:
// Talon's label actionner sends a JSON Patch `replace`, which fails on a missing key (ADR 0013).
const (
	LabelRunID      = "sdp.hubertjablon.ski/run-id"
	LabelScenario   = "sdp.hubertjablon.ski/scenario"
	LabelQuarantine = "sdp.hubertjablon.ski/quarantine"
	LabelManagedBy  = "app.kubernetes.io/managed-by"
	ManagedBy       = "portfolio-api"
)

// Run states, as published in `event: run`.
const (
	StateQueued    = "queued"
	StateStarted   = "started"
	StatePodReady  = "pod_ready"
	StateDetected  = "detected"
	StateResponded = "responded"
	StateFinished  = "finished"
	StateFailed    = "failed"
	StateTimeout   = "timeout"
)

// RunEvent is the public `event: run` payload. Pod is set from `started` on (the pod exists from
// then); for pod_ready, Detail is the container id (12 characters).
type RunEvent struct {
	RunID    string    `json:"run_id"`
	Scenario string    `json:"scenario"`
	State    string    `json:"state"`
	At       time.Time `json:"at"`
	Detail   string    `json:"detail"`
	Pod      string    `json:"pod,omitempty"`
}

// Publisher is the event hub as the runner sees it.
type Publisher interface {
	Publish(typ string, v any) error
}

// Execer runs a command in a container. The production implementation streams over the API
// server's pods/exec subresource (exec.go); tests use a fake.
type Execer interface {
	Exec(ctx context.Context, namespace, pod, container string, command []string, tty bool) error
}

// Config tunes the runner; zero values take the defaults.
type Config struct {
	Namespace string
	// PollInterval is how often the pod is checked while waiting for it to become Ready.
	PollInterval time.Duration
	// QuarantineLinger keeps a quarantined pod around briefly after Talon's label lands, so the
	// isolation is observable (Hubble, kubectl) before cleanup removes the pod.
	QuarantineLinger time.Duration
	// CleanupTimeout bounds the final pod deletion.
	CleanupTimeout time.Duration
	// DeleteWait is how long the end of a run waits for the pod watch to report the deletion, so
	// the `pod` event saying Deleted comes before the run's final state.
	DeleteWait time.Duration
	// VictimPort, VictimInterval and VictimTimeout drive the victim poller: the app's port, how
	// often it is read, and the limit for one read (ADR 0021: 8080, 500 ms, 300 ms).
	VictimPort     int
	VictimInterval time.Duration
	VictimTimeout  time.Duration
}

// Runner runs scenarios. Safe for concurrent use.
type Runner struct {
	client kubernetes.Interface
	exec   Execer
	pub    Publisher
	log    *slog.Logger
	cfg    Config
	now    func() time.Time

	prober *victimProber

	base   context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu    sync.Mutex
	byPod map[string]*run
}

type run struct {
	id, scenario, pod string
	detected          chan struct{}
	responded         chan struct{}
	detectOnce        sync.Once
	respondOnce       sync.Once

	// podVisible: the pod exists, so run events name it. Written and read by the run's own
	// goroutine only.
	podVisible bool
	// gone is closed when the pod is being deleted by someone other than the runner (Talon's
	// terminate); deleted when the watch has seen it disappear from the API server.
	gone, deleted         chan struct{}
	goneOnce, deletedOnce sync.Once
	// selfDelete is set when the runner's own cleanup deletes the pod: from then on a deletion is
	// not Talon's doing and is not reported as the victim being killed.
	selfDelete     atomic.Bool
	victimGoneOnce sync.Once
}

func (rn *run) markGone() {
	if !rn.selfDelete.Load() {
		rn.goneOnce.Do(func() { close(rn.gone) })
	}
}

func (rn *run) isGone() bool {
	select {
	case <-rn.gone:
		return true
	default:
		return false
	}
}

// New returns a runner. Call Shutdown to stop in-flight runs (their pods are still cleaned up).
func New(client kubernetes.Interface, exec Execer, pub Publisher, log *slog.Logger, cfg Config) *Runner {
	if cfg.Namespace == "" {
		cfg.Namespace = "sandbox"
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 500 * time.Millisecond
	}
	if cfg.QuarantineLinger < 0 {
		cfg.QuarantineLinger = 0
	} else if cfg.QuarantineLinger == 0 {
		cfg.QuarantineLinger = 5 * time.Second
	}
	if cfg.CleanupTimeout <= 0 {
		cfg.CleanupTimeout = 15 * time.Second
	}
	if cfg.DeleteWait <= 0 {
		cfg.DeleteWait = 3 * time.Second
	}
	if cfg.VictimPort <= 0 {
		cfg.VictimPort = 8080
	}
	if cfg.VictimInterval <= 0 {
		cfg.VictimInterval = 500 * time.Millisecond
	}
	if cfg.VictimTimeout <= 0 {
		cfg.VictimTimeout = 300 * time.Millisecond
	}
	if log == nil {
		log = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Runner{client: client, exec: exec, pub: pub, log: log, cfg: cfg, now: time.Now,
		prober: newVictimProber(cfg.VictimPort, cfg.VictimTimeout),
		base:   ctx, cancel: cancel, byPod: map[string]*run{}}
}

// Start publishes `queued` and runs sc in the background. release is called exactly once, after the
// run's pod has been deleted. The returned run id is also the suffix of the pod name.
func (r *Runner) Start(sc scenarios.Scenario, release func()) string {
	id := newRunID()
	rn := &run{id: id, scenario: sc.ID, pod: podName(sc.ID, id),
		detected: make(chan struct{}), responded: make(chan struct{}),
		gone: make(chan struct{}), deleted: make(chan struct{})}
	r.mu.Lock()
	r.byPod[rn.pod] = rn
	r.mu.Unlock()
	r.publish(rn, StateQueued, "")
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer release()
		defer func() {
			r.mu.Lock()
			delete(r.byPod, rn.pod)
			r.mu.Unlock()
		}()
		r.execute(rn, sc)
	}()
	return id
}

// ObserveFalco correlates a Falco alert with the active run whose pod it names.
func (r *Runner) ObserveFalco(pod string) {
	if rn := r.lookup(pod); rn != nil {
		rn.detectOnce.Do(func() { close(rn.detected) })
	}
}

// ObserveTalon correlates a successful Talon action with the active run whose pod it names.
func (r *Runner) ObserveTalon(pod, status string) {
	if status != "success" {
		return
	}
	if rn := r.lookup(pod); rn != nil {
		rn.respondOnce.Do(func() { close(rn.responded) })
	}
}

func (r *Runner) lookup(pod string) *run {
	if pod == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byPod[pod]
}

// Shutdown cancels in-flight runs and waits for their cleanup, up to ctx.
func (r *Runner) Shutdown(ctx context.Context) error {
	r.cancel()
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// CleanupOrphans deletes scenario pods left behind by a previous instance of the API (a crash or a
// node restart mid-run). Only pods carrying this API's managed-by label are touched.
func (r *Runner) CleanupOrphans(ctx context.Context) error {
	pods, err := r.client.CoreV1().Pods(r.cfg.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: LabelManagedBy + "=" + ManagedBy,
	})
	if err != nil {
		return err
	}
	for _, p := range pods.Items {
		if r.lookup(p.Name) != nil {
			continue
		}
		r.log.Info("deleting orphaned scenario pod", "pod", p.Name)
		if err := r.deletePod(ctx, p.Name); err != nil {
			r.log.Warn("orphan cleanup failed", "pod", p.Name, "err", err)
		}
	}
	return nil
}

func (r *Runner) execute(rn *run, sc scenarios.Scenario) {
	timeout := sc.Timeout()
	ctx, cancel := context.WithTimeout(r.base, timeout)
	defer cancel()
	log := r.log.With("run_id", rn.id, "scenario", rn.scenario, "pod", rn.pod)

	// The watch outlives the run's timeout (it has to see the cleanup's deletion) but not the API.
	// Opened before the pod is created, so the creation is its first event.
	wctx, stopWatch := context.WithCancel(r.base)
	defer stopWatch()
	w, err := r.openPodWatch(wctx, rn.pod)
	if err != nil {
		log.Warn("pod watch failed; retrying in the background", "err", err)
		w = nil
	}
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		r.watchPod(wctx, rn, sc.Container(), w)
	}()

	// The victim poller, once there is a pod to poll; stopVictim ends it and waits.
	stopVictim, victimStarted := func() {}, false

	created := false
	final, detail := StateFinished, ""
	defer func() {
		// The poller stops first: whatever the cleanup does to the pod from here on is the API's
		// doing, not the attack's or Talon's, and must not show up as the victim's state.
		stopVictim()
		if created {
			rn.selfDelete.Store(true)
			cctx, ccancel := context.WithTimeout(context.Background(), r.cfg.CleanupTimeout)
			alreadyGone, err := r.deletePodFound(cctx, rn.pod)
			if err != nil {
				log.Error("scenario pod cleanup failed; activeDeadlineSeconds will end it", "err", err)
				if final == StateFinished {
					detail = "pod cleanup failed"
				}
			}
			ccancel()
			if alreadyGone {
				// Talon deleted it before the cleanup got there.
				rn.goneOnce.Do(func() { close(rn.gone) })
			}
			if err == nil {
				t := time.NewTimer(r.cfg.DeleteWait)
				select {
				case <-rn.deleted:
				case <-watchDone:
				case <-t.C:
				}
				t.Stop()
			}
		}
		stopWatch()
		<-watchDone
		if victimStarted && rn.isGone() {
			r.publishVictimGone(rn)
		}
		r.publish(rn, final, detail)
		log.Info("run ended", "state", final, "detail", detail)
	}()

	pod := buildPod(rn, sc, r.cfg.Namespace, timeout)
	if _, err := r.client.CoreV1().Pods(r.cfg.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		log.Error("scenario pod rejected", "err", err)
		final, detail = StateFailed, "the sandbox refused the scenario pod"
		if apierrors.IsForbidden(err) || apierrors.IsInvalid(err) {
			// Admission (Pod Security, Kyverno, quota) or validation: the scenario, not the API.
			detail = "admission refused the scenario pod: " + reason(err)
		}
		return
	}
	created = true
	rn.podVisible = true
	r.publish(rn, StateStarted, "pod created")

	ready, err := r.waitReady(ctx, rn.pod)
	if err != nil {
		final, detail = StateFailed, err.Error()
		if errors.Is(err, context.DeadlineExceeded) {
			final, detail = StateTimeout, "pod did not become ready in time"
		}
		if r.base.Err() != nil {
			final, detail = StateFailed, "API shutting down"
		}
		return
	}
	r.publish(rn, StatePodReady, viewOf(ready, sc.Container(), false).containerID)

	if sc.Victim && !ready.Spec.HostNetwork && net.ParseIP(ready.Status.PodIP) != nil {
		// One probe before the attack, synchronously, so "up" is on record before the command can
		// change anything; then the loop.
		vctx, vcancel := context.WithCancel(ctx)
		vdone := make(chan struct{})
		ip := ready.Status.PodIP
		first := r.prober.probe(vctx, ip)
		if first.Status == VictimUnreachable {
			first = VictimEvent{} // still starting: nothing to report yet
		} else {
			first.RunID, first.Pod, first.At = rn.id, rn.pod, r.now().UTC()
			r.emit(rn, "victim", first)
		}
		go func() {
			defer close(vdone)
			r.sleep(vctx, r.cfg.VictimInterval)
			r.pollVictim(vctx, rn, ip, first)
		}()
		victimStarted = true
		stopVictim = func() { vcancel(); <-vdone }
	}

	if sc.Exec != nil {
		// In the background: a terminated pod ends the exec stream with an error, which is the
		// expected outcome of a successful response, not a failure of the run. The pre-exec (no
		// TTY, validated) runs to its end first; its failure does not stop the exec, which is the
		// step the scenario is judged by.
		go func() {
			if sc.PreExec != nil {
				if err := r.exec.Exec(ctx, r.cfg.Namespace, rn.pod, sc.Container(), sc.PreExec.Command, false); err != nil {
					log.Info("pre-exec ended", "err", err)
				}
				if ctx.Err() != nil {
					return
				}
			}
			if err := r.exec.Exec(ctx, r.cfg.Namespace, rn.pod, sc.Container(), sc.Exec.Command, sc.Exec.TTY); err != nil {
				log.Info("exec ended", "err", err)
			}
		}()
	}

	detected := false
	detectedCh := rn.detected
	for {
		select {
		case <-detectedCh:
			detected = true
			r.publish(rn, StateDetected, sc.Detection)
			detectedCh = nil // a closed channel would spin the loop
		case <-rn.responded:
			if !detected {
				r.publish(rn, StateDetected, sc.Detection)
			}
			r.publish(rn, StateResponded, sc.Response)
			if sc.Response == "quarantine" {
				r.sleep(ctx, r.cfg.QuarantineLinger)
			}
			return
		case <-ctx.Done():
			final, detail = StateTimeout, "no response within the scenario timeout"
			if detected {
				detail = "detected, but no response within the scenario timeout"
			}
			if r.base.Err() != nil {
				final, detail = StateFailed, "API shutting down"
			}
			return
		}
	}
}

// waitReady polls until the pod is Running and Ready. A pod that ends (or disappears) first is an
// error: for a terminate scenario that would mean the response beat the readiness probe, which the
// scenario design must avoid.
func (r *Runner) waitReady(ctx context.Context, name string) (*corev1.Pod, error) {
	t := time.NewTicker(r.cfg.PollInterval)
	defer t.Stop()
	for {
		p, err := r.client.CoreV1().Pods(r.cfg.Namespace).Get(ctx, name, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			return nil, errors.New("pod disappeared before it became ready")
		case err != nil && ctx.Err() != nil:
			return nil, ctx.Err()
		case err != nil:
			r.log.Warn("pod status poll failed", "pod", name, "err", err)
		case p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed:
			return nil, fmt.Errorf("pod ended (%s) before it became ready", p.Status.Phase)
		case p.Status.Phase == corev1.PodRunning && podReady(p):
			return p, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

func podReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func (r *Runner) deletePod(ctx context.Context, name string) error {
	_, err := r.deletePodFound(ctx, name)
	return err
}

// deletePodFound deletes the pod and reports whether it was already gone.
func (r *Runner) deletePodFound(ctx context.Context, name string) (bool, error) {
	zero := int64(0)
	err := r.client.CoreV1().Pods(r.cfg.Namespace).Delete(ctx, name, metav1.DeleteOptions{GracePeriodSeconds: &zero})
	if apierrors.IsNotFound(err) {
		return true, nil // Talon's terminate got there first
	}
	return false, err
}

func (r *Runner) sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func (r *Runner) publish(rn *run, state, detail string) {
	ev := RunEvent{RunID: rn.id, Scenario: rn.scenario, State: state, At: r.now().UTC(), Detail: detail}
	if rn.podVisible {
		ev.Pod = rn.pod
	}
	r.emit(rn, "run", ev)
}

func (r *Runner) emit(rn *run, typ string, v any) {
	if err := r.pub.Publish(typ, v); err != nil {
		r.log.Error("publish failed", "type", typ, "run_id", rn.id, "err", err)
	}
}

// buildPod turns the scenario's template into the pod for one run. The template decides what runs;
// the runner decides how long it lives and how it is found again, and removes the two things a
// scenario pod never needs: an API token and service environment variables.
func buildPod(rn *run, sc scenarios.Scenario, namespace string, timeout time.Duration) *corev1.Pod {
	tpl := sc.Template.DeepCopy()
	labels := map[string]string{}
	for k, v := range tpl.Labels {
		labels[k] = v
	}
	labels[LabelRunID] = rn.id
	labels[LabelScenario] = sc.ID
	labels[LabelQuarantine] = "false"
	labels[LabelManagedBy] = ManagedBy

	spec := tpl.Spec
	deadline := int64(timeout / time.Second)
	no := false
	spec.ActiveDeadlineSeconds = &deadline
	spec.RestartPolicy = corev1.RestartPolicyNever
	spec.AutomountServiceAccountToken = &no
	spec.EnableServiceLinks = &no
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        rn.pod,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: tpl.Annotations,
		},
		Spec: spec,
	}
}

// podName is "<scenario id>-<first 10 hex of the run id>": unique, a valid DNS-1123 name (ids are
// at most 40 characters), and readable in the Falco alert a visitor sees.
func podName(scenario, runID string) string { return scenario + "-" + runID[:10] }

func newRunID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on Linux
	}
	return hex.EncodeToString(b)
}

// reason extracts the API server's message without the object dump.
func reason(err error) string {
	var se apierrors.APIStatus
	if errors.As(err, &se) {
		msg := se.Status().Message
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return msg
	}
	return "unknown"
}
