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
// timeout_seconds, at most 300 s) and `failed` (the pod could not be created or never became
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
	"io"
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
	// Pods names both arms of a compare run (ADR 0031): {"guarded": ..., "unguarded": ...}; absent
	// on an ordinary run. Pod stays the guarded arm's pod, since the run states follow it.
	Pods map[string]string `json:"pods,omitempty"`
	// CommandSeq ties a terminal run's `detected`/`responded` to the command it is about, so the
	// page can show "killed N ms after your Enter" (ADR 0029); absent otherwise, best effort.
	CommandSeq int `json:"command_seq,omitempty"`
}

// Publisher is the event hub as the runner sees it.
type Publisher interface {
	Publish(typ string, v any) error
}

// Execer runs a command in a container. The production implementation streams over the API
// server's pods/exec subresource (exec.go); tests use a fake.
//
// Exec discards output (a scripted scenario shows nothing it prints). ExecStream is the terminal
// path (ADR 0029): it writes the command's stdout and stderr to the given writers as they arrive,
// so the runner can forward them to the visitor, and reports the exit code. A non-zero exit is not
// an error (wget fails by design); err is only a transport failure or the pod going away.
type Execer interface {
	Exec(ctx context.Context, namespace, pod, container string, command []string, tty bool) error
	ExecStream(ctx context.Context, namespace, pod, container string, command []string, tty bool, stdout, stderr io.Writer) (exitCode int, err error)
}

// Config tunes the runner; zero values take the defaults.
type Config struct {
	Namespace string
	// UnguardedNamespace is the twin namespace a compare run's second pod goes in (ADR 0031): the
	// same preventive layers, but no Talon response. Empty disables compare (StartCompare then
	// behaves like a single-pod run).
	UnguardedNamespace string
	// CompareHold is how long the unguarded pod is kept after the guarded arm's response, so the
	// visitor sees the contrast, before the API deletes it (ADR 0031: 12 s).
	CompareHold time.Duration
	// PollInterval is how often the pod is checked while waiting for it to become Ready.
	PollInterval time.Duration
	// QuarantineLinger is the grace kept after the first `unreachable` victim event of a
	// quarantine run, so the visitor sees the cut before cleanup removes the pod (FIX 1, ADR 0029):
	// the run waits for that event and then this long, bounded by QuarantineLingerMax. A negative
	// value disables the linger entirely (tests: the pod is deleted as soon as Talon responds).
	QuarantineLinger time.Duration
	// QuarantineLingerMax is the hard ceiling on the post-response wait when a poller is running but
	// the expected `unreachable` never arrives (the probe keeps answering). Without a poller the
	// linger is a short fixed QuarantineLinger instead, not this cap.
	QuarantineLingerMax time.Duration
	// CleanupTimeout bounds the final pod deletion.
	CleanupTimeout time.Duration
	// DeleteWait is how long the end of a run waits for the pod watch to report the deletion, so
	// the `pod` event saying Deleted comes before the run's final state.
	DeleteWait time.Duration
	// ResponseWait is how long a terminal run whose pod was deleted under it waits for Talon's
	// notification before it ends: live, the pod watch reports the deletion a few milliseconds
	// before the webhook that explains it arrives, and a run that has already finished would
	// drop that response. Only while a detection is still unanswered. Default 2 s.
	ResponseWait time.Duration
	// VictimPort, VictimInterval and VictimTimeout drive the victim poller: the app's port, how
	// often it is read, and the limit for one read (ADR 0021: 8080, 500 ms, 300 ms).
	VictimPort     int
	VictimInterval time.Duration
	VictimTimeout  time.Duration
	// CommandTimeout bounds a non-TTY terminal command's exec (ADR 0029: 5 s).
	CommandTimeout time.Duration
	// TTYCommandTimeout bounds a TTY command (an interactive shell, whose empty stdin never ends
	// it): if the pod has not been deleted by then, the exec is cancelled (ADR 0029: 10 s). Without
	// it a shell nobody answers would hold the run, and the global slot, until the run's deadline.
	TTYCommandTimeout time.Duration
}

// Runner runs scenarios. Safe for concurrent use.
type Runner struct {
	client kubernetes.Interface
	exec   Execer
	pub    Publisher
	log    *slog.Logger
	cfg    Config
	now    func() time.Time

	prober         *victimProber
	lingerDisabled bool

	base   context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu    sync.Mutex
	byPod map[string]*run
	byID  map[string]*run
	// ended remembers recently finished terminal run ids (a bounded ring), so a command or a
	// leave on a run that is over gets 409 "already over" rather than 404 (ADR 0029).
	ended     map[string]bool
	endedRing []string
}

// maxEndedTracked bounds the ended-terminal set; older ids fall off and then read as unknown (404),
// which is harmless once a run is long gone.
const maxEndedTracked = 256

type run struct {
	id, scenario, pod string
	detected          chan struct{}
	responded         chan struct{}
	detectOnce        sync.Once
	respondOnce       sync.Once

	// podVisible: the pod exists, so run events name it. Set by the run's own goroutine once the pod
	// is created, and read by every goroutine that publishes a run event for the run - its own, and
	// for a terminal run the webhook handlers' ObserveFalco/ObserveTalon, which may fire at any time
	// after the run is registered. Hence atomic.
	podVisible atomic.Bool
	// gone is closed when the pod is being deleted by someone other than the runner (Talon's
	// terminate); deleted when the watch has seen it disappear from the API server.
	gone, deleted         chan struct{}
	goneOnce, deletedOnce sync.Once
	// selfDelete is set when the runner's own cleanup deletes the pod: from then on a deletion is
	// not Talon's doing and is not reported as the victim being killed.
	selfDelete     atomic.Bool
	victimGoneOnce sync.Once
	// unreachable gets a non-blocking send from the victim poller every time it publishes an
	// `unreachable` event (buffered 1), after it has stored that event's time in lastUnreachable.
	// respondedAt is when the runner observed Talon's response. A quarantine run lingers until an
	// `unreachable` at or after the response is on record - the cut that follows the label, not one
	// seen before it - however the two goroutines interleave (FIX 1, ADR 0029). Both are UnixNano of
	// the runner's clock; 0 means none yet.
	unreachable     chan struct{}
	lastUnreachable atomic.Int64
	respondedAt     atomic.Int64

	// Terminal-run state (ADR 0029), guarded by tmu. A terminal run keeps its pod alive and runs
	// catalogue commands on request, one at a time; the rest is nil/zero for a scripted run.
	// arm is "guarded"/"unguarded" for a pod tracker that belongs to a compare run (ADR 0031);
	// "" for an ordinary single-pod run. It is stamped onto this run's pod/victim events.
	arm string
	// namespace this run's pod lives in: `sandbox` normally, `sandbox-unguarded` for the unguarded
	// arm of a compare run.
	namespace string
	// pods names both arms of a compare run, published on the run events; nil otherwise.
	pods map[string]string
	// deferFinal holds the guarded arm's final run event back for the compare coordinator, which
	// publishes it only once both pods are gone (ADR 0031); finalState/finalDetail carry it.
	deferFinal              bool
	finalState, finalDetail string

	terminal  bool
	sc        scenarios.Scenario
	token     string
	flag      string          // SDP_FLAG set on the pod this run
	cmds      chan commandReq // unbuffered: the loop receives a command only while it can run it
	loopDone  chan struct{}   // closed when the terminal loop stops accepting commands
	answered  chan struct{}   // a detection was answered (buffered 1): the kill's end waits on it
	leave     chan struct{}   // closed by Leave (the visitor pressed "leave")
	leaveOnce sync.Once

	tmu       sync.Mutex
	over      bool      // the run has ended; no new command is accepted
	ready     bool      // the pod is Ready; commands are accepted only between ready and over
	running   bool      // a command is executing right now
	seq       int       // last seq handed out
	count     int       // commands accepted so far (capped per run)
	curSeq    int       // the running command's seq (0 when none running)
	curCmdID  string    // the running command's id
	lastSeq   int       // the last finished command's seq
	lastCmdID string    // the last finished command's id
	lastEnded time.Time // when the last command finished (for the 2 s command_seq window)
	// detections are the `detected` run events published, in order, each paired with at most one
	// `responded`; earlyResponded marks the seqs a response was published for before any detection
	// (terminalResponded).
	detections     []detection
	earlyResponded map[int]bool
	runOut         int // bytes of command output published across the run (32 KiB budget)
	runOutEvents   int // `output` events published across the run (runOutEvents budget)
}

// commandReq is one resolved command the server asked the run goroutine to execute.
type commandReq struct {
	seq int
	cmd scenarios.Command
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
	// A negative QuarantineLinger disables the post-response linger (kept as -0 so the sign is
	// lost but lingerDisabled below has already been read). A zero takes the contract's 3 s grace.
	lingerDisabled := cfg.QuarantineLinger < 0
	if lingerDisabled {
		cfg.QuarantineLinger = 0
	} else if cfg.QuarantineLinger == 0 {
		cfg.QuarantineLinger = 3 * time.Second
	}
	if cfg.QuarantineLingerMax <= 0 {
		cfg.QuarantineLingerMax = 40 * time.Second
	}
	if cfg.CleanupTimeout <= 0 {
		cfg.CleanupTimeout = 15 * time.Second
	}
	if cfg.DeleteWait <= 0 {
		cfg.DeleteWait = 3 * time.Second
	}
	if cfg.ResponseWait <= 0 {
		cfg.ResponseWait = 2 * time.Second
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
	if cfg.CommandTimeout <= 0 {
		cfg.CommandTimeout = 5 * time.Second
	}
	if cfg.TTYCommandTimeout <= 0 {
		cfg.TTYCommandTimeout = 10 * time.Second
	}
	if cfg.CompareHold <= 0 {
		cfg.CompareHold = 12 * time.Second
	}
	if log == nil {
		log = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Runner{client: client, exec: exec, pub: pub, log: log, cfg: cfg, now: time.Now,
		lingerDisabled: lingerDisabled,
		prober:         newVictimProber(cfg.VictimPort, cfg.VictimTimeout),
		base:           ctx, cancel: cancel, byPod: map[string]*run{}, byID: map[string]*run{}, ended: map[string]bool{}}
}

// ErrInteractive is returned by Start and StartCompare for a terminal scenario: it has no scripted
// attack, and its run needs the command loop only StartTerminal sets up (a run started any other way
// would close the nil channels that loop owns and crash the process).
var ErrInteractive = errors.New("an interactive scenario runs only as a terminal run")

// Start publishes `queued` and runs sc in the background. release is called exactly once, after the
// run's pod has been deleted. The returned run id is also the suffix of the pod name. An interactive
// scenario is refused with ErrInteractive; then nothing is started, nothing is published, and
// release is not called (the caller still holds the slot).
func (r *Runner) Start(sc scenarios.Scenario, release func()) (string, error) {
	if sc.Interactive {
		return "", ErrInteractive
	}
	rn := r.newRun(sc)
	r.launch(rn, sc, release)
	return rn.id, nil
}

// StartTerminal begins an interactive run (ADR 0029) and returns its id and a bearer token. The
// token is returned only here - never in an event or in GET /api/runs/{id} - and every command and
// the leave request must present it.
func (r *Runner) StartTerminal(sc scenarios.Scenario, release func()) (string, string) {
	rn := r.newRun(sc)
	rn.terminal = true
	rn.sc = sc
	rn.token = newToken()
	rn.flag = newFlag()
	rn.cmds = make(chan commandReq)
	rn.loopDone = make(chan struct{})
	rn.answered = make(chan struct{}, 1)
	rn.leave = make(chan struct{})
	r.launch(rn, sc, release)
	return rn.id, rn.token
}

func (r *Runner) newRun(sc scenarios.Scenario) *run {
	id := newRunID()
	return &run{id: id, scenario: sc.ID, pod: podName(sc.ID, id), namespace: r.cfg.Namespace,
		detected: make(chan struct{}), responded: make(chan struct{}),
		gone: make(chan struct{}), deleted: make(chan struct{}),
		unreachable: make(chan struct{}, 1)}
}

func (r *Runner) launch(rn *run, sc scenarios.Scenario, release func()) {
	r.mu.Lock()
	r.byPod[podKey(rn.namespace, rn.pod)] = rn
	r.byID[rn.id] = rn
	r.mu.Unlock()
	r.publish(rn, StateQueued, "")
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer release()
		defer func() {
			r.mu.Lock()
			delete(r.byPod, podKey(rn.namespace, rn.pod))
			delete(r.byID, rn.id)
			if rn.terminal {
				r.markEndedLocked(rn.id)
			}
			r.mu.Unlock()
		}()
		r.execute(rn, sc)
	}()
}

// markEndedLocked remembers a finished terminal run id, oldest evicted past the cap. r.mu held.
func (r *Runner) markEndedLocked(id string) {
	if r.ended[id] {
		return
	}
	r.ended[id] = true
	r.endedRing = append(r.endedRing, id)
	if len(r.endedRing) > maxEndedTracked {
		old := r.endedRing[0]
		r.endedRing = r.endedRing[1:]
		delete(r.ended, old)
	}
}

// wasTerminal reports whether id was a terminal run that has since ended.
func (r *Runner) wasTerminal(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ended[id]
}

// ObserveFalco correlates a Falco alert with the active run whose pod it names. For a scripted run
// it unblocks the one detection the run is waiting for; for a terminal run it publishes a
// `detected` run event against the command that is running (or just ran), which may happen more
// than once in the run (ADR 0029). rule is the Falco rule that fired, used as the terminal
// `detected` detail (a command whose catalogue outcome is not `detected` carries no rule of its
// own, so the real rule name is the only honest detail).
func (r *Runner) ObserveFalco(namespace, pod, rule string) {
	rn := r.lookup(namespace, pod)
	if rn == nil {
		return
	}
	if !rn.terminal {
		rn.detectOnce.Do(func() { close(rn.detected) })
		return
	}
	r.terminalDetected(rn, rule)
}

// ObserveTalon correlates a successful Talon action with the active run whose pod it names.
// actionner is the Talon actionner that acted (kubernetes:label, kubernetes:terminate); a terminal
// run uses it to pair the response with the detection it answers.
func (r *Runner) ObserveTalon(namespace, pod, status, actionner string) {
	if status != "success" {
		return
	}
	rn := r.lookup(namespace, pod)
	if rn == nil {
		return
	}
	if !rn.terminal {
		rn.respondOnce.Do(func() {
			rn.respondedAt.Store(r.now().UnixNano())
			close(rn.responded)
		})
		return
	}
	r.terminalResponded(rn, actionner)
}

// podKey indexes a run by the pod's namespace and name together: a compare run's guarded and
// unguarded arms live in different namespaces, so a name alone is no longer a unique key (ADR 0031).
func podKey(namespace, name string) string { return namespace + "/" + name }

func (r *Runner) lookup(namespace, pod string) *run {
	if pod == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byPod[podKey(namespace, pod)]
}

func (r *Runner) lookupID(id string) *run {
	if id == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byID[id]
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
// node restart mid-run). Only pods carrying this API's managed-by label are touched, in the
// guarded sandbox and the unguarded twin alike.
func (r *Runner) CleanupOrphans(ctx context.Context) error {
	var firstErr error
	for _, ns := range r.namespaces() {
		if err := r.cleanupOrphansIn(ctx, ns); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (r *Runner) cleanupOrphansIn(ctx context.Context, namespace string) error {
	pods, err := r.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: LabelManagedBy + "=" + ManagedBy,
	})
	if err != nil {
		return err
	}
	for _, p := range pods.Items {
		if r.lookup(namespace, p.Name) != nil {
			continue
		}
		r.log.Info("deleting orphaned scenario pod", "pod", p.Name, "namespace", namespace)
		if err := r.deletePod(ctx, namespace, p.Name); err != nil {
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

	stopWatch, watchDone := r.startPodWatch(rn, sc, log)
	defer stopWatch()

	// The victim poller, once there is a pod to poll; stopVictim ends it and waits.
	stopVictim, victimStarted := func() {}, false

	created := false
	final, detail := StateFinished, ""
	defer func() {
		// The poller stops first: whatever the cleanup does to the pod from here on is the API's
		// doing, not the attack's or Talon's, and must not show up as the victim's state.
		stopVictim()
		if created {
			r.deleteAndAwait(rn, watchDone, log)
		}
		stopWatch()
		<-watchDone
		if victimStarted && rn.isGone() {
			r.publishVictimGone(rn)
		}
		// A compare run's guarded arm defers its `finished` to the coordinator, which publishes it
		// only once both pods are gone (ADR 0031); an ordinary run publishes it here.
		if rn.deferFinal {
			rn.finalState, rn.finalDetail = final, detail
		} else {
			r.publish(rn, final, detail)
		}
		log.Info("run ended", "state", final, "detail", detail)
	}()

	if err := r.createPod(ctx, rn, sc, timeout); err != nil {
		log.Error("scenario pod rejected", "err", err)
		final, detail = StateFailed, "the sandbox refused the scenario pod"
		if apierrors.IsForbidden(err) || apierrors.IsInvalid(err) {
			// Admission (Pod Security, Kyverno, quota) or validation: the scenario, not the API.
			detail = "admission refused the scenario pod: " + reason(err)
		}
		return
	}
	created = true
	r.publish(rn, StateStarted, "pod created")

	ready, err := r.waitReady(ctx, rn.namespace, rn.pod)
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
	if sc.Interactive {
		// Accept commands from the moment pod_ready is on the wire: a command sent on pod_ready then
		// waits for the loop (an unbuffered hand-off) instead of racing the victim probe for a 409
		// (ADR 0029, item 30). The command loop itself starts just below.
		rn.tmu.Lock()
		rn.ready = true
		rn.tmu.Unlock()
	}
	r.publish(rn, StatePodReady, viewOf(ready, sc.Container(), false).containerID)

	if stop, started := r.startVictim(ctx, rn, sc, ready); started {
		stopVictim, victimStarted = stop, true
	}

	if sc.Interactive {
		// A terminal run takes over here: the pod stays up and the visitor drives it with
		// commands until the pod is killed, the deadline or idle timer fires, or the visitor
		// leaves. The scripted exec/select path below is not used.
		final, detail = r.runTerminal(ctx, rn, sc, log)
		return
	}

	r.startScriptedExec(ctx, rn, sc, log)

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
				r.lingerForQuarantine(ctx, rn, victimStarted)
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

// startPodWatch opens the watch on the run's pod - before the pod is created, so the creation is its
// first event - and runs it in the background. The watch outlives the run's timeout (it has to see
// the cleanup's deletion) but not the API. stop ends it; done is closed when it has returned. Shared
// by a run and the compare twin.
func (r *Runner) startPodWatch(rn *run, sc scenarios.Scenario, log *slog.Logger) (stop func(), done <-chan struct{}) {
	wctx, cancel := context.WithCancel(r.base)
	w, err := r.openPodWatch(wctx, rn.namespace, rn.pod)
	if err != nil {
		log.Warn("pod watch failed; retrying in the background", "err", err)
		w = nil
	}
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		r.watchPod(wctx, rn, sc.Container(), w)
	}()
	return cancel, watchDone
}

// createPod creates the run's pod from the scenario; once it returns nil the pod exists and the
// run's events name it.
func (r *Runner) createPod(ctx context.Context, rn *run, sc scenarios.Scenario, timeout time.Duration) error {
	if _, err := r.client.CoreV1().Pods(rn.namespace).Create(ctx, buildPod(rn, sc, rn.namespace, timeout), metav1.CreateOptions{}); err != nil {
		return err
	}
	rn.podVisible.Store(true)
	return nil
}

// startScriptedExec sends a scripted scenario's pre-exec and exec in the background, if it has them.
// In the background: a terminated pod ends the exec stream with an error, which is the expected
// outcome of a successful response, not a failure of the run. The pre-exec (no TTY, validated) runs
// to its end first; its failure does not stop the exec, which is the step the scenario is judged by.
func (r *Runner) startScriptedExec(ctx context.Context, rn *run, sc scenarios.Scenario, log *slog.Logger) {
	if sc.Exec == nil {
		return
	}
	go func() {
		if sc.PreExec != nil {
			if err := r.exec.Exec(ctx, rn.namespace, rn.pod, sc.Container(), sc.PreExec.Command, false); err != nil {
				log.Info("pre-exec ended", "err", err)
			}
			if ctx.Err() != nil {
				return
			}
		}
		if err := r.exec.Exec(ctx, rn.namespace, rn.pod, sc.Container(), sc.Exec.Command, sc.Exec.TTY); err != nil {
			log.Info("exec ended", "err", err)
		}
	}()
}

// startVictim begins the victim poller for a ready pod that has the app, publishing the first
// observation synchronously so "up" is on record before any command can change it. It returns a
// stop function (cancels the poller and waits) and whether it started.
func (r *Runner) startVictim(ctx context.Context, rn *run, sc scenarios.Scenario, ready *corev1.Pod) (func(), bool) {
	if !sc.Victim || ready.Spec.HostNetwork || net.ParseIP(ready.Status.PodIP) == nil {
		return func() {}, false
	}
	vctx, vcancel := context.WithCancel(ctx)
	vdone := make(chan struct{})
	ip := ready.Status.PodIP
	first := r.prober.probe(vctx, ip)
	if first.Status == VictimUnreachable {
		first = VictimEvent{} // still starting: nothing to report yet
	} else {
		first.RunID, first.Pod, first.At = rn.id, rn.pod, r.now().UTC()
		r.emitVictim(rn, first)
	}
	go func() {
		defer close(vdone)
		r.sleep(vctx, r.cfg.VictimInterval)
		r.pollVictim(vctx, rn, ip, first)
	}()
	return func() { vcancel(); <-vdone }, true
}

// waitReady polls until the pod is Running and Ready. A pod that ends (or disappears) first is an
// error: for a terminate scenario that would mean the response beat the readiness probe, which the
// scenario design must avoid.
func (r *Runner) waitReady(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	t := time.NewTicker(r.cfg.PollInterval)
	defer t.Stop()
	for {
		p, err := r.client.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
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

func (r *Runner) deletePod(ctx context.Context, namespace, name string) error {
	_, err := r.deletePodFound(ctx, namespace, name)
	return err
}

// deletePodFound deletes the pod and reports whether it was already gone.
func (r *Runner) deletePodFound(ctx context.Context, namespace, name string) (bool, error) {
	zero := int64(0)
	err := r.client.CoreV1().Pods(namespace).Delete(ctx, name, metav1.DeleteOptions{GracePeriodSeconds: &zero})
	if apierrors.IsNotFound(err) {
		return true, nil // Talon's terminate got there first
	}
	return false, err
}

// lingerForQuarantine keeps a quarantined pod alive long enough for the visitor to see the cut
// (FIX 1, ADR 0029). The old fixed 5 s linger deleted the pod before Cilium had finished isolating
// it, so the probe was still answering and no `unreachable` event ever reached the page.
//
// With a victim poller running, it waits until an `unreachable` event at or after the response is on
// record (one from before the response belongs to a different moment; one published while the run
// goroutine was still getting here counts) and then QuarantineLinger (3 s) more; a pod deleted
// during the wait (rn.gone) or the overall cap QuarantineLingerMax (40 s) end it early.
// Without a poller - no victim app, or the probe never started - there is nothing to wait for, so a
// short fixed linger stands in rather than the full cap. A negative QuarantineLinger disables it.
func (r *Runner) lingerForQuarantine(ctx context.Context, rn *run, pollerRunning bool) {
	if r.lingerDisabled {
		return
	}
	cap := time.NewTimer(r.cfg.QuarantineLingerMax)
	defer cap.Stop()
	if !pollerRunning {
		fixed := time.NewTimer(r.cfg.QuarantineLinger)
		defer fixed.Stop()
		select {
		case <-fixed.C:
		case <-rn.gone:
		case <-cap.C:
		case <-ctx.Done():
		}
		return
	}
	// Compare times rather than drain the signal: the cut may well be published between Talon's
	// webhook and this point, and draining would throw it away and wait for a second one that never
	// comes (the poller publishes changes only). A signal from before the response just re-checks.
	responded := rn.respondedAt.Load()
	for rn.lastUnreachable.Load() < responded {
		select {
		case <-rn.unreachable:
		case <-rn.gone:
			return // already deleted during the wait: no need to linger
		case <-cap.C:
			return
		case <-ctx.Done():
			return
		}
	}
	grace := time.NewTimer(r.cfg.QuarantineLinger)
	defer grace.Stop()
	select {
	case <-grace.C:
	case <-rn.gone:
	case <-cap.C:
	case <-ctx.Done():
	}
}

// deleteAndAwait deletes the run's pod (as the API's own cleanup, so the deletion is not reported
// as the victim being killed) and waits briefly for the watch to report it, so the pod's
// `deleted=true` event is published before the run ends. Shared by the scripted/terminal path and
// the compare twin (ADR 0031: the twin's delete must be observed, not dropped).
func (r *Runner) deleteAndAwait(rn *run, watchDone <-chan struct{}, log *slog.Logger) {
	rn.selfDelete.Store(true)
	cctx, ccancel := context.WithTimeout(context.Background(), r.cfg.CleanupTimeout)
	alreadyGone, err := r.deletePodFound(cctx, rn.namespace, rn.pod)
	ccancel()
	if err != nil {
		// Logged, not folded into the run's detail: the final `finished` detail is the run's outcome
		// (for a terminal run, one of killed/left/idle/deadline), not a cleanup note.
		// activeDeadlineSeconds still ends the pod.
		log.Error("scenario pod cleanup failed; activeDeadlineSeconds will end it", "err", err)
		return
	}
	if alreadyGone {
		rn.goneOnce.Do(func() { close(rn.gone) }) // Talon deleted it before the cleanup got there
	}
	t := time.NewTimer(r.cfg.DeleteWait)
	defer t.Stop()
	select {
	case <-rn.deleted:
	case <-watchDone:
	case <-t.C:
	}
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
	ev := RunEvent{RunID: rn.id, Scenario: rn.scenario, State: state, At: r.now().UTC(), Detail: detail, Pods: rn.pods}
	if rn.podVisible.Load() {
		ev.Pod = rn.pod
	}
	r.emit(rn, "run", ev)
}

// publishCmd is publish with a command seq, for a terminal run's detected/responded events.
func (r *Runner) publishCmd(rn *run, state, detail string, seq int) {
	ev := RunEvent{RunID: rn.id, Scenario: rn.scenario, State: state, At: r.now().UTC(), Detail: detail,
		Pods: rn.pods, CommandSeq: seq}
	if rn.podVisible.Load() {
		ev.Pod = rn.pod
	}
	r.emit(rn, "run", ev)
}

// namespaces is every namespace the runner creates pods in: the sandbox, and the unguarded twin
// when compare is configured.
func (r *Runner) namespaces() []string {
	if r.cfg.UnguardedNamespace == "" || r.cfg.UnguardedNamespace == r.cfg.Namespace {
		return []string{r.cfg.Namespace}
	}
	return []string{r.cfg.Namespace, r.cfg.UnguardedNamespace}
}

func (r *Runner) emit(rn *run, typ string, v any) {
	if err := r.pub.Publish(typ, v); err != nil {
		r.log.Error("publish failed", "type", typ, "run_id", rn.id, "err", err)
	}
}

// emitVictim stamps the run's arm (compare runs) onto a victim event and publishes it.
func (r *Runner) emitVictim(rn *run, ev VictimEvent) {
	ev.Arm = rn.arm
	r.emit(rn, "victim", ev)
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
	if sc.Interactive {
		// The run's own flag (ADR 0029): a fresh value per run, so one run's flag is never another's.
		// The victim writes it to /srv/shop/.flag (0600) and never serves it; a visitor reaches it
		// only by running a command that reads the file, and once they do, that command's output is
		// broadcast to every subscriber of this run's feed - as any command output is. The flag is
		// the run's secret, not a per-viewer one.
		setEnv(&spec, scenarios.TerminalContainer, "SDP_FLAG", rn.flag)
	}
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

func newRunID() string { return randomHex(8) }

// newToken is the 32-hex bearer token a terminal run hands out once (ADR 0029).
func newToken() string { return randomHex(16) }

// newFlag is the run's SDP_FLAG: "SDP{" + 16 hex + "}".
func newFlag() string { return "SDP{" + randomHex(8) + "}" }

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on Linux
	}
	return hex.EncodeToString(b)
}

// setEnv adds or replaces an environment variable on the named container of spec. Used to give the
// terminal pod its per-run flag; a scenario that already sets the same name is overridden, so the
// catalogue cannot pin the flag to a known value.
func setEnv(spec *corev1.PodSpec, container, name, value string) {
	for i := range spec.Containers {
		if spec.Containers[i].Name != container {
			continue
		}
		env := spec.Containers[i].Env
		for j := range env {
			if env[j].Name == name {
				env[j].Value, env[j].ValueFrom = value, nil // a literal wins; never leave a dangling valueFrom
				spec.Containers[i].Env = env
				return
			}
		}
		spec.Containers[i].Env = append(env, corev1.EnvVar{Name: name, Value: value})
		return
	}
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
