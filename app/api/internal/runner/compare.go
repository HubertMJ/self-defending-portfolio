package runner

// The unguarded twin (ADR 0031): one attack, two pods created together - one in the guarded
// sandbox, one in `sandbox-unguarded`, same spec and same exec. Both have every preventive layer
// (Pod Security, signed images, the quota, default-deny networking) and both are seen by Falco; the
// difference is that no Talon rule matches the twin, so nothing answers it. The guarded arm drives
// the run's states; the unguarded arm only emits its own `pod`/`victim` events (and the Falco
// events the server stamps) with arm="unguarded", and is kept CompareHold after the guarded arm's
// response so the visitor sees the contrast, then deleted by the API (which is not a `gone` event).

import (
	"context"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/scenarios"
)

// StartCompare runs sc in the guarded sandbox and the unguarded twin at once under one run id. When
// the twin namespace is not configured it falls back to a single guarded run, so the endpoint still
// works on a cluster without the twin.
func (r *Runner) StartCompare(sc scenarios.Scenario, release func()) string {
	if r.cfg.UnguardedNamespace == "" || r.cfg.UnguardedNamespace == r.cfg.Namespace {
		return r.Start(sc, release)
	}
	id := newRunID()
	guarded := r.newArm(sc, id, r.cfg.Namespace, "guarded", podName(sc.ID, id))
	unguarded := r.newArm(sc, id, r.cfg.UnguardedNamespace, "unguarded", podName(sc.ID, id)+"-u")
	pods := map[string]string{"guarded": guarded.pod, "unguarded": unguarded.pod}
	guarded.pods = pods

	r.mu.Lock()
	r.byPod[guarded.pod] = guarded
	r.byPod[unguarded.pod] = unguarded
	r.byID[id] = guarded
	r.mu.Unlock()

	r.publish(guarded, StateQueued, "")
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer release()
		defer func() {
			r.mu.Lock()
			delete(r.byPod, guarded.pod)
			delete(r.byPod, unguarded.pod)
			delete(r.byID, id)
			r.mu.Unlock()
		}()
		r.executeCompare(guarded, unguarded, sc)
	}()
	return id
}

func (r *Runner) newArm(sc scenarios.Scenario, id, namespace, arm, pod string) *run {
	return &run{id: id, scenario: sc.ID, pod: pod, namespace: namespace, arm: arm,
		detected: make(chan struct{}), responded: make(chan struct{}),
		gone: make(chan struct{}), deleted: make(chan struct{}), firstUnreachable: make(chan struct{})}
}

func (r *Runner) executeCompare(guarded, unguarded *run, sc scenarios.Scenario) {
	var wg sync.WaitGroup
	uctx, ucancel := context.WithCancel(r.base)
	defer ucancel()
	guardedDone := make(chan struct{})

	wg.Add(2)
	go func() { defer wg.Done(); defer close(guardedDone); r.execute(guarded, sc) }()
	go func() { defer wg.Done(); r.executeArm(uctx, unguarded, sc) }()

	// Keep the twin until the guarded arm has responded and the visitor has had CompareHold to see
	// the difference; if the guarded arm ends without a response, stop the twin with it.
	go func() {
		select {
		case <-guarded.responded:
			r.sleep(r.base, r.cfg.CompareHold)
		case <-guardedDone:
		}
		ucancel()
	}()

	wg.Wait()
}

// executeArm runs the unguarded pod: create, wait ready, probe its victim and run the same exec,
// then hold until ctx is cancelled (by the coordinator) and clean the pod up. It publishes no
// run-state events - the run's states are the guarded arm's - and its own delete is never reported
// as the victim being killed.
func (r *Runner) executeArm(ctx context.Context, rn *run, sc scenarios.Scenario) {
	actx, cancel := context.WithTimeout(ctx, sc.Timeout())
	defer cancel()
	log := r.log.With("run_id", rn.id, "arm", rn.arm, "pod", rn.pod)

	wctx, stopWatch := context.WithCancel(r.base)
	defer stopWatch()
	w, err := r.openPodWatch(wctx, rn.namespace, rn.pod)
	if err != nil {
		log.Warn("unguarded pod watch failed; retrying in the background", "err", err)
		w = nil
	}
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		r.watchPod(wctx, rn, sc.Container(), w)
	}()

	stopVictim := func() {}
	created := false
	defer func() {
		stopVictim()
		if created {
			rn.selfDelete.Store(true)
			cctx, ccancel := context.WithTimeout(context.Background(), r.cfg.CleanupTimeout)
			if _, err := r.deletePodFound(cctx, rn.namespace, rn.pod); err != nil {
				log.Warn("unguarded pod cleanup failed; activeDeadlineSeconds will end it", "err", err)
			}
			ccancel()
		}
		stopWatch()
		<-watchDone
	}()

	pod := buildPod(rn, sc, rn.namespace, sc.Timeout())
	if _, err := r.client.CoreV1().Pods(rn.namespace).Create(actx, pod, metav1.CreateOptions{}); err != nil {
		log.Warn("unguarded pod rejected", "err", err)
		return
	}
	created = true
	rn.podVisible = true

	ready, err := r.waitReady(actx, rn.namespace, rn.pod)
	if err != nil {
		return
	}
	if stop, started := r.startVictim(actx, rn, sc, ready); started {
		stopVictim = stop
	}

	if sc.Exec != nil {
		go func() {
			if sc.PreExec != nil {
				if err := r.exec.Exec(actx, rn.namespace, rn.pod, sc.Container(), sc.PreExec.Command, false); err != nil {
					log.Info("unguarded pre-exec ended", "err", err)
				}
				if actx.Err() != nil {
					return
				}
			}
			if err := r.exec.Exec(actx, rn.namespace, rn.pod, sc.Container(), sc.Exec.Command, sc.Exec.TTY); err != nil {
				log.Info("unguarded exec ended", "err", err)
			}
		}()
	}

	<-actx.Done() // held until the coordinator (or the deadline) stops this arm
}

// ArmFor reports which arm of a compare run a pod belongs to ("guarded"/"unguarded"), or "" for an
// ordinary run or an unknown pod. The server stamps it onto Falco and Talon events.
func (r *Runner) ArmFor(pod string) string {
	rn := r.lookup(pod)
	if rn == nil {
		return ""
	}
	return rn.arm
}
