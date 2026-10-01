package runner

// The pod watch: one watch per run, on exactly one pod (field selector metadata.name), publishing
// `event: pod` whenever something a visitor can verify changes - the phase the kubelet reports, the
// container's id and image digest, a label (Talon's quarantine label shows up here as it lands), the
// deletion. It is the evidence that the scenario pod is a real object in a real API server, with a
// UID and an image digest anyone can compare against the signed image, rather than an animation.
//
// What a `pod` event never contains: the node name, the host IP, the pod IP (contract hard rule).
// The pod object has all three; the view below copies only what is published, so a field cannot
// leak by being forgotten in a filter.
//
// RBAC: `watch` on pods in `sandbox` (cluster/infra/portfolio-api/rbac.yaml). The watch is opened
// before the pod is created, so the first event is the creation itself; it is re-opened if the API
// server closes it mid-run, and ends when the pod is deleted or the run's cleanup is done.

import (
	"context"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
)

// PodEvent is the public `event: pod` payload.
//
// Phase is the pod phase as kubectl would summarise it: Pending, ContainerCreating, Running,
// Succeeded, Failed, Terminating (deletion requested) or Deleted (gone from the API server).
// Reason is the container's waiting/terminated reason, or the pod's (DeadlineExceeded).
// LabelsDelta holds the labels that changed since the previous `pod` event of the run, a removed
// label as null; the first event of a run carries all of them.
type PodEvent struct {
	RunID       string             `json:"run_id"`
	Pod         string             `json:"pod"`
	UID         string             `json:"uid"`
	Phase       string             `json:"phase"`
	Reason      string             `json:"reason"`
	ContainerID string             `json:"container_id"`
	Image       string             `json:"image"`
	LabelsDelta map[string]*string `json:"labels_delta"`
	Deleted     bool               `json:"deleted"`
	At          time.Time          `json:"at"`
}

// podView is the published subset of a pod, for change detection.
type podView struct {
	uid, phase, reason, containerID, image string
	labels                                 map[string]string
	deleted                                bool
}

func viewOf(p *corev1.Pod, container string, deleted bool) podView {
	v := podView{uid: string(p.UID), labels: p.Labels, deleted: deleted}
	var cs *corev1.ContainerStatus
	for i := range p.Status.ContainerStatuses {
		if p.Status.ContainerStatuses[i].Name == container {
			cs = &p.Status.ContainerStatuses[i]
		}
	}
	v.phase = string(p.Status.Phase)
	if v.phase == "" {
		v.phase = string(corev1.PodPending)
	}
	v.reason = p.Status.Reason
	if cs != nil {
		switch {
		case cs.State.Waiting != nil:
			v.reason = cs.State.Waiting.Reason
		case cs.State.Terminated != nil:
			v.reason = cs.State.Terminated.Reason
		}
		v.containerID = shortContainerID(cs.ContainerID)
		v.image = imageRef(cs.ImageID, specImage(p, container))
	} else {
		v.image = imageRef("", specImage(p, container))
	}
	if v.phase == string(corev1.PodPending) && v.reason == "ContainerCreating" {
		v.phase = "ContainerCreating"
	}
	switch {
	case deleted:
		v.phase = "Deleted"
	case p.DeletionTimestamp != nil:
		v.phase = "Terminating"
	}
	return v
}

func specImage(p *corev1.Pod, container string) string {
	for _, c := range p.Spec.Containers {
		if c.Name == container {
			return c.Image
		}
	}
	return ""
}

// shortContainerID turns "containerd://<64 hex>" into the 12 characters crictl and Falco show.
func shortContainerID(id string) string {
	if i := strings.Index(id, "://"); i >= 0 {
		id = id[i+3:]
	}
	if len(id) > 12 {
		id = id[:12]
	}
	return id
}

// imageRef is the image as "repository@sha256:<digest>": the digest the kubelet actually ran
// (containerStatus.imageID) when it is known, else the digest the spec pins. A tag between the two
// is dropped - the digest is the identity, and it is what `cosign verify` takes.
func imageRef(imageID, spec string) string {
	imageID = strings.TrimPrefix(imageID, "docker-pullable://")
	repo, digest := splitDigest(spec)
	if r, d := splitDigest(imageID); d != "" {
		digest = d
		if r != "" {
			repo = r
		}
	} else if strings.HasPrefix(imageID, "sha256:") {
		digest = imageID
	}
	if repo == "" || digest == "" {
		return ""
	}
	return repo + "@" + digest
}

// splitDigest splits "repo[:tag]@sha256:..." into the repository without tag and the digest.
func splitDigest(ref string) (repo, digest string) {
	at := strings.Index(ref, "@")
	if at < 0 {
		repo = ref
	} else {
		repo, digest = ref[:at], ref[at+1:]
	}
	if c := strings.LastIndex(repo, ":"); c > strings.LastIndex(repo, "/") {
		repo = repo[:c]
	}
	return repo, digest
}

// labelsDelta is what changed from prev to cur: added or changed keys with their value, removed
// keys as nil. prev == nil means "first event": every label.
func labelsDelta(prev, cur map[string]string, first bool) map[string]*string {
	out := map[string]*string{}
	for k, v := range cur {
		if old, ok := prev[k]; first || !ok || old != v {
			out[k] = &v
		}
	}
	for k := range prev {
		if _, ok := cur[k]; !ok {
			out[k] = nil
		}
	}
	return out
}

// openPodWatch starts a watch on the run's pod only.
func (r *Runner) openPodWatch(ctx context.Context, name string) (watch.Interface, error) {
	return r.client.CoreV1().Pods(r.cfg.Namespace).Watch(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("metadata.name", name).String(),
	})
}

// watchPod publishes `pod` events until the pod is deleted or ctx ends. w is the watch opened before
// the pod was created; nil (it failed) or a closed watch is re-opened after a pause.
func (r *Runner) watchPod(ctx context.Context, rn *run, container string, w watch.Interface) {
	var (
		prev  podView
		first = true
	)
	publish := func(p *corev1.Pod, deleted bool) {
		v := viewOf(p, container, deleted)
		delta := labelsDelta(prev.labels, v.labels, first)
		if deleted {
			delta = map[string]*string{} // the last known labels, not a removal of all of them
			v.labels = prev.labels
		}
		if !first && len(delta) == 0 && v.uid == prev.uid && v.phase == prev.phase && v.reason == prev.reason &&
			v.containerID == prev.containerID && v.image == prev.image && v.deleted == prev.deleted {
			return
		}
		first, prev = false, v
		r.emit(rn, "pod", PodEvent{RunID: rn.id, Pod: rn.pod, UID: v.uid, Phase: v.phase, Reason: v.reason,
			ContainerID: v.containerID, Image: v.image, LabelsDelta: delta, Deleted: v.deleted, At: r.now().UTC()})
	}
	for {
		if w == nil {
			var err error
			if w, err = r.openPodWatch(ctx, rn.pod); err != nil {
				if ctx.Err() != nil {
					return
				}
				r.log.Warn("pod watch failed; retrying", "pod", rn.pod, "err", err)
				w = nil
				r.sleep(ctx, 2*time.Second)
				if ctx.Err() != nil {
					return
				}
				continue
			}
		}
		closed := false
		for !closed {
			select {
			case <-ctx.Done():
				w.Stop()
				return
			case ev, ok := <-w.ResultChan():
				if !ok || ev.Type == watch.Error {
					closed = true
					continue
				}
				p, isPod := ev.Object.(*corev1.Pod)
				if !isPod || p.Name != rn.pod {
					continue
				}
				switch ev.Type {
				case watch.Added, watch.Modified:
					if p.DeletionTimestamp != nil {
						rn.markGone()
					}
					publish(p, false)
				case watch.Deleted:
					rn.markGone()
					publish(p, true)
					rn.deletedOnce.Do(func() { close(rn.deleted) })
					w.Stop()
					return
				}
			}
		}
		w.Stop()
		w = nil
		r.sleep(ctx, 500*time.Millisecond)
		if ctx.Err() != nil {
			return
		}
	}
}
