package stats

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestConfigMapSaveLoad(t *testing.T) {
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "portfolio-stats", Namespace: "portfolio-api"}}
	kube := fake.NewClientset(cm)
	store := NewStore(kube, "portfolio-api", "portfolio-stats", nil)

	c := New(newStore(t), nil)
	store.Load(context.Background(), c) // the object is read (empty) before it may be written
	c.Record(ev("run", map[string]any{"run_id": "r", "scenario": "shell-in-container", "state": "queued"}))
	if err := store.Save(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	got, err := kube.CoreV1().ConfigMaps("portfolio-api").Get(context.Background(), "portfolio-stats", metav1.GetOptions{})
	if err != nil || got.Data[dataKey] == "" {
		t.Fatalf("configmap not written: %v %q", err, got.Data[dataKey])
	}

	c2 := New(newStore(t), nil)
	store.Load(context.Background(), c2)
	if c2.Snapshot().Runs != 1 {
		t.Fatalf("not restored: %+v", c2.Snapshot())
	}
}

func TestConfigMapMissingIsSoft(t *testing.T) {
	kube := fake.NewClientset() // no object
	store := NewStore(kube, "portfolio-api", "portfolio-stats", nil)
	c := New(newStore(t), nil)
	store.Load(context.Background(), c) // must not panic or fail
	if err := store.Save(context.Background(), c); err == nil {
		t.Fatal("Save to a missing ConfigMap should error (we never create it)")
	}
}

func TestNilClientNoop(t *testing.T) {
	store := NewStore(nil, "ns", "name", nil)
	c := New(newStore(t), nil)
	store.Load(context.Background(), c)
	if err := store.Save(context.Background(), c); err != nil {
		t.Fatalf("nil client Save: %v", err)
	}
}

// statsObject is the counters ConfigMap holding a blob with the given number of runs.
func statsObject(t *testing.T, runs int) *corev1.ConfigMap {
	t.Helper()
	b, err := json.Marshal(map[string]any{"Since": time.Unix(1000, 0).UTC(), "Runs": runs,
		"ByScenario": map[string]any{"shell-in-container": map[string]int{"Runs": runs}}})
	if err != nil {
		t.Fatal(err)
	}
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "portfolio-stats", Namespace: "portfolio-api"},
		Data: map[string]string{dataKey: string(b)}}
}

// storedRuns is the runs counter currently in the ConfigMap, read from the fake's object store
// directly (past any reactor a test installed on get).
func storedRuns(t *testing.T, kube *fake.Clientset) int {
	t.Helper()
	obj, err := kube.Tracker().Get(corev1.SchemeGroupVersion.WithResource("configmaps"), "portfolio-api", "portfolio-stats")
	if err != nil {
		t.Fatal(err)
	}
	cm := obj.(*corev1.ConfigMap)
	var a agg
	if err := json.Unmarshal([]byte(cm.Data[dataKey]), &a); err != nil {
		t.Fatal(err)
	}
	return a.Runs
}

func queued(c *Collector, id string) {
	c.Record(ev("run", map[string]any{"run_id": id, "scenario": "shell-in-container", "state": "queued"}))
}

// A read that fails at start is not "no counters": nothing is written until a read succeeds, and
// the runs counted in the meantime are added to the persisted totals then. Before, the failed read
// started from zero and the next write replaced 5 persisted runs with 1.
func TestConfigMapFailedReadDoesNotWipe(t *testing.T) {
	kube := fake.NewClientset(statsObject(t, 5))
	var failGet atomic.Bool
	failGet.Store(true)
	kube.PrependReactor("get", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		if failGet.Load() {
			return true, nil, apierrors.NewInternalError(errors.New("etcd leader changed"))
		}
		return false, nil, nil
	})
	store := NewStore(kube, "portfolio-api", "portfolio-stats", nil)
	c := New(newStore(t), nil)
	store.Load(context.Background(), c)
	queued(c, "a")
	if err := store.Save(context.Background(), c); err == nil {
		t.Fatal("Save wrote before the counters were ever read")
	}
	store.tick(context.Background(), c) // the read still fails: still nothing written
	if got := storedRuns(t, kube); got != 5 {
		t.Fatalf("persisted runs = %d after a failed read, want 5 untouched", got)
	}
	failGet.Store(false)
	store.tick(context.Background(), c) // the read succeeds: merged, then written
	if got := storedRuns(t, kube); got != 6 {
		t.Fatalf("persisted runs = %d, want 5 persisted + 1 counted meanwhile", got)
	}
	if s := c.Snapshot(); s.Runs != 6 || s.ByScenario["shell-in-container"].Runs != 6 || !s.Since.Equal(time.Unix(1000, 0).UTC()) {
		t.Fatalf("merged snapshot = %+v", s)
	}
}

// An update that conflicts (someone wrote between our read and our write) is retried with a fresh
// read and lands.
func TestConfigMapConflictRetry(t *testing.T) {
	kube := fake.NewClientset(statsObject(t, 0))
	var updates atomic.Int32
	kube.PrependReactor("update", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		if updates.Add(1) == 1 {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, "portfolio-stats", errors.New("stale"))
		}
		return false, nil, nil
	})
	store := NewStore(kube, "portfolio-api", "portfolio-stats", nil)
	c := New(newStore(t), nil)
	store.Load(context.Background(), c)
	queued(c, "a")
	if err := store.Save(context.Background(), c); err != nil {
		t.Fatalf("Save after a conflict: %v", err)
	}
	if updates.Load() != 2 || storedRuns(t, kube) != 1 {
		t.Fatalf("updates = %d, stored runs = %d; want a retried write of 1 run", updates.Load(), storedRuns(t, kube))
	}
}

// A write that fails on a tick puts the dirty flag back, so the next tick retries it.
func TestConfigMapFailedWriteStaysDirty(t *testing.T) {
	kube := fake.NewClientset(statsObject(t, 0))
	kube.PrependReactor("update", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewServiceUnavailable("down")
	})
	store := NewStore(kube, "portfolio-api", "portfolio-stats", nil)
	c := New(newStore(t), nil)
	store.Load(context.Background(), c)
	queued(c, "a")
	store.tick(context.Background(), c)
	if !c.TakeDirty() {
		t.Fatal("a failed write dropped the pending update")
	}
}

// Flush writes what is pending at shutdown, and does not write when nothing is.
func TestConfigMapFlush(t *testing.T) {
	kube := fake.NewClientset(statsObject(t, 3))
	var updates atomic.Int32
	kube.PrependReactor("update", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		updates.Add(1)
		return false, nil, nil
	})
	store := NewStore(kube, "portfolio-api", "portfolio-stats", nil)
	c := New(newStore(t), nil)
	store.Load(context.Background(), c)
	store.Flush(c)
	if updates.Load() != 0 {
		t.Fatal("Flush wrote with nothing pending")
	}
	queued(c, "a")
	store.Flush(c)
	if updates.Load() != 1 || storedRuns(t, kube) != 4 {
		t.Fatalf("Flush: updates = %d, stored runs = %d, want one write of 4", updates.Load(), storedRuns(t, kube))
	}
}

// Shutdown: Run's last tick may be writing when Flush starts, and fail (its context is cancelled) after
// Flush has looked at the dirty flag. Flush waits for that write and then writes itself, so the
// counters reach the ConfigMap. Before, Flush saw the flag already taken, returned, and the failed
// tick put it back with nobody left to write.
func TestConfigMapFlushWaitsForRunningWrite(t *testing.T) {
	kube := fake.NewClientset(statsObject(t, 0))
	entered, unblock := make(chan struct{}), make(chan struct{})
	var once sync.Once
	kube.PrependReactor("update", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		first := false
		once.Do(func() { first = true })
		if first {
			close(entered)
			<-unblock
			return true, nil, context.Canceled // Run's write, cut by the shutdown
		}
		return false, nil, nil
	})
	store := NewStore(kube, "portfolio-api", "portfolio-stats", nil)
	c := New(newStore(t), nil)
	store.Load(context.Background(), c)
	queued(c, "a")
	tickDone := make(chan struct{})
	go func() { defer close(tickDone); store.tick(context.Background(), c) }()
	<-entered
	flushed := make(chan struct{})
	go func() { defer close(flushed); store.Flush(c) }()
	time.Sleep(50 * time.Millisecond) // Flush is now waiting on (or, unguarded, past) the running write
	close(unblock)
	<-tickDone
	<-flushed
	if got := storedRuns(t, kube); got != 1 {
		t.Fatalf("after Flush the ConfigMap holds %d runs, want 1", got)
	}
}
