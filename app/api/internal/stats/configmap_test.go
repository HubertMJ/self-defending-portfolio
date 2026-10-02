package stats

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestConfigMapSaveLoad(t *testing.T) {
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "portfolio-stats", Namespace: "portfolio-api"}}
	kube := fake.NewClientset(cm)
	store := NewStore(kube, "portfolio-api", "portfolio-stats", nil)

	c := New(newStore(t), nil)
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
