package labrun

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// dataKey is the ConfigMap key the serialised state lives under.
const dataKey = "state.json"

// ConfigMapStore keeps the state in one ConfigMap (`lab-run-state` in the API's namespace), which the
// manifests create empty; the API's Role may get and update that one object only (resourceNames),
// never create or delete it. The version is the object's resourceVersion, which the API server
// itself checks on update, so a write based on a stale read fails with a conflict there even when
// two replicas race.
type ConfigMapStore struct {
	client    kubernetes.Interface
	namespace string
	name      string
}

// NewConfigMapStore returns a store for the ConfigMap namespace/name.
func NewConfigMapStore(client kubernetes.Interface, namespace, name string) *ConfigMapStore {
	return &ConfigMapStore{client: client, namespace: namespace, name: name}
}

// Load reads the state and the object's resourceVersion.
func (c *ConfigMapStore) Load(ctx context.Context) ([]byte, string, error) {
	cm, err := c.client.CoreV1().ConfigMaps(c.namespace).Get(ctx, c.name, metav1.GetOptions{})
	if err != nil {
		return nil, "", err
	}
	return []byte(cm.Data[dataKey]), cm.ResourceVersion, nil
}

// Save writes data if the object is still at version. It re-reads the object so its metadata (the
// labels Argo CD tracks it by) is kept as it is, and sends the update with the version read by Load:
// the API server refuses it with a conflict if anything wrote in between.
func (c *ConfigMapStore) Save(ctx context.Context, data []byte, version string) error {
	cms := c.client.CoreV1().ConfigMaps(c.namespace)
	cm, err := cms.Get(ctx, c.name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if cm.ResourceVersion != version {
		return ErrConflict
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[dataKey] = string(data)
	if _, err := cms.Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		if apierrors.IsConflict(err) {
			return ErrConflict
		}
		return err
	}
	return nil
}
