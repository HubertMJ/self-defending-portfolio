package stats

// ConfigMap persistence for the counters (ADR 0030). One ConfigMap, `portfolio-stats` in
// `portfolio-api`, committed empty in git with Argo CD ignoring its data; the API reads it at start
// and updates it at most once a minute and on shutdown. RBAC is a Role in `portfolio-api` with
// exactly `get` and `update` on that one object (owned by the cluster manifests), so losing the
// write path cannot touch anything else and a failed read never blocks start-up.

import (
	"context"
	"log/slog"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// dataKey is the ConfigMap key the serialised counters live under.
const dataKey = "stats.json"

// Store reads and writes the counters ConfigMap. A nil client (tests, or no RBAC) makes Load and
// Save no-ops, so the API runs the same with the counters purely in memory.
type Store struct {
	client    kubernetes.Interface
	namespace string
	name      string
	log       *slog.Logger
}

// NewStore returns a ConfigMap store. client may be nil.
func NewStore(client kubernetes.Interface, namespace, name string, log *slog.Logger) *Store {
	if log == nil {
		log = slog.Default()
	}
	return &Store{client: client, namespace: namespace, name: name, log: log}
}

// Load reads the counters into c. A missing or empty ConfigMap, or no client, starts fresh; a read
// error is logged and swallowed (the counters are not load-bearing for the service).
func (s *Store) Load(ctx context.Context, c *Collector) {
	if s.client == nil {
		return
	}
	cm, err := s.client.CoreV1().ConfigMaps(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			s.log.Warn("stats configmap unreadable; starting counters from zero", "err", err)
		}
		return
	}
	if err := c.Load([]byte(cm.Data[dataKey])); err != nil {
		s.log.Warn("stats configmap unparseable; starting counters from zero", "err", err)
	}
}

// Save writes c's counters, replacing the one data key and nothing else. It updates the existing
// object (the manifest ships it empty); a missing object is logged, not created, because creating
// it would need a wider grant than get/update.
func (s *Store) Save(ctx context.Context, c *Collector) error {
	if s.client == nil {
		return nil
	}
	data, err := c.Marshal()
	if err != nil {
		return err
	}
	cm, err := s.client.CoreV1().ConfigMaps(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[dataKey] = string(data)
	_, err = s.client.CoreV1().ConfigMaps(s.namespace).Update(ctx, cm, metav1.UpdateOptions{})
	return err
}

// Run persists c every interval while ctx is live, but only when the counters changed, and once
// more on exit. Call it in its own goroutine.
func (s *Store) Run(ctx context.Context, c *Collector, interval time.Duration) {
	if s.client == nil {
		<-ctx.Done()
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.flush(c)
			return
		case <-t.C:
			if c.TakeDirty() {
				s.saveLogged(ctx, c)
			}
		}
	}
}

// flush writes a final time on shutdown, with its own short timeout (ctx is already cancelled).
func (s *Store) flush(c *Collector) {
	if !c.TakeDirty() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.saveLogged(ctx, c)
}

func (s *Store) saveLogged(ctx context.Context, c *Collector) {
	if err := s.Save(ctx, c); err != nil {
		s.log.Warn("stats configmap write failed", "err", err)
	}
}
