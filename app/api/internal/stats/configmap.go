package stats

// ConfigMap persistence for the counters (ADR 0030). One ConfigMap, `portfolio-stats` in
// `portfolio-api`, committed empty in git with Argo CD ignoring its data; the API reads it at start
// and updates it at most once a minute and on shutdown. RBAC is a Role in `portfolio-api` with
// exactly `get` and `update` on that one object (owned by the cluster manifests), so losing the
// write path cannot touch anything else and a failed read never blocks start-up.

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// dataKey is the ConfigMap key the serialised counters live under.
const dataKey = "stats.json"

// Store reads and writes the counters ConfigMap. A nil client (tests, or no RBAC) makes Load and
// Save no-ops, so the API runs the same with the counters purely in memory.
//
// The object is written only after it has been read: a read that fails (the API server briefly
// unreachable, a timeout at start-up) is not "there are no counters", and writing the zeros counted
// since would overwrite the persisted totals. Until a read succeeds, Save refuses and Run retries the
// read on each tick; a missing object or an unparseable blob is a successful read with nothing to
// keep (the blob is then replaced).
type Store struct {
	client    kubernetes.Interface
	namespace string
	name      string
	log       *slog.Logger

	// mu serialises the read and write passes: Load, Save, each tick of Run and Flush.
	mu     sync.Mutex
	readOK bool // the object has been read (or found missing/unparseable); writing is allowed
}

// errNotRead is Save's answer before the counters have been read.
var errNotRead = errors.New("stats configmap: not written until it has been read")

// NewStore returns a ConfigMap store. client may be nil.
func NewStore(client kubernetes.Interface, namespace, name string, log *slog.Logger) *Store {
	if log == nil {
		log = slog.Default()
	}
	return &Store{client: client, namespace: namespace, name: name, log: log}
}

// Load reads the counters into c (adding them to anything c has counted so far). A missing or empty
// ConfigMap, or no client, starts fresh; an unparseable one is logged and starts fresh too; a read
// error is logged and leaves the store unread, so nothing is written until a later read succeeds
// (the counters are not load-bearing for the service, the persisted totals are).
func (s *Store) Load(ctx context.Context, c *Collector) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadLocked(ctx, c)
}

func (s *Store) loadLocked(ctx context.Context, c *Collector) {
	if s.client == nil {
		return
	}
	cm, err := s.client.CoreV1().ConfigMaps(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		s.readOK = true
		return
	case err != nil:
		s.log.Warn("stats configmap unreadable; counting from zero, not writing until it can be read", "err", err)
		return
	}
	s.readOK = true
	if err := c.Load([]byte(cm.Data[dataKey])); err != nil {
		s.log.Warn("stats configmap unparseable; starting counters from zero", "err", err)
	}
}

// Save writes c's counters, replacing the one data key and nothing else. It updates the existing
// object (the manifest ships it empty); a missing object is logged, not created, because creating
// it would need a wider grant than get/update. Before the object has been read it refuses.
func (s *Store) Save(ctx context.Context, c *Collector) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked(ctx, c)
}

func (s *Store) saveLocked(ctx context.Context, c *Collector) error {
	if s.client == nil {
		return nil
	}
	if !s.readOK {
		return errNotRead
	}
	data, err := c.Marshal()
	if err != nil {
		return err
	}
	// Retry on a conflict (someone else updated the object between our Get and Update): re-Get for a
	// fresh resourceVersion and write again. A few tries is plenty for a once-a-minute writer.
	for attempt := 0; attempt < 4; attempt++ {
		cm, err := s.client.CoreV1().ConfigMaps(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		cm.Data[dataKey] = string(data)
		if _, err = s.client.CoreV1().ConfigMaps(s.namespace).Update(ctx, cm, metav1.UpdateOptions{}); err == nil {
			return nil
		} else if !apierrors.IsConflict(err) {
			return err
		}
	}
	return errors.New("stats configmap: too many write conflicts")
}

// Run persists c every interval while ctx is live, re-queuing a failed write so it is retried on
// the next tick rather than lost. It does NOT write on ctx cancel: the final write is Flush, which
// main calls after the runner's shutdown has published the last events. Call Run in its own
// goroutine.
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
			return
		case <-t.C:
			s.tick(ctx, c)
		}
	}
}

// tick is one pass of Run: retry the read if it has not succeeded yet, then write if anything is
// pending, re-queuing a failed write.
func (s *Store) tick(ctx context.Context, c *Collector) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.readOK {
		s.loadLocked(ctx, c)
		if !s.readOK {
			return // still unread: keep counting, write nothing
		}
	}
	if c.TakeDirty() {
		if err := s.saveLocked(ctx, c); err != nil {
			s.log.Warn("stats configmap write failed; will retry", "err", err)
			c.markDirty() // do not drop the update
		}
	}
}

// Flush writes a final time, after shutdown has published the last events, if anything is pending.
// It uses its own bounded context (the session context is already cancelled by then). main calls it
// and waits, so the last run's counters reach the ConfigMap.
func (s *Store) Flush(c *Collector) {
	if s.client == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !s.readOK {
		s.loadLocked(ctx, c) // a last chance to read; unread, the totals stay as they are
	}
	if !s.readOK || !c.TakeDirty() {
		return
	}
	if err := s.saveLocked(ctx, c); err != nil {
		s.log.Warn("stats configmap final write failed", "err", err)
		c.markDirty()
	}
}
