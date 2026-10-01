// Package server is the API's HTTP surface (ADR 0015): the public handler behind the Gateway's
// /api route on :8080, and the internal webhook handler on :8081, which only Falcosidekick and
// Falco Talon can reach.
//
// Two listeners rather than one mux with a path check: the network policy can then say "the
// Gateway may reach 8080, falco-response may reach 8081" and nothing else, so a forged alert
// cannot come in through the public route even if a routing rule were ever widened by mistake, and
// a visitor cannot reach /internal/* at all - the Gateway has no route to that port.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/clientip"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/events"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/limits"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/posture"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/ruleindex"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/runlog"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/runner"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/scenarios"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/webhook"
)

// Runner is what the server needs from internal/runner.
type Runner interface {
	Start(sc scenarios.Scenario, release func()) string
	ObserveFalco(pod string)
	ObserveTalon(pod, status string)
}

// Poster is what the server needs from internal/posture.
type Poster interface {
	Get(ctx context.Context) posture.Snapshot
}

// Counter is a 24 h counter the webhooks feed.
type Counter interface{ Add() }

// Config wires the server. Zero durations take the defaults.
type Config struct {
	Scenarios    *scenarios.Store
	Runner       Runner
	Hub          *events.Hub
	Posture      Poster
	Attacks      *limits.Attacks
	Requests     *limits.Requests
	Streams      *limits.Conns
	FalcoAlerts  Counter
	TalonActions Counter
	Log          *slog.Logger
	Now          func() time.Time
	// Runs is the store behind GET /api/runs/{id}; Rules the embedded rule index and Commit the
	// commit the image was built from, both for GET /api/scenarios/{id}/details.
	Runs   *runlog.Store
	Rules  *ruleindex.Index
	Commit string

	// AllowedOrigin is the only Origin a browser may POST from (the site itself).
	AllowedOrigin string
	// Namespace is the only namespace whose Falco and Talon events are published (and correlated).
	Namespace string

	Heartbeat         time.Duration // SSE comment interval (contract: 15 s)
	StreamMaxLifetime time.Duration // an SSE connection is closed after this; EventSource reconnects
	WriteTimeout      time.Duration // per SSE write
}

// Server holds both handlers.
type Server struct {
	cfg Config
}

// New fills defaults and returns the server.
func New(cfg Config) *Server {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "sandbox"
	}
	if cfg.Heartbeat <= 0 {
		cfg.Heartbeat = 15 * time.Second
	}
	if cfg.StreamMaxLifetime <= 0 {
		cfg.StreamMaxLifetime = 30 * time.Minute
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 10 * time.Second
	}
	if !commitPattern.MatchString(cfg.Commit) {
		cfg.Commit = ""
	}
	return &Server{cfg: cfg}
}

// Public is the handler for :8080. Every path is under /api, matching the HTTPRoute.
func (s *Server) Public() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/healthz", s.healthz)
	mux.HandleFunc("GET /api/scenarios", s.listScenarios)
	mux.HandleFunc("POST /api/attack/{id}", s.attack)
	mux.HandleFunc("GET /api/events", s.events)
	mux.HandleFunc("GET /api/posture", s.posture)
	mux.HandleFunc("GET /api/scenarios/{id}/details", s.details)
	mux.HandleFunc("GET /api/runs/{id}", s.run)
	mux.HandleFunc("GET /api/limits", s.limits)
	// The same paths without a method: a wrong method gets a JSON 405 instead of net/http's plain
	// text one, so every /api answer is JSON (the page parses errors too).
	for _, p := range []string{"/api/healthz", "/api/scenarios", "/api/attack/{id}", "/api/events", "/api/posture",
		"/api/scenarios/{id}/details", "/api/runs/{id}", "/api/limits"} {
		mux.HandleFunc(p, methodNotAllowed)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})
	return s.publicMiddleware(mux)
}

// Internal is the handler for :8081.
func (s *Server) Internal() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/falco", s.falco)
	mux.HandleFunc("POST /internal/talon", s.talon)
	mux.HandleFunc("GET /internal/healthz", s.healthz)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})
	return mux
}

// publicMiddleware applies what every public response needs: no caching, no MIME sniffing, the
// per-visitor request budget, and the same-origin rule for state-changing requests.
//
// CORS is "same origin only" by omission: no Access-Control-Allow-* header is ever sent, so a
// browser refuses cross-origin reads, and a preflight (OPTIONS) gets 405 from the mux. Simple
// cross-origin POSTs need no preflight, though, so a POST carrying a foreign Origin, or a
// Sec-Fetch-Site of cross-site / same-site, is refused outright: otherwise any page on the internet
// could make its visitors' browsers spend their attack quota. Requests with neither header are
// not browsers (curl, the abuse test) and are judged by the limits alone.
func (s *Server) publicMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")

		if r.URL.Path != "/api/healthz" && s.cfg.Requests != nil {
			if ok, retry := s.cfg.Requests.Allow(clientip.Key(r)); !ok {
				tooMany(w, retry, "too many requests")
				return
			}
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if o := r.Header.Get("Origin"); o != "" && o != s.cfg.AllowedOrigin {
				writeError(w, http.StatusForbidden, "cross-origin request refused")
				return
			}
			switch r.Header.Get("Sec-Fetch-Site") {
			case "", "same-origin", "none":
			default:
				writeError(w, http.StatusForbidden, "cross-site request refused")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func methodNotAllowed(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) listScenarios(w http.ResponseWriter, _ *http.Request) {
	list := s.cfg.Scenarios.List()
	out := make([]scenarios.Public, 0, len(list))
	for _, sc := range list {
		out = append(out, sc.Public())
	}
	writeJSON(w, http.StatusOK, out)
}

type attackResponse struct {
	RunID    string `json:"run_id"`
	Scenario string `json:"scenario"`
	State    string `json:"state"`
}

// attack: 404 unknown id, 429 over the visitor's or the global budget, 409 a run is in progress,
// 202 accepted. The body is ignored (the contract says empty) but bounded.
func (s *Server) attack(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > 1024 {
		writeError(w, http.StatusRequestEntityTooLarge, "the request body must be empty")
		return
	}
	_, _ = io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, 1024))

	sc, ok := s.cfg.Scenarios.Get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "unknown scenario")
		return
	}
	d, release := s.cfg.Attacks.Acquire(clientip.Key(r))
	switch d.Outcome {
	case limits.RateLimited:
		tooMany(w, d.RetryAfter, "attack rate limit reached")
		return
	case limits.Busy:
		writeError(w, http.StatusConflict, "another attack is running; watch it on the live feed")
		return
	}
	id := s.cfg.Runner.Start(sc, release)
	s.cfg.Log.Info("attack accepted", "run_id", id, "scenario", sc.ID)
	writeJSON(w, http.StatusAccepted, attackResponse{RunID: id, Scenario: sc.ID, State: runner.StateQueued})
}

func (s *Server) posture(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.cfg.Posture.Get(r.Context()))
}

// maxWebhookBody: a Falco alert with every output field is a few KiB.
const maxWebhookBody = 256 << 10

func (s *Server) falco(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBody))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "body too large")
		return
	}
	ev, err := webhook.ParseFalco(body, s.cfg.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, "not a Falco alert")
		return
	}
	if s.cfg.FalcoAlerts != nil {
		s.cfg.FalcoAlerts.Add()
	}
	// Falcosidekick forwards every alert in the cluster at notice or above; only the sandbox is
	// the visitors' business. Alerts elsewhere still count towards alerts_24h.
	if ev.Namespace == s.cfg.Namespace {
		if err := s.cfg.Hub.Publish("falco", ev); err != nil {
			s.cfg.Log.Error("publish falco", "err", err)
		}
		s.cfg.Runner.ObserveFalco(ev.Pod)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) talon(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBody))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "body too large")
		return
	}
	ev, err := webhook.ParseTalon(body, s.cfg.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, "not a Talon notification")
		return
	}
	if s.cfg.TalonActions != nil {
		s.cfg.TalonActions.Add()
	}
	if ev.Namespace == s.cfg.Namespace {
		if err := s.cfg.Hub.Publish("talon", ev); err != nil {
			s.cfg.Log.Error("publish talon", "err", err)
		}
		s.cfg.Runner.ObserveTalon(ev.Pod, ev.Status)
	}
	w.WriteHeader(http.StatusNoContent)
}

// events is the SSE stream: `retry`, the replay, then live events and a heartbeat comment every
// 15 s (which also keeps Cloudflare's and Envoy's idle timers from closing a quiet stream). The
// connection is closed after StreamMaxLifetime; EventSource reconnects with Last-Event-ID and
// loses nothing that is still in the replay buffer.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	key := clientip.Key(r)
	ok, release := s.cfg.Streams.Acquire(key)
	if !ok {
		tooMany(w, 30*time.Second, "too many open event streams")
		return
	}
	defer release()

	var after uint64
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		after, _ = strconv.ParseUint(v, 10, 64)
	}
	sub, replay := s.cfg.Hub.Subscribe(after)
	defer s.cfg.Hub.Unsubscribe(sub)

	h := w.Header()
	// Exactly the SSE media type, without a charset parameter (an event stream is UTF-8 by
	// definition): proxies that pass event streams through unbuffered match on this string, and a
	// parameter is one more way for an exact comparison to miss.
	h.Set("Content-Type", "text/event-stream")
	// no-transform: no hop may compress or otherwise rewrite the stream. A compressing proxy (the
	// Cloudflare edge compresses text/* for browsers that send Accept-Encoding) holds bytes until its
	// compression block fills, which for a stream that sends a few hundred bytes per run means the
	// timeline stays empty. Cloudflare does not compress a response marked no-transform.
	h.Set("Cache-Control", "no-store, no-transform")
	// Tells nginx-style buffering proxies to pass events through.
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	rc := http.NewResponseController(w)
	write := func(chunk string) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout))
		if _, err := io.WriteString(w, chunk); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !write(streamPreamble) {
		return
	}
	for _, ev := range replay {
		if !write(frame(ev)) {
			return
		}
	}

	heartbeat := time.NewTicker(s.cfg.Heartbeat)
	defer heartbeat.Stop()
	lifetime := time.NewTimer(s.cfg.StreamMaxLifetime)
	defer lifetime.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-lifetime.C:
			return
		case <-heartbeat.C:
			if !write(": heartbeat\n\n") {
				return
			}
		case ev, open := <-sub.C:
			if !open { // dropped as a slow subscriber
				return
			}
			if !write(frame(ev)) {
				return
			}
		}
	}
}

// streamPreamble opens every stream: the reconnect delay, then a 2 KiB comment. Proxies that buffer
// the first bytes of a response before deciding to stream it (or until a block is full) have
// something to fill that buffer with, so the replay and the first live event are not held back
// behind it. EventSource ignores comments.
var streamPreamble = "retry: 5000\n\n:" + strings.Repeat(" ", 2048) + "\n\n"

func frame(ev events.Event) string {
	return fmt.Sprintf("id: %d\nevent: %s\ndata: %s\n\n", ev.ID, ev.Type, ev.Data)
}

func tooMany(w http.ResponseWriter, retry time.Duration, msg string) {
	secs := int(math.Ceil(retry.Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeError(w, http.StatusTooManyRequests, msg)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// ListenAndServe runs h on addr until ctx is cancelled, then shuts it down gracefully.
// Read timeouts protect against slow-header clients; there is no server-wide write timeout
// because the event stream is long-lived - it sets a deadline per write instead.
func ListenAndServe(ctx context.Context, addr string, h http.Handler, log *slog.Logger) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		// Cancelled on shutdown, so open event streams end instead of holding Shutdown for 10 s.
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return nil
}
