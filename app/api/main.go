// portfolio-api: the backend of https://hubertjablon.ski/api (ADR 0015).
//
// It lists the attack scenarios, runs one at a time in the `sandbox` namespace on a visitor's
// request, streams what Falco detects and Falco Talon does about it as Server-Sent Events, and
// summarises the cluster's security posture from the reports the phase 4 tools already write.
//
// Configuration is environment variables only (no flags, no file besides the scenarios), all with
// the production values as defaults, so the Deployment states only what differs.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/hubertmj/self-defending-portfolio/app/api/internal/events"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/limits"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/posture"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/ruleindex"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/runlog"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/runner"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/scenarios"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/server"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/stats"
	"github.com/hubertmj/self-defending-portfolio/app/api/internal/webhook"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	attackCfg := limits.DefaultAttackConfig()
	var err error
	if attackCfg.PerKey, err = envInt("ATTACKS_PER_IP", attackCfg.PerKey); err != nil {
		return err
	}
	if attackCfg.PerKeyWindow, err = envDuration("ATTACKS_PER_IP_WINDOW", attackCfg.PerKeyWindow); err != nil {
		return err
	}
	if attackCfg.Global, err = envInt("ATTACKS_GLOBAL", attackCfg.Global); err != nil {
		return err
	}
	if attackCfg.GlobalWindow, err = envDuration("ATTACKS_GLOBAL_WINDOW", attackCfg.GlobalWindow); err != nil {
		return err
	}
	// Not configurable: the contract's single concurrent run is also what the sandbox quota is
	// sized for.
	attackCfg.Concurrent = 1

	restCfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("in-cluster config: %w", err)
	}
	// A small, steady client: one run polls one pod, the posture refresh lists a few kinds once a
	// minute. Low limits keep a bug from turning into API server load.
	restCfg.QPS, restCfg.Burst = 10, 20
	restCfg.UserAgent = "portfolio-api"
	kube, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return err
	}
	dyn, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return err
	}

	sandbox := env("SANDBOX_NAMESPACE", "sandbox")
	unguarded := env("UNGUARDED_NAMESPACE", "sandbox-unguarded")
	scenarioStore := scenarios.NewStore(env("SCENARIOS_FILE", "/etc/portfolio-api/scenarios/scenarios.yaml"), log)
	// The replay buffer covers the run in progress for a visitor who arrives mid-run: a run with its
	// pod and victim evidence publishes a few dozen events (ADR 0021). Complete runs are in the run
	// store, and the cross-visitor counters, both fed by the same tap so neither misses an event.
	hub := events.NewHub(100)
	runs := runlog.New(0, 0, 0, 0) // the defaults: 50 runs, 500 events and 256 KiB each, 8 MiB in all
	statsCollector := stats.New(scenarioStore, nil)
	hub.Tap(func(ev events.Event) {
		runs.Record(ev)
		statsCollector.Record(ev)
	})
	rules, err := ruleindex.Load()
	if err != nil {
		return fmt.Errorf("rule index: %w", err)
	}

	// The counters survive a restart through one ConfigMap in this namespace (ADR 0030). Read once
	// at start; a background loop writes it at most once a minute and once more on shutdown.
	statsStore := stats.NewStore(kube, env("POD_NAMESPACE", "portfolio-api"), env("STATS_CONFIGMAP", "portfolio-stats"), log)
	lctx, lcancel := context.WithTimeout(ctx, 10*time.Second)
	statsStore.Load(lctx, statsCollector)
	lcancel()
	go statsStore.Run(ctx, statsCollector, time.Minute)

	falcoAlerts := webhook.NewDayWindow(nil)
	talonActions := webhook.NewDayWindow(nil)
	run := runner.New(kube, &runner.KubeExecer{Config: restCfg, Client: kube}, hub, log,
		runner.Config{Namespace: sandbox, UnguardedNamespace: unguarded})

	octx, ocancel := context.WithTimeout(ctx, 30*time.Second)
	if err := run.CleanupOrphans(octx); err != nil {
		log.Warn("orphan cleanup failed", "err", err)
	}
	ocancel()

	srv := server.New(server.Config{
		Scenarios: scenarioStore,
		Runner:    run,
		Hub:       hub,
		Posture: posture.New(posture.Config{
			Dynamic: dyn, Kube: kube, KubeBenchNS: env("KUBE_BENCH_NAMESPACE", "kube-bench"),
			FalcoAlerts: falcoAlerts, TalonActions: talonActions, Log: log,
		}),
		Attacks:            limits.NewAttacks(attackCfg, nil),
		Requests:           limits.NewRequests(120, time.Minute, 50000, nil),
		Streams:            limits.NewConns(4, 200),
		FalcoAlerts:        falcoAlerts,
		TalonActions:       talonActions,
		Log:                log,
		AllowedOrigin:      env("ALLOWED_ORIGIN", "https://hubertjablon.ski"),
		Namespace:          sandbox,
		UnguardedNamespace: unguarded,
		Runs:               runs,
		Rules:              rules,
		Stats:              statsCollector,
		// Set by the Dockerfile from the build's --build-arg GIT_SHA (build-images.yml passes
		// github.sha), so the rule links point at the exact source of this image.
		Commit: os.Getenv("GIT_SHA"),
	})

	errc := make(chan error, 2)
	go func() {
		errc <- server.ListenAndServe(ctx, env("LISTEN_ADDR", ":8080"), srv.Public(), log)
	}()
	go func() {
		errc <- server.ListenAndServe(ctx, env("INTERNAL_LISTEN_ADDR", ":8081"), srv.Internal(), log)
	}()
	log.Info("listening", "public", env("LISTEN_ADDR", ":8080"), "internal", env("INTERNAL_LISTEN_ADDR", ":8081"),
		"sandbox", sandbox, "attacks_per_ip", attackCfg.PerKey, "attacks_global", attackCfg.Global, "commit", os.Getenv("GIT_SHA"))

	var first error
	select {
	case first = <-errc:
		stop()
	case <-ctx.Done():
	}
	// Runs in flight get their pods deleted before the process exits (terminationGracePeriodSeconds
	// leaves room for it).
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := run.Shutdown(sctx); err != nil {
		log.Warn("runs still cleaning up at exit", "err", err)
	}
	if first != nil && !errors.Is(first, http.ErrServerClosed) {
		return first
	}
	return nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%s=%q: want a positive integer", key, v)
	}
	return n, nil
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s=%q: want a positive duration", key, v)
	}
	return d, nil
}
