// Entry point. The static HTML is the whole portfolio and renders without this script; this module
// adds the live panels on top, each of which degrades to its own offline state independently.

import { ApiClient } from "./lib/api";
import { Backfill } from "./lib/backfill";
import { byId, h, prefersReducedMotion, replace } from "./lib/dom";
import { installMock } from "./lib/mock-hook";
import { isRunId } from "./lib/contract";
import { type ConnectionState, type EventSourceFactory, EventStream } from "./lib/sse";
import type { TimelineView } from "./lib/timeline";
import { CONNECTION_WORD } from "./ui/common";
import { mountConsole } from "./ui/console";
import { mountCorrelation } from "./ui/correlation";
import { mountDefenceMap } from "./ui/defencemap";
import { mountEvidence } from "./ui/evidence";
import { mountPosture } from "./ui/posture";
import { mountRunStatus } from "./ui/runstatus";
import { SIEM_COMMAND, runEndsWithin } from "./lib/runstatus";
import { mountScenarios } from "./ui/scenarios";
import { mountScope } from "./ui/scope";
import { type Focus, OWN_RUNS_MAX, loadOwnRuns, saveOwnRuns } from "./lib/scope";
import { mountSections, sectionTitle } from "./ui/sections";
import { mountStats } from "./ui/stats";
import { mountTerminal } from "./ui/terminal";
import { mountLimits, setupTechMode } from "./ui/tech";
import { mountTimeline } from "./ui/timeline";
import { mountVerify, pollProvenance } from "./ui/verify";
import { blockedReason } from "./ui/scenarios";

const HIDDEN_DISCONNECT_MS = 60_000;

function setupThemeToggle(): void {
  const btn = document.getElementById("theme-toggle");
  if (!btn) return;
  const root = document.documentElement;
  const effective = () =>
    root.dataset.theme ?? (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  const label = () => {
    const next = effective() === "dark" ? "light" : "dark";
    btn.setAttribute("aria-label", `Switch to ${next} theme`);
    btn.dataset.current = effective();
  };
  btn.hidden = false;
  label();
  btn.addEventListener("click", () => {
    const next = effective() === "dark" ? "light" : "dark";
    root.dataset.theme = next;
    try {
      localStorage.setItem("theme", next);
    } catch {
      // Not persisted; the choice still holds for this page view.
    }
    label();
  });
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", label);
}

/**
 * An API without the terminal (today's live one answers its catalogue with a JSON 404): the one-click
 * scenarios become the attack section, and nothing on the page offers a terminal that is not there.
 */
function degradeToOneClick(): void {
  document.documentElement.dataset.terminal = "off";
  replace(byId("hero-cta"), "Launch an attack");
  replace(sectionTitle(byId("attack-title")), "Launch a real attack");
  replace(
    byId("attack-lead"),
    "Each attack starts a throwaway pod in an isolated ",
    h("code", {}, "sandbox"),
    " namespace (no service-account token, default-deny network, tight quotas, read-only root filesystem) with a little shop running inside it, runs one fixed attack, and plays the detection and the response out below as they happen. One run at a time, a few per visitor.",
  );
}

function main(): void {
  document.documentElement.classList.add("js");
  if (prefersReducedMotion()) document.documentElement.classList.add("reduced-motion");
  setupThemeToggle();

  // Always null in the production bundle: the mock is not in it (lib/mock-hook.ts, ADR 0035).
  const mock = installMock(location.search);
  const api = new ApiClient(mock ? { fetch: mock.fetch } : {});
  const factory: EventSourceFactory | undefined = mock ? mock.eventSource : undefined;

  // Evidence by default (ADR 0035): the newest run in the hero, the ticker and liveness in #evidence.
  // Once the replay is in (the first tick, or 3 s after the stream opened), a page whose feed holds no
  // run loads the newest the run store keeps, so the card shows the last real attack.
  const evidence = mountEvidence(
    byId("evidence-card"),
    { ticker: byId("ticker"), liveness: byId("liveness"), detail: byId("evidence-detail"), announce: byId("ticker-live") },
    () => {
      if (latestView.runs.length) return;
      evidence.setLoading(true);
      void api.runs().then((r) => {
        const newest = r.ok ? r.value[0] : undefined;
        if (newest) {
          verify.set({ latestRunId: newest.run_id });
          // Named from its summary until its events arrive as ordinary timeline events.
          evidence.setLatest(newest);
          backfill.load(newest.run_id);
        } else evidence.setLoading(false);
      });
    },
  );
  let latestView: TimelineView = { runs: [], unmatched: [] };

  // This session first (ADR 0035, amendment 2026-10-06 "this session first"): the lists show the
  // visitor's own runs and a run in progress now; everything else is behind "All activity, last 24 h".
  // The visitor's runs are this tab's, kept in sessionStorage so a reload still knows them.
  const tabStore = (() => {
    try {
      return sessionStorage;
    } catch {
      return undefined;
    }
  })();
  const ownIds = loadOwnRuns(tabStore);
  const earlierOwn = [...ownIds];
  // Another visitor's run in progress now: its incidents count in this session too, labelled.
  let liveRun: string | undefined;
  let focusReady = false;
  const focusNow = (): Focus => ({ all: scope.scope === "all", own: new Set(ownIds) });
  const applyFocus = () => {
    if (!focusReady) return;
    const f = focusNow();
    timeline.setFocus(f);
    runConsole.setFocus(f);
    evidence.setFocus(f);
    correlation.setFocus({ ...f, live: liveRun });
  };
  const addOwn = (ids: readonly string[]) => {
    const fresh = ids.filter((id) => isRunId(id) && !ownIds.includes(id));
    if (!fresh.length) return;
    ownIds.push(...fresh);
    // The run is the visitor's now, not someone else's live one.
    if (liveRun !== undefined && fresh.includes(liveRun)) liveRun = undefined;
    ownIds.splice(0, Math.max(0, ownIds.length - OWN_RUNS_MAX));
    saveOwnRuns(ownIds, tabStore);
    applyFocus();
  };
  const scope = mountScope(() => applyFocus());

  const verify = mountVerify(byId("verify-panel"));
  const posture = mountPosture(byId("posture-panel"), api, (p) => evidence.setPosture(p));
  // The visitor's own run told back (ADR 0035 amendment, UX stage 1): the status strip under the
  // terminal and its toast, joined with the SIEM's incidents for that run. Wired to the terminal and
  // the correlation below, once they exist.
  const runStatus = mountRunStatus({
    toastParent: document.body,
    onTimeline: () => terminal.showTimeline(),
    onAgain: () => terminal.restart(),
    onOpen: (id) => correlation.pulse(id),
    onReading: (r) => {
      correlation.setVisitor(r);
      terminal.setSiem(r.siem);
      quietRuns = r.ownRuns;
      applyQuiet();
      addOwn(r.ownRuns);
    },
    onDismissFocus: () => terminal.focus(),
    earlier: earlierOwn,
  });
  // The other announcers keep quiet about the visitor's own runs, and about any terminal run while the
  // visitor's own start is in flight: its first events can arrive before the POST returns its id.
  let quietRuns: readonly string[] = [];
  let startingTerminal = false;
  const applyQuiet = () => {
    timeline.setQuiet(quietRuns, startingTerminal);
    evidence.setQuiet(quietRuns, startingTerminal);
  };
  // The SIEM's section (ADR 0036): shown only while GET /api/correlation says available.
  const siemNav = document.querySelector<HTMLElement>(".site-nav__siem");
  const correlation = mountCorrelation(
    byId("correlation"),
    { scenario: byId("correlation-scenario"), health: byId("correlation-health"), metrics: byId("correlation-metrics"), board: byId("correlation-board"), rules: byId("correlation-rules") },
    api,
    (available) => {
      verify.set({ correlation: available });
      // The nav names the section only while it is there.
      if (siemNav) siemNav.hidden = !available;
    },
    {
      onData: (c) => runStatus.setCorrelation(c !== null, c?.incidents ?? []),
      onScenario: () => terminal.suggest(SIEM_COMMAND),
      ...(mock?.eagerPollMs !== undefined ? { eagerMs: mock.eagerPollMs } : {}),
    },
  );
  pollProvenance(() => api.provenance(), {
    data: (p) => {
      verify.set({ provenance: p });
      posture.setCommit(p.api.commit);
      correlation.setCommit(p.api.commit);
      if (p.api.started_at) evidence.setApiStart(p.api.started_at);
    },
    unavailable: () => verify.set({ provenance: null }),
  });
  void api.buildInfo().then((r) => verify.set({ build: r.ok ? r.value : null }));

  const stats = mountStats(
    byId("hero-stats"),
    api,
    (s) => {
      if (s.last_run_at) evidence.setLastRunAt(s.last_run_at);
    },
    mock?.statsLabel,
  );
  const defenceMap = mountDefenceMap(byId("defence-map"), api);

  const limits = mountLimits(byId("limits-panel"), api);
  setupTechMode(byId("tech-toggle"), (on) => limits.setEnabled(on));

  // Each scenario's limits, as its details load: they bound how long the timeline believes a run without
  // an end event (lib/timeline.ts staleRunMs), and tell when a busy slot frees up.
  const limitsOf = new Map<string, { timeout?: number; idle?: number }>();
  const runConsole = mountConsole(byId("console"), api, (scenario, d) => {
    if (d.timeout_seconds !== undefined) timeline.setScenarioTimeout(scenario, d.timeout_seconds);
    limitsOf.set(scenario, { timeout: d.timeout_seconds, idle: d.idle_seconds });
    evidence.setDetails(scenario, d);
  });

  // What blocks a fresh run right now (another run active, or a cooldown) — shown on the terminal's
  // own start button. The server is the authority (409/429); this is only the up-front label.
  let launcherState: { activeRun?: { runId: string; scenario: string; since: number; staleMs?: number }; cooldownUntil?: number } = {};
  const terminal = mountTerminal(byId("terminal"), api, {
    blocked: () => blockedReason(launcherState, Date.now()),
    cooldownSeconds: () => Math.max(0, Math.ceil(((launcherState.cooldownUntil ?? 0) - Date.now()) / 1000)),
    blockedEndsIn: () => {
      const r = latestView.activeRun;
      const l = r ? limitsOf.get(r.scenario) : undefined;
      return r && l ? runEndsWithin(r, Date.now(), l.timeout, l.idle) : undefined;
    },
    strip: runStatus.strip,
    onStarting: (pending) => {
      startingTerminal = pending;
      applyQuiet();
    },
    onSession: (s) => runStatus.setSession(s),
    // A live session of this tab's from before a reload is the visitor's, read-only (its key is gone).
    isOwn: (id) => ownIds.includes(id),
    onLit: (lit) => defenceMap.setLit(lit),
    // A 429 starting the terminal sets the shared cooldown, so the blocked state shows on both the
    // terminal's button and the one-click launcher (review item 11).
    onRateLimited: (seconds) => {
      launcherState = { ...launcherState, cooldownUntil: Date.now() + seconds * 1000 };
    },
    onAvailable: (available, objectives, timeoutSeconds, commands, idleSeconds) => {
      if (available) stats.setObjectives(objectives);
      else degradeToOneClick();
      correlation.setTerminal(available);
      if (timeoutSeconds !== undefined) timeline.setScenarioTimeout("terminal", timeoutSeconds);
      limitsOf.set("terminal", { timeout: timeoutSeconds, idle: idleSeconds });
      if (commands?.length) {
        // Why a finished terminal run shows no detection is read from its commands' outcomes (ADR 0035).
        timeline.setOutcomes(new Map(commands.map((c) => [c.id, c.outcome])));
        evidence.setCatalogue(commands);
      }
    },
  });

  let titles = new Map<string, string>();
  const launcher = mountScenarios(
    byId("scenario-panel"),
    byId("launch-status"),
    api,
    (scenarios) => {
      titles = new Map(scenarios.map((s) => [s.id, s.title]));
      timeline.setTitles(titles);
      evidence.setTitles(titles);
      runConsole.setScenarios(scenarios);
    },
    (runId) => {
      addOwn([runId]);
      runConsole.markOwn(runId);
      timeline.setShown(undefined);
      // On a phone the console is far below the button that was just pressed: take the visitor there.
      runConsole.reveal();
    },
  );

  // Same words as the timeline's connection line (ui/common.ts), so the two never disagree.
  const headerConn = byId("header-conn");
  const setHeaderConn = (state: ConnectionState) => {
    headerConn.dataset.state = state;
    // In mock mode the header says so, so "cluster live" is never mistaken for the real cluster (item 26).
    replace(headerConn, h("span", { class: "conn__dot", "aria-hidden": "true" }), `${mock ? mock.headerWord : "cluster"} ${CONNECTION_WORD[state]}`);
  };

  // Assigned right below; the retry callback can only fire after the stream exists.
  let stream: EventStream | undefined;
  let activeId: string | undefined;

  // A run's history from /api/runs/{id} when the live feed missed part of it (lib/backfill.ts).
  const backfill = new Backfill(
    (id) => api.runEvents(id),
    (ev) => timeline.push(ev),
    Date.now,
    (id) => terminal.historyTruncated(id),
  );
  const timeline = mountTimeline(
    byId("timeline-panel"),
    byId("timeline-conn"),
    byId("timeline-live"),
    (view) => {
      const r = view.activeRun;
      const live = r && !ownIds.includes(r.runId) ? r.runId : undefined;
      if (live !== liveRun) {
        liveRun = live;
        if (focusReady) correlation.setFocus({ ...focusNow(), live });
      }
      const wasActive = activeId;
      activeId = r?.runId;
      const active = r ? { runId: r.runId, scenario: r.scenario, since: r.states.started ?? r.states.queued ?? Date.now(), staleMs: r.staleAfterMs } : undefined;
      launcherState = { ...launcherState, activeRun: active };
      launcher.setActiveRun(active);
      runConsole.update(view);
      terminal.update(view);
      latestView = view;
      evidence.update(view);
      // The hero's "last run" tile follows the newest run the feed has shown.
      const newest = view.runs[0];
      if (newest) {
        if (isRunId(newest.runId)) verify.set({ latestRunId: newest.runId });
        stats.setLastRun({
          title: titles.get(newest.scenario) ?? newest.scenario,
          at: newest.states.started ?? newest.states.queued ?? Date.now(),
        });
      }
      if (wasActive && !activeId) limits.refresh();
      backfill.view(view);
    },
    () => stream?.retryNow(),
    (runId) => {
      runConsole.select(runId);
      timeline.setShown(runId);
      runConsole.reveal();
    },
  );

  const events = new EventStream({
    // ?tick=1: the server's clock after the replay and every 15 s (ADR 0035); an older API ignores it.
    url: api.url("/events?tick=1"),
    // Only in mock mode; otherwise the stream's own default, the browser's EventSource.
    ...(factory ? { factory } : {}),
    onEvent: (ev) => timeline.push(ev),
    onTick: (t) => evidence.tick(t),
    // EventSource cannot read why a connect was refused; this asks once per refusal (Retry-After).
    probe: () => api.streamRetryAfterMs(),
    onState: (state, { retryInMs, gaveUp }) => {
      timeline.setConnection(state, retryInMs, gaveUp);
      setHeaderConn(state);
      evidence.setConnection(state);
      if (state === "open") evidence.streamOpened();
      // On opening after a drop or a hidden-tab stop, re-fetch the active run so output lost across
      // the gap is recovered (the replay buffer may not reach back to its start).
      backfill.stream(state, activeId);
    },
  });
  stream = events;
  events.start();

  // The one control, drawn beside each list it scopes; then every scoped part is told the choice.
  byId("timeline-panel").before(scope.control("runs"));
  byId("ticker").before(scope.control("events"));
  byId("correlation-board").before(scope.control("incidents"));
  focusReady = true;
  applyFocus();

  // Each section below the hero folds under its heading; a folded one's panels stop redrawing (the
  // posture is still fetched for the liveness line, the correlation still polled for shown/hidden).
  // The attack section's terminal, launcher, console and history keep running folded or not.
  mountSections((id, open) => {
    if (id === "evidence") evidence.setActive(open);
    else if (id === "posture") posture.setActive(open);
    else if (id === "correlation") correlation.setActive(open);
  });

  // One open SSE connection per forgotten background tab adds up; the server replays the last 50
  // events on reconnect, so dropping it while hidden loses nothing the timeline shows.
  let hiddenTimer: ReturnType<typeof setTimeout> | undefined;
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      hiddenTimer = setTimeout(() => {
        events.stop();
        backfill.stopped();
      }, HIDDEN_DISCONNECT_MS);
    } else {
      clearTimeout(hiddenTimer);
      // Restart a stopped stream; skip the backoff wait of one that is still trying.
      if (!events.start() && events.state !== "open") events.retryNow();
    }
  });
}

main();
