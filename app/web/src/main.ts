// Entry point. The static HTML is the whole portfolio and renders without this script; this module
// adds the live panels on top, each of which degrades to its own offline state independently.

import { ApiClient } from "./lib/api";
import { byId, h, prefersReducedMotion, replace } from "./lib/dom";
import { MockBackend, mockOptionsFromUrl } from "./lib/mock";
import { type ConnectionState, type EventSourceFactory, EventStream } from "./lib/sse";
import { CONNECTION_WORD } from "./ui/common";
import { mountConsole } from "./ui/console";
import { mountDefenceMap } from "./ui/defencemap";
import { mountPosture } from "./ui/posture";
import { mountScenarios } from "./ui/scenarios";
import { mountStats } from "./ui/stats";
import { mountTerminal } from "./ui/terminal";
import { mountLimits, setupTechMode } from "./ui/tech";
import { mountTimeline } from "./ui/timeline";
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

function main(): void {
  document.documentElement.classList.add("js");
  if (prefersReducedMotion()) document.documentElement.classList.add("reduced-motion");
  setupThemeToggle();

  const mockOpts = mockOptionsFromUrl(location.search);
  const mock = mockOpts ? new MockBackend(mockOpts) : null;
  const api = new ApiClient(mock ? { fetch: mock.fetch } : {});
  const factory: EventSourceFactory | undefined = mock ? mock.eventSource : undefined;

  if (mock) {
    const banner = byId("mock-banner");
    banner.hidden = false;
    document.documentElement.dataset.mock = "true";
  }

  mountPosture(byId("posture-panel"), api);
  const stats = mountStats(byId("hero-stats"), api);
  mountDefenceMap(byId("defence-map"), api);

  const limits = mountLimits(byId("limits-panel"), api);
  setupTechMode(byId("tech-toggle"), (on) => limits.setEnabled(on));

  const runConsole = mountConsole(byId("console"), api);

  // What blocks a fresh run right now (another run active, or a cooldown) — shown on the terminal's
  // own start button. The server is the authority (409/429); this is only the up-front label.
  let launcherState: { activeRun?: { runId: string; scenario: string; since: number }; cooldownUntil?: number } = {};
  const terminal = mountTerminal(byId("terminal"), api, {
    blocked: () => blockedReason(launcherState, Date.now()),
  });

  let titles = new Map<string, string>();
  const launcher = mountScenarios(
    byId("scenario-panel"),
    byId("launch-status"),
    api,
    (scenarios) => {
      titles = new Map(scenarios.map((s) => [s.id, s.title]));
      timeline.setTitles(titles);
      runConsole.setScenarios(scenarios);
    },
    (runId) => {
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
    replace(headerConn, h("span", { class: "conn__dot", "aria-hidden": "true" }), mock ? `mock · ${CONNECTION_WORD[state]}` : `cluster ${CONNECTION_WORD[state]}`);
  };

  // Assigned right below; the retry callback can only fire after the stream exists.
  let stream: EventStream | undefined;
  let activeId: string | undefined;
  const timeline = mountTimeline(
    byId("timeline-panel"),
    byId("timeline-conn"),
    byId("timeline-live"),
    (view) => {
      const r = view.activeRun;
      const wasActive = activeId;
      activeId = r?.runId;
      const active = r ? { runId: r.runId, scenario: r.scenario, since: r.states.started ?? r.states.queued ?? Date.now() } : undefined;
      launcherState = { ...launcherState, activeRun: active };
      launcher.setActiveRun(active);
      runConsole.update(view);
      terminal.update(view);
      // The hero's "last run" tile follows the newest run the feed has shown.
      const newest = view.runs[0];
      if (newest) {
        stats.setLastRun({
          title: titles.get(newest.scenario) ?? newest.scenario,
          at: newest.states.started ?? newest.states.queued ?? Date.now(),
          respondMs: newest.timings.respondMs,
        });
      }
      if (wasActive && !activeId) limits.refresh();
    },
    () => stream?.retryNow(),
    (runId) => {
      runConsole.select(runId);
      timeline.setShown(runId);
      runConsole.reveal();
    },
  );

  const events = new EventStream({
    url: api.url("/events"),
    // Only in mock mode; otherwise the stream's own default, the browser's EventSource.
    ...(factory ? { factory } : {}),
    onEvent: (ev) => timeline.push(ev),
    // EventSource cannot read why a connect was refused; this asks once per refusal (Retry-After).
    probe: () => api.streamRetryAfterMs(),
    onState: (state, { retryInMs, gaveUp }) => {
      timeline.setConnection(state, retryInMs, gaveUp);
      setHeaderConn(state);
    },
  });
  stream = events;
  events.start();

  // One open SSE connection per forgotten background tab adds up; the server replays the last 50
  // events on reconnect, so dropping it while hidden loses nothing the timeline shows.
  let hiddenTimer: ReturnType<typeof setTimeout> | undefined;
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      hiddenTimer = setTimeout(() => events.stop(), HIDDEN_DISCONNECT_MS);
    } else {
      clearTimeout(hiddenTimer);
      // Restart a stopped stream; skip the backoff wait of one that is still trying.
      if (!events.start() && events.state !== "open") events.retryNow();
    }
  });
}

main();
