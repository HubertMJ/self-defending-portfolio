// Entry point. The static HTML is the whole portfolio and renders without this script; this module
// adds the live panels on top, each of which degrades to its own offline state independently.

import { ApiClient } from "./lib/api";
import { byId, h, prefersReducedMotion, replace } from "./lib/dom";
import { MockBackend, mockOptionsFromUrl } from "./lib/mock";
import { type ConnectionState, type EventSourceFactory, EventStream } from "./lib/sse";
import { mountPosture } from "./ui/posture";
import { mountScenarios } from "./ui/scenarios";
import { mountTimeline } from "./ui/timeline";

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

  const launcher = mountScenarios(byId("scenario-panel"), byId("launch-status"), api, (scenarios) => {
    timeline.setTitles(new Map(scenarios.map((s) => [s.id, s.title])));
  });

  const headerConn = byId("header-conn");
  const setHeaderConn = (state: ConnectionState) => {
    headerConn.dataset.state = state;
    replace(headerConn, h("span", { class: "conn__dot", "aria-hidden": "true" }), state === "open" ? "cluster live" : state === "offline" ? "cluster offline" : "connecting");
  };

  // Assigned right below; the retry callback can only fire after the stream exists.
  let stream: EventStream | undefined;
  const timeline = mountTimeline(
    byId("timeline-panel"),
    byId("timeline-conn"),
    byId("timeline-live"),
    (view) => {
      const r = view.activeRun;
      launcher.setActiveRun(r ? { runId: r.runId, scenario: r.scenario, since: r.states.started ?? r.states.queued ?? Date.now() } : undefined);
    },
    () => stream?.retryNow(),
  );

  const events = new EventStream({
    url: api.url("/events"),
    factory,
    onEvent: (ev) => timeline.push(ev),
    onState: (state, { retryInMs }) => {
      timeline.setConnection(state, retryInMs);
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
