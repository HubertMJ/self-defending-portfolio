// The live timeline: each run as attack -> Falco detection -> Talon response, with latencies, fed
// by SSE /api/events through EventStream (reconnect + replay dedup live there).

import type { StreamEvent } from "../lib/contract";
import { clockTime, h, replace } from "../lib/dom";
import type { ConnectionState } from "../lib/sse";
import { type RunView, type TimelineView, buildTimeline, formatDuration, ts } from "../lib/timeline";

const MAX_LOG = 400;

const STATE_LABEL: Record<string, string> = {
  queued: "Queued",
  started: "Attacking",
  detected: "Detected",
  responded: "Contained",
  finished: "Finished",
  failed: "Failed",
  timeout: "Timed out",
};

const CONNECTION_LABEL: Record<ConnectionState, string> = {
  connecting: "Connecting to the event stream…",
  open: "Live",
  reconnecting: "Connection lost, reconnecting…",
  offline: "Event stream offline, retrying",
};

export interface TimelineHandle {
  push(ev: StreamEvent): void;
  setConnection(state: ConnectionState, retryInMs?: number): void;
  setTitles(titles: Map<string, string>): void;
}

function stage(opts: {
  key: "attack" | "detect" | "respond";
  title: string;
  reached: boolean;
  at?: number;
  delta?: string;
  what?: Node | string;
}): HTMLElement {
  return h(
    "li",
    { class: `stage stage--${opts.key}`, "data-reached": String(opts.reached) },
    h("span", { class: "stage__dot", "aria-hidden": "true" }),
    h("span", { class: "stage__title" }, opts.title, opts.reached ? null : h("span", { class: "visually-hidden" }, " (pending)")),
    opts.delta ? h("span", { class: "stage__delta" }, opts.delta) : null,
    opts.at ? h("time", { class: "stage__at", datetime: new Date(opts.at).toISOString() }, clockTime(opts.at)) : null,
    opts.what ? h("span", { class: "stage__what" }, opts.what) : null,
  );
}

export function renderRun(run: RunView, title: string, openDetails: Set<string>): HTMLElement {
  const falco = run.falco[0];
  const talon = run.talon[0];
  const startedAt = run.states.started ?? run.states.queued;
  const detectedAt = falco ? ts(falco.at) : run.states.detected;
  const respondedAt = talon ? ts(talon.at) : run.states.responded;
  const failed = run.current === "failed" || run.current === "timeout";

  const details = h(
    "details",
    { class: "run__details", "data-run": run.runId, open: openDetails.has(run.runId) },
    h("summary", {}, "Raw events"),
    h(
      "ul",
      { class: "run__events" },
      run.falco.map((f) =>
        h("li", {}, h("span", { class: "tag tag--detect" }, "falco"), ` ${clockTime(ts(f.at))} `, h("strong", {}, f.priority), ` ${f.rule}`, h("code", { class: "run__output" }, f.output)),
      ),
      run.talon.map((t) =>
        h("li", {}, h("span", { class: "tag tag--respond" }, "talon"), ` ${clockTime(ts(t.at))} `, h("code", {}, t.action), ` on ${t.namespace}/${t.pod}: `, h("strong", {}, t.status)),
      ),
      run.falco.length + run.talon.length === 0 ? h("li", {}, "No Falco or Talon events for this run yet.") : null,
    ),
  );
  details.addEventListener("toggle", () => {
    if (details.open) openDetails.add(run.runId);
    else openDetails.delete(run.runId);
  });

  return h(
    "li",
    { class: `run run--${run.current}`, "data-run": run.runId, "data-active": String(run.active) },
    h(
      "header",
      { class: "run__head" },
      h("h3", { class: "run__title" }, title),
      h("span", { class: `chip chip--state chip--${failed ? "critical" : run.active ? "warning" : "good"}` }, STATE_LABEL[run.current] ?? run.current),
    ),
    h(
      "ol",
      { class: "stages", "aria-label": "Run stages" },
      stage({ key: "attack", title: "Attack", reached: startedAt !== undefined, at: startedAt, what: run.pod ? h("code", {}, run.pod) : run.scenario }),
      stage({
        key: "detect",
        title: "Falco detected",
        reached: detectedAt !== undefined,
        at: detectedAt,
        delta: run.timings.detectMs !== undefined ? `+${formatDuration(run.timings.detectMs)}` : undefined,
        what: falco ? falco.rule : run.states.detected ? run.detail : undefined,
      }),
      stage({
        key: "respond",
        title: "Talon responded",
        reached: respondedAt !== undefined,
        at: respondedAt,
        delta: run.timings.respondMs !== undefined ? `+${formatDuration(run.timings.respondMs)}` : undefined,
        what: talon ? `${talon.action} → ${talon.status}` : undefined,
      }),
    ),
    h(
      "p",
      { class: "run__foot" },
      h("span", {}, "Run ", h("code", {}, run.runId)),
      run.timings.totalMs !== undefined ? h("span", {}, `Total ${formatDuration(run.timings.totalMs)}`) : null,
      failed && run.detail ? h("span", { class: "run__fail" }, run.detail) : null,
    ),
    details,
  );
}

/** One sentence for screen readers when the newest run changes state. */
export function announce(run: RunView, title: string): string {
  switch (run.current) {
    case "queued":
      return `${title}: queued.`;
    case "started":
      return `${title}: attack running.`;
    case "detected":
      return `${title}: detected by Falco after ${formatDuration(run.timings.detectMs)}.`;
    case "responded":
      return `${title}: Talon responded ${formatDuration(run.timings.respondMs)} after detection.`;
    case "finished":
      return `${title}: finished in ${formatDuration(run.timings.totalMs)}.`;
    default:
      return `${title}: ${STATE_LABEL[run.current] ?? run.current}.`;
  }
}

export function mountTimeline(
  root: HTMLElement,
  connEl: HTMLElement,
  liveEl: HTMLElement,
  onView: (view: TimelineView) => void,
  onRetry: () => void,
): TimelineHandle {
  const log: StreamEvent[] = [];
  const openDetails = new Set<string>();
  let titles = new Map<string, string>();
  let lastAnnounced = "";
  let renderQueued = false;

  const titleOf = (scenario: string) => titles.get(scenario) ?? scenario;

  const render = () => {
    renderQueued = false;
    const view = buildTimeline(log);
    onView(view);
    if (view.runs.length === 0) {
      replace(root, h("p", { class: "empty" }, "No runs yet. Launch an attack and it appears here as it happens."));
    } else {
      replace(root, h("ol", { class: "runs", role: "list" }, view.runs.map((r) => renderRun(r, titleOf(r.scenario), openDetails))));
    }
    // Announce transitions of the newest run while it is active, plus the terminal state of a run
    // we were already announcing; replayed history from before the page loaded stays silent.
    const newest = view.runs[0];
    if (newest) {
      const key = `${newest.runId}:${newest.current}`;
      if (key !== lastAnnounced && (newest.active || lastAnnounced.startsWith(`${newest.runId}:`))) {
        lastAnnounced = key;
        replace(liveEl, announce(newest, titleOf(newest.scenario)));
      }
    }
  };

  // Replays arrive as a burst of up to 50 events; render once per frame, not once per event.
  const schedule = () => {
    if (renderQueued) return;
    renderQueued = true;
    (typeof requestAnimationFrame === "function" ? requestAnimationFrame : (f: () => void) => setTimeout(f, 16))(render);
  };

  render();

  return {
    push(ev) {
      log.push(ev);
      if (log.length > MAX_LOG) log.splice(0, log.length - MAX_LOG);
      schedule();
    },
    setConnection(state, retryInMs) {
      connEl.dataset.state = state;
      const label = CONNECTION_LABEL[state];
      const children: (Node | string)[] = [h("span", { class: "conn__dot", "aria-hidden": "true" }), label];
      if (state === "offline" || state === "reconnecting") {
        if (retryInMs !== undefined && state === "offline") children.push(` (next attempt in ${formatDuration(retryInMs)})`);
        const b = h("button", { type: "button", class: "btn btn--ghost btn--small" }, "Retry now");
        b.addEventListener("click", onRetry);
        children.push(b);
      }
      replace(connEl, ...children);
    },
    setTitles(t) {
      titles = t;
      schedule();
    },
  };
}
