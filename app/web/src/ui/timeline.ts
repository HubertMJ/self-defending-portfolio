// The live timeline: each run as attack -> Falco detection -> Talon response, with latencies, fed
// by SSE /api/events through EventStream (reconnect + replay dedup live there).

import type { StreamEvent } from "../lib/contract";
import { clockTime, h, replace } from "../lib/dom";
import { humanAction } from "../lib/pipeline";
import type { ConnectionState } from "../lib/sse";
import { type RunView, type TimelineView, buildTimeline, formatDuration, ts } from "../lib/timeline";
import { CONNECTION_LONG } from "./common";

// A run with victim probes every 500 ms produces a few hundred events; keep a handful of runs' worth.
const MAX_LOG = 1500;

const STATE_LABEL: Record<string, string> = {
  queued: "Queued",
  started: "Attack running",
  pod_ready: "Pod ready",
  detected: "Detected",
  responded: "Contained",
  finished: "Finished",
  failed: "Failed",
  timeout: "Timed out",
};

export interface TimelineHandle {
  push(ev: StreamEvent): void;
  /** retryInMs: delay of the one scheduled retry (counted down here); gaveUp: retries have stopped. */
  setConnection(state: ConnectionState, retryInMs?: number, gaveUp?: boolean): void;
  setTitles(titles: Map<string, string>): void;
  /** The run the live run panel shows, marked on its "Show" button (undefined: following live). */
  setShown(runId: string | undefined): void;
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

export function renderRun(run: RunView, title: string, openDetails: Set<string>, onShow?: (runId: string) => void, shown?: string): HTMLElement {
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
        h("li", {}, h("span", { class: "tag tag--respond" }, "talon"), ` ${clockTime(ts(t.at))} ${humanAction(t.action, t.actionner)} `, h("code", {}, t.actionner ?? t.action), ` on ${t.namespace}/${t.pod}: `, h("strong", {}, t.status)),
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
      stage({ key: "attack", title: "Attack", reached: startedAt !== undefined, at: startedAt, what: run.pod ? h("code", {}, run.pod) : "starting the pod…" }),
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
        what: talon ? `${humanAction(talon.action, talon.actionner)}${talon.status === "success" ? "" : ` (${talon.status})`}` : undefined,
      }),
    ),
    h(
      "p",
      { class: "run__foot" },
      h("span", {}, "Run ", h("code", {}, run.runId)),
      run.timings.totalMs !== undefined
        ? h(
            "span",
            {},
            `Whole run ${formatDuration(run.timings.totalMs)}`,
            // A quarantined pod is kept, isolated, for a while before the run ends; without saying so
            // the long total reads as a slow response.
            run.quarantinedAt !== undefined || run.talon.some((t) => /label/i.test(t.actionner ?? t.action)) ? " (pod start to clean-up, including the time held in quarantine)" : " (pod start to clean-up)",
          )
        : null,
      failed && run.detail ? h("span", { class: "run__fail" }, run.detail) : null,
    ),
    details,
    onShow
      ? (() => {
          const b = h("button", { type: "button", class: "btn btn--ghost btn--small run__show", "data-focus-key": `show:${run.runId}`, "aria-pressed": String(shown === run.runId) }, "Show in the live run panel");
          b.addEventListener("click", () => onShow(run.runId));
          return b;
        })()
      : null,
  );
}

/** One sentence for screen readers when the newest run changes state. */
export function announce(run: RunView, title: string): string {
  switch (run.current) {
    case "queued":
      return `${title}: queued.`;
    case "started":
      return `${title}: scenario pod starting.`;
    case "pod_ready":
      return `${title}: pod ready, attack command running.`;
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

const monotonicNow = (): number => (typeof performance !== "undefined" ? performance.now() : Date.now());

export function mountTimeline(
  root: HTMLElement,
  connEl: HTMLElement,
  liveEl: HTMLElement,
  onView: (view: TimelineView) => void,
  onRetry: () => void,
  onShow?: (runId: string) => void,
): TimelineHandle {
  const log: StreamEvent[] = [];
  const openDetails = new Set<string>();
  let titles = new Map<string, string>();
  let lastAnnounced = "";
  let renderQueued = false;
  let shown: string | undefined;
  // The one countdown of the connection line. Replaced, never stacked: every setConnection clears it.
  let countdownTimer: ReturnType<typeof setInterval> | undefined;

  const titleOf = (scenario: string) => titles.get(scenario) ?? scenario;

  const render = () => {
    renderQueued = false;
    const view = buildTimeline(log);
    onView(view);
    // The list is rebuilt; a focused button inside it is found again by its data-focus-key.
    const active = document.activeElement;
    const focusKey = active instanceof HTMLElement && root.contains(active) ? active.dataset.focusKey : undefined;
    if (view.runs.length === 0) {
      replace(root, h("p", { class: "empty" }, "No runs yet. Launch an attack and it appears here as it happens."));
    } else {
      replace(root, h("ol", { class: "runs", role: "list" }, view.runs.map((r) => renderRun(r, titleOf(r.scenario), openDetails, onShow, shown))));
    }
    if (focusKey) [...root.querySelectorAll<HTMLElement>("[data-focus-key]")].find((el) => el.dataset.focusKey === focusKey)?.focus();
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
    setConnection(state, retryInMs, gaveUp) {
      if (countdownTimer !== undefined) {
        clearInterval(countdownTimer);
        countdownTimer = undefined;
      }
      connEl.dataset.state = state;
      const label = gaveUp ? "Offline: the live feed gave up retrying" : CONNECTION_LONG[state];
      const children: (Node | string)[] = [h("span", { class: "conn__dot", "aria-hidden": "true" }), label];
      if (state === "offline" || state === "reconnecting") {
        if (retryInMs !== undefined) {
          // The deadline is fixed once, here; each tick only renders deadline - now.
          const deadline = monotonicNow() + retryInMs;
          // data-deadline identifies the attempt, so a test (or a reader of the DOM) can tell a new
          // countdown from one that jumped.
          const remaining = h("span", { class: "conn__retry", "data-deadline": String(Math.round(deadline)) });
          const tick = () => {
            const s = Math.max(0, Math.ceil((deadline - monotonicNow()) / 1000));
            remaining.textContent = ` (next attempt in ${s} s)`;
            if (s === 0 && countdownTimer !== undefined) {
              clearInterval(countdownTimer);
              countdownTimer = undefined;
            }
          };
          tick();
          countdownTimer = setInterval(tick, 250);
          children.push(remaining);
        }
        const b = h("button", { type: "button", class: "btn btn--ghost btn--small" }, gaveUp ? "Try again" : "Retry now");
        b.addEventListener("click", onRetry);
        children.push(b);
      }
      replace(connEl, ...children);
    },
    setTitles(t) {
      titles = t;
      schedule();
    },
    setShown(runId) {
      shown = runId;
      schedule();
    },
  };
}
