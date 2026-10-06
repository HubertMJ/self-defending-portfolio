// The live timeline: each run as attack -> Falco detection -> Talon response, with latencies, fed
// by SSE /api/events through EventStream (reconnect + replay dedup live there).

import { type CommandOutcome, type StreamEvent, isRunId } from "../lib/contract";
import { h, replace, timeEl, plClock } from "../lib/dom";
import { humanAction } from "../lib/pipeline";
import type { ConnectionState } from "../lib/sse";
import { type NoDetection, type RunView, type TimelineView, buildTimeline, formatDuration, guardedFalco, guardedTalon, noDetection, publishedPod, ts } from "../lib/timeline";
import { CONNECTION_LONG, extLink } from "./common";

// A run with victim probes every 500 ms produces a few hundred events; keep a handful of runs' worth.
const MAX_LOG = 1500;
/** Run cards shown before the rest fold under "N earlier runs". */
export const HISTORY_SHOWN = 4;

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
  /** A scenario's `timeout_seconds` from its details: how long its runs may last (staleRunMs). */
  setScenarioTimeout(scenario: string, seconds: number): void;
  /** The terminal catalogue's outcome per command id: why a finished run shows no detection. */
  setOutcomes(outcomes: ReadonlyMap<string, CommandOutcome>): void;
  /** Runs the status strip announces (the visitor's own): this announcer keeps quiet about them. */
  setQuiet(runIds: readonly string[]): void;
}

/**
 * A stage's dot: "true" reached, "false" not (yet), "na" not applicable to this run (a neutral mark,
 * not an unreached one), "missed" expected and absent (critical: a miss is shown, not hidden).
 */
type Reached = "true" | "false" | "na" | "missed";

function stage(opts: {
  key: "attack" | "detect" | "respond";
  title: string;
  reached: Reached;
  /** Read after the title by screen readers when the stage is not reached: "pending" or "not reached". */
  note?: string;
  at?: number;
  now: number;
  delta?: string;
  what?: Node | string;
}): HTMLElement {
  return h(
    "li",
    { class: `stage stage--${opts.key}`, "data-reached": opts.reached },
    h("span", { class: "stage__dot", "aria-hidden": "true" }),
    h("span", { class: "stage__title" }, opts.title, opts.note ? h("span", { class: "visually-hidden" }, ` (${opts.note})`) : null),
    opts.delta ? h("span", { class: "stage__delta" }, opts.delta) : null,
    opts.at ? timeEl(opts.at, plClock(opts.at, opts.now, { ms: true }), { class: "stage__at" }) : null,
    opts.what ? h("span", { class: "stage__what" }, opts.what) : null,
  );
}

/** What an unreached detect/respond stage says, by why nothing was detected (lib/timeline.ts noDetection). */
const UNDETECTED: Record<NoDetection, { reached: Reached; title: string; note?: string; what?: string }> = {
  pending: { reached: "false", title: "Falco detected", note: "pending" },
  recon: { reached: "na", title: "No detection expected", what: "recon only - no detection expected" },
  prevented: { reached: "na", title: "No detection expected", what: "recon and commands blocked by a preventive layer" },
  "no-commands": { reached: "na", title: "No commands run" },
  missed: { reached: "missed", title: "Detection expected, none arrived" },
  "not-reached": { reached: "false", title: "Falco detected", note: "not reached" },
};

export function renderRun(
  run: RunView,
  title: string,
  openDetails: Set<string>,
  onShow?: (runId: string) => void,
  shown?: string,
  outcomes?: ReadonlyMap<string, CommandOutcome>,
  now: number = Date.now(),
): HTMLElement {
  const interactive = run.scenario === "terminal";
  const falco = guardedFalco(run);
  const talon = guardedTalon(run);
  const startedAt = run.states.started ?? run.states.queued;
  const detectedAt = falco ? ts(falco.at) : run.states.detected;
  const respondedAt = talon ? ts(talon.at) : run.states.responded;
  const failed = run.current === "failed" || run.current === "timeout";
  const verdict = noDetection(run, outcomes);

  const details = h(
    "details",
    { class: "run__details", "data-run": run.runId, open: openDetails.has(run.runId) },
    h("summary", {}, "Raw events"),
    h(
      "ul",
      { class: "run__events" },
      run.falco.map((f) =>
        h("li", {}, h("span", { class: "tag tag--detect" }, "falco"), " ", timeEl(f.at, plClock(f.at, now, { ms: true })), " ", h("strong", {}, f.priority), ` ${f.rule}`, h("code", { class: "run__output" }, f.output)),
      ),
      run.talon.map((t) =>
        h("li", {}, h("span", { class: "tag tag--respond" }, "talon"), " ", timeEl(t.at, plClock(t.at, now, { ms: true })), ` ${humanAction(t.action, t.actionner)} `, h("code", {}, t.actionner ?? t.action), ` on ${t.namespace}/${t.pod}: `, h("strong", {}, t.status)),
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
      stage({
        key: "attack",
        title: "Attack",
        reached: startedAt !== undefined ? "true" : "false",
        note: startedAt !== undefined ? undefined : run.active ? "pending" : "not reached",
        at: startedAt,
        now,
        what: publishedPod(run) ? h("code", {}, publishedPod(run)) : run.pod ? "pod name withheld: not a sandbox pod" : "starting the pod…",
      }),
      detectedAt !== undefined
        ? stage({
            key: "detect",
            title: "Falco detected",
            reached: "true",
            at: detectedAt,
            now,
            // On a terminal run the gap to the first detected command is the visitor's dwell time, not a
            // detection latency, so it is not shown as one.
            delta: !interactive && run.timings.detectMs !== undefined ? `+${formatDuration(run.timings.detectMs)}` : undefined,
            what: falco ? falco.rule : run.states.detected ? run.detail : undefined,
          })
        : stage({ key: "detect", now, ...UNDETECTED[verdict ?? "not-reached"] }),
      respondedAt !== undefined
        ? stage({
            key: "respond",
            title: "Talon responded",
            reached: "true",
            at: respondedAt,
            now,
            delta: !interactive && run.timings.respondMs !== undefined ? `+${formatDuration(run.timings.respondMs)}` : undefined,
            what: talon ? `${humanAction(talon.action, talon.actionner)}${talon.status === "success" ? "" : ` (${talon.status})`}` : undefined,
          })
        : verdict === "recon" || verdict === "prevented" || verdict === "no-commands"
          ? stage({ key: "respond", now, reached: "na", title: "No response needed" })
          : stage({ key: "respond", now, reached: "false", title: "Talon responded", note: run.active ? "pending" : "not reached" }),
    ),
    h(
      "p",
      { class: "run__foot" },
      h("span", {}, "Run ", h("code", {}, run.runId), isRunId(run.runId) ? [" · ", extLink(`/api/runs/${encodeURIComponent(run.runId)}`, "raw JSON")] : null),
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
    // The live run panel does not replay a terminal run (it has its own panel), so no "Show" there.
    onShow && !interactive
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
  // Backfill from /api/runs/{id} replays events the live feed also delivers; one already here is
  // dropped so it never counts twice. Identity is the hub's event id with the payload (ids restart
  // with the API, payloads differ), else the payload alone: two identical lines of output are two
  // events with two ids and both stay.
  const seen = new Set<string>();
  const keyOf = (ev: StreamEvent) => `${ev.id ?? ""}\u0000${ev.type}\u0000${JSON.stringify(ev.data)}`;
  const openDetails = new Set<string>();
  let titles = new Map<string, string>();
  let lastAnnounced = "";
  let renderQueued = false;
  let shown: string | undefined;
  const timeouts = new Map<string, number>();
  let outcomes: ReadonlyMap<string, CommandOutcome> = new Map();
  let quiet: ReadonlySet<string> = new Set();
  // The fold of the older run cards stays as the visitor left it across the re-renders.
  let moreOpen = false;
  // The one countdown of the connection line. Replaced, never stacked: every setConnection clears it.
  let countdownTimer: ReturnType<typeof setInterval> | undefined;

  const titleOf = (scenario: string) => titles.get(scenario) ?? scenario;

  const render = () => {
    renderQueued = false;
    const view = buildTimeline(log, Date.now(), timeouts);
    onView(view);
    // The list is rebuilt; a focused button inside it is found again by its data-focus-key.
    const active = document.activeElement;
    const focusKey = active instanceof HTMLElement && root.contains(active) ? active.dataset.focusKey : undefined;
    if (view.runs.length === 0) {
      replace(root, h("p", { class: "empty" }, "No runs yet. Launch an attack and it appears here as it happens."));
    } else {
      const card = (r: RunView) => renderRun(r, titleOf(r.scenario), openDetails, onShow, shown, outcomes);
      const rest = view.runs.slice(HISTORY_SHOWN);
      const more = rest.length ? h("details", { class: "runs-more", open: moreOpen }, h("summary", {}, `${rest.length} earlier run${rest.length === 1 ? "" : "s"}`), h("ol", { class: "runs", role: "list" }, rest.map(card))) : null;
      more?.addEventListener("toggle", () => (moreOpen = (more as HTMLDetailsElement).open));
      replace(root, h("ol", { class: "runs", role: "list" }, view.runs.slice(0, HISTORY_SHOWN).map(card)), more);
    }
    if (focusKey) [...root.querySelectorAll<HTMLElement>("[data-focus-key]")].find((el) => el.dataset.focusKey === focusKey)?.focus();
    // Announce transitions of the newest run while it is active, plus the terminal state of a run
    // we were already announcing; replayed history from before the page loaded stays silent.
    const newest = view.runs[0];
    if (newest) {
      const key = `${newest.runId}:${newest.current}`;
      if (key !== lastAnnounced && (newest.active || lastAnnounced.startsWith(`${newest.runId}:`))) {
        lastAnnounced = key;
        if (!quiet.has(newest.runId)) replace(liveEl, announce(newest, titleOf(newest.scenario)));
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
      const key = keyOf(ev);
      if (seen.has(key)) return;
      seen.add(key);
      log.push(ev);
      if (log.length > MAX_LOG) {
        for (const dropped of log.splice(0, log.length - MAX_LOG)) seen.delete(keyOf(dropped));
      }
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
    setScenarioTimeout(scenario, seconds) {
      if (timeouts.get(scenario) === seconds) return;
      timeouts.set(scenario, seconds);
      schedule();
    },
    setOutcomes(o) {
      outcomes = o;
      schedule();
    },
    setQuiet(ids) {
      quiet = new Set(ids);
    },
  };
}
