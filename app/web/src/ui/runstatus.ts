// The status strip under the terminal and its sticky toast (ADR 0035, amendment 2026-10-06 "the
// visitor's run, told back"). The strip says what just happened to the visitor's own run, in the
// sequence lib/runstatus.ts derives from the events the page already has; when it is scrolled out of
// view, a slim toast at the bottom of the screen says the same. Neither is a modal, and both can be
// dismissed; a dismissed message stays away until the next one.
//
// The strip's message is the one live region for the visitor's own run (polite, atomic): the
// timeline's and the ticker's hidden announcers are told to keep quiet about that run, and the toast
// is not live, so nothing is read twice.
//
// This module also joins the two sources the page has (the run from the stream, the incidents from the
// correlation poll) and hands every part that shows them the same reading: the "This run" panel's SIEM
// row, the scenario block's state chip, which runs are the visitor's own, whether to poll eagerly.

import type { CorrelationIncident } from "../lib/contract";
import { h, replace } from "../lib/dom";
import { type ScenarioState, type SiemAvailability, type SiemRow, type Strip, type StripAction, StripTracker, scenarioState, siemPending, siemRow } from "../lib/runstatus";
import type { OwnSession } from "./terminal";

export interface RunReading {
  /** The visitor's current or last session in this page view. */
  runId?: string;
  /** Every session the visitor started in this page view, oldest first. */
  ownRuns: string[];
  scenario: ScenarioState;
  siem: SiemRow;
  /** A filing for the visitor's run is awaited: ask the SIEM more often. */
  eager: boolean;
}

export interface RunStatusHandle {
  /** The strip, for the terminal to carry (under its input, or under the start button). */
  readonly strip: HTMLElement;
  setSession(s: OwnSession): void;
  /** Each correlation poll: whether the SIEM answered, and its incidents. */
  setCorrelation(available: boolean, incidents: readonly CorrelationIncident[]): void;
  /** The latest reading (also handed to onReading on every change). */
  readonly reading: RunReading;
}

const ACTION_WORD: Record<StripAction, string> = { timeline: "Watch the kill timeline", again: "Run again", open: "Open it ↓" };

/** How often the waiting states are re-read without an event (waiting turns late on its own). */
const TICK_MS = 15_000;

export function mountRunStatus(opts: {
  toastParent: HTMLElement;
  onTimeline(): void;
  onAgain(): void;
  /** After an "Open it" link has taken the visitor to the incident: pulse its card. */
  onOpen(incidentId: string): void;
  onReading(r: RunReading): void;
}): RunStatusHandle {
  const tracker = new StripTracker();
  let session: OwnSession | undefined;
  const own: string[] = [];
  let incidents: readonly CorrelationIncident[] = [];
  let siem: SiemAvailability = "unknown";
  let current: Strip | null = null;
  let dismissed: string | undefined;
  let stripVisible = true;
  let tick: ReturnType<typeof setInterval> | undefined;
  let reading: RunReading = { ownRuns: [], scenario: { phase: "idle" }, siem: { text: "nothing to correlate yet", tone: "idle" }, eager: false };
  let readingKey = "";

  // ---- the strip ----
  const msg = h("p", { class: "run-strip__msg", "aria-live": "polite", "aria-atomic": "true" });
  const note = h("p", { class: "run-strip__note", hidden: true });
  const actions = h("div", { class: "run-strip__actions" });
  const close = h("button", { type: "button", class: "run-strip__close", "aria-label": "Dismiss this message" }, "×");
  const strip = h("div", { class: "run-strip", hidden: true, "data-kind": "", "data-tone": "" }, h("span", { class: "run-strip__dot", "aria-hidden": "true" }), h("div", { class: "run-strip__body" }, msg, note), actions, close);

  // ---- the toast: the same words, not live, at the bottom of the screen while the strip is out of view ----
  const toastMsg = h("p", { class: "run-toast__msg" });
  const toastActions = h("div", { class: "run-toast__actions" });
  const toastClose = h("button", { type: "button", class: "run-strip__close", "aria-label": "Dismiss this message" }, "×");
  const toast = h("div", { class: "run-toast", role: "region", "aria-label": "Your run", hidden: true, "data-tone": "" }, h("span", { class: "run-strip__dot", "aria-hidden": "true" }), toastMsg, toastActions, toastClose);
  opts.toastParent.append(toast);

  const dismiss = () => {
    dismissed = current?.key;
    paint();
  };
  close.addEventListener("click", dismiss);
  toastClose.addEventListener("click", dismiss);

  const actionEl = (a: StripAction, s: Strip): HTMLElement => {
    if (a === "open" && s.incidentId) {
      const id = s.incidentId;
      // A link to the card: a folded #correlation opens first (ui/sections.ts), the browser scrolls.
      const link = h("a", { class: "btn btn--small run-strip__btn", href: `#incident-${id}` }, ACTION_WORD.open);
      link.addEventListener("click", () => setTimeout(() => opts.onOpen(id), 0));
      return link;
    }
    const b = h("button", { type: "button", class: "btn btn--small run-strip__btn" }, ACTION_WORD[a]);
    b.addEventListener("click", () => (a === "again" ? opts.onAgain() : opts.onTimeline()));
    return b;
  };

  let shownKey = "";
  const paint = () => {
    const s = current && current.key !== dismissed ? current : null;
    strip.hidden = s === null;
    toast.hidden = s === null || !s.toast || stripVisible || !strip.isConnected;
    if (!s) return;
    // Rewritten only when the message changes: the live region speaks once per message.
    const key = `${s.key}|${s.lead}${s.text}|${s.note ?? ""}|${s.actions.join(",")}`;
    if (key === shownKey) return;
    shownKey = key;
    strip.dataset.kind = s.kind;
    strip.dataset.tone = s.tone;
    toast.dataset.tone = s.tone;
    replace(msg, h("strong", {}, s.lead), s.text);
    replace(toastMsg, h("strong", {}, s.lead), s.text);
    note.hidden = !s.note;
    replace(note, s.note ?? "");
    replace(actions, s.actions.map((a) => actionEl(a, s)));
    replace(toastActions, s.actions.map((a) => actionEl(a, s)));
  };

  if (typeof IntersectionObserver === "function") {
    // A strip under the sticky header counts as out of view.
    new IntersectionObserver(
      (entries) => {
        for (const e of entries) stripVisible = e.isIntersecting;
        paint();
      },
      { rootMargin: "-96px 0px 0px 0px" },
    ).observe(strip);
  }

  const update = () => {
    const now = Date.now();
    const run = session?.run;
    current = tracker.update({ runId: session?.runId, run, commands: session?.commands ?? [], idleSeconds: session?.idleSeconds, incidents, siem, now });
    paint();
    const next: RunReading = {
      runId: session?.runId,
      ownRuns: [...own],
      scenario: scenarioState({ run, incidents, ownRuns: own, siem, now }),
      siem: run ? siemRow({ run, commands: session?.commands ?? [], incidents, siem, now }) : { text: "nothing to correlate yet", tone: "idle" },
      eager: run !== undefined && siem !== "unavailable" && siemPending({ run, commands: session?.commands ?? [], incidents, now }),
    };
    const key = JSON.stringify(next);
    if (key !== readingKey) {
      readingKey = key;
      reading = next;
      opts.onReading(next);
    }
    // Waiting turns late with no event to say so: re-read while something is awaited.
    if (next.eager && tick === undefined) tick = setInterval(update, TICK_MS);
    else if (!next.eager && tick !== undefined) {
      clearInterval(tick);
      tick = undefined;
    }
  };

  return {
    strip,
    get reading() {
      return reading;
    },
    setSession(s) {
      if (!own.includes(s.runId)) own.push(s.runId);
      if (session?.runId !== s.runId) dismissed = undefined;
      session = s;
      update();
    },
    setCorrelation(available, list) {
      siem = available ? "available" : "unavailable";
      incidents = list;
      update();
    },
  };
}
