// The status strip under the terminal and its sticky toast (ADR 0035, amendment 2026-10-06 "the
// visitor's run, told back"). The strip says what just happened to the visitor's own run, in the
// sequence lib/runstatus.ts derives from the events the page already has; when it is scrolled out of
// view, a slim toast at the bottom of the screen says the same. Neither is a modal, and both can be
// dismissed; a dismissed message stays away until the next one.
//
// One live region speaks for the visitor's own run (polite, atomic): a visually hidden line that is
// always in the page, outside the strip, so the first message is heard although the strip appears with
// it; it is rewritten only when the words of the message change. The timeline's and the ticker's
// hidden announcers keep quiet about that run, the strip and the toast are not live, so nothing is
// read twice.
//
// This module also joins the two sources the page has (the run from the stream, the incidents from the
// correlation poll) and hands every part that shows them the same reading: the "This run" panel's SIEM
// row, the scenario block's state chip, which runs are the visitor's own, whether to poll eagerly.

import type { CorrelationIncident } from "../lib/contract";
import { h, replace } from "../lib/dom";
import { EAGER_CAP_MS, type ScenarioState, type SiemAvailability, type SiemRow, type Strip, type StripAction, StripTracker, type WaitClock, scenarioState, siemPending, siemRow } from "../lib/runstatus";
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
  /** Where the focus goes when a dismiss button it was on goes away (the terminal's input or start button). */
  onDismissFocus?(): void;
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
  // The SIEM waits on the page's own clock: when each expectation of the run was first seen here.
  // A visitor's clock that is wrong against the API's then makes no wait endless or late at once.
  const firstSeen = new Map<string, number>();
  const waited: WaitClock = (kind) => {
    const k = `${session?.runId ?? ""}|${kind}`;
    let t = firstSeen.get(k);
    if (t === undefined) firstSeen.set(k, (t = Date.now()));
    return Date.now() - t;
  };
  // The eager poll's hard cap: EAGER_CAP_MS after it began for this session, it stops.
  let eagerSince: { runId: string; at: number } | undefined;

  // ---- the strip ----
  const msg = h("p", { class: "run-strip__msg" });
  const live = h("p", { class: "visually-hidden run-status-live", "aria-live": "polite", "aria-atomic": "true" });
  opts.toastParent.append(live);
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
    const had = strip.contains(document.activeElement) || toast.contains(document.activeElement);
    dismissed = current?.key;
    paint();
    // The button that had the focus is gone: the focus goes back to the terminal, not to <body>.
    if (had) opts.onDismissFocus?.();
  };
  close.addEventListener("click", dismiss);
  toastClose.addEventListener("click", dismiss);

  // The toast's own dismissal: once its "Open it" has been followed, it has done its job for that message.
  let toastDone: string | undefined;

  const actionEl = (a: StripAction, s: Strip): HTMLElement => {
    if (a === "open" && s.incidentId) {
      const id = s.incidentId;
      // A link to the card: a folded #correlation opens first (ui/sections.ts), the browser scrolls.
      const link = h("a", { class: "btn btn--small run-strip__btn", href: `#incident-${id}`, "data-action": a }, ACTION_WORD.open);
      link.addEventListener("click", () => {
        toastDone = s.key;
        placeToast();
        setTimeout(() => opts.onOpen(id), 0);
      });
      return link;
    }
    const b = h("button", { type: "button", class: "btn btn--small run-strip__btn", "data-action": a }, ACTION_WORD[a]);
    b.addEventListener("click", () => (a === "again" ? opts.onAgain() : opts.onTimeline()));
    return b;
  };

  // Each part is patched on its own key: the words (and the live line) only when they change, the
  // note and the buttons apart, so a new note or button never re-reads the message.
  let wordsKey = "";
  let noteKey: string | undefined;
  let actionsKey = "";
  /** True while the board's own or pinned tier, or the linked card, is on screen: the toast would cover what it points at. */
  const boardInView = (s: Strip): boolean => {
    if (typeof document === "undefined") return false;
    const targets = [...document.querySelectorAll<HTMLElement>(".corr-tier--own, .corr-tier--pinned"), ...(s.incidentId ? [document.getElementById(`incident-${s.incidentId}`)] : [])];
    const vh = window.innerHeight || document.documentElement.clientHeight;
    return targets.some((el) => {
      if (!el || !el.isConnected) return false;
      const r = el.getBoundingClientRect();
      return r.height > 0 && r.bottom > 0 && r.top < vh;
    });
  };

  /** The toast: only for news worth it, only while the strip is out of view, never over what it points at. */
  const placeToast = () => {
    const s = current && current.key !== dismissed ? current : null;
    toast.hidden = s === null || !s.toast || stripVisible || !strip.isConnected || toastDone === s.key || boardInView(s);
  };

  const paint = () => {
    const s = current && current.key !== dismissed ? current : null;
    strip.hidden = s === null;
    placeToast();
    if (!s) return;
    strip.dataset.kind = s.kind;
    strip.dataset.tone = s.tone;
    toast.dataset.tone = s.tone;
    const words = `${s.lead}${s.text}`;
    if (words !== wordsKey) {
      wordsKey = words;
      replace(msg, h("strong", {}, s.lead), s.text);
      // On a phone the toast keeps to its lead (styles.css hides the rest and "Run again").
      replace(toastMsg, h("strong", {}, s.lead), h("span", { class: "run-toast__text" }, s.text));
      live.textContent = words;
    }
    if (s.note !== noteKey) {
      noteKey = s.note;
      note.hidden = !s.note;
      replace(note, s.note ?? "");
    }
    const acts = `${s.actions.join(",")}|${s.incidentId ?? ""}`;
    if (acts !== actionsKey) {
      actionsKey = acts;
      replace(actions, s.actions.map((a) => actionEl(a, s)));
      replace(toastActions, s.actions.map((a) => actionEl(a, s)));
    }
  };

  if (typeof IntersectionObserver === "function") {
    // A strip under the sticky header counts as out of view; one just below the fold (a scroll away)
    // still counts as in view, so the toast is for a visitor who has really moved on.
    new IntersectionObserver(
      (entries) => {
        for (const e of entries) stripVisible = e.isIntersecting;
        paint();
      },
      { rootMargin: "-96px 0px 320px 0px" },
    ).observe(strip);
  }
  if (typeof addEventListener === "function") {
    let queued = false;
    const onScroll = () => {
      if (queued) return;
      queued = true;
      (typeof requestAnimationFrame === "function" ? requestAnimationFrame : (f: () => void) => setTimeout(f, 16))(() => {
        queued = false;
        placeToast();
      });
    };
    addEventListener("scroll", onScroll, { passive: true });
    addEventListener("resize", onScroll, { passive: true });
  }

  const update = () => {
    const now = Date.now();
    const run = session?.run;
    current = tracker.update({ runId: session?.runId, run, commands: session?.commands ?? [], idleSeconds: session?.idleSeconds, incidents, siem, now, waited });
    paint();
    const pending = run !== undefined && siem !== "unavailable" && siemPending({ run, commands: session?.commands ?? [], incidents, now, waited });
    if (pending && session && eagerSince?.runId !== session.runId) eagerSince = { runId: session.runId, at: Date.now() };
    const next: RunReading = {
      runId: session?.runId,
      ownRuns: [...own],
      scenario: scenarioState({ run, incidents, ownRuns: own, siem, now, waited }),
      siem: run ? siemRow({ run, commands: session?.commands ?? [], incidents, siem, now, waited }) : { text: "nothing to correlate yet", tone: "idle" },
      eager: pending && eagerSince !== undefined && Date.now() - eagerSince.at <= EAGER_CAP_MS,
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
