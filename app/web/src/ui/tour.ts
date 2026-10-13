// The guided tour (site redesign 2026-10-12, ADR 0035 amendment; amended 2026-10-13): six steps in a
// panel beside the terminal on a wide screen, a compact "Step n of 6" bar above it on a phone. Each
// step names one real thing to do (a catalogue command, a one-click scenario) and is ticked from the
// events the page already has — the visitor's own runs as the timeline assembled them and the SIEM's
// incidents for them — so a reload re-derives the same progress and nothing is ticked that did not
// happen. Only "skipped" is stored.
//
// The panel also carries the notices: Falco's detection, Talon's response and the SIEM's incident for
// the visitor's own runs, each with the time and, where there is somewhere to go, a link the visitor
// may follow. Nothing here scrolls the page or moves the focus: a step completing, an incident landing
// or a run ending changes words in the panel (polite, live) and nothing else. On a phone the newest
// notice is a small toast at the bottom that keeps clear of the terminal's input, auto-hides and can
// be dismissed.
//
// The tour costs runs: one terminal session for steps 1-4 (`sh -i` ends it), one side-by-side run for
// step 5, out of the per-visitor limit. It says so.

import type { CorrelationIncident } from "../lib/contract";
import { type Child, h, plClock, replace } from "../lib/dom";
import { SIEM_COMMAND, lastResponse } from "../lib/runstatus";
import type { RunView } from "../lib/timeline";
import { ts } from "../lib/timeline";

export interface TourStep {
  id: string;
  title: string;
  hint: string;
  /** The catalogue command the button picks (steps that run in the terminal). */
  command?: string;
  /** The one-click scenario the button launches (the twin step). */
  scenario?: string;
  /** What the completed line reads. */
  done: string;
}

export const STEPS: readonly TourStep[] = [
  { id: "look", title: "Look around", hint: "Open the terminal and run id (or any look-around command) — plain recon raises no alarm.", command: "whoami", done: "You looked around: a non-root user in a hardened pod." },
  { id: "tamper", title: "Break something", hint: "Deface the shop, then read the run's flag. Both are allowed — detection is not prevention.", command: "deface", done: "You defaced the shop and read the flag; nothing stopped you." },
  { id: "hide", title: "Hide it in DNS", hint: "Smuggle the flag out in a DNS name. Falco has no rule for name lookups.", command: SIEM_COMMAND, done: "You sent the flag out in a DNS query; Falco saw nothing." },
  { id: "caught", title: "Get caught", hint: "Open a shell with sh -i. Falco detects it and Talon deletes the pod — watch the diagram.", command: "shell", done: "Falco caught the shell and Talon deleted the pod, in milliseconds." },
  { id: "compare", title: "See what the answer is worth", hint: "Run the same attack with and without the response, side by side. (Costs one more run.)", scenario: "shell-in-container", done: "Side by side: the guarded pod died, the unguarded one stayed owned." },
  { id: "siem", title: "See it in the SIEM", hint: "A minute or two later the SIEM files the DNS trick Falco missed. A notice here says when it lands.", done: "The SIEM caught the DNS exfiltration that Falco could not." },
];

export interface TourProgress {
  /** Done step ids. */
  done: Set<string>;
  /** The first not-done step, or undefined when all are done. */
  current?: TourStep;
}

/** One notice in the panel: what happened to the visitor's run, when, and where to see it. */
export interface TourNotice {
  /** Stable across derivations: the same event is the same notice. */
  id: string;
  kind: "falco" | "talon" | "siem";
  /** Epoch ms, for the order. */
  at: number;
  text: string;
  /** An in-page link the visitor may follow (never followed for them). */
  link?: { href: string; label: string };
}

const SKIP_KEY = "sdp:tour-skipped";
/** Beside the terminal from here up (styles.css: the attack stage's two columns). */
export const WIDE_QUERY = "(min-width: 1100px)";
/** How long the phone toast stays unless dismissed. */
const TOAST_MS = 9_000;
const NOTICES_MAX = 6;
/** A notice older than this when first listed (a reload re-listing what the visitor saw) raises no toast. */
const FRESH_MS = 60_000;

function skipped(): boolean {
  try {
    return localStorage.getItem(SKIP_KEY) === "1";
  } catch {
    return false;
  }
}

function setSkipped(v: boolean): void {
  try {
    if (v) localStorage.setItem(SKIP_KEY, "1");
    else localStorage.removeItem(SKIP_KEY);
  } catch {
    // Not persisted; the choice holds for this page view.
  }
}

/**
 * Which steps are done, from the visitor's own runs (commands they ran, as the timeline assembled
 * them) and the SIEM's incidents for those runs. A later step done implies the terminal ones before
 * it (you cannot reach step 4 without the pod having run), but each is still read from its own
 * evidence where there is any.
 */
export function deriveProgress(runs: readonly RunView[], incidents: readonly CorrelationIncident[], ownRunIds: ReadonlySet<string>): TourProgress {
  const done = new Set<string>();
  const ran = (cmd: string) => runs.some((r) => r.commands.some((c) => c.id === cmd && c.endedAt !== undefined));
  const reached = (cmd: string) => runs.some((r) => r.commands.some((c) => c.id === cmd && c.achieved));
  if (ran("whoami") || ran("hostname") || ran("ps") || ran("ls-shop") || ran("caps")) done.add("look");
  // Both: the shop defaced and the flag read (the step's done line says so).
  if (reached("deface") && reached("read-flag")) done.add("tamper");
  if (reached(SIEM_COMMAND)) done.add("hide");
  // Caught: a terminal session of the visitor's in which the shell ran and the pod was then
  // terminated — not any one-click run the cluster killed.
  const terminated = (r: RunView) => r.detail === "killed" || r.talon.some((t) => t.arm !== "unguarded" && /terminate/i.test(`${t.actionner ?? ""} ${t.action}`));
  if (runs.some((r) => r.scenario === "terminal" && r.commands.some((c) => c.id === "shell") && terminated(r))) done.add("caught");
  // Compared: a side-by-side run of the visitor's (two pods).
  if (runs.some((r) => r.armPods !== undefined)) done.add("compare");
  // Filed: a SIEM incident of the DNS exfil kind for one of the visitor's runs.
  if (incidents.some((i) => i.kind === SIEM_COMMAND && ownRunIds.has(i.run_id))) done.add("siem");
  const current = STEPS.find((s) => !done.has(s.id));
  return { done, current };
}

/**
 * The notices, newest first, from the same evidence: Falco's alerts and Talon's response on the
 * visitor's own runs (the guarded arm of a side-by-side run; the unguarded one is the point of it),
 * and the SIEM's incidents for them. Derived, like the progress: a reload shows the same notices.
 */
export function deriveNotices(runs: readonly RunView[], incidents: readonly CorrelationIncident[], ownRunIds: ReadonlySet<string>, now: number = Date.now()): TourNotice[] {
  const out: TourNotice[] = [];
  for (const r of runs) {
    if (!ownRunIds.has(r.runId)) continue;
    for (const f of r.falco) {
      if (f.arm === "unguarded") continue;
      const at = ts(f.at);
      out.push({ id: `falco:${r.runId}:${f.at}:${f.rule}`, kind: "falco", at, text: `Falco detected: ${f.rule} at ${plClock(at, now)}.` });
    }
    const resp = lastResponse(r);
    if (resp) {
      out.push({
        id: `talon:${r.runId}:${resp.action}`,
        kind: "talon",
        at: resp.at,
        text: `${resp.action === "terminate" ? "Talon deleted the pod" : "Talon quarantined the pod"} at ${plClock(resp.at, now)}.`,
      });
    }
  }
  for (const i of incidents) {
    if (!i.run_id || !ownRunIds.has(i.run_id)) continue;
    const at = ts(i.first_at);
    const what = i.kind === SIEM_COMMAND ? "The SIEM caught your DNS exfiltration" : `The SIEM filed an incident: ${i.title || i.kind}`;
    out.push({ id: `siem:${i.id}`, kind: "siem", at, text: `${what} — incident filed at ${plClock(at, now)}.`, link: { href: `#incident-${i.id}`, label: "Show in SIEM" } });
  }
  out.sort((a, b) => b.at - a.at);
  return out.slice(0, NOTICES_MAX);
}

export interface TourHandle {
  /** The newest derivation: the visitor's runs, the incidents, which runs are theirs. */
  update(runs: readonly RunView[], incidents: readonly CorrelationIncident[], ownRunIds: ReadonlySet<string>): void;
  /** The terminal drives the tour; on an API without one it is removed, not merely hidden. */
  setEnabled(enabled: boolean): void;
}

export interface TourHooks {
  /** A step's button: the command to pick in the terminal. */
  onCommand(commandId: string): void;
  /** A step's button: the scenario to launch. */
  onScenario(scenarioId: string): void;
  /** The "caught" step's done button: show the kill timeline (the visitor asked to go there). */
  onTimeline(): void;
  /** Where the phone toast lives; document.body in the page. */
  toastParent?: HTMLElement;
  /** Test seam: the wide/narrow query (window.matchMedia in the page). */
  matchMedia?: (q: string) => MediaQueryList;
}

/**
 * `root`: the tour mount beside the terminal. The hooks answer the visitor's own presses; nothing
 * here scrolls or moves the focus on its own.
 */
export function mountTour(root: HTMLElement, hooks: TourHooks): TourHandle {
  let progress: TourProgress = { done: new Set(), current: STEPS[0] };
  let notices: TourNotice[] = [];
  let shown = skipped();
  let enabled = true;
  // On a phone the bar starts folded: the terminal stays near the top; the current step's button is in the bar.
  let expanded = false;
  const mm = hooks.matchMedia ?? (typeof matchMedia === "function" ? matchMedia : undefined);
  const wideQuery = mm?.(WIDE_QUERY);
  const wide = () => wideQuery?.matches ?? true;
  // The notices' live list is kept across redraws, so a screen reader hears what was added, not the
  // whole list again.
  const noticeList = h("ol", { class: "tour__notices", role: "list", "aria-live": "polite", "aria-relevant": "additions" });
  const noticeHead = h("h3", { class: "tour__nhead", id: "tour-nhead" }, "Notices");
  // Above the steps, so the newest news is the first thing in the panel; not there at all while empty.
  const noticeSec = h("section", { class: "tour__nsec", "aria-labelledby": "tour-nhead", hidden: true }, noticeHead, noticeList);

  // ---- the phone toast ----
  const toastMsg = h("p", { class: "tour-toast__msg" });
  const toastAct = h("span", { class: "tour-toast__act" });
  const toastClose = h("button", { type: "button", class: "tour-toast__close", "aria-label": "Dismiss this notice" }, "×");
  const toast = h("div", { class: "tour-toast", role: "status", hidden: true, "data-kind": "" }, toastMsg, toastAct, toastClose);
  let toastTimer: ReturnType<typeof setTimeout> | undefined;
  const hideToast = () => {
    toast.hidden = true;
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = undefined;
  };
  toastClose.addEventListener("click", hideToast);
  /** Above the terminal's input when the toast would cover it; otherwise at the bottom. */
  const placeToast = () => {
    if (toast.hidden || typeof document === "undefined") return;
    const input = document.querySelector<HTMLElement>("#term-input, .term__form");
    const vh = window.innerHeight || document.documentElement.clientHeight;
    const band = vh - (toast.offsetHeight || 48) - 16;
    let covers = false;
    if (input && input.getClientRects().length) {
      const r = input.getBoundingClientRect();
      covers = r.bottom > band && r.top < vh;
    }
    toast.dataset.pos = covers ? "top" : "bottom";
  };
  const showToast = (n: TourNotice) => {
    if (!hooks.toastParent) return;
    // The run's own toast (ui/runstatus.ts) is up with the same news: one toast is enough.
    if (document.querySelector(".run-toast:not([hidden])")) return;
    if (!toast.isConnected) hooks.toastParent.append(toast);
    toast.dataset.kind = n.kind;
    replace(toastMsg, n.text);
    replace(toastAct, n.link ? link(n.link) : null);
    toast.hidden = false;
    placeToast();
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(hideToast, TOAST_MS);
  };
  if (typeof addEventListener === "function") addEventListener("scroll", placeToast, { passive: true });
  // The toast's link followed: it has done its job.
  toastAct.addEventListener("click", hideToast);

  const link = (l: { href: string; label: string }) => h("a", { class: "btn btn--ghost btn--small tour__btn", href: l.href }, l.label);

  const noticeItem = (n: TourNotice) =>
    h("li", { class: `tour__notice tour__notice--${n.kind}`, "data-id": n.id, "data-kind": n.kind }, h("span", { class: "tour__nmark", "aria-hidden": "true" }), h("span", { class: "tour__ntext" }, n.text), n.link ? h("span", { class: "tour__nact" }, link(n.link)) : null);

  /** Adds the notices not yet listed (in place: the list is live), newest first; drops the oldest past the cap. */
  const syncNotices = () => {
    const listed = new Set([...noticeList.children].map((el) => (el as HTMLElement).dataset.id));
    const fresh = notices.filter((n) => !listed.has(n.id));
    // Oldest of the fresh first, so each goes to the top in order.
    for (const n of [...fresh].reverse()) noticeList.prepend(noticeItem(n));
    while (noticeList.children.length > NOTICES_MAX) noticeList.lastElementChild?.remove();
    noticeSec.hidden = noticeList.children.length === 0;
    // The toast says the newest one, on a narrow screen only, and only news: a reload re-lists what
    // the visitor already saw without raising it again.
    const newest = fresh[0];
    if (newest && !wide() && Date.now() - newest.at < FRESH_MS) showToast(newest);
  };

  const stepItem = (s: TourStep, i: number) => {
    const isDone = progress.done.has(s.id);
    const isCurrent = progress.current?.id === s.id;
    const act = isCurrent ? action(s, isDone) : isDone ? doneAction(s) : null;
    return h(
      "li",
      { class: "tour__step", "data-id": s.id, "data-done": String(isDone), "data-current": String(isCurrent), "aria-current": isCurrent ? "step" : undefined },
      h("span", { class: "tour__mark", "aria-hidden": "true" }, isDone ? "✓" : String(i + 1)),
      h(
        "div",
        { class: "tour__body" },
        h("p", { class: "tour__title" }, s.title, isDone ? h("span", { class: "visually-hidden" }, " (done)") : null),
        // The current step carries its hint; a done one only its tick and, where there is one, its
        // way there — the panel stays short enough to sit beside the terminal whole.
        isCurrent ? h("p", { class: "tour__hint" }, s.hint) : null,
        act ? h("p", { class: "tour__act" }, act) : null,
      ),
    );
  };

  /** The current step's button: a command to pick, a scenario to launch. */
  const action = (s: TourStep, again: boolean): Child => {
    if (s.command) return button(again ? "Run it again" : "Do this step", () => hooks.onCommand(s.command as string));
    if (s.scenario) return button(again ? "Run it again" : "Launch side by side", () => hooks.onScenario(s.scenario as string));
    return null;
  };

  /** A done step's way to where it happened: offered, never taken for the visitor. */
  const doneAction = (s: TourStep): Child => {
    if (s.id === "caught") return button("Watch the kill timeline", () => hooks.onTimeline());
    if (s.id === "compare") return link({ href: "#console", label: "Show the live run" });
    if (s.id === "siem") {
      const inc = notices.find((n) => n.kind === "siem");
      return link({ href: inc?.link?.href ?? "#correlation", label: "Show in SIEM" });
    }
    return null;
  };

  const draw = () => {
    if (!enabled) {
      replace(root);
      return;
    }
    if (shown) {
      replace(
        root,
        h(
          "p",
          { class: "tour tour--skipped" },
          "Tour hidden. ",
          button("Show the guided tour", () => {
            setSkipped(false);
            shown = false;
            draw();
          }),
        ),
      );
      return;
    }
    const total = STEPS.length;
    const current = progress.current;
    const complete = progress.done.size === total;
    const isWide = wide();
    const open = isWide || expanded;
    // The current step's number (steps can complete out of order: getting caught before the DNS trick).
    const stepN = current ? STEPS.indexOf(current) + 1 : total;
    const count = h("p", { class: "tour__count" }, complete ? "Tour complete" : `Step ${stepN} of ${total}`, h("span", { class: "tour__cost" }, " · uses two of your runs"));
    // On a phone the head is the bar: the count, the current step's title and button, and the toggle.
    const toggle = isWide
      ? null
      : (() => {
          const b = h("button", { type: "button", class: "tour__toggle", "aria-expanded": String(open), "aria-controls": "tour-steps" }, h("span", { class: "tour__toggle-text" }, open ? "Hide the steps" : "Show the steps"), h("span", { class: "tour__chevron", "aria-hidden": "true" }));
          b.addEventListener("click", () => {
            expanded = !expanded;
            draw();
          });
          return b;
        })();
    const barStep = !isWide && !open && current ? h("p", { class: "tour__barstep" }, h("span", { class: "tour__bartitle" }, current.title), " ", action(current, false)) : null;
    const skip = button("Skip the tour", () => {
      setSkipped(true);
      shown = true;
      draw();
    });
    replace(
      root,
      h(
        "div",
        { class: "tour", "data-complete": String(complete), "data-layout": isWide ? "side" : "bar", "data-open": String(open) },
        h("div", { class: "tour__head" }, count, toggle, isWide ? skip : null),
        barStep,
        h(
          "div",
          { class: "tour__panel", id: "tour-steps", hidden: !open },
          noticeSec,
          h("ol", { class: "tour__list", role: "list" }, STEPS.map(stepItem)),
          isWide ? null : h("p", { class: "tour__foot" }, skip),
        ),
      ),
    );
    // The list is live where it can be seen as it changes; on a phone the toast speaks instead.
    noticeList.setAttribute("aria-live", isWide ? "polite" : "off");
  };

  draw();
  syncNotices();
  wideQuery?.addEventListener?.("change", () => {
    hideToast();
    draw();
  });

  return {
    setEnabled(next) {
      if (enabled === next) return;
      enabled = next;
      draw();
    },
    update(runs, incidents, ownRunIds) {
      if (!enabled) return;
      progress = deriveProgress(runs, incidents, ownRunIds);
      notices = deriveNotices(runs, incidents, ownRunIds);
      draw();
      syncNotices();
    },
  };
}

function button(label: string, onClick: () => void): HTMLButtonElement {
  const b = h("button", { type: "button", class: "btn btn--ghost btn--small tour__btn" }, label);
  b.addEventListener("click", onClick);
  return b;
}
