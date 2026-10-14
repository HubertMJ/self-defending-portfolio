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
// The tour costs runs: one terminal session for steps 1-4 (getting caught ends it), one side-by-side run for
// step 5, out of the per-visitor limit. It says so.

import type { CatalogueCommand, CorrelationIncident } from "../lib/contract";
import { type Child, h, plClock, replace } from "../lib/dom";
import { SIEM_COMMAND, lastResponse } from "../lib/runstatus";
import type { CommandRun, RunView } from "../lib/timeline";
import { formatDuration, ts } from "../lib/timeline";
import type { LaunchState } from "./scenarios";
import { heldMs } from "./twin";

export interface TourStep {
  id: string;
  title: string;
  hint: string;
  /** The catalogue command the button picks (steps that run in the terminal). */
  command?: string;
  /** The step's second command, picked once the first has reached its objective (break something: the flag after the deface). */
  then?: string;
  /** The one-click scenario the button launches (the twin step). */
  scenario?: string;
  /** What the completed line reads. */
  done: string;
}

export const STEPS: readonly TourStep[] = [
  { id: "look", title: "Look around", hint: "Open the terminal and run id (or any look-around command) — plain recon raises no alarm.", command: "whoami", done: "You looked around: a non-root user in a hardened pod." },
  { id: "tamper", title: "Break something", hint: "Deface the shop, then read the run's flag. Both are allowed — detection is not prevention.", command: "deface", then: "read-flag", done: "You defaced the shop and read the flag; nothing stopped you." },
  { id: "hide", title: "Hide it in DNS", hint: "Smuggle the flag out in a DNS name. Falco has no rule for name lookups.", command: SIEM_COMMAND, done: "You sent the flag out in a DNS query; Falco saw nothing." },
  { id: "caught", title: "Get caught", hint: "Open a shell with sh -i, or run any other command Falco detects. Talon answers on your pod — watch the diagram.", command: "shell", done: "Falco caught you and Talon answered on your pod, in milliseconds." },
  { id: "compare", title: "See what the answer is worth", hint: "Run the same attack with and without the response, side by side. (Costs one more run.)", scenario: "shell-in-container", done: "You ran it side by side: one pod with the response, one without." },
  { id: "siem", title: "See it in the SIEM", hint: "A minute or two later the SIEM files your run as an incident — even the DNS trick Falco missed. A notice here says when it lands.", done: "The SIEM filed an incident for your run." },
];

export interface TourProgress {
  /** Done step ids. */
  done: Set<string>;
  /** The first not-done step, or undefined when all are done. */
  current?: TourStep;
  /** The run that completed a step with somewhere to go back to: the session caught, the side-by-side run. */
  runs: { caught?: string; compare?: string };
}

/** One notice in the panel: what happened to the visitor's run, when, and where to see it. */
export interface TourNotice {
  /** Stable across derivations: the same event is the same notice. */
  id: string;
  kind: "falco" | "talon" | "siem";
  /** Epoch ms: the event's own time (for the SIEM, the first event of the incident, not its filing). */
  at: number;
  /** The words before the time ("Falco detected: Terminal shell in container"). */
  what: string;
  /** How the clock joins `what`: "at" for a moment, "first seen" for an incident, whose first event this is. */
  join: "at" | "first seen";
  /** An in-page link the visitor may follow (never followed for them). */
  link?: { href: string; label: string };
}

/** The notice's sentence, on `now`'s day: "Falco detected: X at 20:00:05 CEST.", "The SIEM caught … (first seen 20:02:00 CEST)." (with the date when not today). */
export function noticeText(n: TourNotice, now: number = Date.now()): string {
  const clock = plClock(n.at, now);
  return n.join === "at" ? `${n.what} at ${clock}.` : `${n.what} (first seen ${clock}).`;
}

const SKIP_KEY = "sdp:tour-skipped";
/** Beside the terminal from here up (styles.css: the attack stage's two columns). */
export const WIDE_QUERY = "(min-width: 1100px)";
/** How long the phone toast stays unless dismissed. */
const TOAST_MS = 9_000;
const NOTICES_MAX = 6;
/** The notices the side panel shows open; the rest behind "Earlier notices (n)", so it never scrolls inside. */
const NOTICES_OPEN = 2;
/**
 * A notice listed within this long of the mount is what the page already knew (a reload re-listing
 * the visitor's earlier runs and incidents as the feed's replay and the first correlation poll come
 * in): no toast. After it, a new notice is news. Not the notice's own time: the SIEM files an
 * incident minutes after the event it dates.
 */
export const SETTLE_MS = 8_000;

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
 * them, with Falco's and Talon's events on their pods) and the SIEM's incidents for those runs. Each
 * step ticks on the outcome its text names, whichever command got there (2026-10-14): the catalogue
 * (`commands`, the terminal's own) says which objective and outcome a command has; the step's button
 * only suggests one. Without the catalogue the command steps cannot be read and stay open.
 */
export function deriveProgress(
  runs: readonly RunView[],
  incidents: readonly CorrelationIncident[],
  ownRunIds: ReadonlySet<string>,
  commands: readonly CatalogueCommand[] = [],
): TourProgress {
  const done = new Set<string>();
  const own = runs.filter((r) => ownRunIds.has(r.runId));
  const sessions = own.filter((r) => r.scenario === "terminal");
  const byId = new Map(commands.map((c) => [c.id, c]));
  /** A command of the visitor's sessions, with its catalogue entry, that `ok` accepts. */
  const some = (ok: (c: CommandRun, k: CatalogueCommand) => boolean) =>
    sessions.some((r) => r.commands.some((c) => {
      const k = byId.get(c.id);
      return k !== undefined && ok(c, k);
    }));
  // Looked around: any recon command that ran to its end (plain recon raises no alarm).
  if (some((c, k) => k.objective === "recon" && c.endedAt !== undefined)) done.add("look");
  // Both: the shop defaced (the tamper objective reached) and the flag read (a credentials command on
  // the run's .flag that succeeded) - the step's done line says so.
  const flag = (k: CatalogueCommand) => k.objective === "credentials" && k.command.some((a) => /\/\.flag$/.test(a));
  if (some((c, k) => c.achieved && k.objective === "tamper") && some((c, k) => c.achieved && flag(k))) done.add("tamper");
  // Hidden: the flag sent out by a command Falco has no rule for - exfiltration the catalogue calls
  // allowed (only the SIEM sees it), and it succeeded.
  if (some((c, k) => c.achieved && k.objective === "exfiltration" && k.outcome === "allowed")) done.add("hide");
  // Caught: a terminal session of the visitor's in which Falco detected something on its pod and
  // Talon then acted on that pod (terminate or quarantine), whatever command it was - not any
  // one-click run the cluster killed.
  // (Talon acts only on Falco's alerts; their clocks differ, so the order is not compared.)
  const caught = sessions.find((r) => r.falco.some((f) => f.arm !== "unguarded") && lastResponse(r) !== undefined);
  if (caught) done.add("caught");
  // Compared: a side-by-side run of the visitor's, both pods seen.
  const compare = own.find((r) => r.armPods !== undefined || (r.pods.length > 0 && r.unguardedPods.length > 0));
  if (compare) done.add("compare");
  // Filed: a SIEM incident, of any kind, for one of the visitor's runs.
  if (incidents.some((i) => ownRunIds.has(i.run_id))) done.add("siem");
  const current = STEPS.find((s) => !done.has(s.id));
  return { done, current, runs: { caught: caught?.runId, compare: compare?.runId } };
}

/**
 * The notices, newest first, from the same evidence: Falco's alerts and Talon's response on the
 * visitor's own runs (the guarded arm of a side-by-side run; the unguarded one is the point of it),
 * and the SIEM's incidents for them. Derived, like the progress: a reload shows the same notices.
 */
export function deriveNotices(runs: readonly RunView[], incidents: readonly CorrelationIncident[], ownRunIds: ReadonlySet<string>): TourNotice[] {
  const out: TourNotice[] = [];
  for (const r of runs) {
    if (!ownRunIds.has(r.runId)) continue;
    for (const f of r.falco) {
      if (f.arm === "unguarded") continue;
      const at = ts(f.at);
      out.push({ id: `falco:${r.runId}:${f.at}:${f.rule}`, kind: "falco", at, what: `Falco detected: ${f.rule}`, join: "at" });
    }
    const resp = lastResponse(r);
    if (resp) {
      out.push({
        id: `talon:${r.runId}:${resp.action}`,
        kind: "talon",
        at: resp.at,
        what: resp.action === "terminate" ? "Talon deleted the pod" : "Talon quarantined the pod",
        join: "at",
      });
    }
  }
  for (const i of incidents) {
    if (!i.run_id || !ownRunIds.has(i.run_id)) continue;
    const at = ts(i.first_at);
    // The API publishes the incident's first and last event, not when the SIEM filed it (ADR 0036):
    // the notice dates the attack it caught, not the filing.
    const what = i.kind === SIEM_COMMAND ? "The SIEM caught your DNS exfiltration" : `The SIEM filed an incident: ${i.title || i.kind}`;
    out.push({ id: `siem:${i.id}`, kind: "siem", at, what, join: "first seen", link: { href: `#incident-${i.id}`, label: "Show in SIEM" } });
  }
  out.sort((a, b) => b.at - a.at);
  return out.slice(0, NOTICES_MAX);
}

export interface TourHandle {
  /** The newest derivation: the visitor's runs, the incidents, which runs are theirs. */
  update(runs: readonly RunView[], incidents: readonly CorrelationIncident[], ownRunIds: ReadonlySet<string>): void;
  /** The terminal drives the tour; on an API without one it is removed, not merely hidden. */
  setEnabled(enabled: boolean): void;
  /** The terminal's catalogue: which objective and outcome each command has, read by the steps. */
  setCatalogue(commands: readonly CatalogueCommand[]): void;
  /** What the one-click launcher says and allows: step 5's button and its line in the rail. */
  setLaunch(s: LaunchState): void;
}

/**
 * One pod of the side-by-side run as step 5 says it, live: `state` changes only when something
 * happened (it is announced), `since` is when the count beside it began (the unguarded pod still
 * running after its detection: the count ticks every second and is never announced).
 */
export interface ArmLine {
  state: string;
  since?: number;
}

/**
 * The side-by-side run in two lines, for the rail: what each pod has got so far. Without the run
 * (the press accepted, its first event not in yet) both are starting.
 */
export function liveLines(run: RunView | undefined, now: number = Date.now()): { guarded: ArmLine; unguarded: ArmLine } {
  if (!run) return { guarded: { state: "Starting…" }, unguarded: { state: "Starting…" } };
  const running = (pods: RunView["pods"]) => pods.some((p) => /running/i.test(p.phase));
  const gFalco = run.falco.find((f) => f.arm !== "unguarded");
  const uFalco = run.falco.find((f) => f.arm === "unguarded");
  const resp = lastResponse(run);
  const ms = resp?.afterAlertMs ?? run.timings.respondMs;
  const detected = (at: string) => `Falco detected it at ${plClock(at, now)}`;
  const guarded: ArmLine = resp
    ? { state: `${gFalco ? `${detected(gFalco.at)}; ` : ""}Talon ${resp.action === "terminate" ? "deleted" : "quarantined"} the pod${ms !== undefined ? ` in ${formatDuration(ms)}` : ""}.` }
    : gFalco
      ? { state: `${detected(gFalco.at)}; waiting for Talon.` }
      : !run.active
        ? { state: "Ended: no detection." }
        : run.states.pod_ready !== undefined || running(run.pods)
          ? { state: "Pod running." }
          : { state: "Starting the pod…" };
  const uEnded = !run.active || run.unguardedPods.some((p) => p.deleted);
  const held = heldMs(run, now);
  const unguarded: ArmLine = uFalco
    ? uEnded
      ? { state: `${detected(uFalco.at)}; nothing answered${held !== undefined ? `: held for ${formatDuration(held)}` : ""}.` }
      : { state: `${detected(uFalco.at)}; nothing answered: still running`, since: ts(uFalco.at) }
    : uEnded
      ? { state: "Ended: no detection." }
      : running(run.unguardedPods)
        ? { state: "Pod running." }
        : { state: "Starting the pod…" };
  return { guarded, unguarded };
}

/** The count beside a still-running pod: whole seconds, so it changes once a second and no faster. */
export function countText(since: number, now: number): string {
  const sec = Math.max(0, Math.floor((now - since) / 1000));
  return `, ${sec < 60 ? `${sec} s` : `${Math.floor(sec / 60)} min ${sec % 60} s`} and counting.`;
}

export interface TourHooks {
  /** A step's button: the command to pick in the terminal (the visitor asked to go there); `step` is its number, for the target's "Step n" tag. */
  onCommand(commandId: string, step: number): void;
  /** A step's button: the scenario to launch. */
  onScenario(scenarioId: string, step: number): void;
  /** The step whose button was pressed is done: its target's mark goes. */
  onStepDone?(): void;
  /** What a catalogue command types ("id" for whoami), for the step's command chip; undefined until the catalogue is in. */
  commandInput?(commandId: string): string | undefined;
  /** The "caught" step's done button: show this session's kill timeline (the visitor asked to go there). */
  onTimeline(): void;
  /** Whether the terminal shows that run now, so its kill timeline is there to watch. */
  showsRun?(runId: string): boolean;
  /** Step 5's "Watch it side by side": put that run in the live-run console, open it (in the default view too) and go there. */
  onShowRun(runId: string): void;
  /** Where the phone toast lives; document.body in the page. */
  toastParent?: HTMLElement;
  /** Below the terminal: where the phone's opened steps and notices go, so nothing above it grows. */
  below?: HTMLElement;
  /** Test seam: the clock. */
  now?: () => number;
  /** Test seam: the wide/narrow query (window.matchMedia in the page). */
  matchMedia?: (q: string) => MediaQueryList;
}

/**
 * `root`: the tour mount beside the terminal. The hooks answer the visitor's own presses; nothing
 * here scrolls or moves the focus on its own.
 */
export function mountTour(root: HTMLElement, hooks: TourHooks): TourHandle {
  const now = hooks.now ?? Date.now;
  let progress: TourProgress = { done: new Set(), current: STEPS[0], runs: {} };
  let notices: TourNotice[] = [];
  /** The step whose button the visitor pressed last: its target stays marked until the step is done. */
  let pressed: string | undefined;
  /** The commands that have reached their objective in the visitor's runs (which of a step's two to offer). */
  let reached = new Set<string>();
  /**
   * Step 5's run, shown live under the step once step 5 was pressed in this page view: the newest
   * side-by-side run since the press. A run launched from a card (Technical Mode) does not grow the
   * rail under the visitor; after a reload the done step offers its way to the console instead.
   */
  let liveRun: RunView | undefined;
  /** The runs there were when step 5 was pressed: the run it started is the first one not among them. */
  let launchedFrom: Set<string> | undefined;
  let lastRuns: readonly RunView[] = [];
  let liveTimer: ReturnType<typeof setInterval> | undefined;
  let launch: LaunchState = { blocked: null };
  /** The terminal's catalogue (which objective and outcome each command has), and the last update's evidence to re-read with it. */
  let catalogue: readonly CatalogueCommand[] = [];
  let last: { runs: readonly RunView[]; incidents: readonly CorrelationIncident[]; ownRunIds: ReadonlySet<string> } | undefined;
  // Step 5's line: what the launcher said (a polite live region kept across redraws), and the blocked
  // reason with the cooldown, in the rail where the one-click cards may be hidden (default view).
  const launchText = h("span", {});
  // A timer (not live): the wait, said with the line and read on request, never every second.
  const launchCount = h("span", { class: "tour__launchcount", role: "timer" });
  // While step 5 is current, in both views (2026-10-13 c): in Technical Mode the launcher's own line
  // is far below the rail, where a press on step 5 seemed to do nothing.
  const launchLine = h("p", { class: "tour__launch", id: "tour-launch", "aria-live": "polite" }, launchText, launchCount);
  const tagLaunch = (current: boolean) => {
    launchLine.classList.toggle("tech-less", !current);
    return launchLine;
  };
  const syncLaunch = () => {
    const msg = launch.text?.replace(/ Watch it play out in the live run below\.$/, " Both pods show here as it plays out.");
    // Why the button is off (a run in progress, a cooldown, the request in flight), then what was said.
    // A cooldown's own message says why and how long: no "Rate limited." before it.
    const reason = !launch.blocked || (launch.countdown && msg) ? "" : /[.…]$/.test(launch.blocked) ? launch.blocked : `${launch.blocked}.`;
    const text = [reason, msg ?? ""].filter(Boolean).join(" ");
    if (launchText.textContent !== text) launchText.textContent = text;
    launchCount.textContent = launch.countdown ? ` ${launch.countdown}` : "";
    launchLine.dataset.tone = launch.tone ?? "";
    for (const b of document.querySelectorAll<HTMLButtonElement>('[data-focus="step:compare"], [data-focus="bar"][data-scenario]')) markLaunch(b);
  };
  /** Step 5's button follows the launcher: off while blocked, "Starting…" while its request is in flight. */
  const markLaunch = (b: HTMLButtonElement) => {
    b.setAttribute("aria-disabled", String(launch.blocked !== null));
    if (launch.pending) b.setAttribute("aria-busy", "true");
    else b.removeAttribute("aria-busy");
    const label = launch.pending ? "Starting…" : (b.dataset.label ?? b.textContent ?? "");
    if (b.textContent !== label) b.textContent = label;
  };
  // Step 5's run, live in the rail (2026-10-14): each pod's state in a polite live region kept across
  // redraws, so a screen reader hears each change once; the count beside a pod still running is a
  // timer, read on request and never announced every second.
  const armState = { guarded: h("span", { class: "tour__armstate", "aria-live": "polite", "aria-atomic": "true" }), unguarded: h("span", { class: "tour__armstate", "aria-live": "polite", "aria-atomic": "true" }) };
  const armCount = { guarded: h("span", { class: "tour__armcount", role: "timer" }), unguarded: h("span", { class: "tour__armcount", role: "timer" }) };
  // The visitor's own press goes to the side-by-side view; nothing goes there for them.
  const watchBtn = button("Watch it side by side ↓", () => {
    if (liveRun) hooks.onShowRun(liveRun.runId);
  }, "watch", "btn btn--ghost btn--small tour__btn tour__watch", "Watch it side by side");
  const liveBox = h(
    "div",
    { class: "tour__live" },
    h(
      "dl",
      { class: "tour__twin" },
      h("div", {}, h("dt", {}, "With response"), h("dd", {}, armState.guarded, armCount.guarded)),
      h("div", {}, h("dt", {}, "Without response"), h("dd", {}, armState.unguarded, armCount.unguarded)),
    ),
    h("p", { class: "tour__act" }, watchBtn),
  );
  const syncLive = () => {
    const t = now();
    const l = liveLines(liveRun, t);
    let counting = false;
    for (const arm of ["guarded", "unguarded"] as const) {
      if (armState[arm].textContent !== l[arm].state) armState[arm].textContent = l[arm].state;
      const since = l[arm].since;
      const c = since !== undefined ? countText(since, t) : "";
      if (armCount[arm].textContent !== c) armCount[arm].textContent = c;
      if (since !== undefined) counting = true;
    }
    watchBtn.hidden = !liveRun;
    if (counting && !liveTimer) liveTimer = setInterval(syncLive, 1000);
    if (!counting && liveTimer) {
      clearInterval(liveTimer);
      liveTimer = undefined;
    }
  };
  const pickLive = () => {
    const sides = lastRuns.filter((r) => r.scenario !== "terminal");
    liveRun = launchedFrom ? sides.find((r) => !launchedFrom?.has(r.runId)) : undefined;
  };
  let shown = skipped();
  let enabled = true;
  // On a phone the bar starts folded: the terminal stays near the top; the current step's button is in the bar.
  let expanded = false;
  const mountedAt = now();
  // The first update that carries incidents: the first correlation poll's answer, which (after a
  // reload) lists what the SIEM filed earlier - known, not news, however late that poll comes.
  let incidentsSeen = false;
  const mm = hooks.matchMedia ?? (typeof matchMedia === "function" ? matchMedia : undefined);
  const wideQuery = mm?.(WIDE_QUERY);
  const wide = () => wideQuery?.matches ?? true;
  // The notices' live list is kept across redraws, so a screen reader hears what was added, not the
  // whole list again.
  const noticeList = h("ol", { class: "tour__notices", role: "list", "aria-live": "polite", "aria-relevant": "additions" });
  const noticeHead = h("h3", { class: "tour__nhead", id: "tour-nhead" }, "Notices");
  // The newest two show; the older ones open in place on the visitor's press (the list stays one live list).
  const moreBtn = h("button", { type: "button", class: "tour__more", "aria-expanded": "false", "aria-controls": "tour-notices", hidden: true, "data-focus": "more" });
  noticeList.id = "tour-notices";
  const noticeSec = h("section", { class: "tour__nsec", "aria-labelledby": "tour-nhead", hidden: true, "data-all": "false" }, noticeHead, noticeList, moreBtn);
  moreBtn.addEventListener("click", () => {
    const all = noticeSec.dataset.all !== "true";
    noticeSec.dataset.all = String(all);
    moreBtn.setAttribute("aria-expanded", String(all));
    syncMore();
  });
  const syncMore = () => {
    const older = Math.max(0, noticeList.children.length - NOTICES_OPEN);
    moreBtn.hidden = older === 0;
    moreBtn.textContent = noticeSec.dataset.all === "true" ? "Fewer notices" : `Earlier notices (${older})`;
  };
  // The steps and the notices: in the side panel on a wide screen; below the terminal on a phone,
  // where the bar above it keeps one fixed height whatever happens.
  const panel = h("div", { class: "tour__panel", id: "tour-steps", hidden: true });

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
    const vv = window.visualViewport;
    const vh = vv?.height ?? window.innerHeight ?? document.documentElement.clientHeight;
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
    replace(toastMsg, noticeText(n, now()));
    replace(toastAct, n.link ? link(n.link) : null);
    toast.hidden = false;
    placeToast();
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(hideToast, TOAST_MS);
  };
  if (typeof addEventListener === "function") {
    addEventListener("scroll", placeToast, { passive: true });
    addEventListener("resize", placeToast);
    // The keyboard up on a phone: the visual viewport shrinks and moves while the page's does not.
    window.visualViewport?.addEventListener("resize", placeToast);
    window.visualViewport?.addEventListener("scroll", placeToast);
  }
  // The toast's link followed: it has done its job.
  toastAct.addEventListener("click", hideToast);

  const link = (l: { href: string; label: string }, key?: string) => h("a", { class: "btn btn--ghost btn--small tour__btn", href: l.href, "data-focus": key }, l.label);

  const noticeItem = (n: TourNotice) =>
    h(
      "li",
      { class: `tour__notice tour__notice--${n.kind}`, "data-id": n.id, "data-kind": n.kind },
      h("span", { class: "tour__nmark", "aria-hidden": "true" }),
      h("span", { class: "tour__ntext" }, noticeText(n, now())),
      n.link ? h("span", { class: "tour__nact" }, link(n.link, `notice:${n.id}`)) : null,
    );

  /** Adds the notices not yet listed (in place: the list is live), newest first; drops the oldest past the cap. */
  const syncNotices = () => {
    const items = new Map([...noticeList.children].map((el) => [(el as HTMLElement).dataset.id, el as HTMLElement]));
    const fresh = notices.filter((n) => !items.has(n.id));
    // Oldest of the fresh first, so each goes to the top in order.
    for (const n of [...fresh].reverse()) noticeList.prepend(noticeItem(n));
    while (noticeList.children.length > NOTICES_MAX) noticeList.lastElementChild?.remove();
    // A listed notice's clock is re-read on `now`'s day: past midnight it gains its date.
    for (const n of notices) {
      const t = items.get(n.id)?.querySelector(".tour__ntext");
      const text = noticeText(n, now());
      if (t && t.textContent !== text) t.textContent = text;
    }
    noticeSec.hidden = noticeList.children.length === 0;
    syncMore();
    fit();
    // The toast says the newest one, on a narrow screen only, and only news: what the page lists in
    // its first seconds, or with the first incidents it hears of, is what it already knew before a reload.
    const newest = fresh[0];
    if (newest && !wide() && now() - mountedAt > SETTLE_MS && !(newest.kind === "siem" && !incidentsSeen)) showToast(newest);
    if (notices.some((n) => n.kind === "siem")) incidentsSeen = true;
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
        h("p", { class: "tour__title" }, h("span", { class: "tour__tname" }, s.title), isDone ? h("span", { class: "visually-hidden" }, " (done)") : null, isDone && !isCurrent ? act : null),
        // The current step carries its hint and its button; a done one is one line, its tick and,
        // where there is one, its way there - the panel sits beside the terminal whole, never scrolled.
        isCurrent ? h("p", { class: "tour__hint" }, s.hint) : null,
        isCurrent && act ? h("p", { class: "tour__act" }, act) : null,
        // In Technical Mode the cards and the console say all this where it happens: the rail stays
        // short, but the current step's own press is answered beside its button (2026-10-13 c).
        s.scenario && (isCurrent || isDone) ? tagLaunch(isCurrent) : null,
        s.scenario && (liveRun || launchedFrom) ? liveBox : null,
      ),
    );
  };

  /** The current step's button: a command to pick, a scenario to launch. */
  const action = (s: TourStep, again: boolean, key = `step:${s.id}`): Child => {
    const n = STEPS.indexOf(s) + 1;
    const press = (go: () => void) => () => {
      pressed = s.id;
      go();
    };
    if (s.command) {
      const id = s.then && reached.has(s.command) ? s.then : s.command;
      const input = key === "bar" ? undefined : hooks.commandInput?.(id);
      // The step's one command, as a chip: the visitor sees what it will type, and the press fills it
      // in the terminal (the full palette is in Technical Mode).
      if (input) {
        const chip = h("button", { type: "button", class: "tour__btn tour__cmd", "data-focus": key }, h("span", { class: "visually-hidden" }, "Run in the terminal: "), h("code", {}, input));
        chip.addEventListener("click", press(() => hooks.onCommand(id, n)));
        return chip;
      }
      return button(again ? "Run it again" : "Do this step", press(() => hooks.onCommand(id, n)), key);
    }
    if (s.scenario) {
      const label = again ? "Run it again" : "Launch side by side";
      const b = button(label, () => {
        // Blocked: the line under the step says why; nothing is sent.
        if (launch.blocked) return;
        // Pressed: the button says so at once, before the launcher's answer redraws it; both pods'
        // lines show under the step from now (on a phone the steps open below the terminal).
        launch = { ...launch, blocked: "Starting…", pending: true, tone: undefined, text: undefined, countdown: undefined };
        launchedFrom = new Set(lastRuns.map((r) => r.runId));
        liveRun = undefined;
        if (!wide()) expanded = true;
        syncLive();
        draw();
        press(() => hooks.onScenario(s.scenario as string, n))();
      }, key);
      b.dataset.scenario = s.scenario;
      b.dataset.label = label;
      b.setAttribute("aria-describedby", "tour-launch");
      markLaunch(b);
      return b;
    }
    return null;
  };

  /**
   * A done step's way to where it happened: offered, never taken for the visitor, and only where
   * the target is there to see. The kill timeline is in "This run" beside the terminal, for the
   * session the terminal shows now (a new session, or a reload, has its own). The side-by-side run's
   * way there is "Watch it side by side" under the step once pressed, else "Live run" (Technical Mode).
   */
  const doneAction = (s: TourStep): Child => {
    const key = `step:${s.id}`;
    const { caught, compare } = progress.runs;
    // On the done step's one line, short words; the full name for a screen reader, which carries them.
    if (s.id === "caught") return caught && (hooks.showsRun?.(caught) ?? true) ? button("Timeline", () => hooks.onTimeline(), key, "tour__doneact tech-more", "Watch the kill timeline") : null;
    // Without step 5's lines (a reload, a run from a card), the side-by-side run's way to the console.
    if (s.id === "compare") return compare && !launchedFrom ? button("Live run", () => hooks.onShowRun(compare), key, "tour__doneact tech-more", "Show the live run") : null;
    if (s.id === "siem") {
      const inc = notices.find((n) => n.kind === "siem");
      return h("a", { class: "tour__doneact", href: inc?.link?.href ?? "#correlation", "data-focus": key, "aria-label": "Show in SIEM" }, "SIEM");
    }
    return null;
  };

  /** The focused control's key, so a redraw under the keyboard puts the focus back on its equivalent. */
  const focusKey = (): string | undefined => {
    const el = document.activeElement;
    if (!(el instanceof HTMLElement) || !(root.contains(el) || panel.contains(el))) return undefined;
    return el.dataset.focus;
  };
  const refocus = (key: string | undefined) => {
    if (!key) return;
    const usable = (e: HTMLElement | null) => e && e.isConnected && !e.closest("[hidden]");
    const find = (sel: string) => [root, panel].map((m) => m.querySelector<HTMLElement>(sel)).find(usable);
    // A step's button that is gone (the step just completed and offers nothing): the current step's.
    const el = find(`[data-focus="${key}"]`) ?? (key.startsWith("step:") ? find('.tour__step[data-current="true"] [data-focus]') : undefined);
    el?.focus({ preventScroll: true });
  };

  /**
   * The side panel never scrolls inside (2026-10-13): it is compact enough to sit whole beside the
   * terminal, sticky under the header. Where it would still be taller than the screen under the
   * header (a short window), it lets go of sticky and goes with the page instead of being cut.
   */
  const fit = () => {
    const p = root.querySelector<HTMLElement>('.tour[data-layout="side"]');
    if (!p || typeof innerHeight !== "number") return;
    const header = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--header-h")) || 60;
    p.dataset.fits = String(p.offsetHeight <= innerHeight - header - 32);
  };
  if (typeof ResizeObserver === "function") new ResizeObserver(fit).observe(root);
  if (typeof addEventListener === "function") addEventListener("resize", fit);

  const draw = () => {
    const key = focusKey();
    if (!enabled) {
      replace(root);
      replace(panel);
      panel.hidden = true;
      return;
    }
    const total = STEPS.length;
    const current = progress.current;
    const complete = progress.done.size === total;
    const isWide = wide();
    const open = isWide || expanded;
    const skip = button("Skip the tour", () => {
      setSkipped(true);
      shown = true;
      draw();
    }, "skip", isWide ? "tour__skip" : undefined);
    const unskip = button("Show the guided tour", () => {
      setSkipped(false);
      shown = false;
      draw();
    }, "skip");
    // The panel: where it goes depends on the width; what it holds, on the tour being shown.
    const below = hooks.below;
    const home = isWide || !below ? null : below;
    if (home) {
      if (panel.parentElement !== home) home.append(panel);
    }
    replace(panel, shown ? noticeSec : [noticeSec, h("ol", { class: "tour__list", role: "list" }, STEPS.map(stepItem)), isWide ? null : h("p", { class: "tour__foot" }, skip)]);
    panel.hidden = !open || (shown && noticeSec.hidden);
    panel.dataset.layout = isWide ? "side" : "bar";
    if (shown) {
      // Hidden tour: one line and the way back; the notices stay (in the panel beside the terminal,
      // as a toast on a phone).
      replace(
        root,
        h(
          "div",
          { class: "tour tour--skipped", "data-layout": isWide ? "side" : "bar" },
          h("p", { class: "tour__skipline" }, "Tour hidden. ", unskip),
          isWide ? panel : null,
        ),
      );
      refocus(key);
      return;
    }
    // The current step's number (steps can complete out of order: getting caught before the DNS trick).
    const stepN = current ? STEPS.indexOf(current) + 1 : total;
    const count = h("p", { class: "tour__count" }, complete ? "Tour complete" : `Step ${stepN} of ${total}`);
    // What the tour costs, on its own small line under the head (the phone's bar has no room for it).
    const cost = isWide ? h("p", { class: "tour__cost" }, "Uses two of your runs.") : null;
    // On a phone the head is the bar, one fixed height: the count and the toggle, then the current
    // step's title (cut with an ellipsis) and its button; "Tour done" once there is no step left.
    const toggle = isWide
      ? null
      : (() => {
          const b = h("button", { type: "button", class: "tour__toggle", "aria-expanded": String(open), "aria-controls": "tour-steps", "data-focus": "toggle" }, h("span", { class: "tour__toggle-text" }, open ? "Hide the steps" : "Show the steps"), h("span", { class: "tour__chevron", "aria-hidden": "true" }));
          b.addEventListener("click", () => {
            expanded = !expanded;
            draw();
          });
          return b;
        })();
    const barStep = isWide ? null : h("p", { class: "tour__barstep" }, h("span", { class: "tour__bartitle" }, current ? current.title : "Tour done"), current ? action(current, false, "bar") : null);
    replace(
      root,
      h(
        "div",
        { class: "tour", "data-complete": String(complete), "data-layout": isWide ? "side" : "bar", "data-open": String(open) },
        h("div", { class: "tour__head" }, count, toggle, isWide ? skip : null),
        cost,
        barStep,
        isWide ? panel : null,
      ),
    );
    // The list is live where it can be seen as it changes; on a phone the toast speaks instead.
    noticeList.setAttribute("aria-live", isWide ? "polite" : "off");
    refocus(key);
    fit();
  };

  draw();
  syncNotices();
  wideQuery?.addEventListener?.("change", () => {
    hideToast();
    draw();
  });

  const handle: TourHandle = {
    setEnabled(next) {
      if (enabled === next) return;
      enabled = next;
      draw();
    },
    update(runs, incidents, ownRunIds) {
      if (!enabled) return;
      last = { runs, incidents, ownRunIds };
      progress = deriveProgress(runs, incidents, ownRunIds, catalogue);
      reached = new Set(runs.flatMap((r) => r.commands.filter((c) => c.achieved).map((c) => c.id)));
      if (pressed && progress.done.has(pressed)) {
        pressed = undefined;
        hooks.onStepDone?.();
      }
      notices = deriveNotices(runs, incidents, ownRunIds);
      lastRuns = runs;
      pickLive();
      syncLive();
      draw();
      syncNotices();
      syncLaunch();
    },
    setCatalogue(commands) {
      catalogue = commands;
      if (last) handle.update(last.runs, last.incidents, last.ownRunIds);
    },
    setLaunch(s) {
      launch = s;
      // The press refused (a limit, an error) and no run started: the lines go, the line above says why.
      if (launchedFrom && !liveRun && !s.pending && (s.tone === "warn" || s.tone === "error")) {
        launchedFrom = undefined;
        pickLive();
        syncLive();
        draw();
      }
      syncLaunch();
    },
  };
  return handle;
}

function button(label: string, onClick: () => void, key?: string, cls?: string, ariaLabel?: string): HTMLButtonElement {
  const b = h("button", { type: "button", class: cls ?? "btn btn--ghost btn--small tour__btn", "data-focus": key, "aria-label": ariaLabel }, label);
  b.addEventListener("click", onClick);
  return b;
}
