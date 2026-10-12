// The guided tour (site redesign 2026-10-12, ADR 0035 amendment): six steps at the top of the attack
// section, revealed as sections, never an overlay. Each step names one real thing to do (a catalogue
// command, a one-click scenario) and is ticked from the events the page already has — the visitor's
// own runs as the timeline assembled them and the SIEM's incidents for them — so a reload re-derives
// the same progress and nothing is ticked that did not happen. Only "skipped" is stored.
//
// The tour costs runs: one terminal session for steps 1-4 (`sh -i` ends it), one side-by-side run for
// step 5, out of the per-visitor limit. It says so.

import type { CorrelationIncident } from "../lib/contract";
import { h, replace } from "../lib/dom";
import { SIEM_COMMAND } from "../lib/runstatus";
import type { RunView } from "../lib/timeline";

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
  { id: "siem", title: "See it in the SIEM", hint: "A minute or two later the SIEM files the DNS trick Falco missed. It opens below when it lands.", done: "The SIEM caught the DNS exfiltration that Falco could not." },
];

export interface TourProgress {
  /** Done step ids. */
  done: Set<string>;
  /** The first not-done step, or undefined when all are done. */
  current?: TourStep;
}

const SKIP_KEY = "sdp:tour-skipped";

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

export interface TourHandle {
  /** The newest derivation: the visitor's runs, the incidents, which runs are theirs. */
  update(runs: readonly RunView[], incidents: readonly CorrelationIncident[], ownRunIds: ReadonlySet<string>): void;
  /** The terminal drives the tour; on an API without one it is removed, not merely hidden. */
  setEnabled(enabled: boolean): void;
}

/**
 * `root`: the tour mount at the top of #attack. `onStep`: the button of a step was pressed — a command
 * to pick in the terminal, or a scenario to launch. `onReveal`: a step was completed — open and scroll
 * to the section it explains (the SIEM step opens #correlation).
 */
export function mountTour(
  root: HTMLElement,
  hooks: {
    onCommand(commandId: string): void;
    onScenario(scenarioId: string): void;
    onReveal(sectionId: string): void;
  },
): TourHandle {
  let progress: TourProgress = { done: new Set(), current: STEPS[0] };
  let shown = skipped();
  let enabled = true;
  const revealed = new Set<string>();

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
    const doneN = progress.done.size;
    const current = progress.current;
    const items = STEPS.map((s, i) => {
      const isDone = progress.done.has(s.id);
      const isCurrent = current?.id === s.id;
      const act = s.command
        ? button(isDone ? "Run it again" : "Do this step", () => hooks.onCommand(s.command as string))
        : s.scenario
          ? button(isDone ? "Run it again" : "Launch side by side", () => hooks.onScenario(s.scenario as string))
          : null;
      return h(
        "li",
        { class: "tour__step", "data-id": s.id, "data-done": String(isDone), "data-current": String(isCurrent), "aria-current": isCurrent ? "step" : undefined },
        h("span", { class: "tour__mark", "aria-hidden": "true" }, isDone ? "✓" : String(i + 1)),
        h(
          "div",
          { class: "tour__body" },
          h("p", { class: "tour__title" }, s.title),
          h("p", { class: "tour__hint" }, isDone ? s.done : s.hint),
          isCurrent && act ? h("p", { class: "tour__act" }, act) : null,
        ),
      );
    });
    replace(
      root,
      h(
        "div",
        { class: "tour", "data-complete": String(doneN === total) },
        h(
          "div",
          { class: "tour__head" },
          h("p", { class: "tour__count" }, doneN === total ? "Tour complete" : `Step ${Math.min(doneN + 1, total)} of ${total}`, h("span", { class: "tour__cost" }, " · uses two of your runs")),
          button("Skip the tour", () => {
            setSkipped(true);
            shown = true;
            draw();
          }),
        ),
        h("ol", { class: "tour__list", role: "list" }, items),
      ),
    );
  };

  draw();

  return {
    setEnabled(next) {
      if (enabled === next) return;
      enabled = next;
      draw();
    },
    update(runs, incidents, ownRunIds) {
      if (!enabled) return;
      const next = deriveProgress(runs, incidents, ownRunIds);
      const newlyDone = [...next.done].filter((id) => !progress.done.has(id));
      progress = next;
      draw();
      // Open and scroll to the section a just-finished step explains; once each, so the visitor is not
      // pulled around by a redraw. The terminal steps explain the attack (where they already are);
      // the SIEM step opens the correlation.
      for (const id of newlyDone) {
        if (revealed.has(id)) continue;
        revealed.add(id);
        if (id === "siem") hooks.onReveal("correlation");
      }
    },
  };
}

function button(label: string, onClick: () => void): HTMLButtonElement {
  const b = h("button", { type: "button", class: "btn btn--ghost btn--small tour__btn" }, label);
  b.addEventListener("click", onClick);
  return b;
}
