// Stats and objectives (ADR 0033, E+F; site redesign 2026-10-12). One line of numbers in the hero: the
// counters across every visitor's runs (with the window they cover) and how fast the last response
// was; and, in the attack section, how many runs reached each objective — including, honestly, the
// ones no one has. Numbers come from GET /api/stats; objective titles from the terminal catalogue; the
// last run from the live feed names what ran. If stats are unavailable both hide and the static page
// reads as it always did.

import type { ApiClient } from "../lib/api";
import type { Objective, Stats } from "../lib/contract";
import { TIME_ZONE, h, replace, when } from "../lib/dom";
import { humanSpeed } from "./console";

const REPO_ISSUES = "https://github.com/HubertMJ/self-defending-portfolio/issues";

/** The last real run the page saw, for the hero's "last run" tile. */
export interface LastRun {
  title: string;
  at: number;
}

const own = (o: Record<string, { attempts: number; achieved: number }>, id: string) =>
  Object.prototype.hasOwnProperty.call(o, id) ? o[id] : { attempts: 0, achieved: 0 };

/**
 * The hero's numbers: one line, three figures, nothing else (site redesign 2026-10-12). The last run's
 * time is under the diagram, not here. `last` is accepted for the handle's sake and not drawn.
 */
export function renderStats(s: Stats, _objectives: Objective[] = [], _last?: LastRun, now: number = Date.now()): HTMLElement {
  const detected = Object.values(s.by_scenario).reduce((a, x) => a + x.detected, 0);
  const responded = Object.values(s.by_scenario).reduce((a, x) => a + x.responded, 0);
  const num = (value: string, words: string, title?: string) => h("span", { class: "herostats__num", ...(title ? { title } : {}) }, h("strong", {}, value), ` ${words}`);
  const sep = () => h("span", { class: "herostats__sep", "aria-hidden": "true" }, " · ");
  const figures = [
    // The window is in the words ("since 6 Sep"); the exact time is the title.
    num(String(s.runs), s.since ? `attacks since ${shortDay(s.since)}` : "attacks so far", s.since ? `since ${when(s.since, now)}` : undefined),
    // Both counts are runs: of the runs Falco detected, how many Talon answered at least once.
    num(`${responded} of ${detected}`, "detected runs answered", `${s.unanswered} ran out of time with a detection unanswered`),
    s.response_ms.last > 0 ? num(`${s.response_ms.last} ms`, "last detection to response", humanSpeed(s.response_ms.last)) : null,
  ].filter((x): x is HTMLElement => x !== null);
  const line = h("p", { class: "herostats__line" }, h("span", { class: "herostats__label" }, "Live, all visitors — not only yours"), " ");
  figures.forEach((f, i) => line.append(i ? sep() : "", f));
  return h("div", { class: "herostats", "data-count": figures.length }, line);
}

/** "6 Sep": the day a window opened, in Polish time. */
export function shortDay(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  // en-GB spells "Sept"; three letters for every month.
  return new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", timeZone: TIME_ZONE }).format(t).replace(/^(\d+ [A-Z][a-z]{2})[a-z]*$/, "$1");
}

/** The objectives, in the catalogue's order, with how many runs reached each; the never-reached say so. */
export function renderObjectives(s: Stats, objectives: Objective[]): HTMLElement | null {
  const title = (id: string) => objectives.find((o) => o.id === id)?.title ?? id;
  const order = objectives.length ? objectives.map((o) => o.id) : Object.keys(s.objectives);
  if (!order.length) return null;
  const objEls = order.map((id) => {
    const o = own(s.objectives, id);
    const never = o.achieved === 0;
    return h(
      "li",
      { class: "herostats__obj", "data-never": String(never) },
      h("span", { class: "herostats__objtitle" }, title(id)),
      // The API counts runs, not keystrokes: "of N runs that tried it".
      h("span", { class: "herostats__objcount" }, never ? `not reached yet — tried in ${o.attempts} run${o.attempts === 1 ? "" : "s"}` : `reached in ${o.achieved} of ${o.attempts} run${o.attempts === 1 ? "" : "s"} that tried`),
    );
  });
  return h(
    "div",
    { class: "herostats__objectives" },
    h("ul", { class: "herostats__objlist", role: "list" }, objEls),
    // What "reached" means on the API side: the objective's command exited 0. A credential read
    // and a dropped binary finish before the kill lands, so they count — detection is not
    // prevention — and the line says how long the attacker then kept the pod.
    h(
      "p",
      { class: "small herostats__reached" },
      "Reached means the command for it exited 0. Detection is not prevention: ",
      h("code", {}, "cat /etc/shadow"),
      " and a dropped binary finish before the kill lands, so they count",
      s.terminal.median_survival_s > 0 ? ` — and the attacker kept the pod a median ${s.terminal.median_survival_s} s per session.` : ".",
    ),
    h("p", { class: "small" }, "Think you can get further than this says is possible? ", h("a", { href: REPO_ISSUES, rel: "noopener noreferrer", target: "_blank" }, "Open an issue"), "."),
  );
}

export interface StatsHandle {
  refresh(): void;
  setLastRun(last: LastRun): void;
  /** The objectives' titles and order, from the terminal's catalogue (loaded once, by the terminal). */
  setObjectives(objectives: Objective[]): void;
}

/**
 * `root`: the hero's numbers; `objectivesRoot`: the attack section's objectives fold (its <details>
 * parent is shown once there is something to list). `onData`: every fresh snapshot (the evidence card
 * reads its last_run_at). `label`: replaces "Live, all visitors — not only yours" (the mock's, from
 * lib/mock-hook.ts: mock data must not claim to be live).
 */
export function mountStats(root: HTMLElement, api: ApiClient, onData?: (s: Stats) => void, label?: string, objectivesRoot?: HTMLElement): StatsHandle {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let objectives: Objective[] = [];
  let snapshot: Stats | undefined;
  let last: LastRun | undefined;

  const draw = () => {
    if (!snapshot) return;
    root.hidden = false;
    const el = renderStats(snapshot, objectives, last);
    if (label) {
      const heading = el.querySelector(".herostats__label");
      if (heading) heading.textContent = label;
    }
    replace(root, el);
    if (objectivesRoot) {
      const obj = renderObjectives(snapshot, objectives);
      replace(objectivesRoot, obj);
      const fold = objectivesRoot.closest<HTMLElement>("details");
      if (fold) fold.hidden = obj === null;
    }
  };

  // After a failure: an API without /api/stats (a 404) is not asked again; anything else is retried
  // a few times, further apart each time, then left alone until the page is reloaded.
  let failures = 0;
  const refresh = async () => {
    clearTimeout(timer);
    const res = await api.stats();
    if (res.ok) {
      failures = 0;
      snapshot = res.value;
      draw();
      onData?.(res.value);
      timer = setTimeout(() => void refresh(), 60_000);
      return;
    }
    failures += 1;
    if (!snapshot) root.hidden = true;
    if (res.message !== "HTTP 404" && failures < 4) timer = setTimeout(() => void refresh(), 60_000 * 2 ** failures);
  };

  root.hidden = true;
  void refresh();
  return {
    refresh: () => void refresh(),
    setObjectives(o) {
      objectives = o;
      draw();
    },
    setLastRun(l) {
      // Called on every event of the feed; the band is redrawn only when the tile would change.
      if (last && last.title === l.title && last.at === l.at) return;
      last = l;
      draw();
    },
  };
}
