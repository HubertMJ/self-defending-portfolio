// Stats and objectives (ADR 0033, E+F). A compact band in the hero: the last real run, the counters
// across every visitor's runs (with the window they cover), how fast the last response was, and how
// many runs reached each objective — including, honestly, the ones no one has. Numbers come from
// GET /api/stats; objective titles from the terminal catalogue; the last run from the live feed. If
// stats are unavailable the band hides and the static hero reads as it always did.

import type { ApiClient } from "../lib/api";
import type { Objective, Stats } from "../lib/contract";
import { h, relativeTime, replace, timeEl, plClock, when } from "../lib/dom";
import { humanSpeed } from "./console";

const REPO_ISSUES = "https://github.com/HubertMJ/self-defending-portfolio/issues";

/** The last real run the page saw, for the hero's "last run" tile. */
export interface LastRun {
  title: string;
  at: number;
}

const own = (o: Record<string, { attempts: number; achieved: number }>, id: string) =>
  Object.prototype.hasOwnProperty.call(o, id) ? o[id] : { attempts: 0, achieved: 0 };

export function renderStats(s: Stats, objectives: Objective[], last?: LastRun, now: number = Date.now()): HTMLElement {
  const title = (id: string) => objectives.find((o) => o.id === id)?.title ?? id;
  const detected = Object.values(s.by_scenario).reduce((a, x) => a + x.detected, 0);
  const responded = Object.values(s.by_scenario).reduce((a, x) => a + x.responded, 0);

  // The newest run the feed showed; without one, the API's persisted time of the last run (ADR 0035).
  const lastAt = last ? last.at : s.last_run_at ? Date.parse(s.last_run_at) : undefined;
  const ago = (t: number) => relativeTime(new Date(t).toISOString(), now);
  const list = [
    // The last run names what ran; how fast the answer came is the API's one figure, the tile below.
    // The absolute time (Polish) first, how long ago beside it.
    lastAt !== undefined ? statTile(timeEl(lastAt, plClock(lastAt, now)), "last run", last ? `${ago(lastAt)} · ${last.title}` : ago(lastAt)) : null,
    statTile(String(s.runs), "attacks, all visitors", s.since ? `since ${when(s.since, now)}` : ""),
    // Both counts are runs: of the runs Falco detected, how many Talon answered at least once; and how
    // many ran out of time with a detection still unanswered (a terminal run can be both).
    statTile(`${responded} of ${detected}`, "detected runs answered", `${s.unanswered} ran out of time with a detection unanswered`),
    s.response_ms.last > 0 ? statTile(`${s.response_ms.last} ms`, "last detection to response", humanSpeed(s.response_ms.last)) : null,
  ].filter((x): x is HTMLElement => x !== null);
  // The stylesheet lays the tiles out by their count, so none is ever left alone on a row.
  const tiles = h("div", { class: "herostats__tiles", "data-count": list.length }, list);

  // Objectives, in the catalogue's order, with how many runs reached each; the never-reached say so.
  const order = objectives.length ? objectives.map((o) => o.id) : Object.keys(s.objectives);
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
    { class: "herostats" },
    h("p", { class: "herostats__label" }, "Live, across every visitor"),
    tiles,
    objectives.length || Object.keys(s.objectives).length
      ? h(
          "div",
          { class: "herostats__objectives" },
          h("p", { class: "herostats__objhead" }, "Objectives, and who has reached them"),
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
        )
      : null,
  );
}

function statTile(value: string | Node, label: string, foot: string): HTMLElement {
  return h("div", { class: "herostats__tile" }, h("span", { class: "herostats__value" }, value), h("span", { class: "herostats__name" }, label), foot ? h("span", { class: "herostats__foot" }, foot) : null);
}

export interface StatsHandle {
  refresh(): void;
  setLastRun(last: LastRun): void;
  /** The objectives' titles and order, from the terminal's catalogue (loaded once, by the terminal). */
  setObjectives(objectives: Objective[]): void;
}

/**
 * `onData`: every fresh snapshot (the evidence card reads its last_run_at). `label`: replaces "Live,
 * across every visitor" (the mock's, from lib/mock-hook.ts: mock data must not claim to be live).
 */
export function mountStats(root: HTMLElement, api: ApiClient, onData?: (s: Stats) => void, label?: string): StatsHandle {
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
