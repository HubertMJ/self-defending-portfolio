// Stats and objectives (ADR 0033, E+F). A compact band in the hero: the last real run, the counters
// across every visitor's runs (with the window they cover), how fast the last response was, and how
// many runs reached each objective — including, honestly, the ones no one has. Numbers come from
// GET /api/stats; objective titles from the terminal catalogue; the last run from the live feed. If
// stats are unavailable the band hides and the static hero reads as it always did.

import type { ApiClient } from "../lib/api";
import type { Objective, Stats } from "../lib/contract";
import { h, relativeTime, replace } from "../lib/dom";
import { humanSpeed } from "./console";

const REPO_ISSUES = "https://github.com/HubertMJ/self-defending-portfolio/issues";

/** The last real run the page saw, for the hero's "last run" tile. */
export interface LastRun {
  title: string;
  at: number;
  respondMs?: number;
}

const own = (o: Record<string, { attempts: number; achieved: number }>, id: string) =>
  Object.prototype.hasOwnProperty.call(o, id) ? o[id] : { attempts: 0, achieved: 0 };

export function renderStats(s: Stats, objectives: Objective[], last?: LastRun, now: number = Date.now()): HTMLElement {
  const title = (id: string) => objectives.find((o) => o.id === id)?.title ?? id;
  const detected = Object.values(s.by_scenario).reduce((a, x) => a + x.detected, 0);
  const responded = Object.values(s.by_scenario).reduce((a, x) => a + x.responded, 0);

  const tiles = h(
    "div",
    { class: "herostats__tiles" },
    last
      ? statTile(relativeTime(new Date(last.at).toISOString(), now), "last run", `${last.title}${last.respondMs !== undefined ? ` · answered in ${last.respondMs} ms` : ""}`)
      : statTile(String(s.runs), "attacks launched", s.since ? `since ${relativeTime(s.since, now)}` : ""),
    statTile(String(s.runs), "attacks, all visitors", s.since ? `since ${relativeTime(s.since, now)}` : ""),
    statTile(`${responded} of ${detected}`, "detections answered", `${s.unanswered} went unanswered`),
    s.response_ms.last > 0 ? statTile(`${s.response_ms.last} ms`, "last response", humanSpeed(s.response_ms.last)) : null,
  );

  // Objectives, in the catalogue's order, with how many runs reached each; the never-reached say so.
  const order = objectives.length ? objectives.map((o) => o.id) : Object.keys(s.objectives);
  const objEls = order.map((id) => {
    const o = own(s.objectives, id);
    const never = o.achieved === 0;
    return h(
      "li",
      { class: "herostats__obj", "data-never": String(never) },
      h("span", { class: "herostats__objtitle" }, title(id)),
      h("span", { class: "herostats__objcount" }, never ? `not reached yet — 0 of ${o.attempts} tries` : `reached in ${o.achieved} of ${o.attempts} tries`),
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
          h("p", { class: "small" }, "Think you can get further than this says is possible? ", h("a", { href: REPO_ISSUES, rel: "noopener noreferrer", target: "_blank" }, "Open an issue"), "."),
        )
      : null,
  );
}

function statTile(value: string, label: string, foot: string): HTMLElement {
  return h("div", { class: "herostats__tile" }, h("span", { class: "herostats__value" }, value), h("span", { class: "herostats__name" }, label), foot ? h("span", { class: "herostats__foot" }, foot) : null);
}

export interface StatsHandle {
  refresh(): void;
  setLastRun(last: LastRun): void;
}

export function mountStats(root: HTMLElement, api: ApiClient): StatsHandle {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let objectives: Objective[] = [];
  let snapshot: Stats | undefined;
  let last: LastRun | undefined;
  // In the mock the stats label must not claim "live"; the header banner already says it is a mock.
  const isMock = (() => {
    try {
      return document.documentElement.dataset.mock === "true";
    } catch {
      return false;
    }
  })();

  const draw = () => {
    if (!snapshot) return;
    root.hidden = false;
    const el = renderStats(snapshot, objectives, last);
    if (isMock) {
      const label = el.querySelector(".herostats__label");
      if (label) label.textContent = "Mock data — across every visitor";
    }
    replace(root, el);
  };

  const refresh = async () => {
    clearTimeout(timer);
    const [statsRes, detailsRes] = await Promise.all([api.stats(), api.scenarioDetails("terminal")]);
    if (detailsRes.ok && detailsRes.value.objectives) objectives = detailsRes.value.objectives;
    if (statsRes.ok) {
      snapshot = statsRes.value;
      draw();
      timer = setTimeout(() => void refresh(), 60_000);
    } else {
      // No /api/stats: hide the band and back off (don't poll a 404 every minute, review item 14).
      root.hidden = true;
      timer = setTimeout(() => void refresh(), 10 * 60_000);
    }
  };

  root.hidden = true;
  void refresh();
  return {
    refresh: () => void refresh(),
    setLastRun(l) {
      last = l;
      draw();
    },
  };
}
