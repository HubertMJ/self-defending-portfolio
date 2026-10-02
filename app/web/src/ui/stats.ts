// Stats and objectives (ADR 0033, E+F). A compact band in the hero: the counters across every
// visitor's runs (with the window they cover), how fast the last real response was, and how many
// visitors' runs reached each objective — including, honestly, the ones no one has. The numbers come
// from GET /api/stats; the objective titles from the terminal catalogue. If neither is available the
// band simply hides and the static hero reads as it always did.

import type { ApiClient } from "../lib/api";
import type { Objective, Stats } from "../lib/contract";
import { h, relativeTime, replace } from "../lib/dom";
import { humanSpeed } from "./console";

const REPO_ISSUES = "https://github.com/HubertMJ/self-defending-portfolio/issues";

export function renderStats(s: Stats, objectives: Objective[], now: number = Date.now()): HTMLElement {
  const title = (id: string) => objectives.find((o) => o.id === id)?.title ?? id;
  const detected = Object.values(s.by_scenario).reduce((a, x) => a + x.detected, 0);
  const responded = Object.values(s.by_scenario).reduce((a, x) => a + x.responded, 0);
  const net = s.by_scenario["network-tool"];

  const tiles = h(
    "div",
    { class: "herostats__tiles" },
    statTile(String(s.runs), "attacks launched", s.since ? `since ${relativeTime(s.since, now)}` : ""),
    statTile(`${responded}`, "answered by Talon", `${detected} detected · ${s.unanswered} unanswered`),
    net ? statTile(`${net.runs - net.responded} of ${net.runs}`, "call-homes that got out", "the rest were cut off by Cilium") : null,
    s.response_ms.last > 0 ? statTile(`${s.response_ms.last} ms`, "last response", humanSpeed(s.response_ms.last)) : null,
  );

  // Objectives, in the order the catalogue gives them, with how many runs reached each.
  const order = objectives.length ? objectives.map((o) => o.id) : Object.keys(s.objectives);
  const objEls = order.map((id) => {
    const o = s.objectives[id] ?? { attempts: 0, achieved: 0 };
    const never = o.achieved === 0;
    return h(
      "li",
      { class: "herostats__obj", "data-never": String(never) },
      h("span", { class: "herostats__objtitle" }, title(id)),
      h("span", { class: "herostats__objcount" }, never ? "not reached by anyone yet" : `reached by ${o.achieved} of ${o.attempts} runs that tried`),
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

export function mountStats(root: HTMLElement, api: ApiClient): { refresh(): void } {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let objectives: Objective[] = [];

  const draw = (s: Stats) => {
    root.hidden = false;
    replace(root, renderStats(s, objectives));
  };

  const refresh = async () => {
    clearTimeout(timer);
    const [statsRes, detailsRes] = await Promise.all([api.stats(), api.scenarioDetails("terminal")]);
    if (detailsRes.ok && detailsRes.value.objectives) objectives = detailsRes.value.objectives;
    if (statsRes.ok) draw(statsRes.value);
    else root.hidden = true; // no /api/stats: the static hero stands on its own
    timer = setTimeout(() => void refresh(), 60_000);
  };

  root.hidden = true;
  void refresh();
  return { refresh: () => void refresh() };
}
