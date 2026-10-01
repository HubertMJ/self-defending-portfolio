// Technical Mode: one switch that reveals the raw material behind the friendly view -- every event as
// JSON, Falco's output fields, Talon's parameters, the policies with links at the commit, and the API's
// rate limits as it counts them. Off by default: the page has to make sense to a visitor who has never
// heard of eBPF, and the detail is one click away for one who has.
//
// The state lives on <html data-tech="on">, so CSS alone shows or hides every .tech-only element, and
// in localStorage (theme.ts applies it before first paint, like the theme, so a returning visitor does
// not see the page jump). Storage can be blocked; the switch then still works for the page view.

import type { ApiClient } from "../lib/api";
import type { Limits } from "../lib/contract";
import { h, replace } from "../lib/dom";
import { formatCountdown } from "./scenarios";

export const TECH_KEY = "tech";

export function readTech(): boolean {
  try {
    return localStorage.getItem(TECH_KEY) === "on";
  } catch {
    return false;
  }
}

function writeTech(on: boolean): void {
  try {
    if (on) localStorage.setItem(TECH_KEY, "on");
    else localStorage.removeItem(TECH_KEY);
  } catch {
    // Not persisted; the choice still holds for this page view.
  }
}

export function setupTechMode(btn: HTMLElement, onChange?: (on: boolean) => void): { on(): boolean } {
  const root = document.documentElement;
  const apply = (on: boolean) => {
    if (on) root.dataset.tech = "on";
    else delete root.dataset.tech;
    btn.setAttribute("aria-pressed", String(on));
    onChange?.(on);
  };
  btn.hidden = false;
  apply(root.dataset.tech === "on" || readTech());
  btn.addEventListener("click", () => {
    const on = root.dataset.tech !== "on";
    writeTech(on);
    apply(on);
  });
  return { on: () => root.dataset.tech === "on" };
}

/** "10 min", "hour", "90 s": a window length as a reader says it. */
export function formatWindow(s: number): string {
  if (s === 3600) return "hour";
  if (s > 0 && s % 3600 === 0) return `${s / 3600} h`;
  if (s > 0 && s % 60 === 0) return `${s / 60} min`;
  return `${s} s`;
}

export function renderLimits(l: Limits): HTMLElement {
  const v = l.per_visitor;
  const g = l.global;
  return h(
    "dl",
    { class: "limits" },
    h(
      "div",
      {},
      h("dt", {}, "Your network address"),
      h("dd", {}, h("strong", {}, `${v.remaining} of ${v.limit}`), ` attacks left per ${formatWindow(v.window_s)}`, v.reset_in_s > 0 ? `, next one back in ${formatCountdown(v.reset_in_s)}` : ""),
    ),
    h("div", {}, h("dt", {}, "Whole site"), h("dd", {}, h("strong", {}, `${g.remaining} of ${g.limit}`), ` per ${formatWindow(g.window_s)}`)),
    h("div", {}, h("dt", {}, "Run in progress"), h("dd", {}, l.active_run ? "yes" : "no")),
    h("div", {}, h("dt", {}, "Free event-stream slots"), h("dd", {}, String(l.stream_slots_remaining))),
  );
}

/** The limits panel: fetched while Technical Mode is on, refreshed every 15 s and after each run. */
export function mountLimits(el: HTMLElement, api: ApiClient): { refresh(): void; setEnabled(on: boolean): void } {
  let timer: ReturnType<typeof setInterval> | undefined;
  let enabled = false;
  const refresh = async () => {
    if (!enabled) return;
    const r = await api.limits();
    replace(
      el,
      h("h4", { class: "limits__title" }, "Rate limits, as the API counts them"),
      r.ok ? renderLimits(r.value) : h("p", { class: "small" }, "This API version does not publish its limits (GET /api/limits)."),
    );
  };
  return {
    refresh: () => void refresh(),
    setEnabled(on) {
      enabled = on;
      clearInterval(timer);
      timer = undefined;
      if (on) {
        void refresh();
        timer = setInterval(() => void refresh(), 15_000);
      }
    },
  };
}
