// The unguarded twin (ADR 0033, part C). One click runs the same catalogue attack in two pods at
// once: one in `sandbox`, where Talon answers, and one in `sandbox-unguarded`, where Falco still
// detects but nothing responds. Side by side, the value of the response is the difference between the
// two windows — the left one dies or goes dark, the right one stays compromised while a timer counts
// how long the attacker has had it.
//
// Both windows are drawn from the API's probe fields as text only (ui/victim.ts), never from the
// pod's own HTML; the arm tells which pod each probe belongs to.

import { h } from "../lib/dom";
import { type RunView, formatDuration, victimByArm } from "../lib/timeline";
import { renderVictim } from "./victim";

/** A compare run has `armPods`; this renders its two shop windows and the contrast between them. */
export function renderTwin(run: RunView, now: number = Date.now()): HTMLElement {
  const guardedSpan = victimByArm(run, "guarded");
  const unguardedSpan = victimByArm(run, "unguarded");
  const guardedFalco = run.falco.some((f) => f.arm === "guarded" || f.arm === undefined);
  const unguardedFalco = run.falco.some((f) => f.arm === "unguarded");

  const held = heldMs(run, now);

  return h(
    "div",
    { class: "twin" },
    h(
      "div",
      { class: "twin__grid" },
      arm("Guarded · sandbox", "Falco detects and Talon answers.", guardedSpan ? renderVictimFor(run, "guarded") : waiting(), guardedFalco, run.talon.length > 0, undefined),
      arm("Unguarded · sandbox-unguarded", "Falco detects. Nothing answers.", unguardedSpan ? renderVictimFor(run, "unguarded") : waiting(), unguardedFalco, false, held),
    ),
    h("p", { class: "twin__foot small" }, "Same image, same policies, same attack — the only difference is whether a response rule matches the namespace. Everything that prevents (non-root, read-only, no token, no capabilities) is in force on both; only the automatic response is missing on the right."),
  );
}

function arm(title: string, sub: string, window: HTMLElement, sawFalco: boolean, answered: boolean, heldMs: number | undefined): HTMLElement {
  return h(
    "section",
    { class: `twin__arm twin__arm--${answered ? "guarded" : "unguarded"}`, "aria-label": title },
    h("header", { class: "twin__armhead" }, h("h4", {}, title), h("p", { class: "small" }, sub)),
    window,
    h(
      "p",
      { class: "twin__verdict", "data-answered": String(answered) },
      sawFalco ? h("span", { class: "twin__chip twin__chip--detect" }, "Falco saw it") : h("span", { class: "twin__chip" }, "watching…"),
      answered ? h("span", { class: "twin__chip twin__chip--respond" }, "Talon answered") : h("span", { class: "twin__chip twin__chip--none" }, "nothing answered"),
      heldMs !== undefined ? h("span", { class: "twin__held" }, ...heldText(heldMs)) : null,
    ),
  );
}

/**
 * How long the attacker has held the unguarded pod: from its first compromised probe until now, and
 * at most until that pod was deleted (the API's compare hold) or the run ended. The probe publishes
 * only changes, so nothing arrives while the pod stays compromised: the console re-reads this every
 * second instead of waiting for an event.
 */
export function heldMs(run: RunView, now: number): number | undefined {
  const firstHit = run.victim.find((v) => v.arm === "unguarded" && v.status !== "up");
  if (!firstHit) return undefined;
  const deleted = run.unguardedPods.find((p) => p.deleted);
  const ends = [deleted && tsOf(deleted.at), run.states.finished, run.states.failed, run.states.timeout].filter((t): t is number => t !== undefined);
  const end = ends.length ? Math.min(...ends) : run.active ? now : undefined;
  return Math.max(0, (end ?? now) - tsOf(firstHit.at));
}

/** The counter's words; the duration is one unbreakable piece, so "2.7 s" never splits over two lines. */
export const heldText = (ms: number): (string | HTMLElement)[] => ["attacker has held this pod ", h("span", { class: "twin__dur" }, formatDuration(ms))];

function waiting(): HTMLElement {
  return h("div", { class: "browser" }, h("div", { class: "browser__view" }, h("div", { class: "browser__blank" }, h("span", { class: "browser__spinner", "aria-hidden": "true" }), "Starting the pod…")));
}

/** renderVictim draws the latest span for the run; for a compare run we want one arm's latest span. */
function renderVictimFor(run: RunView, armName: "guarded" | "unguarded"): HTMLElement {
  const span = victimByArm(run, armName);
  if (!span) return waiting();
  // Build a one-arm view so renderVictim shows this pod's state, not the interleaved stream.
  const armRun: RunView = { ...run, victim: run.victim.filter((v) => v.arm === armName), pod: armName === "guarded" ? run.armPods?.guarded : run.armPods?.unguarded };
  return renderVictim(armRun, true);
}

function tsOf(iso: string): number {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? 0 : t;
}
