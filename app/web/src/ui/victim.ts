// The victim: a fake browser window showing the little "SDP Shop" that runs inside the scenario pod,
// as the API's probe sees it (GET /state.json on the pod, every 500 ms during a run). The page never
// talks to the pod -- it is not reachable from the internet at all -- and never renders the pod's
// HTML: it draws the window from the probe's structured fields (status, title, banner, checksum),
// as text nodes only, so whatever an attack writes into the shop cannot become markup here.
//
// States, in the order a run moves through them:
//   fresh        a new replica: up, nothing has happened to it yet
//   up           the shop answers normally
//   defaced      the attack rewrote the shop's page
//   compromised  the attack is running inside it (credentials read, payload started, beaconing)
//   unreachable  the probe gets no answer: the quarantine policy cut the pod's network
//   gone         the pod no longer exists: Talon deleted it

import type { VictimStatus } from "../lib/contract";
import { h, utcClock } from "../lib/dom";
import type { RunView, VictimSpan } from "../lib/timeline";

export type VictimView = VictimStatus | "fresh" | "waiting" | "none";

/** Which state the window shows for a run. */
export function victimState(run: RunView): VictimView {
  const last = run.victim[run.victim.length - 1];
  if (!last) return run.active ? "waiting" : "none";
  if (last.status === "up" && run.victim.every((v) => v.status === "up")) return run.active ? "fresh" : "up";
  return last.status;
}

const PRODUCTS = [
  ["Distroless tee", "€24"],
  ["Seccomp socks", "€9"],
  ["Read-only mug", "€14"],
] as const;

function shop(span: VictimSpan, crossed: boolean): HTMLElement {
  return h(
    "div",
    { class: "shop" },
    h("p", { class: "shop__brand" }, span.title || "SDP Shop"),
    span.banner ? h("p", { class: "shop__banner" }, span.banner) : null,
    h(
      "ul",
      { class: "shop__grid", role: "list", "data-crossed": String(crossed) },
      PRODUCTS.map(([name, price]) => h("li", { class: "shop__item" }, h("span", { class: "shop__thumb", "aria-hidden": "true" }), h("span", {}, name), h("strong", {}, price))),
    ),
  );
}

function errorPage(code: string, title: string, body: string): HTMLElement {
  return h("div", { class: "browser__error" }, h("p", { class: "browser__error-title" }, title), h("p", {}, body), h("code", {}, code));
}

const STATUS_LINE: Record<VictimView, string> = {
  fresh: "200 OK",
  up: "200 OK",
  defaced: "200 OK · content changed",
  compromised: "200 OK · compromised",
  unreachable: "no response",
  gone: "pod deleted",
  waiting: "no answer yet",
  none: "no data",
};

const CAPTION: Record<VictimView, string> = {
  fresh: "A fresh replica from the signed image. Nothing has touched it yet.",
  up: "The shop answers normally.",
  defaced: "The attack rewrote the shop's front page from inside the container.",
  compromised: "The attack is running inside the shop's container.",
  unreachable: "Network cut by Cilium: the quarantine label isolates the pod, so even the API's probe gets no answer.",
  gone: "Pod killed by Talon: there is nothing left to answer.",
  waiting: "The scenario pod is starting the shop; it shows here once it answers the API's first probe.",
  none: "This run has no victim telemetry (the API or scenario predates it).",
};

export function renderVictim(run: RunView, readOnly: boolean): HTMLElement {
  const state = victimState(run);
  const spans = run.victim;
  const last = spans[spans.length - 1];
  const healthy = spans.find((s) => s.status === "up");
  let view: HTMLElement;
  switch (state) {
    case "fresh":
    case "up":
      view = shop(last, false);
      break;
    case "defaced":
      view = h(
        "div",
        { class: "defaced" },
        // The terminal's deface leaves only {"status":"defaced"}: no title or banner to show, so the
        // window says what the probe knows.
        h("p", { class: "defaced__title" }, last.title || "Page replaced"),
        h("p", { class: "defaced__banner" }, last.banner || "The shop now serves whatever the attacker wrote instead of its front page."),
        healthy && last.checksum ? h("p", { class: "defaced__sum" }, `checksum ${healthy.checksum || "?"} → ${last.checksum}`) : null,
      );
      break;
    case "compromised":
      view = h("div", { class: "compromised" }, shop(last, true), h("p", { class: "compromised__alert", role: "presentation" }, last.banner || "Something is running in here that should not be."));
      break;
    case "unreachable":
      view = errorPage("ERR_CONNECTION_TIMED_OUT", "This site can’t be reached", `The probe waited ${last.probe_ms > 0 ? `${last.probe_ms} ms` : "its full timeout"} and got nothing back. The pod is still running, but Cilium drops every packet to and from it.`);
      break;
    case "gone":
      view = errorPage("ERR_POD_NOT_FOUND", "This site no longer exists", `Pod ${last.pod} was deleted by Falco Talon. The next run gets a fresh replica.`);
      break;
    case "waiting": {
      // No answer from the shop yet. The pod watch says how far the pod is; the probe only reports
      // once the shop has answered once, so "booting" is what the visitor is looking at.
      const phase = run.pods[run.pods.length - 1]?.phase;
      view = h(
        "div",
        { class: "browser__blank" },
        h("span", { class: "browser__spinner", "aria-hidden": "true" }),
        h("span", {}, "Shop booting", phase ? h("span", { class: "browser__phase" }, ` · pod ${phase}`) : null),
      );
      break;
    }
    default:
      view = h("div", { class: "browser__blank" }, "No victim app in this run.");
  }
  const host = run.pod ?? "scenario pod";
  return h(
    "figure",
    { class: "browser", "data-status": state },
    h(
      "div",
      { class: "browser__bar" },
      h("span", { class: "browser__dots", "aria-hidden": "true" }, h("i"), h("i"), h("i")),
      h("span", { class: "browser__url" }, h("span", { class: "browser__scheme" }, "http://"), host, h("span", { class: "browser__path" }, ":8080/")),
      state === "fresh" ? h("span", { class: "browser__ribbon" }, "fresh replica") : null,
    ),
    h("div", { class: "browser__view" }, view),
    h(
      "div",
      { class: "browser__status" },
      h("span", { class: "browser__code" }, STATUS_LINE[state]),
      last && last.probe_ms >= 0 && state !== "gone" ? h("span", {}, `probe ${last.probe_ms} ms`) : null,
      last ? h("span", {}, `seen ${utcClock(last.until, Date.now(), { ms: true })}`) : null,
      readOnly ? h("span", { class: "browser__ro" }, "read-only") : null,
    ),
    h("figcaption", { class: "browser__caption" }, h("strong", {}, `${labelOf(state)}. `), CAPTION[state]),
  );
}

export function labelOf(state: VictimView): string {
  switch (state) {
    case "fresh":
      return "Fresh replica";
    case "up":
      return "Up";
    case "defaced":
      return "Defaced";
    case "compromised":
      return "Compromised";
    case "unreachable":
      return "Unreachable";
    case "gone":
      return "Gone";
    case "waiting":
      return "Booting";
    default:
      return "No data";
  }
}
