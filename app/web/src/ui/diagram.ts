// The hero's live architecture diagram (site redesign 2026-10-12, ADR 0035 amendment). The SVG itself
// is in the static HTML (scripts/build.mjs draws it from src/diagram at build time, so it is there
// without JavaScript); this module attaches behaviour to it by node id: a caption panel under the
// drawing for the node the visitor picked (click, tap, Enter or Space), and the live states — the
// path of the newest run lit from the events the timeline already assembled, with the real time from
// the detection to the response in the caption.
//
// Honest motion: nothing loops. A path lights when a run's events say so and stays lit; the packet
// animation plays once per state change (styles.css) and not at all under prefers-reduced-motion.

import { MODEL, type DiagramNode } from "../diagram/model";
import { h, plClock, replace, timeEl } from "../lib/dom";
import type { RunView } from "../lib/timeline";
import { formatDuration } from "../lib/timeline";
import { REPO_URL, extLink } from "./common";

export type NodeState = "idle" | "attack" | "detect" | "respond" | "prevented";

export interface DiagramHandle {
  /** The newest run the page knows (its events as the timeline assembled them), or none. */
  setRun(run: RunView | undefined, title?: string): void;
  /** The SIEM filed an incident for one of the visitor's runs. */
  setSiem(filed: boolean): void;
  /** Opens the caption of one node (the tour's "see it on the diagram"). */
  show(nodeId: string): void;
}

/** The nodes a run's events light, in the order the packet travels. */
export function pathOf(run: RunView | undefined): { nodes: Map<string, NodeState>; edges: string[]; summary: string } {
  const nodes = new Map<string, NodeState>();
  const edges: string[] = [];
  if (!run) return { nodes, edges, summary: "" };
  // The attack: the visitor's request came in through the edge to the API, which started the pod.
  for (const id of ["visitor", "cloudflare", "cloudflared", "gateway", "site", "kube-apiserver", "pod"]) nodes.set(id, "attack");
  edges.push("visitor-cloudflare", "cloudflare-cloudflared", "cloudflared-gateway", "gateway-site", "site-kube-apiserver");
  const guardedFalco = run.falco.filter((f) => f.arm !== "unguarded");
  const twinFalco = run.falco.some((f) => f.arm === "unguarded");
  if (run.armPods) nodes.set("twin", twinFalco ? "detect" : "attack");
  if (twinFalco) edges.push("twin-falco");
  let summary = run.active ? "attack in progress" : "no detection: nothing this run did matched a rule";
  if (guardedFalco.length || run.states.detected !== undefined) {
    nodes.set("falco", "detect");
    edges.push("pod-falco");
    summary = run.active ? "detected, waiting for the answer" : "detected, not answered";
  }
  const answered = run.talon.some((t) => t.arm !== "unguarded") || run.states.responded !== undefined;
  if (answered) {
    nodes.set("talon", "respond");
    nodes.set("kube-apiserver", "respond");
    nodes.set("pod", "respond");
    edges.push("falco-talon", "talon-kube-apiserver", "kube-apiserver-pod");
    const ms = run.timings.respondMs;
    summary = ms !== undefined ? `answered in ${formatDuration(ms)}` : "answered";
  }
  return { nodes, edges, summary };
}

function nodeMeta(id: string): DiagramNode | undefined {
  return MODEL.nodes.find((n) => n.id === id);
}

/** The caption panel's content for a node: its blurb and where it is in the repository. */
export function renderCaption(n: DiagramNode): HTMLElement {
  return h(
    "div",
    { class: "dg-caption__body" },
    h("p", { class: "dg-caption__title" }, n.label, n.sub ? h("span", { class: "dg-caption__sub" }, ` · ${n.sub}`) : null),
    h("p", { class: "dg-caption__text" }, n.blurb),
    n.sources.length
      ? h(
          "p",
          { class: "dg-caption__sources small" },
          "In the repository: ",
          ...n.sources.flatMap((s, i) => [i ? ", " : "", extLink(`${REPO_URL}/tree/main/${s}`, h("code", {}, s))]),
        )
      : null,
  );
}

/**
 * `figure`: the hero's <figure> holding one or two SVGs (wide and narrow) and the caption mount.
 * Every node of every SVG in it answers; the state is set on all of them at once.
 */
export function mountDiagram(figure: HTMLElement, opts: { caption: HTMLElement; status: HTMLElement }): DiagramHandle {
  const nodeEls = (id: string) => [...figure.querySelectorAll<SVGGElement>(`.dg-node[data-node="${id}"]`)];
  const allNodes = [...figure.querySelectorAll<SVGGElement>(".dg-node")];
  const allEdges = [...figure.querySelectorAll<SVGGElement>(".dg-edge")];
  let open: string | undefined;

  const closeCaption = () => {
    open = undefined;
    opts.caption.hidden = true;
    replace(opts.caption);
    for (const el of allNodes) el.setAttribute("aria-expanded", "false");
  };

  const show = (id: string) => {
    const n = nodeMeta(id);
    if (!n) return;
    if (open === id) return closeCaption();
    open = id;
    for (const el of allNodes) el.setAttribute("aria-expanded", String(el.dataset.node === id));
    const close = h("button", { type: "button", class: "btn btn--ghost btn--small dg-caption__close", "aria-label": "Close" }, "×");
    close.addEventListener("click", () => {
      closeCaption();
      nodeEls(id).find((el) => el.getClientRects().length)?.focus();
    });
    replace(opts.caption, renderCaption(n), close);
    opts.caption.hidden = false;
  };

  for (const el of allNodes) {
    const id = el.dataset.node ?? "";
    el.addEventListener("click", () => show(id));
    el.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        show(id);
      } else if (e.key === "Escape" && open === id) closeCaption();
    });
  }

  let lastKey = "";
  const setRun = (run: RunView | undefined, title?: string) => {
    const { nodes, edges, summary } = pathOf(run);
    const key = `${run?.runId ?? ""}|${[...nodes.entries()].join(",")}|${edges.join(",")}|${summary}`;
    if (key === lastKey) return;
    lastKey = key;
    for (const el of allNodes) el.dataset.state = nodes.get(el.dataset.node ?? "") ?? "idle";
    for (const el of allEdges) el.dataset.lit = String(edges.includes(el.dataset.edge ?? ""));
    figure.dataset.run = run ? (run.active ? "active" : "over") : "none";
    if (!run) {
      replace(opts.status, "No attack yet since this page loaded. ", h("a", { href: "#attack" }, "Attack this cluster"), " and watch the path light up.");
      return;
    }
    const at = run.talon.find((t) => t.arm !== "unguarded")?.at;
    const when = at ? Date.parse(at) : (run.states.responded ?? run.states.detected ?? run.states.started);
    replace(
      opts.status,
      h("span", { class: "dg-status__what" }, title ? `${title}: ` : "Last run: "),
      summary,
      when !== undefined && !Number.isNaN(when) ? [", ", timeEl(when, plClock(when, Date.now()))] : null,
      ".",
    );
  };

  return {
    setRun,
    setSiem(filed) {
      for (const el of nodeEls("siem")) el.dataset.state = filed ? "detect" : "idle";
      for (const el of allEdges) if (el.dataset.edge === "kube-apiserver-siem") el.dataset.lit = String(filed);
    },
    show,
  };
}
