// The architecture diagram's one model (site redesign 2026-10-12): the model is consistent, the layout
// turns it into a valid SVG tree with a node per element and no HTML sink, the hero path lights from a
// run's events, and the committed docs/architecture/overview.svg is what the model generates.

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildTimeline } from "../../src/lib/timeline";
import { MODEL, nodesOf, validateModel } from "../../src/diagram/model";
import { FULL_MODEL } from "../../src/diagram/model-docs";
import { layout } from "../../src/diagram/layout";
import { serialise } from "../../src/diagram/tree";
import { renderDocsSvg } from "../../src/diagram/docs";
import { describeStates, mountDiagram, pathOf } from "../../src/ui/diagram";
import { svg as svgEl } from "../../src/lib/dom";
import type { Tree } from "../../src/diagram/tree";
import type { StreamEvent } from "../../src/lib/contract";

describe("diagram model", () => {
  it("is consistent: unique ids, edges between known nodes, every hero node placed (page and docs models)", () => {
    expect(validateModel()).toEqual([]);
    expect(validateModel(FULL_MODEL)).toEqual([]);
  });

  it("the page's model carries no port, VLAN or address; the docs model may (ADR 0021)", () => {
    const text = JSON.stringify(MODEL);
    expect(text).not.toMatch(/:\d{2,5}\b|VLAN|\b10\.\d+\.\d+\.\d+\b/);
    expect(JSON.stringify(FULL_MODEL)).toMatch(/VLAN 42/);
    expect(FULL_MODEL.nodes.length).toBeGreaterThan(MODEL.nodes.length);
  });

  it("the hero carries the attack-and-answer story, not the supply chain or GitOps", () => {
    const hero = new Set(nodesOf("hero").map((n) => n.id));
    for (const id of ["visitor", "cloudflare", "gateway", "pod", "falco", "talon", "kube-apiserver", "siem"]) expect(hero.has(id)).toBe(true);
    for (const id of ["cosign", "trivy", "argocd", "ghcr", "build"]) expect(hero.has(id)).toBe(false);
    const full = new Set(nodesOf("full", FULL_MODEL).map((n) => n.id));
    for (const id of ["cosign", "trivy", "argocd", "ghcr", "build"]) expect(full.has(id)).toBe(true);
  });

  it("the phone's path is the hero's nodes in reading order, no repeats", () => {
    const narrow = nodesOf("narrow").map((n) => n.id);
    expect(narrow.length).toBe(new Set(narrow).size);
    expect(narrow[0]).toBe("visitor");
    expect(narrow).toContain("siem");
  });

  it("every node names at least a blurb, and its sources are repo paths", () => {
    for (const n of MODEL.nodes) {
      expect(n.blurb.length).toBeGreaterThan(10);
      for (const src of n.sources) expect(src).toMatch(/^[\w./-]+$/);
    }
  });
});

describe("diagram layout", () => {
  for (const view of ["hero", "narrow", "full"] as const) {
    it(`renders ${view} as an svg tree with a group per node and no markup text`, () => {
      const model = view === "full" ? FULL_MODEL : MODEL;
      const tree = layout(view, { interactive: view !== "full" }, model);
      expect(tree.tag).toBe("svg");
      const svg = serialise(tree);
      expect(svg.startsWith("<svg")).toBe(true);
      // No HTML/script sink in the output, and every drawn node is present.
      expect(svg).not.toMatch(/<script|innerHTML|<foreignObject/i);
      for (const n of nodesOf(view, model)) expect(svg).toContain(`data-node="${n.id}"`);
    });
  }

  it("interactive nodes are focusable buttons inside a role=group svg; the docs view is one role=img", () => {
    const page = serialise(layout("hero", { interactive: true }));
    expect(page).toContain('role="button"');
    expect(page).toContain('tabindex="0"');
    expect(page).toMatch(/<svg[^>]*role="group"[^>]*aria-labelledby="dg-title dg-desc"/);
    expect(page).not.toContain('role="img"');
    const docs = serialise(layout("full", { interactive: false }, FULL_MODEL));
    expect(docs).not.toContain('role="button"');
    expect(docs).toMatch(/<svg[^>]*role="img"/);
  });

  it("renders no raw angle brackets from labels (text is escaped)", () => {
    const svg = serialise(layout("hero"));
    // Markup only from the tree's own tags: no stray "<" from a label or sublabel.
    expect(svg).not.toContain("<b>");
    expect(svg).not.toContain("</b>");
  });
});

/** A terminal run that was detected and terminated, from stream events. */
function killedRun() {
  const now = Date.parse("2026-10-03T18:00:10Z");
  const evs: StreamEvent[] = [
    { type: "run", data: { run_id: "aa11bb22cc33dd44", scenario: "terminal", state: "queued", at: "2026-10-03T18:00:00Z" } },
    { type: "run", data: { run_id: "aa11bb22cc33dd44", scenario: "terminal", state: "started", at: "2026-10-03T18:00:01Z", pod: "terminal-aa11bb22cc" } },
    { type: "run", data: { run_id: "aa11bb22cc33dd44", scenario: "terminal", state: "pod_ready", at: "2026-10-03T18:00:02Z" } },
    { type: "falco", data: { at: "2026-10-03T18:00:05Z", rule: "Terminal shell in container", priority: "Critical", namespace: "sandbox", pod: "terminal-aa11bb22cc", output: "shell" } },
    { type: "talon", data: { at: "2026-10-03T18:00:05.5Z", action: "Terminate Pod", actionner: "kubernetes:terminate", namespace: "sandbox", pod: "terminal-aa11bb22cc", status: "success" } },
    { type: "run", data: { run_id: "aa11bb22cc33dd44", scenario: "terminal", state: "responded", at: "2026-10-03T18:00:05.6Z" } },
    { type: "run", data: { run_id: "aa11bb22cc33dd44", scenario: "terminal", state: "finished", at: "2026-10-03T18:00:06Z", detail: "killed" } },
  ];
  return buildTimeline(evs, now).runs[0];
}

describe("the hero diagram lights the path of a run (ADR 0035 amendment)", () => {
  it("no run: nothing is lit", () => {
    const { nodes, edges } = pathOf(undefined);
    expect(nodes.size).toBe(0);
    expect(edges.size).toBe(0);
  });

  it("a detected and answered run lights the attack path, Falco, Talon and the answer back to the pod", () => {
    const { nodes, edges, summary } = pathOf(killedRun());
    expect(nodes.get("pod")).toBe("respond");
    expect(nodes.get("falco")).toBe("detect");
    expect(nodes.get("talon")).toBe("respond");
    expect(nodes.get("kube-apiserver")).toBe("respond");
    // Each edge carries the stage of what travelled it, so the colour is never the only cue.
    expect(edges.get("visitor-cloudflare")).toBe("attack");
    expect(edges.get("pod-falco")).toBe("detect");
    expect(edges.get("falco-talon")).toBe("respond");
    expect(edges.get("kube-apiserver-pod")).toBe("respond");
    expect(summary).toMatch(/answered/);
    expect(describeStates(nodes)).toMatch(/attack path: .*Visitor.*; detected: Falco; answered: .*Falco Talon/);
  });
});

describe("docs/architecture/overview.svg is generated from the model", () => {
  it("the committed file matches `npm run diagram` (run it when this fails)", () => {
    // The script counts Argo apps from cluster/apps; count them the same way here.
    const apps = readdirApps();
    const generated = renderDocsSvg({ argoApps: apps });
    const committed = readFileSync(join(process.cwd(), "..", "..", "docs", "architecture", "overview.svg"), "utf8");
    expect(committed).toBe(generated);
  });
});

function readdirApps(): number {
  const dir = join(process.cwd(), "..", "..", "cluster", "apps");
  return readdirSync(dir).filter((f) => f.endsWith(".yaml") && f !== "kustomization.yaml").length;
}

/** The hero figure as the build injects it: the SVG tree walked into real DOM, plus the caption mounts. */
function heroFigure(): { figure: HTMLElement; caption: HTMLElement; status: HTMLElement } {
  const walk = (node: Tree | string): Node => (typeof node === "string" ? document.createTextNode(node) : svgEl(node.tag, node.attrs, ...node.children.map(walk)));
  const figure = document.createElement("figure");
  figure.append(walk(layout("hero", { interactive: true })));
  const caption = document.createElement("div");
  caption.hidden = true;
  const status = document.createElement("p");
  figure.append(status, caption);
  document.body.replaceChildren(figure);
  return { figure, caption, status };
}

describe("mountDiagram: nodes open a caption by click and keyboard, the SIEM state survives setRun", () => {
  const key = (el: Element, k: string) => el.dispatchEvent(new KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true }));

  it("Enter and Space open the caption with the node's blurb and repo link, Escape and the close button shut it; aria-expanded follows", () => {
    const { figure, caption, status } = heroFigure();
    mountDiagram(figure, { caption, status });
    const falco = figure.querySelector('.dg-node[data-node="falco"]') as SVGGElement;
    expect(falco.getAttribute("tabindex")).toBe("0");
    expect(falco.getAttribute("role")).toBe("button");
    key(falco, "Enter");
    expect(caption.hidden).toBe(false);
    expect(falco.getAttribute("aria-expanded")).toBe("true");
    expect(caption.textContent).toContain("Falco watches every syscall over eBPF");
    expect(caption.querySelector('a[href^="https://github.com/HubertMJ/self-defending-portfolio/tree/main/cluster/infra/falco"]')).not.toBeNull();
    key(falco, "Escape");
    expect(caption.hidden).toBe(true);
    expect(falco.getAttribute("aria-expanded")).toBe("false");
    key(falco, " ");
    expect(caption.hidden).toBe(false);
    (caption.querySelector(".dg-caption__close") as HTMLButtonElement).click();
    expect(caption.hidden).toBe(true);
    // A click on another node swaps the caption; a click on the open node closes it.
    const pod = figure.querySelector('.dg-node[data-node="pod"]') as SVGGElement;
    pod.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(caption.textContent).toContain("What the pod is allowed to be");
    expect(pod.getAttribute("aria-expanded")).toBe("true");
    expect(falco.getAttribute("aria-expanded")).toBe("false");
    pod.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(caption.hidden).toBe(true);
    // The caption shows no markup from a blurb: text only.
    expect(caption.querySelector("script")).toBeNull();
  });

  it("setRun lights the path and names the lit nodes in words; setSiem is kept across a later setRun", () => {
    const { figure, caption, status } = heroFigure();
    const d = mountDiagram(figure, { caption, status });
    d.setSiem(true);
    const siem = figure.querySelector('.dg-node[data-node="siem"]') as SVGGElement;
    const siemEdge = figure.querySelector('.dg-edge[data-edge="kube-apiserver-siem"]') as SVGGElement;
    expect(siem.dataset.state).toBe("detect");
    expect(siemEdge.dataset.lit).toBe("true");
    d.setRun(killedRun(), "Shell in a container");
    expect((figure.querySelector('.dg-node[data-node="falco"]') as SVGGElement).dataset.state).toBe("detect");
    expect((figure.querySelector('.dg-edge[data-edge="visitor-cloudflare"]') as SVGGElement).dataset.tone).toBe("attack");
    expect((figure.querySelector('.dg-edge[data-edge="falco-talon"]') as SVGGElement).dataset.tone).toBe("respond");
    expect(status.textContent).toContain("Shell in a container: answered in");
    expect(status.textContent).toMatch(/Lit — attack path: .*; detected: Falco; answered: /);
    // The SIEM's own state was not wiped by the run.
    expect(siem.dataset.state).toBe("detect");
    expect(siemEdge.dataset.lit).toBe("true");
    d.setRun(undefined);
    expect(status.textContent).toContain("No attack yet");
    expect(siem.dataset.state).toBe("detect");
    d.setSiem(false);
    expect(siem.dataset.state).toBe("idle");
    expect(siemEdge.dataset.lit).toBe("false");
  });
});
