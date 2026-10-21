// The architecture diagram's one model (site redesign 2026-10-12): the model is consistent, the layout
// turns it into a valid SVG tree with a node per element and no HTML sink, the hero path lights from a
// run's events, and the committed docs/architecture/overview.svg is what the model generates.

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildTimeline } from "../../src/lib/timeline";
import { MODEL, ROLE_LEGEND, nodesOf, validateModel } from "../../src/diagram/model";
import { FULL_MODEL } from "../../src/diagram/model-docs";
import { PAD_X, TRAFFIC, fitReport, layout, panel, textWidth, trafficCss, wrapSub } from "../../src/diagram/layout";
import { serialise } from "../../src/diagram/tree";
import { renderDocsSvg } from "../../src/diagram/docs";
import { describeStates, mountDiagram, pathOf } from "../../src/ui/diagram";
import { mountNodePanels } from "../../src/node-panel";
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

  it("every node has a role, drawn as its class; the roles are the owner's (2026-10-13), the legend in index.html names each one", () => {
    const roles = ["entry", "attack", "detect", "respond", "record", "neutral"];
    for (const n of FULL_MODEL.nodes) expect(roles).toContain(n.role);
    const of = (id: string) => MODEL.nodes.find((n) => n.id === id)?.role;
    for (const id of ["visitor", "cloudflare", "cloudflared", "gateway", "site"]) expect(of(id)).toBe("entry");
    expect([of("pod"), of("falco"), of("talon"), of("kube-apiserver"), of("siem"), of("twin")]).toEqual(["attack", "detect", "respond", "respond", "record", "neutral"]);
    const hero = serialise(layout("hero", { interactive: true }));
    for (const n of MODEL.nodes) expect(hero).toMatch(new RegExp(`class="dg-node dg-node--\\w+ dg-role--${n.role}(?: dg-node--sub\\d)?"[^>]*data-node="${n.id}"`));
    const html = readFileSync(join(process.cwd(), "src", "index.html"), "utf8");
    for (const { role, word } of ROLE_LEGEND) expect(html).toMatch(new RegExp(`dg-legend__item dg-role--${role}"[^>]*>(?:<[^>]+>)*${word}<`));
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

  it("the page carries the ambient traffic (two dots, a glow on each lane edge) and its generated routes; the docs file is still", () => {
    const hero = serialise(layout("hero", { interactive: true }));
    expect((hero.match(/<circle class="dg-dot" id="dg-dot-(req|loop)" r="3"/g) ?? []).length).toBe(2);
    for (const id of [...TRAFFIC.req.edges, ...TRAFFIC.loop.edges]) expect(hero).toContain(`class="dg-glow" id="dg-glow-${id}"`);
    // No overlay at rest: no stub of a packet path, no glow on the side edges.
    expect(hero).not.toContain("dg-packet");
    expect(hero).not.toMatch(/dg-edge--side[^>]*>(?:(?!<\/g>).)*dg-glow/s);
    expect(serialise(layout("narrow", { interactive: true }))).toContain('id="dgn-dot-req"');
    const docs = serialise(layout("full", { interactive: false }, FULL_MODEL));
    expect(docs).not.toMatch(/dg-dot|dg-glow/);
    const css = trafficCss();
    for (const p of ["dg", "dgn"]) for (const l of ["req", "loop"]) expect(css).toMatch(new RegExp(`#${p}-dot-${l} \\{ offset-path: path\\("M[\\d. L]+"\\); --tr-name: dg-tr-${p}-${l}; --tr-period: [\\d.]+s; \\}`));
    expect(css).toContain("@keyframes dg-tr-dg-gateway-site");
  });

  it("edges stop short of the boxes: one arrowhead per direction, 8 units, its tip clear of the node", () => {
    const hero = serialise(layout("hero", { interactive: true }));
    expect(hero).toMatch(/<marker id="dg-arrow-flow"[^>]*markerWidth="8" markerHeight="8" markerUnits="userSpaceOnUse"/);
    // The tunnel: one line, a head at each end; every other line one head.
    const tunnel = hero.match(/data-edge="cloudflare-cloudflared"[^]*?<\/g>/)?.[0] ?? "";
    expect((tunnel.match(/marker-(start|end)=/g) ?? []).length).toBe(2);
    // Cloudflare's box ends at x=200, cloudflared's starts at 254: the line runs 207 to 247.
    expect(tunnel).toMatch(/class="dg-line" d="M207,[\d.]+ L247,[\d.]+"/);
  });

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

// The image build (app/web/Dockerfile) sees app/web only, without docs/ or cluster/: there the check
// cannot run, and `make validate` runs the same check (`node scripts/diagram.mjs --check`) on the whole repo.
const DOCS_SVG = join(process.cwd(), "..", "..", "docs", "architecture", "overview.svg");

describe("docs/architecture/overview.svg is generated from the model", () => {
  it.skipIf(!existsSync(DOCS_SVG))("the committed file matches `npm run diagram` (run it when this fails)", () => {
    // The script counts Argo apps from cluster/apps; count them the same way here.
    const apps = readdirApps();
    const generated = renderDocsSvg({ argoApps: apps });
    const committed = readFileSync(DOCS_SVG, "utf8");
    expect(committed).toBe(generated);
  });
});

function readdirApps(): number {
  const dir = join(process.cwd(), "..", "..", "cluster", "apps");
  return readdirSync(dir).filter((f) => f.endsWith(".yaml") && f !== "kustomization.yaml").length;
}

/** The hero figure as the build injects it: the SVG tree walked into real DOM, the node panel's markup and the status line. */
function heroFigure(): { figure: HTMLElement; status: HTMLElement } {
  const walk = (node: Tree | string): Node => (typeof node === "string" ? document.createTextNode(node) : svgEl(node.tag, node.attrs, ...node.children.map(walk)));
  const figure = document.createElement("figure");
  figure.append(walk(layout("hero", { interactive: true })));
  const status = document.createElement("p");
  figure.append(status);
  figure.insertAdjacentHTML("beforeend", panel());
  document.body.replaceChildren(figure);
  return { figure, status };
}

describe("the node panel under the diagram: a node's details by keyboard, click and close; the SIEM state survives setRun", () => {
  const key = (el: Element, k: string) => el.dispatchEvent(new KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true }));

  it("the build writes one entry per drawn node, its blurb and repository links, as text", () => {
    const html = panel();
    const shown = new Set([...nodesOf("hero"), ...nodesOf("narrow")].map((n) => n.id));
    expect(html.match(/class="np-item"/g)).toHaveLength(shown.size);
    expect(html).toContain('<a href="https://github.com/HubertMJ/self-defending-portfolio/tree/main/cluster/infra/falco/" rel="noopener noreferrer" tabindex="-1"><code>cluster/infra/falco/</code></a>');
    expect(html).toContain("On GitHub: ");
    // A node with no source (the visitor) has no links line.
    const visitor = html.slice(html.indexOf('data-for="visitor"'), html.indexOf("</div>", html.indexOf('data-for="visitor"')));
    expect(visitor).not.toContain("np-links");
  });

  it("Enter and Space open the node's details with its blurb and repo link, Escape and × close them; aria-expanded follows", () => {
    const { figure, status } = heroFigure();
    mountNodePanels(figure);
    mountDiagram(figure, { status });
    const panelEl = figure.querySelector(".np-panel") as HTMLElement;
    const shownItem = () => figure.querySelector('.np-item[data-on="true"]') as HTMLElement | null;
    const falco = figure.querySelector('.dg-node[data-node="falco"]') as SVGGElement;
    expect(falco.getAttribute("tabindex")).toBe("0");
    expect(falco.getAttribute("role")).toBe("button");
    expect(panelEl.dataset.open).toBe("false");
    key(falco, "Enter");
    expect(panelEl.dataset.open).toBe("true");
    expect(panelEl.dataset.role).toBe("detect");
    expect(falco.getAttribute("aria-expanded")).toBe("true");
    expect(shownItem()?.textContent).toContain("Falco watches every syscall over eBPF");
    const link = shownItem()?.querySelector('a[href^="https://github.com/HubertMJ/self-defending-portfolio/tree/main/cluster/infra/falco"]') as HTMLAnchorElement;
    expect(link.tabIndex).toBe(0);
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
    expect(panelEl.dataset.open).toBe("false");
    expect(falco.getAttribute("aria-expanded")).toBe("false");
    expect(link.tabIndex).toBe(-1);
    key(falco, " ");
    expect(panelEl.dataset.open).toBe("true");
    (figure.querySelector(".np-close") as HTMLButtonElement).click();
    expect(panelEl.dataset.open).toBe("false");
    // A click on another node swaps the details in place.
    const pod = figure.querySelector('.dg-node[data-node="pod"]') as SVGGElement;
    key(falco, "Enter");
    pod.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(shownItem()?.dataset.for).toBe("pod");
    expect(shownItem()?.textContent).toContain("What the pod is allowed to be");
    expect(pod.getAttribute("aria-expanded")).toBe("true");
    expect(falco.getAttribute("aria-expanded")).toBe("false");
    // The details show no markup from a blurb: text only.
    expect(figure.querySelector(".np-slot script")).toBeNull();
  });

  it("setRun lights the path and names the lit nodes in words; setSiem is kept across a later setRun", () => {
    const { figure, status } = heroFigure();
    const d = mountDiagram(figure, { status });
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

describe("every word fits its box (2026-10-14)", () => {
  it("each node's label and sublabel lines, estimated, keep PAD_X clear on both sides; each zone's title and subtitle fit inside it; zones hold their nodes 12 units clear (page and docs models, every view)", () => {
    const cases: [string, ReturnType<typeof fitReport>][] = [
      ["hero", fitReport("hero")],
      ["narrow", fitReport("narrow")],
      ["full", fitReport("full", FULL_MODEL, { argocd: "26 Applications" })],
    ];
    for (const [view, report] of cases) {
      for (const { box, texts } of report) {
        for (const tx of texts) {
          const where = `${view}: "${tx.text}" in a ${box.w} wide box`;
          if (tx.kind === "label" || tx.kind === "sub") {
            expect(tx.w + 2 * PAD_X, where).toBeLessThanOrEqual(box.w);
          } else {
            expect(tx.x, where).toBeGreaterThanOrEqual(box.x + 12);
            expect(tx.x + tx.w, where).toBeLessThanOrEqual(box.x + box.w - 12);
          }
        }
      }
    }
    // A long sublabel wraps at its separators instead of spilling: the gateway's, the sandbox pod's.
    expect(wrapSub("gateway · TLS from Let's Encrypt", 150)).toEqual(["gateway ·", "TLS from Let's Encrypt"]);
    expect(textWidth("RBAC: sandbox pods only", "sub")).toBeGreaterThan(textWidth("falco", "sub"));
  });

  it("the drawing starts inside its viewBox: no zone or node at a negative or edge coordinate", () => {
    for (const { box } of [...fitReport("hero"), ...fitReport("full", FULL_MODEL)]) expect(box.x).toBeGreaterThanOrEqual(4);
  });
});
