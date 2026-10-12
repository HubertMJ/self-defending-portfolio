// The architecture diagram's one model (site redesign 2026-10-12): the model is consistent, the layout
// turns it into a valid SVG tree with a node per element and no HTML sink, the hero path lights from a
// run's events, and the committed docs/architecture/overview.svg is what the model generates.

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildTimeline } from "../../src/lib/timeline";
import { MODEL, nodesOf, validateModel } from "../../src/diagram/model";
import { layout } from "../../src/diagram/layout";
import { serialise } from "../../src/diagram/tree";
import { renderDocsSvg } from "../../src/diagram/docs";
import { pathOf } from "../../src/ui/diagram";
import type { StreamEvent } from "../../src/lib/contract";

describe("diagram model", () => {
  it("is consistent: unique ids, edges between known nodes, every hero node placed", () => {
    expect(validateModel()).toEqual([]);
  });

  it("the hero carries the attack-and-answer story, not the supply chain or GitOps", () => {
    const hero = new Set(nodesOf("hero").map((n) => n.id));
    for (const id of ["visitor", "cloudflare", "gateway", "pod", "falco", "talon", "kube-apiserver", "siem"]) expect(hero.has(id)).toBe(true);
    for (const id of ["cosign", "trivy", "argocd", "ghcr", "build"]) expect(hero.has(id)).toBe(false);
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
      const tree = layout(view, { interactive: view !== "full" });
      expect(tree.tag).toBe("svg");
      const svg = serialise(tree);
      expect(svg.startsWith("<svg")).toBe(true);
      // No HTML/script sink in the output, and every drawn node is present.
      expect(svg).not.toMatch(/<script|innerHTML|<foreignObject/i);
      for (const n of nodesOf(view)) expect(svg).toContain(`data-node="${n.id}"`);
    });
  }

  it("interactive nodes are focusable buttons; the docs view's are not", () => {
    const page = serialise(layout("hero", { interactive: true }));
    expect(page).toContain('role="button"');
    expect(page).toContain('tabindex="0"');
    const docs = serialise(layout("full", { interactive: false }));
    expect(docs).not.toContain('role="button"');
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
    expect(edges).toEqual([]);
  });

  it("a detected and answered run lights the attack path, Falco, Talon and the answer back to the pod", () => {
    const { nodes, edges, summary } = pathOf(killedRun());
    expect(nodes.get("pod")).toBe("respond");
    expect(nodes.get("falco")).toBe("detect");
    expect(nodes.get("talon")).toBe("respond");
    expect(nodes.get("kube-apiserver")).toBe("respond");
    expect(edges).toContain("pod-falco");
    expect(edges).toContain("falco-talon");
    expect(edges).toContain("kube-apiserver-pod");
    expect(summary).toMatch(/answered/);
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
