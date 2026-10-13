// docs/architecture/overview.svg: the full view of the model as a standalone file with its own
// <style> (GitHub renders an SVG's light/dark media query), written by scripts/diagram.mjs and
// checked against the committed file by a unit test, so the drawing on GitHub never drifts from the
// one on the page.

import { layout } from "./layout";
import { FULL_MODEL } from "./model-docs";
import { type Tree, escape, serialise } from "./tree";

/** The file's stylesheet: the same classes the page colours from styles.css, in GitHub's palette. */
const STYLE = `
    .dg-bg { fill: #ffffff; }
    .dg-zonebox { fill: #f6f8fa; stroke: #d0d7de; stroke-width: 1; }
    .dg-zonetitle { font: 600 13px system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; fill: #1f2328; }
    .dg-zonesub { font: 11px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; fill: #57606a; }
    .dg-box { fill: #ffffff; stroke: #57606a; stroke-width: 1.2; }
    .dg-node--control .dg-box { fill: #ddf4ff; stroke: #0969da; stroke-width: 1.4; }
    .dg-label { font: 600 13px system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; fill: #1f2328; }
    .dg-sub { font: 10.5px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; fill: #57606a; }
    .dg-line { fill: none; stroke: #57606a; stroke-width: 1.5; }
    .dg-edge--side .dg-line { stroke-dasharray: 3 4; }
    .dg-edge--response .dg-line { stroke: #cf222e; }
    .dg-edgelabel { font: 10.5px system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; fill: #57606a; paint-order: stroke; stroke: #ffffff; stroke-width: 4px; stroke-linejoin: round; }
    .dg-head { fill: #57606a; }
    .dg-head--response { fill: #cf222e; }
    .dg-title { font: 600 18px system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; fill: #1f2328; }
    .dg-foot { font: 11px system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; fill: #57606a; }
    @media (prefers-color-scheme: dark) {
      .dg-bg { fill: #0d1117; }
      .dg-zonebox { fill: #161b22; stroke: #30363d; }
      .dg-zonetitle, .dg-label, .dg-title { fill: #e6edf3; }
      .dg-zonesub, .dg-sub, .dg-edgelabel, .dg-foot { fill: #9198a1; }
      .dg-edgelabel { stroke: #0d1117; }
      .dg-box { fill: #0d1117; stroke: #8b949e; }
      .dg-node--control .dg-box { fill: #0c2d6b; stroke: #4493f8; }
      .dg-line { stroke: #8b949e; }
      .dg-head { fill: #8b949e; }
      .dg-edge--response .dg-line, .dg-head--response { stroke: #f85149; fill: #f85149; }
      .dg-edge--response .dg-line { fill: none; }
    }
`;

export interface DocsOptions {
  /** How many Argo CD Applications cluster/apps/ holds (counted by the script, so the drawing is current). */
  argoApps: number;
}

/** The whole file: a background, a title line, the full diagram, a footer naming the sources. */
export function renderDocsSvg(opts: DocsOptions): string {
  const title = "self-defending-portfolio: architecture overview";
  const tree = layout("full", {
    idPrefix: "ov",
    interactive: false,
    notes: { argocd: `${opts.argoApps} Applications` },
    title,
    desc: "The network path from the visitor through Cloudflare and an outbound-only tunnel to the Cilium Gateway and the page with its API; GitOps from a push through CI and Argo CD; the supply chain from the build workflow through Trivy, keyless cosign signing and GHCR to Kyverno admission; detection and response from a sandbox pod through Falco, Falcosidekick and Falco Talon back to kube-apiserver, and from everything to the SIEM on its own VM.",
  }, FULL_MODEL);
  const [, , w, h] = String(tree.attrs.viewBox).split(" ").map(Number);
  const descNode = tree.children.find((c): c is Tree => typeof c !== "string" && c.tag === "desc");
  const desc = descNode ? String(descNode.children[0] ?? "") : "";
  const headH = 58;
  const footH = 70;
  const height = h + headH + footH;
  const inner = { ...tree, attrs: { ...tree.attrs, x: 0, y: headH, width: w, height: h } };
  delete (inner.attrs as Record<string, unknown>).xmlns;
  const lines = [
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${height}" width="${w}" height="${height}" role="img" aria-labelledby="ov-t ov-d">`,
    `  <title id="ov-t">${escape(title)}</title>`,
    `  <desc id="ov-d">${escape(desc)}</desc>`,
    `  <style>${STYLE}  </style>`,
    `  <rect class="dg-bg" x="0" y="0" width="${w}" height="${height}"/>`,
    `  <text class="dg-title" x="16" y="30">${escape(title)}</text>`,
    `  <text class="dg-foot" x="16" y="48">Generated from app/web/src/diagram/model.ts (npm run diagram); the same model draws the live diagram on the site. Details and sources: docs/architecture/README.md</text>`,
    serialise(inner, "  "),
    `  <text class="dg-foot" x="16" y="${h + headH + 24}">Solid line: the main path of a request, an action or an artefact. Dotted: a side relationship. Red: the automatic response.</text>`,
    `  <text class="dg-foot" x="16" y="${h + headH + 42}">Falco rules: a terminal shell, a sensitive file read, a dropped binary, execution from the shop volume → terminate (grace 0); a network tool → quarantine (a label selects a CiliumClusterwideNetworkPolicy that denies all ingress and egress).</text>`,
    `  <text class="dg-foot" x="16" y="${h + headH + 60}">Proof: tests/runtime/run.sh asserts alert → POST → terminate, the quarantine and Talon's RBAC limits; tests/scenarios/run.sh runs every scenario; siem/ holds the Sigma rules and the correlations.</text>`,
    `</svg>`,
    "",
  ];
  return lines.join("\n");
}
