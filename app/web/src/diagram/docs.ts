// docs/architecture/overview.svg: the full view of the model as a standalone file with its own
// <style> (GitHub renders an SVG's light/dark media query), written by scripts/diagram.mjs and
// checked against the committed file by a unit test, so the drawing on GitHub never drifts from the
// one on the page.

import { layout } from "./layout";
import { ROLE_LEGEND } from "./model";
import { FULL_MODEL } from "./model-docs";
import { type Tree, escape, serialise } from "./tree";

/** The file's stylesheet: the same classes the page colours from styles.css, in GitHub's palette. */
const STYLE = `
    .dg-bg { fill: #ffffff; }
    .dg-zonebox { fill: #f6f8fa; stroke: #d0d7de; stroke-width: 1; }
    .dg-zonetitle { font: 600 13px system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; fill: #1f2328; }
    .dg-zonesub { font: 11px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; fill: #57606a; }
    .dg-box { stroke-width: 1.6; }
    .dg-role--entry > .dg-box { fill: #e9f2fc; stroke: #0969da; }
    .dg-swatch.dg-role--entry { fill: #0969da; stroke: #0969da; }
    .dg-role--attack > .dg-box { fill: #faeee9; stroke: #c2410c; }
    .dg-swatch.dg-role--attack { fill: #c2410c; stroke: #c2410c; }
    .dg-role--detect > .dg-box { fill: #f6f1e8; stroke: #9a6700; }
    .dg-swatch.dg-role--detect { fill: #9a6700; stroke: #9a6700; }
    .dg-role--respond > .dg-box { fill: #e8f3ef; stroke: #047a52; }
    .dg-swatch.dg-role--respond { fill: #047a52; stroke: #047a52; }
    .dg-role--record > .dg-box { fill: #f4effc; stroke: #8250df; }
    .dg-swatch.dg-role--record { fill: #8250df; stroke: #8250df; }
    .dg-role--neutral > .dg-box { fill: #f0f1f2; stroke: #57606a; }
    .dg-label { font: 600 13px system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; fill: #1f2328; }
    .dg-sub { font: 10.5px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; fill: #57606a; }
    .dg-line { fill: none; stroke: #57606a; stroke-width: 1.5; }
    .dg-edge--side .dg-line { stroke-dasharray: 3 4; }
    .dg-edge--response .dg-line { stroke: #047a52; }
    .dg-edgelabel { font: 10.5px system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; fill: #57606a; paint-order: stroke; stroke: #ffffff; stroke-width: 4px; stroke-linejoin: round; }
    .dg-head { fill: #57606a; }
    .dg-head--response { fill: #047a52; }
    .dg-title { font: 600 18px system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; fill: #1f2328; }
    .dg-legendtext { font: 11px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; fill: #57606a; }
    .dg-foot { font: 11px system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; fill: #57606a; }
    @media (prefers-color-scheme: dark) {
      .dg-bg { fill: #0d1117; }
      .dg-zonebox { fill: #161b22; stroke: #30363d; }
      .dg-zonetitle, .dg-label, .dg-title { fill: #e6edf3; }
      .dg-zonesub, .dg-sub, .dg-edgelabel, .dg-foot, .dg-legendtext { fill: #9198a1; }
      .dg-edgelabel { stroke: #0d1117; }
      .dg-role--entry > .dg-box { fill: #192635; stroke: #6cb6ff; }
      .dg-swatch.dg-role--entry { fill: #6cb6ff; stroke: #6cb6ff; }
      .dg-role--attack > .dg-box { fill: #2c1e1f; stroke: #ff7657; }
      .dg-swatch.dg-role--attack { fill: #ff7657; stroke: #ff7657; }
      .dg-role--detect > .dg-box { fill: #2b281e; stroke: #f4bf4f; }
      .dg-swatch.dg-role--detect { fill: #f4bf4f; stroke: #f4bf4f; }
      .dg-role--respond > .dg-box { fill: #182c29; stroke: #5ee0a4; }
      .dg-swatch.dg-role--respond { fill: #5ee0a4; stroke: #5ee0a4; }
      .dg-role--record > .dg-box { fill: #232233; stroke: #b392f0; }
      .dg-swatch.dg-role--record { fill: #b392f0; stroke: #b392f0; }
      .dg-role--neutral > .dg-box { fill: #1d2229; stroke: #8b949e; }
      .dg-line { stroke: #8b949e; }
      .dg-head { fill: #8b949e; }
      .dg-edge--response .dg-line, .dg-head--response { stroke: #5ee0a4; fill: #5ee0a4; }
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
  const footH = 92;
  const foot = h + headH;
  // The colour key, as on the page: a swatch per role and its word (11 px mono, about 6.7 px a character).
  let lx = 16;
  const legend = ROLE_LEGEND.map(({ role, word }) => {
    const item = [
      `    <rect class="dg-swatch dg-role--${role}" x="${lx}" y="${foot + 15}" width="10" height="10" rx="2"/>`,
      `    <text class="dg-legendtext" x="${lx + 16}" y="${foot + 24}">${escape(word)}</text>`,
    ];
    lx += 16 + Math.ceil(word.length * 6.7) + 20;
    return item.join("\n");
  });
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
    `  <g class="dg-legend" aria-label="Colour key">`,
    ...legend,
    `  </g>`,
    `  <text class="dg-foot" x="16" y="${foot + 46}">Box colour: the node's role. Solid line: the main path of a request, an action or an artefact. Dotted: a side relationship. Green: the automatic response.</text>`,
    `  <text class="dg-foot" x="16" y="${foot + 64}">Falco rules: a terminal shell, a sensitive file read, a dropped binary, execution from the shop volume → terminate (grace 0); a network tool → quarantine (a label selects a CiliumClusterwideNetworkPolicy that denies all ingress and egress).</text>`,
    `  <text class="dg-foot" x="16" y="${foot + 82}">Proof: tests/runtime/run.sh asserts alert → POST → terminate, the quarantine and Talon's RBAC limits; tests/scenarios/run.sh runs every scenario; siem/ holds the Sigma rules and the correlations.</text>`,
    `</svg>`,
    "",
  ];
  return lines.join("\n");
}
