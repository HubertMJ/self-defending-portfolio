// Lays the model out as an SVG tree (src/diagram/tree.ts) for one of three views: the hero's wide
// diagram, the phone's vertical path, and the full docs diagram. Positions come from the model's grid
// cells; this module only turns cells into pixels, routes the edges and names every part with the
// classes styles.css (the page) and scripts/diagram.mjs (the docs file's own <style>) colour.
//
// No colours, no sizes of text and no animation live here: classes only, so the same drawing obeys the
// page's CSP (style-src 'self', no style attributes) and the docs file's light/dark <style>.

import { type DiagramEdge, type DiagramModel, type DiagramNode, type DiagramZone, MODEL, type View, nodesOf } from "./model";
import { type Tree, t } from "./tree";

interface Box {
  x: number;
  y: number;
  w: number;
  h: number;
}

interface Metrics {
  cw: number;
  ch: number;
  gx: number;
  gy: number;
  pad: number;
  /** Space above a zone's first row for its title. */
  zoneHead: number;
  zonePad: number;
}

const METRICS: Record<"hero" | "full", Metrics> = {
  hero: { cw: 170, ch: 56, gx: 54, gy: 50, pad: 14, zoneHead: 26, zonePad: 14 },
  full: { cw: 176, ch: 60, gx: 48, gy: 44, pad: 16, zoneHead: 28, zonePad: 14 },
};

const cx = (b: Box) => b.x + b.w / 2;
const cy = (b: Box) => b.y + b.h / 2;
const right = (b: Box) => b.x + b.w;
const bottom = (b: Box) => b.y + b.h;

export interface LayoutOptions {
  /** Prefix for element ids (two diagrams on one page must not share ids). The SVG is role="group" when interactive (its nodes are buttons), role="img" in the docs file. */
  idPrefix?: string;
  /** Interactive nodes (focusable, role=button) — the page; off for the docs file. */
  interactive?: boolean;
  /** Extra line under a node's sub label, by node id (the docs diagram's live counts). */
  notes?: Record<string, string>;
  title?: string;
  desc?: string;
}

/** The SVG tree of a view. */
export function layout(view: View, opts: LayoutOptions = {}, model: DiagramModel = MODEL): Tree {
  return view === "narrow" ? layoutNarrow(opts, model) : layoutGrid(view, opts, model);
}

/** Edges stop this far from a node's border, so an arrowhead never touches the box it points at. */
const GAP = 7;

/**
 * A node's words, centred in its box: the label and its sublabel as one block. On the page the
 * sublabel is shown only in Technical Mode, and styles.css moves a lone label down by 7.5 units
 * (half the block's second line) so it sits in the middle then too.
 */
function nodeTree(n: DiagramNode, b: Box, opts: LayoutOptions): Tree {
  const id = `${opts.idPrefix ?? "dg"}-${n.id}`;
  const attrs: Record<string, string | number> = { class: `dg-node dg-node--${n.tone} dg-role--${n.role}`, id, "data-node": n.id, "data-state": "idle", transform: `translate(${b.x} ${b.y})` };
  if (opts.interactive) {
    attrs.tabindex = 0;
    attrs.role = "button";
    attrs["aria-label"] = n.label;
    attrs["aria-expanded"] = "false";
  }
  const note = opts.notes?.[n.id];
  // Baselines: two lines centred as a block (three with a note), 15 units apart.
  const mid = b.h / 2;
  const first = note ? mid - 10.5 : mid - 3;
  return t(
    "g",
    attrs,
    t("rect", { class: "dg-box", width: b.w, height: b.h, rx: 8 }),
    t("text", { class: "dg-label", x: b.w / 2, y: first, "text-anchor": "middle" }, n.label),
    t("text", { class: "dg-sub", x: b.w / 2, y: first + 15, "text-anchor": "middle" }, n.sub),
    note ? t("text", { class: "dg-sub dg-note", x: b.w / 2, y: first + 30, "text-anchor": "middle" }, note) : null,
  );
}

function zoneTree(z: DiagramZone, b: Box, m: Metrics): Tree {
  return t(
    "g",
    { class: "dg-zone", "data-zone": z.id },
    t("rect", { class: "dg-zonebox", x: b.x, y: b.y, width: b.w, height: b.h, rx: 10 }),
    t("text", { class: "dg-zonetitle", x: b.x + m.zonePad, y: b.y + 17 }, z.title),
    z.sub ? t("text", { class: "dg-zonesub", x: b.x + m.zonePad + z.title.length * 7.2 + 10, y: b.y + 17 }, z.sub) : null,
  );
}

/**
 * The marker definitions: one arrowhead per edge kind, coloured by class, one size in user units
 * (8 by 8, whatever the line's width). Its tip is the line's end, GAP short of the node.
 */
function defs(prefix: string): Tree {
  const marker = (kind: string) =>
    t(
      "marker",
      { id: `${prefix}-arrow-${kind}`, viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 8, markerHeight: 8, markerUnits: "userSpaceOnUse", orient: "auto-start-reverse" },
      t("path", { class: `dg-head dg-head--${kind}`, d: "M0,1 L10,5 L0,9 z" }),
    );
  return t("defs", {}, marker("flow"), marker("side"), marker("response"));
}

type Pt = [number, number];

/** The path through the points, its first and last segment cut GAP short of the boxes they leave and reach. */
function trimmed(pts: Pt[], gap = GAP): Pt[] {
  const out = pts.map((p) => [...p] as Pt);
  const pull = (p: Pt, toward: Pt) => {
    const dx = toward[0] - p[0];
    const dy = toward[1] - p[1];
    const len = Math.hypot(dx, dy) || 1;
    const k = Math.min(gap, len / 3) / len;
    p[0] += dx * k;
    p[1] += dy * k;
  };
  pull(out[0], out[1]);
  pull(out[out.length - 1], out[out.length - 2]);
  return out;
}

const r1 = (n: number) => Math.round(n * 10) / 10;
const pathD = (pts: Pt[]) => pts.map(([x, y], i) => `${i ? "L" : "M"}${r1(x)},${r1(y)}`).join(" ");

/** An orthogonal path between two boxes (border to border); and where its label sits. */
function route(e: DiagramEdge, a: Box, b: Box, m: Metrics): { pts: Pt[]; label: Pt; vertical?: boolean } {
  const r = e.route ?? "auto";
  const sameRow = Math.abs(cy(a) - cy(b)) < 1;
  const sameCol = Math.abs(cx(a) - cx(b)) < 1;
  if (r === "under") {
    const y = Math.max(bottom(a), bottom(b)) + m.gy * 0.55;
    const x0 = cx(a) - 14;
    const x1 = cx(b);
    return { pts: [[x0, bottom(a)], [x0, y], [x1, y], [x1, bottom(b)]], label: [(x0 + x1) / 2, y - 7] };
  }
  if (r === "over") {
    const y = Math.min(a.y, b.y) - m.gy * 0.55;
    return { pts: [[cx(a), a.y], [cx(a), y], [cx(b), y], [cx(b), b.y]], label: [(cx(a) + cx(b)) / 2, y - 7] };
  }
  if (sameRow || (r === "auto" && Math.abs(cy(a) - cy(b)) < m.ch)) {
    const forward = cx(b) > cx(a);
    const x0 = forward ? right(a) : a.x;
    const x1 = forward ? b.x : right(b);
    return { pts: [[x0, cy(a)], [x1, cy(a)]], label: [(x0 + x1) / 2, cy(a) - 8] };
  }
  if (sameCol) {
    const down = cy(b) > cy(a);
    const y0 = down ? bottom(a) : a.y;
    const y1 = down ? b.y : bottom(b);
    return { pts: [[cx(a), y0], [cx(a), y1]], label: [cx(a) + 9, (y0 + y1) / 2 + 4], vertical: true };
  }
  const down = cy(b) > cy(a);
  const forward = cx(b) > cx(a);
  if (r === "hv") {
    // Out of a's side, along to b's column, then into b's top or bottom.
    const x0 = forward ? right(a) : a.x;
    const y1 = down ? b.y : bottom(b);
    return { pts: [[x0, cy(a)], [cx(b), cy(a)], [cx(b), y1]], label: [(x0 + cx(b)) / 2, cy(a) - 8] };
  }
  // vh: out of a's bottom or top, down to b's row, then into b's side.
  const y0 = down ? bottom(a) : a.y;
  const x0 = cx(a) + 14;
  const x1 = forward ? b.x : right(b);
  return { pts: [[x0, y0], [x0, cy(b)], [x1, cy(b)]], label: [(x0 + x1) / 2, cy(b) - 8] };
}

/**
 * The ambient traffic (2026-10-13, redrawn the same day): a small glowing dot runs the request path
 * from the visitor to the page every few seconds, and now and then the detect-and-respond loop; each
 * edge it passes brightens for a moment. On the page only (the docs file is still). The dot's route
 * and timing are drawn here into a stylesheet (trafficCss) that the build bundles with styles.css:
 * the page's CSP allows no style attribute, and offset-path needs the route.
 */
export const TRAFFIC = {
  req: { edges: ["visitor-cloudflare", "cloudflare-cloudflared", "cloudflared-gateway", "gateway-site"], period: 6, start: 0, travel: 2.4 },
  loop: { edges: ["pod-falco", "falco-talon", "talon-kube-apiserver", "kube-apiserver-pod"], period: 18, start: 3.2, travel: 2.6 },
} as const;
type Lane = keyof typeof TRAFFIC;

const laneOf = (edgeId: string): Lane | undefined => (Object.keys(TRAFFIC) as Lane[]).find((l) => (TRAFFIC[l].edges as readonly string[]).includes(edgeId));

/** An edge's group: the line with its arrowheads, its brightening on the page's traffic lanes, its label. */
function edgeGroup(e: DiagramEdge, pts: Pt[], label: Pt | null, anchor: string, prefix: string, interactive?: boolean): Tree {
  const id = `${e.from}-${e.to}`;
  const d = pathD(trimmed(pts));
  const marker = `url(#${prefix}-arrow-${e.kind})`;
  return t(
    "g",
    { class: `dg-edge dg-edge--${e.kind}`, "data-edge": id, "data-lit": "false" },
    t("path", { class: "dg-line", d, "marker-end": marker, ...(e.both ? { "marker-start": marker } : {}) }),
    interactive && laneOf(id) ? t("path", { class: "dg-glow", id: `${prefix}-glow-${id}`, d }) : null,
    label && e.label ? t("text", { class: "dg-edgelabel", x: r1(label[0]), y: r1(label[1]), "text-anchor": anchor }, e.label) : null,
  );
}

/** The traffic's dots, above the edges and under the nodes (a dot passes behind a box, out the other side). */
function trafficDots(prefix: string, interactive?: boolean): Tree | null {
  if (!interactive) return null;
  return t("g", { class: "dg-traffic", "aria-hidden": "true" }, ...(Object.keys(TRAFFIC) as Lane[]).map((l) => t("circle", { class: "dg-dot", id: `${prefix}-dot-${l}`, r: 3 })));
}

/** Each view's edge routes, for the traffic: the route's points by edge id and the boxes by node id. */
interface Routes {
  pts: Map<string, Pt[]>;
  boxes: Map<string, Box>;
}

/**
 * The traffic's stylesheet for one drawn view: each dot's offset-path (from the first node's centre,
 * along the lane's edges, into the last node's centre: it emerges from behind a box and sinks into the
 * next) and keyframes; each edge's brightening while the dot is on it. styles.css runs them (and stops
 * them under reduced motion, off screen, in a hidden tab and while a run lights the path).
 */
function laneCss(prefix: string, routes: Routes): string {
  const css: string[] = [];
  const pct = (n: number) => `${Math.round(Math.min(100, Math.max(0, n)) * 100) / 100}%`;
  for (const lane of Object.keys(TRAFFIC) as Lane[]) {
    const L = TRAFFIC[lane];
    const segs = L.edges.map((id) => routes.pts.get(id));
    if (segs.some((s) => !s)) continue;
    const first = routes.boxes.get(L.edges[0].split("-")[0]) as Box;
    const lastId = L.edges[L.edges.length - 1];
    const lastTo = [...routes.boxes.keys()].find((k) => lastId.endsWith(`-${k}`)) as string;
    const last = routes.boxes.get(lastTo) as Box;
    const pts: Pt[] = [[cx(first), cy(first)], ...(segs as Pt[][]).flat(), [cx(last), cy(last)]];
    // Cumulative length at each edge's start and end, as fractions of the whole.
    const len = (a: Pt, b: Pt) => Math.hypot(b[0] - a[0], b[1] - a[1]);
    let total = 0;
    for (let i = 1; i < pts.length; i++) total += len(pts[i - 1], pts[i]);
    const span: [number, number][] = [];
    let at = len(pts[0], (segs[0] as Pt[])[0]);
    for (const s of segs as Pt[][]) {
      let l = 0;
      for (let i = 1; i < s.length; i++) l += len(s[i - 1], s[i]);
      span.push([at / total, (at + l) / total]);
      at += l;
      const next = segs[span.length];
      if (next) at += len(s[s.length - 1], next[0]);
    }
    // Time: most of the travel on the edges (at one speed), a short hop through each box.
    const t0 = (L.start / L.period) * 100;
    const tw = (L.travel / L.period) * 100;
    const visible = span.reduce((sum, [s0, s1]) => sum + (s1 - s0), 0);
    const hop = (tw * 0.24) / (span.length + 1);
    const onEdges = tw - hop * (span.length + 1);
    const times: [number, number][] = [];
    let clock = t0 + hop;
    for (const [s0, s1] of span) {
      const dt = (onEdges * (s1 - s0)) / visible;
      times.push([clock, clock + dt]);
      clock += dt + hop;
    }
    const name = `dg-tr-${prefix}-${lane}`;
    const dPath = pts.map(([x, y], i) => `${i ? "L" : "M"}${r1(x)} ${r1(y)}`).join(" ");
    const frames = [`0%, ${pct(t0)} { offset-distance: 0%; opacity: 0; }`, `${pct(t0 + hop * 0.6)} { opacity: 1; }`];
    span.forEach(([s0, s1], i) => {
      frames.push(`${pct(times[i][0])} { offset-distance: ${pct(s0 * 100)}; }`, `${pct(times[i][1])} { offset-distance: ${pct(s1 * 100)}; }`);
    });
    frames.push(`${pct(t0 + tw - hop * 0.4)} { opacity: 1; }`, `${pct(t0 + tw)}, 100% { offset-distance: 100%; opacity: 0; }`);
    css.push(`#${prefix}-dot-${lane} { offset-path: path("${dPath}"); --tr-name: ${name}; --tr-period: ${L.period}s; }`);
    css.push(`@keyframes ${name} { ${frames.join(" ")} }`);
    L.edges.forEach((id, i) => {
      const [on, off] = times[i];
      const g = `dg-tr-${prefix}-${id}`;
      css.push(`#${prefix}-glow-${id} { --tr-name: ${g}; --tr-period: ${L.period}s; }`);
      css.push(`@keyframes ${g} { 0%, ${pct(on - 0.5)} { opacity: 0; } ${pct(on + 1)}, ${pct(off)} { opacity: 1; } ${pct(off + (L.period > 10 ? 4 : 10))}, 100% { opacity: 0; } }`);
    });
  }
  return css.join("\n");
}

/** The traffic's stylesheet for the page's two drawings (the build bundles it with styles.css). */
export function trafficCss(model: DiagramModel = MODEL): string {
  return [
    "/* Generated by src/diagram/layout.ts (trafficCss) at build time: the ambient traffic's routes. */",
    laneCss("dg", gridRoutes("hero", model)),
    laneCss("dgn", narrowRoutes(model)),
    "",
  ].join("\n");
}

/** The grid views' geometry: boxes by node id, zone boxes, the drawn edges and their routes. */
function gridGeometry(view: "hero" | "full", model: DiagramModel) {
  const m = METRICS[view];
  const px = m.cw + m.gx;
  const py = m.ch + m.gy;
  const top = m.pad + m.zoneHead;
  const cell = ([c, r]: [number, number]): Box => ({ x: m.pad + c * px, y: top + r * py, w: m.cw, h: m.ch });
  const nodes = nodesOf(view, model);
  const boxes = new Map(nodes.map((n) => [n.id, cell(n.at[view] as [number, number])]));
  const zones = model.zones.filter((z) => z.at[view]);
  const zoneBox = (z: DiagramZone): Box => {
    const [c, r, cs, rs] = z.at[view] as [number, number, number, number];
    const b = cell([c, r]);
    return { x: b.x - m.zonePad, y: b.y - m.zonePad - m.zoneHead, w: cs * px - m.gx + 2 * m.zonePad, h: rs * py - m.gy + 2 * m.zonePad + m.zoneHead };
  };
  const zoneBoxes = zones.map((z) => [z, zoneBox(z)] as const);
  const edges = model.edges.filter((e) => boxes.has(e.from) && boxes.has(e.to) && (view === "full" || e.detail === "hero") && (!e.views || e.views.includes(view)));
  const routes = new Map(edges.map((e) => [`${e.from}-${e.to}`, route(e, boxes.get(e.from) as Box, boxes.get(e.to) as Box, m)]));
  return { m, nodes, boxes, zoneBoxes, edges, routes };
}

function gridRoutes(view: "hero" | "full", model: DiagramModel): Routes {
  const g = gridGeometry(view, model);
  return { boxes: g.boxes, pts: new Map([...g.routes].map(([id, r]) => [id, trimmed(r.pts)])) };
}

function layoutGrid(view: "hero" | "full", opts: LayoutOptions, model: DiagramModel): Tree {
  const prefix = opts.idPrefix ?? "dg";
  const { m, nodes, boxes, zoneBoxes, edges, routes } = gridGeometry(view, model);
  let width = 0;
  let height = 0;
  for (const b of [...boxes.values(), ...zoneBoxes.map(([, b]) => b)]) {
    width = Math.max(width, right(b));
    height = Math.max(height, bottom(b));
  }
  // The "under" routes run below their row.
  for (const e of edges) if (e.route === "under") height = Math.max(height, Math.max(bottom(boxes.get(e.from) as Box), bottom(boxes.get(e.to) as Box)) + m.gy * 0.55 + 4);
  width += m.pad;
  height += m.pad;
  const titleId = `${prefix}-title`;
  const descId = `${prefix}-desc`;
  return t(
    "svg",
    { xmlns: "http://www.w3.org/2000/svg", viewBox: `0 0 ${width} ${height}`, class: `dg dg--${view}`, role: opts.interactive ? "group" : "img", "aria-labelledby": `${titleId} ${descId}` },
    t("title", { id: titleId }, opts.title ?? "Architecture: how an attack on this site is detected and answered"),
    t("desc", { id: descId }, opts.desc ?? describe(nodes, edges)),
    defs(prefix),
    t("g", { class: "dg-zones" }, ...zoneBoxes.map(([z, b]) => zoneTree(z, b, m))),
    t(
      "g",
      { class: "dg-edges" },
      ...edges.map((e) => {
        const r = routes.get(`${e.from}-${e.to}`) as ReturnType<typeof route>;
        return edgeGroup(e, r.pts, r.label, r.vertical ? "start" : "middle", prefix, opts.interactive);
      }),
    ),
    trafficDots(prefix, opts.interactive),
    t("g", { class: "dg-nodes" }, ...nodes.map((n) => nodeTree(n, boxes.get(n.id) as Box, opts))),
  );
}

/** The phone's geometry: the story's nodes top to bottom, the answer looping back up the right side. */
function narrowGeometry(model: DiagramModel) {
  const m: Metrics = { cw: 236, ch: 50, gx: 0, gy: 30, pad: 12, zoneHead: 18, zonePad: 0 };
  const nodes = nodesOf("narrow", model);
  const boxes = new Map<string, Box>();
  const heads: { x: number; y: number; title: string }[] = [];
  let y = m.pad;
  let zone = "";
  const x = m.pad + 20;
  const order = new Map(nodes.map((n, i) => [n.id, i]));
  for (const n of nodes) {
    if (n.zone !== zone) {
      zone = n.zone;
      const z = model.zones.find((zz) => zz.id === zone);
      heads.push({ x, y: y + 12, title: z?.title ?? zone });
      y += m.zoneHead;
    }
    boxes.set(n.id, { x, y, w: m.cw, h: m.ch });
    y += m.ch + m.gy;
  }
  const height = y - m.gy + m.pad;
  const width = x + m.cw + 92;
  const edges = model.edges.filter((e) => e.detail === "hero" && boxes.has(e.from) && boxes.has(e.to));
  const routes = new Map(
    edges.map((e) => {
      const a = boxes.get(e.from) as Box;
      const b = boxes.get(e.to) as Box;
      const down = b.y > a.y;
      const adjacent = (order.get(e.to) ?? 0) - (order.get(e.from) ?? 0) === 1;
      let pts: Pt[];
      let label: Pt | null = null;
      let anchor = "start";
      let text = e.label;
      if (down && adjacent) {
        pts = [[cx(a), bottom(a)], [cx(a), b.y]];
        label = [cx(a) + 9, (bottom(a) + b.y) / 2 + 4];
      } else if (down) {
        // Skips rows: down the left margin. The margins are too narrow for its words.
        pts = [[a.x, cy(a)], [a.x - 12, cy(a)], [a.x - 12, cy(b)], [b.x, cy(b)]];
      } else {
        // The answer, back up the right side.
        const xr = right(a) + 28;
        pts = [[right(a), cy(a)], [xr, cy(a)], [xr, cy(b)], [right(b), cy(b)]];
        label = [xr + 6, (cy(a) + cy(b)) / 2 + 4];
        text = "answer";
      }
      return [`${e.from}-${e.to}`, { pts, label, anchor, text }] as const;
    }),
  );
  return { nodes, boxes, heads, edges, routes, width, height };
}

function narrowRoutes(model: DiagramModel): Routes {
  const g = narrowGeometry(model);
  return { boxes: g.boxes, pts: new Map([...g.routes].map(([id, r]) => [id, trimmed(r.pts)])) };
}

/** The phone's hero: the story's nodes top to bottom, the answer looping back up the right side. */
function layoutNarrow(opts: LayoutOptions, model: DiagramModel): Tree {
  const prefix = opts.idPrefix ?? "dgn";
  const { nodes, boxes, heads, edges, routes, width, height } = narrowGeometry(model);
  const titleId = `${prefix}-title`;
  const descId = `${prefix}-desc`;
  return t(
    "svg",
    { xmlns: "http://www.w3.org/2000/svg", viewBox: `0 0 ${width} ${height}`, class: "dg dg--narrow", role: opts.interactive ? "group" : "img", "aria-labelledby": `${titleId} ${descId}` },
    t("title", { id: titleId }, opts.title ?? "Architecture: how an attack on this site is detected and answered"),
    t("desc", { id: descId }, opts.desc ?? describe(nodes, edges)),
    defs(prefix),
    t("g", { class: "dg-zones" }, ...heads.map((hd) => t("text", { class: "dg-zonetitle", x: hd.x, y: hd.y }, hd.title))),
    t(
      "g",
      { class: "dg-edges" },
      ...edges.map((e) => {
        const r = routes.get(`${e.from}-${e.to}`) as NonNullable<ReturnType<typeof routes.get>>;
        return edgeGroup({ ...e, label: r.text, both: false }, r.pts, r.label, r.anchor, prefix, opts.interactive);
      }),
    ),
    trafficDots(prefix, opts.interactive),
    t("g", { class: "dg-nodes" }, ...nodes.map((n) => nodeTree(n, boxes.get(n.id) as Box, opts))),
  );
}

/** A text description of the drawing for screen readers and the docs file. */
function describe(nodes: DiagramNode[], edges: DiagramEdge[]): string {
  const name = (id: string) => nodes.find((n) => n.id === id)?.label ?? id;
  return `${nodes.length} components: ${nodes.map((n) => n.label).join(", ")}. Connections: ${edges.map((e) => `${name(e.from)} to ${name(e.to)}${e.label ? ` (${e.label})` : ""}`).join("; ")}.`;
}
