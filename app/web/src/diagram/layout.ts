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
  /** Prefix for element ids (two diagrams on one page must not share ids). */
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

function nodeTree(n: DiagramNode, b: Box, opts: LayoutOptions): Tree {
  const id = `${opts.idPrefix ?? "dg"}-${n.id}`;
  const attrs: Record<string, string | number> = { class: `dg-node dg-node--${n.tone}`, id, "data-node": n.id, "data-state": "idle", transform: `translate(${b.x} ${b.y})` };
  if (opts.interactive) {
    attrs.tabindex = 0;
    attrs.role = "button";
    attrs["aria-label"] = n.label;
    attrs["aria-expanded"] = "false";
  }
  const note = opts.notes?.[n.id];
  return t(
    "g",
    attrs,
    t("rect", { class: "dg-box", width: b.w, height: b.h, rx: 8 }),
    t("text", { class: "dg-label", x: b.w / 2, y: note ? 19 : 23, "text-anchor": "middle" }, n.label),
    t("text", { class: "dg-sub", x: b.w / 2, y: note ? 34 : 41, "text-anchor": "middle" }, n.sub),
    note ? t("text", { class: "dg-sub dg-note", x: b.w / 2, y: 49, "text-anchor": "middle" }, note) : null,
  );
}

function zoneTree(z: DiagramZone, b: Box, m: Metrics): Tree {
  return t(
    "g",
    { class: "dg-zone", "data-zone": z.id },
    t("rect", { class: "dg-zonebox", x: b.x, y: b.y, width: b.w, height: b.h, rx: 12 }),
    t("text", { class: "dg-zonetitle", x: b.x + m.zonePad, y: b.y + 17 }, z.title),
    z.sub ? t("text", { class: "dg-zonesub", x: b.x + m.zonePad + z.title.length * 7.2 + 10, y: b.y + 17 }, z.sub) : null,
  );
}

/** The marker definitions: one arrowhead per edge kind, coloured by class. */
function defs(prefix: string): Tree {
  const marker = (kind: string) =>
    t("marker", { id: `${prefix}-arrow-${kind}`, viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 6, markerHeight: 6, orient: "auto-start-reverse" }, t("path", { class: `dg-head dg-head--${kind}`, d: "M0,0 L10,5 L0,10 z" }));
  return t("defs", {}, marker("flow"), marker("side"), marker("response"), marker("lit"));
}

/** An orthogonal path between two boxes; returns the path and where its label sits. */
function route(e: DiagramEdge, a: Box, b: Box, m: Metrics): { d: string; label: [number, number]; vertical?: boolean } {
  const r = e.route ?? "auto";
  const sameRow = Math.abs(cy(a) - cy(b)) < 1;
  const sameCol = Math.abs(cx(a) - cx(b)) < 1;
  if (r === "under") {
    const y = Math.max(bottom(a), bottom(b)) + m.gy * 0.55;
    const x0 = cx(a) - 14;
    const x1 = cx(b);
    return { d: `M${x0},${bottom(a)} V${y} H${x1} V${bottom(b)}`, label: [(x0 + x1) / 2, y - 6] };
  }
  if (r === "over") {
    const y = Math.min(a.y, b.y) - m.gy * 0.55;
    return { d: `M${cx(a)},${a.y} V${y} H${cx(b)} V${b.y}`, label: [(cx(a) + cx(b)) / 2, y - 6] };
  }
  if (sameRow || (r === "auto" && Math.abs(cy(a) - cy(b)) < m.ch)) {
    const forward = cx(b) > cx(a);
    const x0 = forward ? right(a) : a.x;
    const x1 = forward ? b.x : right(b);
    return { d: `M${x0},${cy(a)} H${x1}`, label: [(x0 + x1) / 2, cy(a) - 7] };
  }
  if (sameCol) {
    const down = cy(b) > cy(a);
    const y0 = down ? bottom(a) : a.y;
    const y1 = down ? b.y : bottom(b);
    return { d: `M${cx(a)},${y0} V${y1}`, label: [cx(a) + 8, (y0 + y1) / 2 + 4], vertical: true };
  }
  const down = cy(b) > cy(a);
  const forward = cx(b) > cx(a);
  if (r === "hv") {
    // Out of a's side, along to b's column, then into b's top or bottom.
    const x0 = forward ? right(a) : a.x;
    const y1 = down ? b.y : bottom(b);
    return { d: `M${x0},${cy(a)} H${cx(b)} V${y1}`, label: [(x0 + cx(b)) / 2, cy(a) - 7] };
  }
  // vh: out of a's bottom or top, down to b's row, then into b's side.
  const y0 = down ? bottom(a) : a.y;
  const x0 = cx(a) + 14;
  const x1 = forward ? b.x : right(b);
  return { d: `M${x0},${y0} V${cy(b)} H${x1}`, label: [(x0 + x1) / 2, cy(b) - 7] };
}

function edgeTree(e: DiagramEdge, a: Box, b: Box, m: Metrics, prefix: string): Tree {
  const { d, label, vertical } = route(e, a, b, m);
  const id = `${e.from}-${e.to}`;
  return t(
    "g",
    { class: `dg-edge dg-edge--${e.kind}`, "data-edge": id, "data-lit": "false" },
    t("path", { class: "dg-line", d, "marker-end": `url(#${prefix}-arrow-${e.kind})`, ...(e.both ? { "marker-start": `url(#${prefix}-arrow-${e.kind})` } : {}) }),
    t("path", { class: "dg-packet", d }),
    e.label ? t("text", { class: "dg-edgelabel", x: label[0], y: label[1], "text-anchor": vertical ? "start" : "middle" }, e.label) : null,
  );
}

function layoutGrid(view: "hero" | "full", opts: LayoutOptions, model: DiagramModel): Tree {
  const m = METRICS[view];
  const prefix = opts.idPrefix ?? "dg";
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
    { xmlns: "http://www.w3.org/2000/svg", viewBox: `0 0 ${width} ${height}`, class: `dg dg--${view}`, role: "img", "aria-labelledby": `${titleId} ${descId}` },
    t("title", { id: titleId }, opts.title ?? "Architecture: how an attack on this site is detected and answered"),
    t("desc", { id: descId }, opts.desc ?? describe(nodes, edges)),
    defs(prefix),
    t("g", { class: "dg-zones" }, ...zoneBoxes.map(([z, b]) => zoneTree(z, b, m))),
    t("g", { class: "dg-edges" }, ...edges.map((e) => edgeTree(e, boxes.get(e.from) as Box, boxes.get(e.to) as Box, m, prefix))),
    t("g", { class: "dg-nodes" }, ...nodes.map((n) => nodeTree(n, boxes.get(n.id) as Box, opts))),
  );
}

/** The phone's hero: the story's nodes top to bottom, the answer looping back up the right side. */
function layoutNarrow(opts: LayoutOptions, model: DiagramModel): Tree {
  const prefix = opts.idPrefix ?? "dgn";
  const m: Metrics = { cw: 236, ch: 50, gx: 0, gy: 30, pad: 12, zoneHead: 18, zonePad: 0 };
  const nodes = nodesOf("narrow", model);
  const boxes = new Map<string, Box>();
  const heads: Tree[] = [];
  let y = m.pad;
  let zone = "";
  const x = m.pad + 20;
  const order = new Map(nodes.map((n, i) => [n.id, i]));
  for (const n of nodes) {
    if (n.zone !== zone) {
      zone = n.zone;
      const z = model.zones.find((zz) => zz.id === zone);
      heads.push(t("text", { class: "dg-zonetitle", x, y: y + 12 }, z?.title ?? zone));
      y += m.zoneHead;
    }
    boxes.set(n.id, { x, y, w: m.cw, h: m.ch });
    y += m.ch + m.gy;
  }
  const height = y - m.gy + m.pad;
  const width = x + m.cw + 92;
  const edges = model.edges.filter((e) => e.detail === "hero" && boxes.has(e.from) && boxes.has(e.to));
  const edgeTrees = edges.map((e) => {
    const a = boxes.get(e.from) as Box;
    const b = boxes.get(e.to) as Box;
    const down = b.y > a.y;
    let d: string;
    let label: [number, number];
    let anchor = "start";
    const adjacent = (order.get(e.to) ?? 0) - (order.get(e.from) ?? 0) === 1;
    if (down && adjacent) {
      d = `M${cx(a)},${bottom(a)} V${b.y}`;
      label = [cx(a) + 8, (bottom(a) + b.y) / 2 + 4];
    } else if (down) {
      // Skips rows: down the left margin.
      d = `M${a.x},${cy(a)} H${a.x - 12} V${cy(b)} H${b.x}`;
      label = [a.x - 16, (cy(a) + cy(b)) / 2];
      anchor = "end";
    } else {
      // The answer, back up the right side.
      const xr = right(a) + 28;
      d = `M${right(a)},${cy(a)} H${xr} V${cy(b)} H${right(b)}`;
      label = [xr + 6, (cy(a) + cy(b)) / 2 + 4];
    }
    return t(
      "g",
      { class: `dg-edge dg-edge--${e.kind}`, "data-edge": `${e.from}-${e.to}`, "data-lit": "false" },
      t("path", { class: "dg-line", d, "marker-end": `url(#${prefix}-arrow-${e.kind})` }),
      t("path", { class: "dg-packet", d }),
      // Only a straight hop carries its words: the margins are too narrow for a label.
      e.label && down && adjacent ? t("text", { class: "dg-edgelabel", x: label[0], y: label[1], "text-anchor": anchor }, e.label) : null,
      !down ? t("text", { class: "dg-edgelabel", x: label[0], y: label[1], "text-anchor": anchor }, "answer") : null,
    );
  });
  const titleId = `${prefix}-title`;
  const descId = `${prefix}-desc`;
  return t(
    "svg",
    { xmlns: "http://www.w3.org/2000/svg", viewBox: `0 0 ${width} ${height}`, class: "dg dg--narrow", role: "img", "aria-labelledby": `${titleId} ${descId}` },
    t("title", { id: titleId }, opts.title ?? "Architecture: how an attack on this site is detected and answered"),
    t("desc", { id: descId }, opts.desc ?? describe(nodes, edges)),
    defs(prefix),
    t("g", { class: "dg-zones" }, ...heads),
    t("g", { class: "dg-edges" }, ...edgeTrees),
    t("g", { class: "dg-nodes" }, ...nodes.map((n) => nodeTree(n, boxes.get(n.id) as Box, opts))),
  );
}

/** A text description of the drawing for screen readers and the docs file. */
function describe(nodes: DiagramNode[], edges: DiagramEdge[]): string {
  const name = (id: string) => nodes.find((n) => n.id === id)?.label ?? id;
  return `${nodes.length} components: ${nodes.map((n) => n.label).join(", ")}. Connections: ${edges.map((e) => `${name(e.from)} to ${name(e.to)}${e.label ? ` (${e.label})` : ""}`).join("; ")}.`;
}
