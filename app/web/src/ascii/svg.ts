// An SVG diagram, read back as ASCII. Every diagram on the site is drawn the same way: nodes are
// <g data-node> holding a <rect> and lines of <text>; edges are orthogonal paths (M/L only); zones are
// rects whose class names a zone, with a zone-title text. So one reader turns any of them into a
// character grid: coordinates scaled so the widest label fits its box, words wrapped into the box's
// rows, lines walked cell by cell and trimmed at the boxes they join.

import { Grid, walk, type Cell, type Step } from "./grid";

export interface Edge { el: Element | null; cells: Cell[]; to: string | null; k: string }
export interface Drawing { g: Grid; edges: Edge[]; nodes: Map<string, Element> }

const num = (v: string | null): number => (v ? parseFloat(v) || 0 : 0);
const cls = (el: Element | null): string => el?.getAttribute("class") ?? "";

/** The translate() of an element and its ancestors up to the svg (the only transform the diagrams use). */
function offset(el: Element, svg: Element): [number, number] {
  let x = 0, y = 0;
  for (let e: Element | null = el; e && e !== svg; e = e.parentElement) {
    const m = e.getAttribute("transform")?.match(/translate\(\s*(-?[\d.]+)[\s,]+(-?[\d.]+)/);
    if (m) { x += Number(m[1]); y += Number(m[2]); }
  }
  return [x, y];
}

/** The colour class of a node: its role--x class, the landing page's project colour (em-site,
 * em-project, em-lab on the node or its box group), or neutral. */
const role = (el: Element): string => {
  const all = `${cls(el)} ${cls(el.querySelector("g"))}`;
  return all.match(/role--([\w-]+)/)?.[1] ?? all.match(/\bem-(site|project|lab|path)\b/)?.[1] ?? "neutral";
};

/** Word-wrap one line to `w` characters, breaking at " · " or spaces. */
export function wrap(s: string, w: number): string[] {
  const out: string[] = [];
  let line = "";
  for (const word of s.split(/(?<= · )|(?<= )/)) {
    if ([...(line + word).trimEnd()].length > w && line) { out.push(line.trimEnd()); line = ""; }
    line += word;
  }
  if (line.trim()) out.push(line.trimEnd());
  return out.map((l) => [...l].slice(0, w).join(""));
}

interface NodeIn { id: string; el: Element; x: number; y: number; w: number; h: number; lines: string[]; k: string; boxed: boolean }

export function fromSvg(svg: SVGSVGElement, maxCols: number): Drawing {
  const vb = (svg.getAttribute("viewBox") ?? "0 0 100 100").split(/[\s,]+/).map(Number);
  const nodes: NodeIn[] = [];
  // A node is any element carrying data-node: a <g>, or a link (<a>) around one.
  for (const el of svg.querySelectorAll("[data-node]")) {
    if (el.parentElement?.closest("[data-node]")) continue;
    const rect = el.querySelector("rect");
    const texts = [...el.querySelectorAll("text")].filter((t) => !t.hasAttribute("data-count"));
    let lines = texts.map((t) => (t.textContent ?? "").trim()).filter(Boolean);
    // A gauge (the incident's monitor): its pips and count as one line of [■][ ].
    const pips = [...el.querySelectorAll("rect[data-on]")];
    if (pips.length) {
      const count = el.querySelector("[data-count]")?.textContent?.trim() ?? "";
      lines = [...lines, `${pips.map((p) => (p.getAttribute("data-on") === "true" ? "[■]" : "[ ]")).join("")} ${count}`.trim()];
    }
    if (rect) {
      const [tx, ty] = offset(rect, svg);
      nodes.push({ id: el.getAttribute("data-node") ?? "", el, x: num(rect.getAttribute("x")) + tx, y: num(rect.getAttribute("y")) + ty,
        w: num(rect.getAttribute("width")), h: num(rect.getAttribute("height")), lines, k: `b-${role(el)}`, boxed: true });
    } else if (texts.length) {
      // A node drawn as words only (the landing page's destinations): placed where its words are.
      const [tx, ty] = offset(texts[0], svg);
      const x = num(texts[0].getAttribute("x")) + tx, y = num(texts[0].getAttribute("y")) + ty;
      const wid = Math.max(...lines.map((l) => [...l].length)) * 7;
      nodes.push({ id: el.getAttribute("data-node") ?? "", el, x: x - (texts[0].getAttribute("text-anchor") === "middle" ? wid / 2 : 0), y: y - 12,
        w: wid, h: lines.length * 16, lines, k: `b-${role(el)}`, boxed: false });
    }
  }
  // Scale: every box wide enough for its title and up to 26 characters of its words, tall enough for them wrapped.
  let sx = 0;
  for (const n of nodes) if (n.boxed) sx = Math.max(sx, (Math.min(26, Math.max(...n.lines.map((l) => [...l].length))) + 3) / n.w, ([...(n.lines[0] ?? "")].length + 3) / n.w);
  if (!sx) sx = 0.12;
  const cols = Math.ceil(vb[2] * sx) + 2;
  if (cols > maxCols) sx *= maxCols / cols;
  const wrapped = new Map<NodeIn, string[]>();
  let sy = 0;
  for (const n of nodes) {
    if (!n.boxed) { wrapped.set(n, n.lines); continue; }
    const iw = Math.max(4, Math.round((n.x + n.w) * sx) - Math.round(n.x * sx) - 1);
    const ws = n.lines.flatMap((l, i) => (i === 0 ? [[...l].slice(0, iw).join("")] : wrap(l, iw)));
    wrapped.set(n, ws);
    sy = Math.max(sy, (ws.length + 2.2) / n.h);
  }
  if (!sy) sy = 0.06;
  const X = (x: number): number => Math.round((x - vb[0]) * sx);
  const Y = (y: number): number => Math.round((y - vb[1]) * sy);
  const g = new Grid(Math.ceil(vb[2] * sx) + 2);
  g.put(Math.ceil(vb[3] * sy) + 1, 0, " ");

  // Zones, then their titles (lines pass behind a title).
  for (const r of svg.querySelectorAll("rect")) {
    if (r.closest("[data-node]") || !/zone/.test(`${cls(r)} ${cls(r.parentElement)}`)) continue;
    const [tx, ty] = offset(r, svg);
    const x = num(r.getAttribute("x")) + tx, y = num(r.getAttribute("y")) + ty;
    g.frame(Y(y), X(x), X(x + num(r.getAttribute("width"))) - X(x) + 1, Y(y + num(r.getAttribute("height"))) - Y(y) + 1);
  }
  const labels: { s: string; x: number; y: number; a: string }[] = [];
  for (const t of svg.querySelectorAll("text")) {
    if (t.closest("[data-node]")) continue;
    const [tx, ty] = offset(t, svg);
    const x = num(t.getAttribute("x")) + tx, y = num(t.getAttribute("y")) + ty;
    if (/zone/.test(cls(t))) {
      const main = [...t.childNodes].filter((c) => c.nodeType === 3).map((c) => c.textContent).join("").trim();
      const sub = [...t.querySelectorAll("tspan")].map((c) => c.textContent?.trim()).filter(Boolean).join(" ");
      // On the frame's top edge when the frame is just above, as a terminal draws a titled box.
      const r = [Y(y) - 1, Y(y) - 2].find((rr) => /^[┄╭]$/.test(g.get(rr, X(x)))) ?? Y(y);
      // A zone's name in capitals, as a terminal heading; a subtitle drawn as its own text stays as written.
      const isSub = /sub/.test(cls(t));
      g.put(r, X(x), ` ${isSub ? main : main.toUpperCase()} `, isSub ? "z-s" : "z-t");
      if (sub) g.put(r, X(x) + [...main].length + 3, `${sub} `, "z-s");
    } else {
      const s = (t.textContent ?? "").trim();
      if (s) labels.push({ s, x, y, a: t.getAttribute("text-anchor") ?? "start" });
    }
  }

  // Boxes, with their words centred in their rows.
  const boxes: { n: NodeIn; r0: number; c0: number; r1: number; c1: number }[] = [];
  const map = new Map<string, Element>();
  for (const n of nodes) {
    map.set(n.id, n.el);
    const ws = wrapped.get(n) ?? n.lines;
    if (!n.boxed) {
      ws.forEach((l, i) => g.put(Y(n.y + 12) + i, X(n.x), l, i === 0 ? `${n.k}-t` : `${n.k}-s`));
      continue;
    }
    const r0 = Y(n.y), c0 = X(n.x), c1 = X(n.x + n.w), r1 = Math.max(r0 + ws.length + 1, Y(n.y + n.h));
    g.box(n.id, r0, c0, c1 - c0 + 1, r1 - r0 + 1, n.k, ws, Math.floor((r1 - r0 - 1 - ws.length) / 2));
    boxes.push({ n, r0, c0, r1, c1 });
  }
  const boxAt = (r: number, c: number) => boxes.find((b) => r >= b.r0 && r <= b.r1 && c >= b.c0 && c <= b.c1);

  // Edges: one drawn path per edge (not its glow or draw-in copy), walked and trimmed at the boxes.
  const edges: Edge[] = [];
  const seen = new Set<Element>();
  for (const p of svg.querySelectorAll("path")) {
    const c = cls(p);
    if (p.closest("defs, marker, [data-node]") || !/line|edge/.test(c) || /head|glow|draw|arrow/.test(c)) continue;
    const group = p.closest("[data-edge]");
    if (group) { if (seen.has(group)) continue; seen.add(group); }
    const n = (p.getAttribute("d") ?? "").match(/-?\d*\.?\d+(?:e-?\d+)?/gi)?.map(Number) ?? [];
    const [tx, ty] = offset(p, svg);
    const pts: Cell[] = [];
    for (let i = 0; i + 1 < n.length; i += 2) pts.push([Y(n[i + 1] + ty), X(n[i] + tx)]);
    if (pts.length < 2) continue;
    const cells: Step[] = walk(pts);
    while (cells.length && boxAt(cells[cells.length - 1][0], cells[cells.length - 1][1])) cells.pop();
    while (cells.length && boxAt(cells[0][0], cells[0][1])) cells.shift();
    if (!cells.length) continue;
    const end = cells[cells.length - 1];
    const to = boxAt(end[0] + end[2], end[1] + end[3])?.n ?? null;
    const k = to ? `r-${to.k.slice(2)}` : "r-neutral";
    edges.push({ el: group ?? p, cells: g.line(cells, k), to: to?.id ?? null, k });
  }

  // Edge labels, where they find blank cells next to their spot.
  for (const l of labels) {
    const len = [...l.s].length;
    const r = Y(l.y) - 1, c = X(l.x) - (l.a === "middle" ? Math.floor(len / 2) : l.a === "end" ? len : 0);
    const spot = [[r, c], [r - 1, c], [r + 1, c], [r, c + 1], [r, c - 1]].find(([rr, cc]) => g.blank(rr, cc, len));
    if (spot) g.put(spot[0], spot[1], l.s, "lbl");
  }
  return { g, edges, nodes: map };
}
