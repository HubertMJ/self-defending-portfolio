// Lays the model out as an SVG tree (src/diagram/tree.ts) for one of three views: the hero's wide
// diagram, the phone's vertical path, and the full docs diagram. Positions come from the model's grid
// cells; this module only turns cells into pixels, routes the edges and names every part with the
// classes styles.css (the page) and scripts/diagram.mjs (the docs file's own <style>) colour.
//
// No colours, no sizes of text and no animation live here: classes only, so the same drawing obeys the
// page's CSP (style-src 'self', no style attributes) and the docs file's light/dark <style>.

import { type DiagramEdge, type DiagramModel, type DiagramNode, type DiagramZone, MODEL, type View, nodesOf } from "./model";
import { type Tree, t } from "./tree";
import { panelMarkup } from "../node-panel/markup";
import { REPO_URL } from "../ui/common";

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

/** The smallest node box and the grid's gaps; a box widens or heightens to fit its words (fitted). */
const METRICS: Record<"hero" | "full", Metrics> = {
  hero: { cw: 170, ch: 56, gx: 54, gy: 50, pad: 18, zoneHead: 26, zonePad: 14 },
  full: { cw: 176, ch: 60, gx: 48, gy: 44, pad: 20, zoneHead: 28, zonePad: 14 },
};

// ---------- text that fits (2026-10-14) ----------
//
// A box is sized from its words, not the other way round: each text's width is estimated per
// character for the larger of the page's font (styles.css) and the docs file's (docs.ts), with a
// safety margin, and every text keeps PAD_X units clear of its box on each side. A sublabel too long
// for the smallest box wraps at its " · " separators; a zone's subtitle that does not fit beside its
// title goes under it. Deterministic: the same model always draws the same boxes.

/** Clear space between a node's text and its box, each side; around a zone's contents (zonePad, 14) at least 12. */
export const PAD_X = 10;
const SAFETY = 1.08;
/** Line pitch of a node's words. */
const LINE = 15;

type TextKind = "label" | "sub" | "zonetitle" | "zonesub";
/** Font size in user units (the larger of page and docs) and whether the face is monospace; the page's zone title is uppercase mono with letter-spacing, the docs file's sans: 8.1 per character covers both. */
const FONTS: Record<TextKind, { size: number; mono: boolean; perChar?: number }> = {
  label: { size: 13.44, mono: false },
  sub: { size: 10.5, mono: true },
  zonetitle: { size: 13, mono: false, perChar: 8.1 },
  zonesub: { size: 11, mono: true },
};

/** One character's advance in ems for a bold sans face (generous: system-ui varies). */
function sansEm(c: string): number {
  if (/[ijlI.,:;'|!]/.test(c)) return 0.32;
  if (/[ frt()\[\]\-]/.test(c)) return 0.42;
  if (/[mwMW@]/.test(c)) return 0.95;
  if (/[A-Z+×]/.test(c)) return 0.74;
  return 0.6;
}

/** The estimated width of `s` drawn as `kind`, in user units, safety margin included. */
export function textWidth(s: string, kind: TextKind): number {
  const f = FONTS[kind];
  const raw = f.perChar ? s.length * f.perChar : f.mono ? s.length * 0.62 * f.size : [...s].reduce((w, c) => w + sansEm(c) * f.size, 0);
  return Math.ceil(raw * SAFETY);
}

/** A sublabel as lines no wider than `max`: whole " · " parts, greedily; one part longer than `max` stays whole (its box widens). */
export function wrapSub(sub: string, max: number): string[] {
  if (textWidth(sub, "sub") <= max) return [sub];
  const lines: string[] = [];
  for (const part of sub.split(" · ")) {
    const last = lines[lines.length - 1];
    if (last !== undefined && textWidth(`${last} · ${part}`, "sub") <= max) lines[lines.length - 1] = `${last} · ${part}`;
    else lines.push(part);
  }
  // A separator ends the line it breaks, so the reader sees the list goes on.
  return lines.map((l, i) => (i < lines.length - 1 ? `${l} ·` : l));
}

/** Each node's sublabel lines and the box size that holds every node's words with PAD_X each side. */
function fitted(nodes: DiagramNode[], cw: number, ch: number, notes?: Record<string, string>): { cw: number; ch: number; subs: Map<string, string[]> } {
  // The labels never wrap: the box is at least as wide as the widest; the sublabels wrap within it,
  // and a box widened by one sublabel lets the others wrap less (until nothing changes).
  let w = Math.max(cw, ...nodes.map((n) => textWidth(n.label, "label") + 2 * PAD_X));
  let subs = new Map<string, string[]>();
  for (let i = 0; i < 4; i++) {
    subs = new Map(nodes.map((n) => [n.id, wrapSub(n.sub, w - 2 * PAD_X)]));
    const next = Math.max(w, ...nodes.flatMap((n) => (subs.get(n.id) as string[]).map((l) => textWidth(l, "sub") + 2 * PAD_X)));
    if (next === w) break;
    w = next;
  }
  let lines = 2;
  for (const n of nodes) {
    const sl = subs.get(n.id) as string[];
    const note = notes?.[n.id];
    w = Math.max(w, textWidth(n.label, "label") + 2 * PAD_X, ...sl.map((l) => textWidth(l, "sub") + 2 * PAD_X), note ? textWidth(note, "sub") + 2 * PAD_X : 0);
    lines = Math.max(lines, 1 + sl.length + (note ? 1 : 0));
  }
  // The block: a label's ascent (10), the line pitch between baselines, the last line's descent (3); PAD_X above and below.
  return { cw: Math.ceil(w), ch: Math.max(ch, 10 + (lines - 1) * LINE + 3 + 2 * PAD_X), subs };
}

/** For the tests: every node's and zone's words with the box that holds them. */
export function fitReport(view: "hero" | "full" | "narrow", model: DiagramModel = MODEL, notes?: Record<string, string>): { box: Box; texts: { kind: TextKind; text: string; x: number; w: number }[] }[] {
  const out: { box: Box; texts: { kind: TextKind; text: string; x: number; w: number }[] }[] = [];
  const g = view === "narrow" ? narrowGeometry(model) : gridGeometry(view, model, notes);
  for (const n of g.nodes) {
    const b = g.boxes.get(n.id) as Box;
    const lines = [n.label, ...(g.subs.get(n.id) as string[]), ...(notes?.[n.id] ? [notes[n.id]] : [])];
    // Centred: each text starts half its width left of the box's middle.
    out.push({ box: b, texts: lines.map((text, i) => ({ kind: i === 0 ? "label" : "sub", text, x: b.x + b.w / 2 - textWidth(text, i === 0 ? "label" : "sub") / 2, w: textWidth(text, i === 0 ? "label" : "sub") })) });
  }
  if (view !== "narrow") {
    const zg = g as ReturnType<typeof gridGeometry>;
    for (const [z, b] of zg.zoneBoxes) {
      const zt = zoneText(z, b, zg.m);
      out.push({ box: b, texts: [{ kind: "zonetitle", text: z.title, x: zt.title[0], w: textWidth(z.title, "zonetitle") }, ...(z.sub && zt.sub ? [{ kind: "zonesub" as const, text: z.sub, x: zt.sub[0], w: textWidth(z.sub, "zonesub") }] : [])] });
    }
  }
  return out;
}

/** Where a zone's title and subtitle sit: the subtitle beside the title when it fits, else under it (the zone grows up by a line for it). */
function zoneText(z: DiagramZone, b: Box, m: Metrics): { title: Pt; sub?: Pt } {
  const tx = b.x + m.zonePad;
  if (!z.sub) return { title: [tx, b.y + 17] };
  const beside = tx + textWidth(z.title, "zonetitle") + 10;
  if (beside + textWidth(z.sub, "zonesub") <= right(b) - m.zonePad) return { title: [tx, b.y + 17], sub: [beside, b.y + 17] };
  return { title: [tx, b.y + 17], sub: [tx, b.y + 32] };
}

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
/** A blurb's first sentence (two when the first is a word or two). */
function firstSentence(s: string): string {
  let out = "";
  for (const x of s.match(/.*?[.!?](?=\s|$)/g) ?? [s]) { out += x; if (out.trim().length >= 30) break; }
  return out.trim() || s;
}

function nodeTree(n: DiagramNode, b: Box, opts: LayoutOptions, subs: string[] = [n.sub]): Tree {
  const id = `${opts.idPrefix ?? "dg"}-${n.id}`;
  // A wrapped sublabel: styles.css moves a lone label down by half the block's extra lines.
  const attrs: Record<string, string | number> = { class: `dg-node dg-node--${n.tone} dg-role--${n.role}${subs.length > 1 ? ` dg-node--sub${subs.length}` : ""}`, id, "data-node": n.id, "data-state": "idle", transform: `translate(${b.x} ${b.y})` };
  if (opts.interactive) {
    attrs.tabindex = 0;
    attrs.role = "button";
    attrs["aria-label"] = n.label;
    attrs["aria-expanded"] = "false";
    // The blurb's first sentence, for ASCII mode's popup beside the box (src/ascii).
    attrs["data-tip"] = firstSentence(n.blurb);
  }
  const note = opts.notes?.[n.id];
  // Baselines: the label, the sublabel's lines and the note centred as a block, LINE units apart.
  const lines = 1 + subs.length + (note ? 1 : 0);
  const first = b.h / 2 - ((lines - 1) * LINE) / 2 + 4.5;
  return t(
    "g",
    attrs,
    t("rect", { class: "dg-box", width: b.w, height: b.h, rx: 8 }),
    t("text", { class: "dg-label", x: b.w / 2, y: first, "text-anchor": "middle" }, n.label),
    ...subs.map((l, i) => t("text", { class: "dg-sub", x: b.w / 2, y: first + LINE * (i + 1), "text-anchor": "middle" }, l)),
    note ? t("text", { class: "dg-sub dg-note", x: b.w / 2, y: first + LINE * (subs.length + 1), "text-anchor": "middle" }, note) : null,
  );
}

function zoneTree(z: DiagramZone, b: Box, m: Metrics): Tree {
  const at = zoneText(z, b, m);
  return t(
    "g",
    { class: "dg-zone", "data-zone": z.id },
    t("rect", { class: "dg-zonebox", x: b.x, y: b.y, width: b.w, height: b.h, rx: 10 }),
    t("text", { class: "dg-zonetitle", x: at.title[0], y: at.title[1] }, z.title),
    at.sub ? t("text", { class: "dg-zonesub", x: at.sub[0], y: at.sub[1] }, z.sub) : null,
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
  req: { edges: ["visitor-cloudflare", "cloudflare-cloudflared", "cloudflared-gateway", "gateway-site"], period: 3.2, start: 0, travel: 2.4 },
  loop: { edges: ["pod-falco", "falco-talon", "talon-kube-apiserver", "kube-apiserver-pod"], period: 9, start: 3.2, travel: 2.6 },
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
function gridGeometry(view: "hero" | "full", model: DiagramModel, notes?: Record<string, string>) {
  const nodes = nodesOf(view, model);
  const fit = fitted(nodes, METRICS[view].cw, METRICS[view].ch, notes);
  const m: Metrics = { ...METRICS[view], cw: fit.cw, ch: fit.ch };
  const px = m.cw + m.gx;
  const py = m.ch + m.gy;
  const top = m.pad + m.zoneHead;
  const cell = ([c, r]: [number, number]): Box => ({ x: m.pad + c * px, y: top + r * py, w: m.cw, h: m.ch });
  const boxes = new Map(nodes.map((n) => [n.id, cell(n.at[view] as [number, number])]));
  const zones = model.zones.filter((z) => z.at[view]);
  const zoneBox = (z: DiagramZone): Box => {
    const [c, r, cs, rs] = z.at[view] as [number, number, number, number];
    const b = cell([c, r]);
    const box = { x: b.x - m.zonePad, y: b.y - m.zonePad - m.zoneHead, w: cs * px - m.gx + 2 * m.zonePad, h: rs * py - m.gy + 2 * m.zonePad + m.zoneHead };
    return zoneText(z, box, m).sub?.[1] === box.y + 32 ? { ...box, y: box.y - 15, h: box.h + 15 } : box;
  };
  const zoneBoxes = zones.map((z) => [z, zoneBox(z)] as const);
  const edges = model.edges.filter((e) => boxes.has(e.from) && boxes.has(e.to) && (view === "full" || e.detail === "hero") && (!e.views || e.views.includes(view)));
  const routes = new Map(edges.map((e) => [`${e.from}-${e.to}`, route(e, boxes.get(e.from) as Box, boxes.get(e.to) as Box, m)]));
  return { m, nodes, boxes, zoneBoxes, edges, routes, subs: fit.subs };
}

function gridRoutes(view: "hero" | "full", model: DiagramModel): Routes {
  const g = gridGeometry(view, model);
  return { boxes: g.boxes, pts: new Map([...g.routes].map(([id, r]) => [id, trimmed(r.pts)])) };
}

function layoutGrid(view: "hero" | "full", opts: LayoutOptions, model: DiagramModel): Tree {
  const prefix = opts.idPrefix ?? "dg";
  const { m, nodes, boxes, zoneBoxes, edges, routes, subs } = gridGeometry(view, model, opts.notes);
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
  // A zone grown up for its subtitle's line may reach above the first row's: the drawing starts above it.
  const minY = Math.min(0, ...zoneBoxes.map(([, b]) => b.y - m.pad));
  const titleId = `${prefix}-title`;
  const descId = `${prefix}-desc`;
  return t(
    "svg",
    { xmlns: "http://www.w3.org/2000/svg", viewBox: `0 ${minY} ${width} ${height - minY}`, class: `dg dg--${view}`, role: opts.interactive ? "group" : "img", "aria-labelledby": `${titleId} ${descId}` },
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
    t("g", { class: "dg-nodes" }, ...nodes.map((n) => nodeTree(n, boxes.get(n.id) as Box, opts, subs.get(n.id)))),
  );
}

/** The phone's geometry: the story's nodes top to bottom, the answer looping back up the right side. */
function narrowGeometry(model: DiagramModel) {
  const nodes = nodesOf("narrow", model);
  const fit = fitted(nodes, 236, 50);
  const m: Metrics = { cw: fit.cw, ch: fit.ch, gx: 0, gy: 30, pad: 12, zoneHead: 18, zonePad: 0 };
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
  return { nodes, boxes, heads, edges, routes, width, height, subs: fit.subs };
}

function narrowRoutes(model: DiagramModel): Routes {
  const g = narrowGeometry(model);
  return { boxes: g.boxes, pts: new Map([...g.routes].map(([id, r]) => [id, trimmed(r.pts)])) };
}

/** The phone's hero: the story's nodes top to bottom, the answer looping back up the right side. */
function layoutNarrow(opts: LayoutOptions, model: DiagramModel): Tree {
  const prefix = opts.idPrefix ?? "dgn";
  const { nodes, boxes, heads, edges, routes, width, height, subs } = narrowGeometry(model);
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
    t("g", { class: "dg-nodes" }, ...nodes.map((n) => nodeTree(n, boxes.get(n.id) as Box, opts, subs.get(n.id)))),
  );
}

/** A text description of the drawing for screen readers and the docs file. */
function describe(nodes: DiagramNode[], edges: DiagramEdge[]): string {
  const name = (id: string) => nodes.find((n) => n.id === id)?.label ?? id;
  return `${nodes.length} components: ${nodes.map((n) => n.label).join(", ")}. Connections: ${edges.map((e) => `${name(e.from)} to ${name(e.to)}${e.label ? ` (${e.label})` : ""}`).join("; ")}.`;
}

/**
 * The node panel under both drawings (src/node-panel), written into the page beside them at build time:
 * each part's blurb and where it lives on GitHub (as the lab's panel words it), for every node either
 * drawing shows.
 */
export function panel(model: DiagramModel = MODEL): string {
  const shown = new Set([...nodesOf("hero", model), ...nodesOf("narrow", model)].map((n) => n.id));
  return panelMarkup(
    "diagram",
    model.nodes
      .filter((n) => shown.has(n.id))
      .map((n) => ({
        id: n.id,
        title: n.label,
        sub: n.sub,
        text: n.blurb,
        role: n.role,
        links: n.sources.map((s) => ({ href: `${REPO_URL}/tree/main/${s}`, label: s })),
        linksLead: "On GitHub: ",
      })),
  );
}
