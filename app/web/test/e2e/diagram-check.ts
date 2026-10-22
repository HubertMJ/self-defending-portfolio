// The diagrams' geometry, measured in the browser: every drawing on a page (any SVG with g[data-node])
// as it renders with the fonts the page has. The same file is copied into every repository that
// serves a page of the site, beside its own diagram tests. What it holds a drawing to:
// - a box's words sit inside it, 8 units clear of its sides;
// - a label on the drawing (an edge's words, a zone's title) keeps 2 units clear of every box and every
//   arrowhead, does not touch a line, does not overlap another label, and stays inside the drawing;
// - a line starts and ends at a box (within 9 units of its border, never inside it), so no arrow points
//   at nothing, and runs under no box on the way;
// - an arrowhead has room: the straight run it ends shows 10 units of line behind the head, and a
//   two-way line keeps 14 between its two heads; no two arrowheads touch;
// - lines keep apart: no two cross, no two run side by side (parallel, closer than 16, for more than 40
//   units), and no two arrowheads sit within 24 of each other on one side of a box. A fan is the
//   exception: lines that leave one point (or reach one) may share a trunk, run on top of each other
//   (0 apart, not near), and end in one arrowhead where they reach one tip from one direction.
// A text's box is its em box (ascent to descent), so these are clearances of the ink and then some.

import type { Page } from "@playwright/test";

export async function diagramProblems(page: Page): Promise<string[]> {
  // The drawings' fonts are fetched when text first asks for them (a drawing in a closed dialog asks
  // late): load both before measuring anything.
  await page.evaluate(() => Promise.all([document.fonts.load("650 14px LabDiagramSans"), document.fonts.load("10.5px LabDiagramMono"), document.fonts.load("600 10.5px LabDiagramMono")]).then(() => document.fonts.ready));
  return page.evaluate(() => {
    type B = { x: number; y: number; width: number; height: number };
    const out: string[] = [];
    const grow = (b: B, d: number): B => ({ x: b.x - d, y: b.y - d, width: b.width + 2 * d, height: b.height + 2 * d });
    const hit = (a: B, b: B) => a.x < b.x + b.width && a.x + a.width > b.x && a.y < b.y + b.height && a.y + a.height > b.y;
    for (const svg of document.querySelectorAll<SVGSVGElement>("svg")) {
      if (!svg.querySelector("[data-node]") || getComputedStyle(svg).display === "none" || svg.getBoundingClientRect().width < 50) continue;
      // Everything in the drawing's own units, whatever transform a group carries (a node may be a
      // translated <g> whose rect sits at 0,0).
      const toSvg = (el: SVGGraphicsElement): DOMMatrix => (svg.getScreenCTM() as DOMMatrix).inverse().multiply(el.getScreenCTM() as DOMMatrix);
      const box = (el: SVGGraphicsElement): B => {
        const b = el.getBBox();
        const m = toSvg(el);
        const pts = [[b.x, b.y], [b.x + b.width, b.y], [b.x, b.y + b.height], [b.x + b.width, b.y + b.height]].map(([x, y]) => new DOMPoint(x, y).matrixTransform(m));
        const xs = pts.map((q) => q.x);
        const ys = pts.map((q) => q.y);
        return { x: Math.min(...xs), y: Math.min(...ys), width: Math.max(...xs) - Math.min(...xs), height: Math.max(...ys) - Math.min(...ys) };
      };
      const at = (p: SVGPathElement, l: number): DOMPoint => p.getPointAtLength(l).matrixTransform(toSvg(p));
      const name = `${(svg.getAttribute("class") ?? "svg").split(" ")[0]}${svg.dataset.diagram ? `:${svg.dataset.diagram}` : ""}:${svg.getAttribute("class")?.match(/wide|narrow/)?.[0] ?? ""}`;
      const nodes = [...svg.querySelectorAll("[data-node]")].filter((n) => !n.parentElement?.closest("[data-node]"));
      const boxes = nodes.map((n) => ({ n, b: box(n.querySelector("rect") as SVGRectElement) }));
      const lines = [...svg.querySelectorAll<SVGPathElement>("path")].filter((p) => !p.closest("defs, marker, [data-node]") && /edge|line/.test(p.getAttribute("class") ?? "") && !/glow|head|arrow|dot/.test(p.getAttribute("class") ?? ""));
      // An arrowhead's area: 11 units back from the line's end, 5.5 either side of it.
      const heads: B[] = [];
      const tips: DOMPoint[] = [];
      const ways: [number, number][] = [];
      for (const p of lines) {
        const len = p.getTotalLength();
        const head = (tip: number, back: number) => {
          const a = at(p, tip);
          const b = at(p, back);
          const n = Math.hypot(a.x - b.x, a.y - b.y) || 1;
          const [dx, dy] = [(a.x - b.x) / n, (a.y - b.y) / n];
          // Lines of a fan meeting at one tip from one direction draw one arrowhead there.
          if (tips.some((q, i) => Math.hypot(q.x - a.x, q.y - a.y) < 0.5 && Math.hypot(ways[i][0] - dx, ways[i][1] - dy) < 0.05)) return;
          tips.push(a);
          ways.push([dx, dy]);
          const pts = [[a.x, a.y], [a.x - dx * 11 + dy * 5.5, a.y - dy * 11 - dx * 5.5], [a.x - dx * 11 - dy * 5.5, a.y - dy * 11 + dx * 5.5]];
          const xs = pts.map((q) => q[0]);
          const ys = pts.map((q) => q[1]);
          heads.push({ x: Math.min(...xs), y: Math.min(...ys), width: Math.max(...xs) - Math.min(...xs), height: Math.max(...ys) - Math.min(...ys) });
        };
        if (p.getAttribute("marker-end")) head(len, Math.max(0, len - 2));
        if (p.getAttribute("marker-start")) head(0, Math.min(len, 2));
      }
      // Where a line may end: on a box, within reach of its border (each drawing stops its lines a few
      // units short: 2 to 7), not inside it.
      const reach = 9;
      const outside = (q: DOMPoint, r: B) => Math.max(r.x - q.x, q.x - r.x - r.width, r.y - q.y, q.y - r.y - r.height);
      for (const p of lines) {
        const len = p.getTotalLength();
        const what = `${name}: the line "${(p.getAttribute("d") ?? "").slice(0, 40)}"`;
        for (const [end, l] of [["start", 0], ["end", len]] as const) {
          const q = at(p, l);
          const d = Math.min(...boxes.map(({ b }) => outside(q, b)));
          if (d > reach) out.push(`${what} ${end}s ${d.toFixed(0)} from any box`);
          else if (d < -1) out.push(`${what} ${end}s inside a box`);
        }
        for (let l = 3; l <= len - 3; l += 1) {
          const q = at(p, l);
          const under = boxes.find(({ b }) => outside(q, b) < -2);
          if (under) {
            out.push(`${what} runs under "${under.n.getAttribute("data-node")}"`);
            break;
          }
        }
        // The straight run behind a head: back from the tip while the line keeps its direction.
        const run = (tip: number, dir: 1 | -1) => {
          const a = at(p, tip);
          const b = at(p, tip + dir * Math.min(2, len));
          const n = Math.hypot(b.x - a.x, b.y - a.y) || 1;
          let l = 2;
          for (; l <= len; l += 1) {
            const q = at(p, tip + dir * l);
            if (Math.abs(((q.x - a.x) * (b.y - a.y) - (q.y - a.y) * (b.x - a.x)) / n) > 0.5) break;
          }
          return l - 1;
        };
        const ends = [p.getAttribute("marker-end") ? run(len, -1) : 0, p.getAttribute("marker-start") ? run(0, 1) : 0];
        for (const r of ends) if (r && r < 11 + 10) out.push(`${what} has ${(r - 11).toFixed(0)} of line behind its arrowhead`);
        if (ends[0] && ends[1] && ends[0] >= len - 1 && len < 2 * 11 + 14) out.push(`${what} has ${(len - 22).toFixed(0)} between its two arrowheads`);
      }
      for (const [i, h] of heads.entries()) if (heads.slice(i + 1).some((o) => hit(h, o))) out.push(`${name}: two arrowheads touch at ${h.x.toFixed(0)},${h.y.toFixed(0)}`);
      // Each line as its straight runs (a corner ends one; a curve is many short ones), in the drawing's units.
      type P = { x: number; y: number };
      const stops = lines.map((p) => [at(p, 0), at(p, p.getTotalLength())]);
      const runs = lines.map((p) => {
        const len = p.getTotalLength();
        const rs: [P, P][] = [];
        let [s, e] = [at(p, 0), at(p, Math.min(1, len))];
        for (let l = 2; l < len + 1; l += 1) {
          const q = at(p, Math.min(l, len));
          const n = Math.hypot(e.x - s.x, e.y - s.y) || 1;
          if (Math.abs(((q.x - s.x) * (e.y - s.y) - (q.y - s.y) * (e.x - s.x)) / n) > 0.5) {
            rs.push([s, e]);
            s = e;
          }
          e = q;
        }
        rs.push([s, e]);
        return rs;
      });
      const xy = (q: P) => `${q.x.toFixed(0)},${q.y.toFixed(0)}`;
      const meet = (a: P, b: P) => Math.hypot(a.x - b.x, a.y - b.y) < 1;
      for (const [i, ra] of runs.entries()) {
        for (const [j, rb] of runs.entries()) {
          if (j <= i) continue;
          // Two lines of one fan: they leave one point or reach one.
          const fan = meet(stops[i][0], stops[j][0]) || meet(stops[i][1], stops[j][1]);
          for (const [a0, a1] of ra) {
            for (const [b0, b1] of rb) {
              const [ax, ay, bx, by] = [a1.x - a0.x, a1.y - a0.y, b1.x - b0.x, b1.y - b0.y];
              const [la, lb] = [Math.hypot(ax, ay), Math.hypot(bx, by)];
              if (!la || !lb) continue;
              const den = ax * by - ay * bx;
              // Crossing: each run passes through the other's inside, a unit or more from its ends.
              if (Math.abs(den) / (la * lb) > 0.02) {
                const t = ((b0.x - a0.x) * by - (b0.y - a0.y) * bx) / den;
                const u = ((b0.x - a0.x) * ay - (b0.y - a0.y) * ax) / den;
                if (t * la > 1 && (1 - t) * la > 1 && u * lb > 1 && (1 - u) * lb > 1) out.push(`${name}: two lines cross at ${xy({ x: a0.x + t * ax, y: a0.y + t * ay })}`);
                continue;
              }
              // Side by side: parallel runs, closer than 16, sharing more than 40 of their length.
              const gap = Math.abs((b0.x - a0.x) * ay - (b0.y - a0.y) * ax) / la;
              const [s0, s1] = [((b0.x - a0.x) * ax + (b0.y - a0.y) * ay) / la, ((b1.x - a0.x) * ax + (b1.y - a0.y) * ay) / la];
              const shared = Math.min(la, Math.max(s0, s1)) - Math.max(0, Math.min(s0, s1));
              // A fan's trunk: its lines on top of each other, which is one line.
              if (fan && gap < 0.5) continue;
              if (gap < 16 && shared > 40) out.push(`${name}: two lines run side by side, ${gap.toFixed(0)} apart for ${shared.toFixed(0)}, at ${xy(a0)} to ${xy(a1)} and ${xy(b0)} to ${xy(b1)}`);
            }
          }
        }
      }
      // Arrowheads on one side of a box: the side the tip faces, and how far apart along it.
      const sides = tips.map((q) => {
        const near = boxes.map(({ n, b }) => ({ n, d: [b.x - q.x, q.x - b.x - b.width, b.y - q.y, q.y - b.y - b.height] })).map((o) => ({ ...o, out: Math.max(...o.d) }));
        const o = near.reduce((a, b) => (b.out < a.out ? b : a));
        return o.out > reach ? null : { n: o.n, side: o.d.indexOf(o.out), q };
      });
      for (const [i, a] of sides.entries()) {
        for (const b of sides.slice(i + 1)) {
          if (!a || !b || a.n !== b.n || a.side !== b.side) continue;
          const along = a.side < 2 ? Math.abs(a.q.y - b.q.y) : Math.abs(a.q.x - b.q.x);
          if (along < 24) out.push(`${name}: two arrowheads ${along.toFixed(0)} apart on "${a.n.getAttribute("data-node")}"'s ${["left", "right", "top", "bottom"][a.side]} side, at ${xy(a.q)} and ${xy(b.q)}`);
        }
      }
      const onLine = (b: B) =>
        lines.some((p) => {
          for (let l = 0; l <= p.getTotalLength(); l += 1) {
            const q = at(p, l);
            if (q.x > b.x && q.x < b.x + b.width && q.y > b.y && q.y < b.y + b.height) return true;
          }
          return false;
        });
      for (const { n, b: r } of boxes) {
        for (const t of n.querySelectorAll<SVGTextElement>("text")) {
          const b = box(t);
          if (!b.width) continue;
          const side = Math.min(b.x - r.x, r.x + r.width - b.x - b.width);
          if (side < 8 || b.y < r.y || b.y + b.height > r.y + r.height) out.push(`${name}: "${t.textContent}" is ${side.toFixed(1)} from its box's side`);
        }
      }
      const labels = [...svg.querySelectorAll<SVGTextElement>("text")]
        .filter((t) => !t.closest("[data-node], title, desc") && (t.textContent ?? "").trim())
        .map((t) => ({ t, b: box(t), zone: /zone/.test(t.getAttribute("class") ?? "") }));
      const vb = svg.viewBox.baseVal;
      for (const [i, { t, b, zone }] of labels.entries()) {
        const what = `${name}: "${t.textContent?.trim()}"`;
        if (boxes.some(({ b: r }) => hit(grow(b, 2), r))) out.push(`${what} is within 2 of a box`);
        if (!zone && heads.some((h) => hit(grow(b, 2), h))) out.push(`${what} crowds an arrowhead`);
        if (onLine(grow(b, 1))) out.push(`${what} touches a line`);
        for (const o of labels.slice(i + 1)) if (hit(grow(b, 1), o.b)) out.push(`${what} overlaps "${o.t.textContent?.trim()}"`);
        if (b.x < vb.x || b.x + b.width > vb.x + vb.width || b.y < vb.y || b.y + b.height > vb.y + vb.height) out.push(`${what} runs out of the drawing`);
      }
      const r = svg.getBoundingClientRect();
      if (r.right > innerWidth + 0.5 || r.left < -0.5) out.push(`${name}: wider than the page`);
    }
    if (document.documentElement.scrollWidth > document.documentElement.clientWidth) out.push("the page scrolls sideways");
    return out;
  });
}
