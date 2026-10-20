// A grid of characters for the ASCII mode's drawings: boxes, dashed zones, routed lines, and an
// overlay per frame (packets riding a route, a box flipping to double lines while its title decodes).
// It renders into a <pre> with DOM nodes only, one <span> per run of one class (Trusted Types: no
// HTML strings).

export type Cell = [number, number];
/** Per frame, a cell's character (null keeps the drawn one) and its class. */
export type Over = Map<number, [string | null, string]>;

export interface GBox { id: string; r: number; c: number; w: number; h: number; k: string; cells: Cell[] }

const CORNER: Record<string, string> = {
  "0,1,1,0": "┐", "0,1,-1,0": "┘", "0,-1,1,0": "┌", "0,-1,-1,0": "└",
  "1,0,0,1": "└", "1,0,0,-1": "┘", "-1,0,0,1": "┌", "-1,0,0,-1": "┐",
};

/** A cell on a line and the direction the line moves in through it. */
export type Step = [number, number, number, number];

/** The cells of an orthogonal polyline through `pts`, each with its direction; a diagonal segment
 * (never drawn by the diagrams, but possible after rounding) steps vertically first. */
export function walk(pts: Cell[]): Step[] {
  const cells: Step[] = [];
  for (let i = 0; i < pts.length - 1; i++) {
    let [r, c] = pts[i];
    const [r1, c1] = pts[i + 1];
    for (;;) {
      const dr = Math.sign(r1 - r), dc = dr ? 0 : Math.sign(c1 - c);
      const last = cells[cells.length - 1];
      if (!last || last[0] !== r || last[1] !== c) cells.push([r, c, dr, dc]);
      else { last[2] = dr; last[3] = dc; }
      if (r === r1 && c === c1) break;
      r += dr; c += dc;
    }
  }
  // Each cell carries the direction it was entered by, so corners read from the next cell's turn.
  for (let j = cells.length - 1; j > 0; j--) { cells[j][2] = cells[j][0] - cells[j - 1][0]; cells[j][3] = cells[j][1] - cells[j - 1][1]; }
  if (cells.length > 1) { cells[0][2] = cells[1][2]; cells[0][3] = cells[1][3]; }
  return cells;
}

export class Grid {
  readonly w: number;
  private c: string[][] = [];
  private k: string[][] = [];
  readonly boxes = new Map<string, GBox>();

  constructor(w: number) { this.w = w; }

  get rows(): number { return this.c.length; }

  private row(r: number): void {
    while (this.c.length <= r) { this.c.push(Array<string>(this.w).fill(" ")); this.k.push(Array<string>(this.w).fill("")); }
  }

  get(r: number, c: number): string { return this.c[r]?.[c] ?? " "; }
  cls(r: number, c: number): string { return this.k[r]?.[c] ?? ""; }

  put(r: number, c: number, s: string, k = ""): void {
    this.row(r);
    let x = c;
    for (const ch of s) { if (x >= 0 && x < this.w) { this.c[r][x] = ch; this.k[r][x] = k; } x++; }
  }

  /** A box: its first line is the title (k-t), the rest its words (k-s), centred and cut to fit,
   * starting `top` rows below the frame. */
  box(id: string, r: number, c: number, w: number, h: number, k: string, lines: (string | null)[], top = 0): GBox {
    this.put(r, c, `┌${"─".repeat(w - 2)}┐`, k);
    for (let i = 1; i < h - 1; i++) { this.put(r + i, c, "│", k); this.put(r + i, c + w - 1, "│", k); }
    this.put(r + h - 1, c, `└${"─".repeat(w - 2)}┘`, k);
    lines.forEach((s, i) => {
      if (s == null || top + i > h - 3) return;
      const t = [...s].slice(0, w - 2).join("");
      this.put(r + 1 + top + i, c + 1 + Math.floor((w - 2 - [...t].length) / 2), t, i === 0 ? `${k}-t` : `${k}-s`);
    });
    const cells: Cell[] = [];
    for (let x = c; x < c + w; x++) cells.push([r, x], [r + h - 1, x]);
    for (let y = r + 1; y < r + h - 1; y++) cells.push([y, c], [y, c + w - 1]);
    const b = { id, r, c, w, h, k, cells };
    this.boxes.set(id, b);
    return b;
  }

  /** A dashed frame with no title (a zone whose title is drawn where its drawing puts it). */
  frame(r: number, c: number, w: number, h: number): void {
    this.put(r, c, `╭${"┄".repeat(w - 2)}╮`, "z");
    for (let i = 1; i < h - 1; i++) { this.put(r + i, c, "┆", "z"); this.put(r + i, c + w - 1, "┆", "z"); }
    this.put(r + h - 1, c, `╰${"┄".repeat(w - 2)}╯`, "z");
  }

  /** Whether a run of cells is blank (for placing a label). */
  blank(r: number, c: number, len: number): boolean {
    if (r < 0 || c < 0 || c + len > this.w) return false;
    for (let x = c; x < c + len; x++) if (this.get(r, x) !== " ") return false;
    return true;
  }

  /** A dashed zone with its title on the top edge. */
  zone(r: number, c: number, w: number, h: number, title: string, sub = "", tx = c + 2): void {
    this.put(r, c, `╭${"┄".repeat(w - 2)}╮`, "z");
    for (let i = 1; i < h - 1; i++) { this.put(r + i, c, "┆", "z"); this.put(r + i, c + w - 1, "┆", "z"); }
    this.put(r + h - 1, c, `╰${"┄".repeat(w - 2)}╯`, "z");
    this.put(r, tx, ` ${title} `, "z-t");
    if (sub) this.put(r, tx + 2 + [...title].length, `${sub} `, "z-s");
  }

  /** A line through the given corners, with an arrowhead at its end; returns its cells in order. */
  path(pts: Cell[], k: string, arrow = true): Cell[] {
    return this.line(walk(pts), k, arrow);
  }

  /** Draws walked cells as a line. A line passes behind a zone's title instead of cutting it, and
   * crossing another line makes a ┼. */
  line(cells: Step[], k: string, arrow = true): Cell[] {
    cells.forEach(([r, c, dr, dc], j) => {
      let ch = dr ? "│" : "─";
      const nx = cells[j + 1];
      if (nx && (nx[2] !== dr || nx[3] !== dc)) ch = CORNER[[dr, dc, nx[2], nx[3]].join()] ?? ch;
      if (j === cells.length - 1 && arrow) ch = dr > 0 ? "▼" : dr < 0 ? "▲" : dc > 0 ? "▶" : "◀";
      if (/^z-[ts]$/.test(this.cls(r, c))) return;
      const ex = this.get(r, c);
      if ((ex === "│" && ch === "─") || (ex === "─" && ch === "│")) ch = "┼";
      this.put(r, c, ch, k);
    });
    return cells.map(([r, c]) => [r, c]);
  }

  /** Which box, if any, covers a cell. */
  boxAt(r: number, c: number): GBox | undefined {
    for (const b of this.boxes.values()) if (r >= b.r && r < b.r + b.h && c >= b.c && c < b.c + b.w) return b;
    return undefined;
  }

  render(pre: HTMLElement, over?: Over): void {
    const frag = document.createDocumentFragment();
    for (let r = 0; r < this.c.length; r++) {
      let cur: string | null = null, buf = "";
      const flush = (): void => {
        if (!buf) return;
        if (cur) { const s = document.createElement("span"); s.className = cur; s.textContent = buf; frag.append(s); } else frag.append(buf);
        buf = "";
      };
      for (let c = 0; c < this.w; c++) {
        let ch = this.c[r][c], k = this.k[r][c];
        const o = over?.get(r * this.w + c);
        if (o) { if (o[0] !== null) ch = o[0]; k = o[1]; }
        if (k !== cur) { flush(); cur = k; }
        buf += ch;
      }
      flush();
      frag.append("\n");
    }
    pre.replaceChildren(frag);
  }
}

export const GLYPHS = "#%&@$*+=?/\\<>[]{}~^!";
export const HEX = "0123456789abcdef";
const DOUBLE: Record<string, string> = { "┌": "╔", "┐": "╗", "└": "╚", "┘": "╝", "─": "═", "│": "║" };
export const pick = (s: string): string => s[Math.floor(Math.random() * s.length)];

/** A box reached or lit: for a few frames its frame doubles and its title flickers through glyphs;
 * `strong` (the incident opening) inverts the whole box for the first frames instead. */
export function boxFx(g: Grid, over: Over, b: GBox, n: number, strong = false): void {
  const inv = strong && n > 4;
  for (const [r, c] of b.cells) { const ch = g.get(r, c); over.set(r * g.w + c, [DOUBLE[ch] ?? ch, `${inv ? "inv" : "on"} ${b.k}`]); }
  for (let r = b.r + 1; r < b.r + b.h - 1; r++) {
    for (let c = b.c + 1; c < b.c + b.w - 1; c++) {
      const ch = g.get(r, c);
      if (inv) over.set(r * g.w + c, [ch !== " " && Math.random() < 0.3 ? pick(GLYPHS) : ch, `inv ${b.k}`]);
      else if (r === b.r + 1 && ch !== " " && n > 3 && Math.random() < 0.15) over.set(r * g.w + c, [pick(GLYPHS), `${b.k}-t`]);
    }
  }
}

/** A packet: a hex digit at its head and a ▓▒░ trail behind it. */
export function packet(g: Grid, over: Over, cells: Cell[], pos: number, k: string): void {
  for (let t = 1; t <= 3; t++) { const q = cells[pos - t]; if (q) over.set(q[0] * g.w + q[1], ["▓▒░"[t - 1], `hot ${k}`]); }
  const at = cells[Math.min(pos, cells.length - 1)];
  if (at) over.set(at[0] * g.w + at[1], [pick(HEX), `pk ${k}`]);
}
