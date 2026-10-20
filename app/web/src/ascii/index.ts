// ASCII mode: a hidden second look for every page of the site, kept beside the normal one until the
// owner decides to switch. Off by default; typing "ascii" anywhere (or tapping the page's title five
// times, on a phone) turns it on or off, and ?ascii=1 / ?ascii=0 in a link does the same. The choice is
// stored under one key on the origin, so it follows the visitor from page to page.
//
// What it changes: the stylesheet's html.ascii block re-skins the page as a terminal; this module adds
// a slow ASCII field behind it, a block-letter banner over the title, and turns every diagram (any SVG
// with g[data-node]) into a character drawing that follows the SVG's own state each frame. The SVG
// stays in the page, visually hidden, so screen readers, keyboard focus and click handlers keep using
// it; the drawing shows the focused node and passes clicks on a box to its node.
//
// The same directory is copied into every repository that serves a page of the site.

import { boxFx, packet, pick, type Over } from "./grid";
import { fromSvg, wrap, type Drawing } from "./svg";

import { KEY } from "./prepaint";

export { prepaintAscii } from "./prepaint";
const TICK_MS = 70;
const root = document.documentElement;
const calm = (): boolean => typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;

// ---------- block letters for the banner ----------
const FONT: Record<string, string[]> = {
  A: [" ███ ", "█   █", "█████", "█   █", "█   █"], B: ["████ ", "█   █", "████ ", "█   █", "████ "], C: [" ████", "█    ", "█    ", "█    ", " ████"],
  D: ["████ ", "█   █", "█   █", "█   █", "████ "], E: ["█████", "█    ", "████ ", "█    ", "█████"], F: ["█████", "█    ", "████ ", "█    ", "█    "],
  G: [" ████", "█    ", "█  ██", "█   █", " ████"], H: ["█   █", "█   █", "█████", "█   █", "█   █"], I: ["███", " █ ", " █ ", " █ ", "███"],
  J: ["  ███", "   █ ", "   █ ", "█  █ ", " ██  "], K: ["█   █", "█  █ ", "███  ", "█  █ ", "█   █"], L: ["█    ", "█    ", "█    ", "█    ", "█████"],
  M: ["█   █", "██ ██", "█ █ █", "█   █", "█   █"], N: ["█   █", "██  █", "█ █ █", "█  ██", "█   █"], O: [" ███ ", "█   █", "█   █", "█   █", " ███ "],
  P: ["████ ", "█   █", "████ ", "█    ", "█    "], Q: [" ███ ", "█   █", "█ █ █", "█  █ ", " ██ █"], R: ["████ ", "█   █", "████ ", "█  █ ", "█   █"],
  S: [" ████", "█    ", " ███ ", "    █", "████ "], T: ["█████", "  █  ", "  █  ", "  █  ", "  █  "], U: ["█   █", "█   █", "█   █", "█   █", " ███ "],
  V: ["█   █", "█   █", "█   █", " █ █ ", "  █  "], W: ["█   █", "█   █", "█ █ █", "██ ██", "█   █"], X: ["█   █", " █ █ ", "  █  ", " █ █ ", "█   █"],
  Y: ["█   █", " █ █ ", "  █  ", "  █  ", "  █  "], Z: ["█████", "   █ ", "  █  ", " █   ", "█████"],
  0: [" ███ ", "█  ██", "█ █ █", "██  █", " ███ "], 1: [" █ ", "██ ", " █ ", " █ ", "███"], 2: ["████ ", "    █", " ███ ", "█    ", "█████"],
  3: ["████ ", "    █", " ███ ", "    █", "████ "], 4: ["█   █", "█   █", "█████", "    █", "    █"], 5: ["█████", "█    ", "████ ", "    █", "████ "],
  6: [" ███ ", "█    ", "████ ", "█   █", " ███ "], 7: ["█████", "    █", "   █ ", "  █  ", "  █  "], 8: [" ███ ", "█   █", " ███ ", "█   █", " ███ "],
  9: [" ███ ", "█   █", " ████", "    █", " ███ "], ".": [" ", " ", " ", " ", "█"], "-": ["   ", "   ", "███", "   ", "   "],
  "/": ["    █", "   █ ", "  █  ", " █   ", "█    "], " ": ["  ", "  ", "  ", "  ", "  "],
};
/** Five rows of block letters; accents are dropped (Jabłoński is JABLONSKI), unknown characters are gaps. */
export const bigText = (s: string): string[] => {
  const plain = s.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/ł/gi, "L").toUpperCase();
  return [0, 1, 2, 3, 4].map((r) => [...plain].map((ch) => (FONT[ch] ?? FONT[" "])[r]).join(" "));
};

/** The largest font size, at most `max` px, at which the pre's drawn text fits its container. Measured
 * on the drawing itself, not assumed: some platforms round each glyph's advance to whole pixels. */
const fitted = new WeakMap<HTMLElement, string>();
function fit(pre: HTMLElement, cols: number, max: number): void {
  const avail = contentWidth(pre.parentElement);
  const key = `${Math.round(avail)}:${cols}:${max}:${document.fonts?.check("12px LabMono") ?? true}`;
  if (fitted.get(pre) === key) return;
  const fits = (size: number): boolean => {
    pre.style.setProperty("--fs", `${size.toFixed(2)}px`);
    return pre.scrollWidth <= avail + 0.5;
  };
  let fs = Math.min(max, avail / cols / 0.602);
  if (!fits(fs)) {
    let lo = 4, hi = fs;
    for (let i = 0; i < 8; i++) { const mid = (lo + hi) / 2; if (fits(mid)) lo = mid; else hi = mid; }
    fs = lo;
    fits(fs);
  }
  fitted.set(pre, key);
}

/** The width a child of `el` can take: its box less its padding. */
function contentWidth(el: Element | null): number {
  if (!el) return innerWidth;
  const cs = getComputedStyle(el);
  return el.getBoundingClientRect().width - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight) - parseFloat(cs.borderLeftWidth) - parseFloat(cs.borderRightWidth);
}

// ---------- the parts the mode adds, and how they are taken away ----------
interface View { svg: SVGSVGElement; pre: HTMLPreElement; d: Drawing; dirty: boolean; onScreen: boolean; mo: MutationObserver; io: IntersectionObserver;
  packets: { e: Drawing["edges"][number]; pos: number }[]; fx: Map<string, number>; wasLit: Map<Element, boolean>; wasState: Map<string, string>; t: number;
  /** The box under the pointer, and the popup beside it (or beside the focused node). */
  hover: string | null; tip: HTMLPreElement; tipFor: string | null; tipT: number }

let views: View[] = [];
let added: Element[] = [];
let timers: number[] = [];
let watch: MutationObserver | null = null;
let banner = "";
const cleanups: (() => void)[] = [];

function mount(): void {
  const still = calm();
  // The field behind everything.
  const bg = document.createElement("pre");
  bg.className = "ascii-bg";
  bg.setAttribute("aria-hidden", "true");
  document.body.prepend(bg);
  added.push(bg);
  const ramp = " .·:-=+";
  let ft = 0;
  const field = (): void => {
    const cols = Math.ceil(innerWidth / 8.4) + 1, rows = Math.ceil(innerHeight / 16.8) + 1;
    let out = "";
    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        const v = Math.sin(c * 0.09 + ft * 0.5) + Math.sin(r * 0.21 - ft * 0.35) + Math.sin((c + r * 1.7) * 0.045 + ft * 0.22);
        out += ramp[Math.max(0, Math.min(ramp.length - 1, Math.floor(((v + 3) / 6) * ramp.length)))];
      }
      out += "\n";
    }
    bg.textContent = out;
    ft += 0.05;
  };
  field();
  if (!still) timers.push(window.setInterval(() => { if (!document.hidden) field(); }, 100));

  // The banner over the page's title.
  const h1 = document.querySelector("main h1");
  if (h1 && banner) {
    const pre = document.createElement("pre");
    pre.className = "ascii-banner";
    pre.setAttribute("aria-hidden", "true");
    const words = banner.split(" ");
    const draw = (): void => {
      const narrow = innerWidth <= 760 && words.length > 1;
      const rows = narrow ? words.flatMap((w, i) => [...(i ? [""] : []), ...bigText(w)]) : bigText(banner);
      const frag = document.createDocumentFragment();
      rows.forEach((line, i) => {
        let buf = "";
        for (const ch of line) {
          if (ch === "█" && !still && Math.random() < 0.005) {
            if (buf) frag.append(buf);
            buf = "";
            const s = document.createElement("span");
            s.className = "ascii-glitch";
            s.textContent = pick("▓▒░");
            frag.append(s);
          } else buf += ch;
        }
        frag.append(buf + (i < rows.length - 1 ? "\n" : ""));
      });
      pre.replaceChildren(frag);
      if (pre.isConnected) fit(pre, Math.max(...rows.map((l) => [...l].length)), 15);
    };
    h1.before(pre);
    draw();
    // When the banner spells the title itself (the landing page's name), the title steps back for
    // screen readers only, rather than saying it twice on screen.
    const plain = (x: string): string => x.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/ł/gi, "l").toLowerCase().trim();
    if (plain(h1.textContent ?? "") === plain(banner)) {
      h1.classList.add("ascii-said");
      cleanups.push(() => h1.classList.remove("ascii-said"));
    }
    added.push(pre);
    if (!still) timers.push(window.setInterval(() => { if (!document.hidden) draw(); }, 320));
    const onResize = (): void => draw();
    addEventListener("resize", onResize);
    cleanups.push(() => removeEventListener("resize", onResize));
  }

  // The diagrams, now and as pages mount new ones (the lab's incident drawing arrives with its data).
  scan();
  watch = new MutationObserver(() => scan());
  watch.observe(document.body, { childList: true, subtree: true });
  timers.push(window.setInterval(() => { if (!document.hidden) for (const v of views) frame(v, still); }, still ? 500 : TICK_MS));
}

function unmount(): void {
  timers.forEach(clearInterval);
  timers = [];
  watch?.disconnect();
  watch = null;
  for (const v of views) { v.mo.disconnect(); v.io.disconnect(); v.pre.remove(); v.tip.remove(); v.svg.classList.remove("ascii-src"); }
  views = [];
  added.forEach((el) => el.remove());
  added = [];
  cleanups.splice(0).forEach((f) => f());
}

function scan(): void {
  views = views.filter((v) => {
    if (v.svg.isConnected) return true;
    v.mo.disconnect(); v.io.disconnect(); v.pre.remove(); v.tip.remove();
    return false;
  });
  for (const svg of document.querySelectorAll<SVGSVGElement>("svg")) {
    if (views.some((v) => v.svg === svg) || !svg.querySelector("g[data-node]")) continue;
    const narrow = /narrow/.test(svg.getAttribute("class") ?? "");
    const pre = document.createElement("pre");
    pre.className = `ascii-dg${narrow ? " ascii-dg--narrow" : ""}`;
    pre.setAttribute("aria-hidden", "true");
    svg.after(pre);
    svg.classList.add("ascii-src");
    const tip = document.createElement("pre");
    tip.className = "ascii-tip";
    tip.setAttribute("aria-hidden", "true");
    tip.hidden = true;
    document.body.append(tip);
    const v: View = { svg, pre, d: fromSvg(svg, narrow ? 48 : 176), dirty: false, onScreen: true, mo: new MutationObserver(() => { v.dirty = true; }),
      io: new IntersectionObserver((es) => { for (const e of es) v.onScreen = e.isIntersecting; }), packets: [], fx: new Map(), wasLit: new Map(), wasState: new Map(), t: 0,
      hover: null, tip, tipFor: null, tipT: 0 };
    // Words and gauges change as a story plays: redraw the grid then (states are read every frame).
    v.mo.observe(svg, { subtree: true, characterData: true, childList: true, attributes: true, attributeFilter: ["data-on"] });
    v.io.observe(pre);
    const boxUnder = (e: MouseEvent) => {
      const rect = pre.getBoundingClientRect();
      const c = Math.floor(((e.clientX - rect.left) / rect.width) * v.d.g.w);
      const r = Math.floor(((e.clientY - rect.top) / rect.height) * v.d.g.rows);
      return v.d.g.boxAt(r, c);
    };
    pre.addEventListener("click", (e) => {
      const b = boxUnder(e);
      if (b) v.d.nodes.get(b.id)?.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });
    // The popup follows a pointer that can hover; on a touch screen a tap opens the caption instead.
    if (matchMedia("(hover: hover)").matches) {
      pre.addEventListener("mousemove", (e) => { const b = boxUnder(e); v.hover = b?.id ?? null; pre.classList.toggle("ascii-dg--over", !!b); });
      pre.addEventListener("mouseleave", () => { v.hover = null; pre.classList.remove("ascii-dg--over"); });
    }
    views.push(v);
    frame(v, calm());
  }
}

const FX = 6;
const TONE: Record<string, string> = { run: "r-attack", detect: "r-detect", record: "r-record", deliver: "r-entry", incident: "r-incident", respond: "r-respond" };
const STATE_K: Record<string, string> = { run: "b-attack", detect: "b-detect", record: "b-record", deliver: "b-entry", incident: "b-incident", respond: "b-respond" };

function frame(v: View, still: boolean): void {
  // The drawing follows its SVG: shown when the SVG's own layout would show it (wide or phone).
  // (Rects, not its own display: a page may hide the variant by hiding its container.)
  const shown = v.svg.getClientRects().length > 0;
  v.pre.hidden = !shown;
  if (!shown) { v.tip.hidden = true; return; }
  // Off screen: no drawing, but keep its size right (the font arriving, a resize), so nothing jumps
  // when it scrolls in.
  if (!v.onScreen && v.t > 0) { fit(v.pre, v.d.g.w, 14); v.tip.hidden = true; return; }
  if (v.dirty) { v.d = fromSvg(v.svg, /narrow/.test(v.pre.className) ? 48 : 176); v.dirty = false; v.packets = []; }
  const { g, edges, nodes } = v.d;
  const over: Over = new Map();
  const focus = document.activeElement;
  for (const b of g.boxes.values()) {
    const el = nodes.get(b.id);
    const st = el?.getAttribute("data-state") ?? "idle";
    const lit = st !== "idle";
    const k = lit ? STATE_K[st] ?? b.k : b.k;
    if (lit && (v.wasState.get(b.id) ?? "idle") === "idle" && !still) v.fx.set(b.id, st === "incident" ? FX + 1 : FX);
    v.wasState.set(b.id, st);
    if (lit) for (const [r, c] of b.cells) over.set(r * g.w + c, [null, `on ${k}`]);
    if (el && focus && (el === focus || el.contains(focus))) for (const [r, c] of b.cells) over.set(r * g.w + c, [null, `focus ${k}`]);
  }
  for (const e of edges) {
    const lit = e.el?.getAttribute("data-lit") === "true";
    if (lit) {
      const k = TONE[e.el?.getAttribute("data-tone") ?? ""] ?? e.k;
      for (const [r, c] of e.cells) over.set(r * g.w + c, [null, `hot ${k}`]);
      if (!v.wasLit.get(e.el!) && !still) v.packets.push({ e: { ...e, k }, pos: 0 });
    }
    if (e.el) v.wasLit.set(e.el, lit);
  }
  // Now and then a packet rides an edge on its own, so the drawing breathes between runs.
  if (!still && edges.length && v.t % 24 === 0 && Math.random() < 0.8) v.packets.push({ e: edges[Math.floor(Math.random() * edges.length)], pos: 0 });
  for (const [id, n] of v.fx) {
    if (n <= 0) { v.fx.delete(id); continue; }
    v.fx.set(id, n - 1);
    const b = g.boxes.get(id);
    if (b) boxFx(g, over, b, n, nodes.get(id)?.getAttribute("data-state") === "incident");
  }
  for (let i = v.packets.length - 1; i >= 0; i--) {
    const p = v.packets[i];
    packet(g, over, p.e.cells, p.pos, p.e.k);
    p.pos += 1;
    if (p.pos >= p.e.cells.length) { v.packets.splice(i, 1); if (p.e.to && !v.fx.has(p.e.to)) v.fx.set(p.e.to, FX); }
  }
  g.render(v.pre, over);
  // Sized to the column it sits in: as large as 14px allows, never wider than its container.
  fit(v.pre, g.w, 14);
  popup(v, focus, still);
  v.t++;
}

const TIP_W = 36;

/** The short words of the box under the pointer (or of the focused node), in a small frame beside it,
 * typed in. Fixed to the screen and never in the flow, so nothing on the page moves. */
function popup(v: View, focus: Element | null, still: boolean): void {
  const { g, nodes } = v.d;
  const focused = [...nodes].find(([, el]) => focus && (el === focus || el.contains(focus)))?.[0] ?? null;
  const id = v.hover ?? focused;
  const el = id ? nodes.get(id) : undefined;
  const text = el?.getAttribute("data-tip");
  const b = id ? g.boxes.get(id) : undefined;
  if (!id || !text || !b) { v.tip.hidden = true; v.tipFor = null; return; }
  if (v.tipFor !== id) { v.tipFor = id; v.tipT = 0; }
  v.tipT++;
  const title = [...(el?.querySelector("text")?.textContent?.trim() ?? id)].slice(0, TIP_W - 6).join("");
  const body = wrap(text, TIP_W - 4);
  let left = still ? Infinity : v.tipT * 14; // characters revealed so far
  const frag = document.createDocumentFragment();
  const span = (cls: string, s: string): void => { const x = document.createElement("span"); x.className = cls; x.textContent = s; frag.append(x); };
  span("ascii-tip__f", "┌─ "); span("ascii-tip__t", title); span("ascii-tip__f", ` ${"─".repeat(Math.max(1, TIP_W - 5 - [...title].length))}┐\n`);
  for (const line of body) {
    const shown = [...line].slice(0, Math.max(0, left)).join("");
    left -= [...line].length;
    span("ascii-tip__f", "│ "); frag.append(shown.padEnd(TIP_W - 4)); span("ascii-tip__f", " │\n");
  }
  span("ascii-tip__f", `└${"─".repeat(TIP_W - 2)}┘`);
  v.tip.replaceChildren(frag);
  v.tip.hidden = false;
  // Beside the box: to its right if there is room, else to its left; kept on screen.
  const rect = v.pre.getBoundingClientRect();
  const cw = rect.width / g.w, rh = rect.height / g.rows;
  const tw = v.tip.offsetWidth, th = v.tip.offsetHeight;
  let x = rect.left + (b.c + b.w + 1) * cw;
  if (x + tw > innerWidth - 8) x = rect.left + (b.c - 1) * cw - tw;
  x = Math.max(8, Math.min(x, innerWidth - tw - 8));
  const y = Math.max(8, Math.min(rect.top + b.r * rh, innerHeight - th - 8));
  v.tip.style.setProperty("left", `${Math.round(x)}px`);
  v.tip.style.setProperty("top", `${Math.round(y)}px`);
}

function toast(text: string): void {
  const t = document.createElement("p");
  t.className = "ascii-toast";
  t.setAttribute("role", "status");
  t.textContent = text;
  document.body.append(t);
  window.setTimeout(() => t.remove(), 4200);
}

function set(on: boolean, announce = true): void {
  if (on === root.classList.contains("ascii")) return;
  try { localStorage.setItem(KEY, on ? "1" : "0"); } catch { /* not kept: holds for this page view */ }
  if (on) { root.classList.add("ascii"); mount(); } else { unmount(); root.classList.remove("ascii"); }
  if (announce) toast(on ? "ASCII mode on — type “ascii” again to leave" : "ASCII mode off");
}

/** Wire the hidden switch, and mount the mode if the page opened in it. `title` is the banner's text. */
export function setupAscii(title: string): void {
  banner = title;
  let typed = "";
  addEventListener("keydown", (e) => {
    const t = e.target as HTMLElement | null;
    if (e.ctrlKey || e.metaKey || e.altKey || (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName)))) return;
    typed = (typed + e.key.toLowerCase()).slice(-5);
    if (typed === "ascii") { typed = ""; set(!root.classList.contains("ascii")); }
  });
  // On a phone: five quick taps on the page's title.
  let taps: number[] = [];
  document.querySelector("main h1")?.addEventListener("click", () => {
    const now = Date.now();
    taps = [...taps.filter((x) => now - x < 2500), now];
    if (taps.length >= 5) { taps = []; set(!root.classList.contains("ascii")); }
  });
  if (root.classList.contains("ascii")) mount();
}
