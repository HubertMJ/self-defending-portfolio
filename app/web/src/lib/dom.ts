// The only way this code builds DOM. Strings become text nodes, never markup: Falco output is text a
// visitor's attack shaped, and the page enforces Trusted Types (`require-trusted-types-for 'script'`),
// so an HTML sink would be both a vulnerability and a runtime error. scripts/check-dom-sinks.mjs
// fails the lint if one appears anywhere in src/.

export type Child = Node | string | number | null | undefined | false;
type Attrs = Record<string, string | number | boolean | null | undefined>;

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: (Child | Child[])[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = String(v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  append(el, children);
  return el;
}

const SVG_NS = "http://www.w3.org/2000/svg";

export function svg(tag: string, attrs: Attrs = {}, ...children: Node[]): SVGElement {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v !== null && v !== undefined && v !== false) el.setAttribute(k, String(v));
  }
  el.append(...children);
  return el;
}

function append(el: Node, children: (Child | Child[])[]): void {
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.appendChild(typeof c === "object" ? c : document.createTextNode(String(c)));
  }
}

/** Replaces an element's children, keeping the element (and its focus/ARIA wiring) in place. */
export function replace(el: Element, ...children: (Child | Child[])[]): void {
  el.replaceChildren();
  append(el, children);
}

export function byId<T extends HTMLElement = HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing #${id}`);
  return el as T;
}

const rtf = typeof Intl !== "undefined" ? new Intl.RelativeTimeFormat("en", { numeric: "auto" }) : null;

/** "2 minutes ago" style relative time, falling back to the ISO string. */
export function relativeTime(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return "never";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  const s = Math.round((t - now) / 1000);
  if (!rtf) return new Date(t).toISOString();
  const abs = Math.abs(s);
  if (abs < 60) return rtf.format(s, "second");
  if (abs < 3600) return rtf.format(Math.round(s / 60), "minute");
  if (abs < 86_400) return rtf.format(Math.round(s / 3600), "hour");
  return rtf.format(Math.round(s / 86_400), "day");
}

// Absolute times are UTC and say so (ADR 0035): a visitor in any zone reads the same instant as the
// cluster's records and the raw JSON, and a relative "6 hours ago" only ever stands next to one.

const toMs = (t: string | number): number => (typeof t === "number" ? t : Date.parse(t));
const pad2 = (n: number, w = 2) => String(n).padStart(w, "0");
const ymd = (d: Date) => `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}`;
const hms = (d: Date, ms: boolean) =>
  `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}${ms ? `.${pad2(d.getUTCMilliseconds(), 3)}` : ""}`;

/** "2026-10-03 18:01:57 UTC" ("…18:01:57.123 UTC" with ms); an unparseable string comes back as is. */
export function utc(t: string | number, opts: { ms?: boolean } = {}): string {
  const n = toMs(t);
  if (Number.isNaN(n)) return typeof t === "string" ? t : "–";
  const d = new Date(n);
  return `${ymd(d)} ${hms(d, opts.ms ?? false)} UTC`;
}

/** "18:01:57 UTC" on the same UTC day as `now`, else with the date in front as utc() writes it. */
export function utcClock(t: string | number, now: number = Date.now(), opts: { ms?: boolean } = {}): string {
  const n = toMs(t);
  if (Number.isNaN(n)) return typeof t === "string" ? t : "–";
  const d = new Date(n);
  return ymd(d) === ymd(new Date(now)) ? `${hms(d, opts.ms ?? false)} UTC` : utc(n, opts);
}

/** "18:01:57 UTC (6 hours ago)": the absolute time, then how long ago; "never" for none. */
export function when(t: string | number | null | undefined, now: number = Date.now()): string {
  if (t === null || t === undefined || t === "") return "never";
  const n = toMs(t);
  if (Number.isNaN(n)) return String(t);
  return `${utcClock(n, now)} (${relativeTime(new Date(n).toISOString(), now)})`;
}

/** A <time> element whose datetime is the exact instant and whose text is `text` (utc() by default). */
export function timeEl(t: string | number, text?: string, attrs: Attrs = {}): HTMLTimeElement {
  const n = toMs(t);
  return h("time", { ...attrs, datetime: Number.isNaN(n) ? null : new Date(n).toISOString() }, text ?? utc(t));
}

export function prefersReducedMotion(): boolean {
  return typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/** A <time> reading when(t); refreshRelative() keeps its "x ago" current in place. */
export function whenEl(t: string | number, now: number = Date.now(), attrs: Attrs = {}): HTMLTimeElement {
  const n = toMs(t);
  return timeEl(t, when(t, now), Number.isNaN(n) ? attrs : { ...attrs, "data-when": String(n) });
}

/**
 * Rewrites the relative texts under `root` ([data-when]: when(), [data-ago]: " (x ago)") by changing
 * text node data only: no element is replaced, so focus, selection and the DOM's structure stay.
 */
export function refreshRelative(root: ParentNode, now: number = Date.now()): void {
  for (const el of root.querySelectorAll<HTMLElement>("[data-when]")) setText(el, when(Number(el.dataset.when), now));
  for (const el of root.querySelectorAll<HTMLElement>("[data-ago]")) setText(el, ` (${relativeTime(new Date(Number(el.dataset.ago)).toISOString(), now)})`);
}

/** Sets an element's text through its one text node when it has exactly one (a characterData change, not a child list one). */
export function setText(el: Element, text: string): void {
  const n = el.firstChild;
  if (n instanceof Text && !n.nextSibling) {
    if (n.data !== text) n.data = text;
  } else el.textContent = text;
}
