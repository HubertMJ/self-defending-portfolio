// A greeting for whoever opens the browser's console: a ">_" mark, the site's name in block letters in
// its accent green, and a few lines (the hidden ASCII mode, the code on GitHub, the build it came from).
// The banner sits on its own dark ground, so it reads the same in a light or a dark DevTools.
//
// Printed once per page load, in the top window only, never under automation (navigator.webdriver:
// the e2e suites watch the console). Console styling only: no DOM is touched, so Trusted Types and the
// CSP have nothing to object to; the mark is a data: SVG the console itself paints. Nothing here throws.
//
// The same directory is copied into every repository that serves a page of the site (as src/ascii is);
// test/unit/console-hello.test.ts checks the copies agree.

export interface HelloOptions {
  /** Where this page comes from, e.g. "work-mockups"; the GitHub line names it. */
  repo?: string;
  /** A same-origin JSON with a "commit" field (an image's build.json); its first 7 characters are shown. */
  buildInfo?: string;
}

/** One console.log call: a format string with %c markers, then one style per marker. */
export type LogCall = string[];

const GREEN = "#5ee0a4";
const GROUND = "#0c0e12";
/* Readable on a white and on a near-black console alike. */
const ACCENT = "#22a06b";

// Five rows per letter, as ASCII mode's banner draws them.
const FONT: Record<string, string[]> = {
  ">": ["█   ", " █  ", "  █ ", " █  ", "█   "], _: ["     ", "     ", "     ", "     ", "█████"], " ": ["  ", "  ", "  ", "  ", "  "],
  a: [" ███ ", "█   █", "█████", "█   █", "█   █"], b: ["████ ", "█   █", "████ ", "█   █", "████ "], e: ["█████", "█    ", "████ ", "█    ", "█████"],
  h: ["█   █", "█   █", "█████", "█   █", "█   █"], i: ["███", " █ ", " █ ", " █ ", "███"], j: ["  ███", "   █ ", "   █ ", "█  █ ", " ██  "],
  k: ["█   █", "█  █ ", "███  ", "█  █ ", "█   █"], l: ["█    ", "█    ", "█    ", "█    ", "█████"], n: ["█   █", "██  █", "█ █ █", "█  ██", "█   █"],
  o: [" ███ ", "█   █", "█   █", "█   █", " ███ "], r: ["████ ", "█   █", "████ ", "█  █ ", "█   █"], s: [" ████", "█    ", " ███ ", "    █", "████ "],
  t: ["█████", "  █  ", "  █  ", "  █  ", "  █  "], u: ["█   █", "█   █", "█   █", "█   █", " ███ "], ".": [" ", " ", " ", " ", "█"],
};

/** The words in block letters, five rows; a character the font lacks is a gap. */
export function banner(words: string): string[] {
  return [0, 1, 2, 3, 4].map((r) => [...words].map((ch) => (FONT[ch] ?? FONT[" "])[r]).join(" ").replace(/\s+$/, ""));
}

const MARK = `<svg xmlns="http://www.w3.org/2000/svg" width="56" height="56" viewBox="0 0 56 56"><rect width="56" height="56" rx="12" fill="${GROUND}"/><path d="M15 19l9 9-9 9" fill="none" stroke="${GREEN}" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M28 38h13" stroke="${GREEN}" stroke-width="4" stroke-linecap="round"/></svg>`;

/** Every console.log call the greeting makes, in order. Pure: what sayHello prints, for the tests. */
export function helloCalls(o: HelloOptions = {}, commit = ""): LogCall[] {
  const mono = "font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";
  // The console's own text colour for the words, so they suit its theme; colour only for the accents.
  const text = `${mono}; font-size: 12px; line-height: 1.6; color: inherit`;
  const strong = `${mono}; font-size: 12px; line-height: 1.6; color: ${ACCENT}; font-weight: 700`;
  const calls: LogCall[] = [
    // The mark: an empty run, as large as the picture, painted with it.
    ["%c ", `font-size: 1px; padding: 28px; background: url("data:image/svg+xml,${encodeURIComponent(MARK)}") no-repeat center / 56px 56px`],
    [`%c${banner("hubertjablon.ski").join("\n")}`, `${mono}; font-size: 9px; line-height: 1.15; color: ${GREEN}; background: ${GROUND}; padding: 10px 14px; border-radius: 8px`],
    [`%cYou opened the console, so you are my kind of visitor.`, `${text}; font-weight: 600`],
    [`%cType %cascii%c anywhere on the page, or add %c?ascii=1%c, for the terminal look.`, text, strong, text, strong, text],
    [`%cThe code: https://github.com/HubertMJ${o.repo ? `/${o.repo}` : ""}  ·  no cookies, no trackers, nothing else talks here.`, text],
  ];
  if (commit) calls.push([`%cBuilt from commit ${commit.slice(0, 7)}.`, text]);
  return calls;
}

const KEY = "__hubertjablonskiHello";

/** Prints the greeting, once, if this is a person's top-level page. Never throws. */
export function sayHello(o: HelloOptions = {}): void {
  try {
    const w = window as unknown as Record<string, unknown> & Window;
    if (w[KEY] || w.top !== w.self || navigator.webdriver) return;
    w[KEY] = true;
    const print = (commit = "") => {
      for (const args of helloCalls(o, commit)) console.log(...args);
    };
    if (!o.buildInfo || typeof fetch !== "function") return print();
    // The commit is a nicety: anything wrong with it and the greeting goes out without it.
    fetch(o.buildInfo, { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null))
      .then((j: { commit?: unknown } | null) => print(typeof j?.commit === "string" && /^[0-9a-f]{7,40}$/.test(j.commit) ? j.commit : ""))
      .catch(() => print());
  } catch {
    // A console greeting is never worth an error.
  }
}
