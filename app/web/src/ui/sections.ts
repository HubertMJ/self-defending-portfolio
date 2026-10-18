// Every section below the hero folds away under its heading (ADR 0035, amended 2026-10-05 and
// 2026-10-12). The static HTML carries each section's content in a .section__body; without this script
// nothing folds and everything shows. With it, the h2's text moves into a real <button> (the
// disclosure pattern: aria-expanded, aria-controls naming the body), every section starts open
// (lib/folds.ts, 2026-10-17), and a visitor's choice is kept per section in localStorage. A link to
// anything inside a folded section opens it first.

import { h, replace } from "../lib/dom";
import { FOLD_KEY as KEY, startsFolded } from "../lib/folds";

interface Fold {
  section: HTMLElement;
  body: HTMLElement;
  btn: HTMLButtonElement;
}

// Storage can be missing or throw (a privacy mode, a full quota, a sandboxed frame): the choice then
// holds only for this page view.
function stored(id: string): boolean {
  let v: string | null = null;
  try {
    v = localStorage.getItem(KEY + id);
  } catch {
    // Unremembered: the default.
  }
  return startsFolded(id, v);
}

function store(id: string, expanded: boolean): void {
  try {
    localStorage.setItem(KEY + id, expanded ? "0" : "1");
  } catch {
    // Not persisted.
  }
}

/** The text of a section's heading, wherever it is now (inside the toggle once mounted). */
export function sectionTitle(heading: HTMLElement): HTMLElement {
  return heading.querySelector<HTMLElement>(".section__label") ?? heading;
}

/**
 * Turns each `main > .section` with a .section__head h2 and a .section__body into a disclosure.
 * `onChange(id, expanded)`: each change of a section's state, including a folded one restored at
 * mount, so its live panels can stop redrawing while nobody can see them. Nothing opens a section
 * but the visitor: a click on its heading, or on a link into it (ADR 0035, amendment 2026-10-13).
 */
export interface SectionsHandle {
  /** Opens a section, as a click on its heading would; the choice is kept like a click's. */
  open(id: string): void;
}

/** What ends a landing's hold: the visitor's own move. */
const HOLD_STOPS = ["wheel", "touchstart", "keydown", "pointerdown"] as const;

export function mountSections(onChange?: (id: string, expanded: boolean) => void): SectionsHandle {
  const folds = new Map<string, Fold>();
  const isOpen = (f: Fold) => f.btn.getAttribute("aria-expanded") === "true";

  const set = (f: Fold, expanded: boolean, persist: boolean) => {
    const was = isOpen(f);
    f.btn.setAttribute("aria-expanded", String(expanded));
    f.body.hidden = !expanded;
    f.section.classList.toggle("section--collapsed", !expanded);
    if (persist) store(f.section.id, expanded);
    if (was !== expanded) onChange?.(f.section.id, expanded);
  };

  for (const section of document.querySelectorAll<HTMLElement>("main > .section")) {
    const heading = section.querySelector<HTMLElement>(":scope > .wrap > .section__head > h2");
    const body = section.querySelector<HTMLElement>(":scope > .wrap > .section__body");
    if (!section.id || !heading || !body?.id) continue;
    const btn = h(
      "button",
      { type: "button", class: "section__toggle", "aria-expanded": "true", "aria-controls": body.id },
      h("span", { class: "section__label" }, [...heading.childNodes]),
      h("span", { class: "section__chevron", "aria-hidden": "true" }),
    );
    replace(heading, btn);
    const fold = { section, body, btn };
    folds.set(section.id, fold);
    btn.addEventListener("click", () => set(fold, !isOpen(fold), true));
    if (stored(section.id)) set(fold, false, false);
  }

  // The folded sections are folded by their buttons now: theme.ts's stand-in (styles.css) goes.
  delete document.documentElement.dataset.folded;

  // The landing being held (hold() below), if any.
  let held: { hash: string; stop: () => void } | undefined;

  const byHash = (hash: string): HTMLElement | null => {
    if (hash.length < 2) return null;
    try {
      return document.getElementById(decodeURIComponent(hash.slice(1)));
    } catch {
      return null;
    }
  };

  /** Opens the folded section holding the element `hash` names; that element if it was folded. */
  const reveal = (hash: string): HTMLElement | null => {
    const target = byHash(hash);
    const fold = folds.get(target?.closest<HTMLElement>("main > .section")?.id ?? "");
    if (!target || !fold || isOpen(fold)) return null;
    set(fold, true, true);
    return target;
  };

  // A click on an in-page link opens the section before the browser scrolls to it; the same link
  // clicked again (no hashchange) still works.
  // A modified or non-primary click opens no section here: it opens a tab or a window, or nothing.
  document.addEventListener("click", (e) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    const a = e.target instanceof Element ? e.target.closest("a[href^='#']") : null;
    if (!a) return;
    const href = a.getAttribute("href") ?? "";
    reveal(href);
    // The sections start open (2026-10-17), so a panel above the target can still be drawing its data
    // (the SIEM board, shortly after the page opens) while the browser scrolls: the landing holds,
    // without cutting the browser's own smooth scroll short unless the page's size changes. A target
    // not drawn yet (an incident card while #correlation was folded, main.ts) is landed on once drawn.
    if (href.length > 1) hold(href, 4_000, HOLD_STOPS, byHash(href) !== null);
  });
  // Back/forward and a typed hash: the browser has already scrolled, to a section that was folded.
  // A landing still held for another hash ends: the visitor went somewhere else.
  window.addEventListener("hashchange", () => {
    if (held && byHash(held.hash) !== byHash(location.hash)) held.stop();
    reveal(location.hash)?.scrollIntoView();
  });
  // Opened at #anchor: open its section, and land on it again if a section folded above it moved it
  // (at once, as the browser lands on a fragment when a page opens). Not on a reload or back/forward,
  // where the browser restores the visitor's own scroll position, unless a folded section was opened.
  const opened = reveal(location.hash);
  const nav = typeof performance.getEntriesByType === "function" ? (performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming | undefined) : undefined;
  const restoring = nav?.type === "reload" || nav?.type === "back_forward";
  if (opened) opened.scrollIntoView({ behavior: "instant" });
  else if (!restoring && [...folds.values()].some((f) => !isOpen(f))) byHash(location.hash)?.scrollIntoView({ behavior: "instant" });

  // Opened at #anchor, the landing does not hold on its own: the live parts render after their data
  // (the hero's counters, the terminal's start panel, #correlation shown only once the SIEM answers),
  // which moves the target, or shows it, after the browser landed. Until the visitor scrolls, touches
  // or types, or for 10 s, each change of the page's size lands on the hash again. Not on a reload or
  // back/forward, where the browser restores the visitor's own position.
  // `afterFirst`: the observer's first report (at once, on observe) is not a change of size; a link's
  // click leaves it to the browser's own scroll.
  const hold = (hash: string, ms: number, events: readonly string[], afterFirst = false) => {
    if (typeof ResizeObserver !== "function") return;
    // One landing at a time: a new one ends the one before.
    held?.stop();
    let done = false;
    let first = afterFirst;
    // Where the hold last put the page, and how tall the page was then: a scroll that moves it further
    // than the layout could (a scrollbar dragged, a key or a gesture no event above caught) is the
    // visitor's, and ends it. A scroll while the page is still loading (the browser retries its own
    // landing on the fragment) or after the page's height changed (scroll anchoring keeping what is on
    // screen in place) is the layout's: the observer lands on the target again.
    let placed: number | undefined;
    let placedHeight = 0;
    const place = () => {
      placed = scrollY;
      placedHeight = document.documentElement.scrollHeight;
    };
    const ro = new ResizeObserver(() => {
      if (first) {
        first = false;
        return;
      }
      const target = done ? null : byHash(hash);
      if (target && target.getClientRects().length) {
        target.scrollIntoView({ behavior: "instant" });
        place();
      }
    });
    // Left to the browser's scroll, the hold counts from where that scroll ends (no scroll for
    // 300 ms): a scrollbar dragged after it (no event above catches one) moves the page further, and
    // ends the hold.
    let quiet: ReturnType<typeof setTimeout> | undefined;
    const settling = () => {
      if (!afterFirst || placed !== undefined) return;
      clearTimeout(quiet);
      quiet = setTimeout(() => {
        if (placed === undefined) place();
      }, 300);
    };
    settling();
    const onScroll = () => {
      settling();
      if (placed === undefined || document.readyState !== "complete" || document.documentElement.scrollHeight !== placedHeight) return;
      if (Math.abs(scrollY - placed) > 40) stop();
    };
    const stop = () => {
      done = true;
      if (held?.stop === stop) held = undefined;
      ro.disconnect();
      for (const ev of events) removeEventListener(ev, stop);
      removeEventListener("scroll", onScroll);
      clearTimeout(quiet);
    };
    ro.observe(document.querySelector("main") ?? document.body);
    for (const ev of events) addEventListener(ev, stop, { passive: true });
    addEventListener("scroll", onScroll, { passive: true });
    setTimeout(stop, ms);
    held = { hash, stop };
  };
  if (location.hash.length > 1 && !restoring) hold(location.hash, 10_000, HOLD_STOPS);

  return {
    open(id) {
      const f = folds.get(id);
      if (f && !isOpen(f)) set(f, true, true);
    },
  };
}
