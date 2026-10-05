// Every section below the hero folds away under its heading (ADR 0035, amended 2026-10-05). The static
// HTML carries each section's content in a .section__body; without this script nothing folds and
// everything shows. With it, the h2's text moves into a real <button> (the disclosure pattern:
// aria-expanded, aria-controls naming the body), every section starts open, and a visitor's choice is
// kept per section in localStorage. A link to anything inside a folded section opens it first.

import { h, replace } from "../lib/dom";

const KEY = "collapsed:";

interface Fold {
  section: HTMLElement;
  body: HTMLElement;
  btn: HTMLButtonElement;
}

// Storage can be missing or throw (a privacy mode, a full quota, a sandboxed frame): the choice then
// holds only for this page view.
function stored(id: string): boolean {
  try {
    return localStorage.getItem(KEY + id) === "1";
  } catch {
    return false;
  }
}

function store(id: string, expanded: boolean): void {
  try {
    if (expanded) localStorage.removeItem(KEY + id);
    else localStorage.setItem(KEY + id, "1");
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
 * mount, so its live panels can stop redrawing while nobody can see them.
 */
export function mountSections(onChange?: (id: string, expanded: boolean) => void): void {
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
  document.addEventListener("click", (e) => {
    const a = e.target instanceof Element ? e.target.closest("a[href^='#']") : null;
    if (a) reveal(a.getAttribute("href") ?? "");
  });
  // Back/forward and a typed hash: the browser has already scrolled, to a section that was folded.
  window.addEventListener("hashchange", () => reveal(location.hash)?.scrollIntoView());
  // Opened at #anchor: open its section, and land on it again if a section folded above it moved it
  // (at once, as the browser lands on a fragment when a page opens).
  const opened = reveal(location.hash);
  if (opened || [...folds.values()].some((f) => !isOpen(f))) (opened ?? byHash(location.hash))?.scrollIntoView({ behavior: "instant" });
}
