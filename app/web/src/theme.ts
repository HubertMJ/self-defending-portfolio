// Loaded as a classic, render-blocking script in <head> so a stored theme choice applies before
// first paint. Kept to a few lines on purpose: everything else waits for the deferred module.
import { FOLDED_BY_DEFAULT, FOLD_KEY, startsFolded } from "./lib/folds";

// Scripts run: what the default view leaves to Technical Mode (styles.css .tech-more) is hidden from
// the first paint; without JavaScript everything shows.
document.documentElement.classList.add("js");

try {
  const t = localStorage.getItem("theme");
  if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
  // Technical Mode (ui/tech.ts), applied here for the same reason: no layout jump on load.
  if (localStorage.getItem("tech") === "on") document.documentElement.dataset.tech = "on";
  // Folded sections (ui/sections.ts, same "sdp:collapsed:<id>" keys, lib/folds.ts defaults), named
  // for styles.css so a folded section is folded at first paint; sections.ts drops the attribute once
  // its buttons are in place.
  const ids = new Set<string>(FOLDED_BY_DEFAULT);
  for (let i = 0; i < localStorage.length; i++) {
    const id = /^sdp:collapsed:([a-z-]+)$/.exec(localStorage.key(i) ?? "")?.[1];
    if (id) ids.add(id);
  }
  const folded = [...ids].filter((id) => startsFolded(id, localStorage.getItem(FOLD_KEY + id)));
  if (folded.length) document.documentElement.dataset.folded = folded.join(" ");
} catch {
  // Storage blocked (private mode, sandboxed preview): the OS preference applies, and the defaults
  // fold at first paint all the same.
  document.documentElement.dataset.folded = FOLDED_BY_DEFAULT.join(" ");
}

// A module only so the unit tests can import it; the build wraps it as a classic script all the same.
export {};
