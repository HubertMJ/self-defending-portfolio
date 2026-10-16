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


// The pages sit side by side like desktops, as the landing page lays out its cards: the cluster on
// the left, the landing page (/) in the middle, the lab on the right. A move to a page further right
// slides the whole screen left, a move to the left slides it right, so a way back always runs the
// other way: the header's logo and the browser's or mouse's back button alike (styles.css,
// :active-view-transition-type). Set here, in the render-blocking script, because pagereveal fires
// before the first frame of the new page. Any other move keeps the plain cross-fade.
const DESKTOPS = ["/cluster/", "/", "/lab/"];
const desktop = (url: string | undefined): number => {
  if (!url) return -1;
  try {
    const u = new URL(url, location.href);
    if (u.origin !== location.origin) return -1;
    if (u.pathname === "/" || u.pathname === "/index.html") return DESKTOPS.indexOf("/");
    return DESKTOPS.findIndex((p) => p !== "/" && (u.pathname === p.slice(0, -1) || u.pathname.startsWith(p)));
  } catch {
    return -1;
  }
};
interface Reveal extends Event {
  viewTransition?: { types?: Set<string> } | null;
}
addEventListener("pagereveal", (e) => {
  const types = (e as Reveal).viewTransition?.types;
  if (!types) return;
  // The Navigation API knows where the visitor came from, back/forward included; the referrer only
  // for a link followed.
  const nav = (globalThis as { navigation?: { activation?: { from?: { url?: string } | null } } }).navigation;
  const from = desktop(nav?.activation?.from?.url ?? document.referrer);
  const to = desktop(location.href);
  if (from >= 0 && to >= 0 && from !== to) types.add(to > from ? "forward" : "backward");
});

// A module only so the unit tests can import it; the build wraps it as a classic script all the same.
export {};
