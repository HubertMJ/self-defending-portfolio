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

// Firefox (and older Safari) cannot animate between documents, so there the same slide is played by
// hand: a link to another desktop first slides the page out, then navigates, and the new page slides
// in from the other side. The way back runs the other way, the back button included, which the
// previous page records on pagehide. The header stays still: only what follows it in <body> moves.
const nativeSlide = "onpagereveal" in window && "CSSViewTransitionRule" in window;
const calm = typeof matchMedia === "function" ? matchMedia("(prefers-reduced-motion: reduce)") : null;
if (!nativeSlide) {
  const root = document.documentElement;
  const SLIDE = ["slide-in-forward", "slide-in-backward", "slide-out-forward", "slide-out-backward"];
  const play = (cls: string, ms: number, then?: () => void): void => {
    root.classList.remove(...SLIDE);
    void root.offsetWidth; // restart the animation when the same class comes back (bfcache)
    root.classList.add(cls);
    // Removed afterwards: a transform left on <main> would pin its sticky and fixed children to it.
    const done = (): void => {
      setTimeout(() => {
        if (then) then();
        else root.classList.remove(cls);
      }, ms);
    };
    // A page sliding in starts moving when its body is parsed, not when this head script runs.
    if (document.readyState === "loading") addEventListener("DOMContentLoaded", done, { once: true });
    else done();
  };
  const arrive = (): void => {
    if (calm?.matches) return;
    let from = -1;
    try {
      from = desktop(sessionStorage.getItem("desktop-from") ?? undefined);
    } catch {
      // Storage blocked: no slide, the page simply appears.
    }
    const entry = performance.getEntriesByType?.("navigation")[0] as PerformanceNavigationTiming | undefined;
    const followed = desktop(document.referrer) >= 0 || entry?.type === "back_forward";
    const to = desktop(location.href);
    if (followed && from >= 0 && to >= 0 && from !== to) play(to > from ? "slide-in-forward" : "slide-in-backward", 400);
  };
  arrive();
  addEventListener("pageshow", (e) => {
    if (e.persisted) {
      root.classList.remove(...SLIDE);
      arrive();
    }
  });
  addEventListener("pagehide", () => {
    try {
      sessionStorage.setItem("desktop-from", location.href);
    } catch {
      // Storage blocked: the next page simply appears.
    }
  });
  addEventListener("click", (e) => {
    if (calm?.matches || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    const a = (e.target as Element | null)?.closest?.("a[href]") as HTMLAnchorElement | null;
    if (!a || (a.target && a.target !== "_self") || a.hasAttribute("download")) return;
    const from = desktop(location.href);
    const to = desktop(a.href);
    if (from < 0 || to < 0 || from === to) return;
    e.preventDefault();
    play(to > from ? "slide-out-forward" : "slide-out-backward", 220, () => location.assign(a.href));
  });
}

// A module only so the unit tests can import it; the build wraps it as a classic script all the same.
export {};
