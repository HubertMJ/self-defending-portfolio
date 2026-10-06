// Loaded as a classic, render-blocking script in <head> so a stored theme choice applies before
// first paint. Kept to a few lines on purpose: everything else waits for the deferred module.
try {
  const t = localStorage.getItem("theme");
  if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
  // Technical Mode (ui/tech.ts), applied here for the same reason: no layout jump on load.
  if (localStorage.getItem("tech") === "on") document.documentElement.dataset.tech = "on";
  // Folded sections (ui/sections.ts, same "sdp:collapsed:<id>" keys), named for styles.css so a folded
  // section is folded at first paint; sections.ts drops the attribute once its buttons are in place.
  const folded: string[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const id = /^sdp:collapsed:([a-z-]+)$/.exec(localStorage.key(i) ?? "")?.[1];
    if (id && localStorage.getItem(`sdp:collapsed:${id}`) === "1") folded.push(id);
  }
  if (folded.length) document.documentElement.dataset.folded = folded.join(" ");
} catch {
  // Storage blocked (private mode, sandboxed preview): the OS preference applies.
}

// A module only so the unit tests can import it; the build wraps it as a classic script all the same.
export {};
