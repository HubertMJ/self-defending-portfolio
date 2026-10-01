// Loaded as a classic, render-blocking script in <head> so a stored theme choice applies before
// first paint. Kept to a few lines on purpose: everything else waits for the deferred module.
try {
  const t = localStorage.getItem("theme");
  if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
} catch {
  // Storage blocked (private mode, sandboxed preview): the OS preference applies.
}
