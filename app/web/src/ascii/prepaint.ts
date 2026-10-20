// The part of ASCII mode (index.ts) that runs before first paint, from the page's render-blocking
// script: a stored or linked choice applies at once, so the page never flashes its normal look first.

export const KEY = "ascii";

export function prepaintAscii(): void {
  const q = new URLSearchParams(location.search).get(KEY);
  let v: string | null = null;
  try {
    if (q === "1" || q === "0") localStorage.setItem(KEY, q);
    v = localStorage.getItem(KEY);
  } catch {
    v = q; // storage blocked: only a link turns it on, for this page view
  }
  if (v === "1") document.documentElement.classList.add("ascii");
}
