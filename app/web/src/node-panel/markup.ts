// The node panel's markup (src/node-panel): one slot under a diagram, holding every node's details at
// once, stacked in a single grid cell. The slot is as tall as its tallest entry from the first paint,
// whichever entry shows and whether any does, so opening, swapping and closing never move the page.
// Strings for the build script, which writes the slot into the page beside the drawings.
//
// The same directory is copied into every repository that serves a page of the site (as src/ascii is);
// test/unit/node-panel.test.ts checks the copies agree.

export interface PanelItem {
  /** The node's data-node id. */
  id: string;
  title: string;
  sub?: string;
  /** What ASCII mode's popup says (data-tip), or more. */
  text: string;
  /** The node's colour (the panel's accent): path, site, project, lab, work, or the lab's entry,
   * attack, detect, record, neutral. */
  role: string;
  /** Where the node's box leads, for the panel's "Open →" (a tap shows the details first). */
  href?: string;
  /** Links under the text, after `linksLead` ("On GitHub: "): where the part lives. */
  links?: { href: string; label: string }[];
  linksLead?: string;
}

const ESC: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ESC[c]);

/** The slot for one figure's diagram; `key` keeps its ids apart from another figure's on the page. */
export function panelMarkup(key: string, items: PanelItem[]): string {
  const entries = items.map(
    (it) =>
      `<div class="np-item" data-for="${esc(it.id)}" data-role="${esc(it.role)}" data-on="false" aria-hidden="true">` +
      `<p class="np-title">${esc(it.title)}${it.sub ? ` <span class="np-sub">${esc(it.sub)}</span>` : ""}</p>` +
      `<p class="np-text">${esc(it.text)}</p>` +
      (it.links?.length
        ? `<p class="np-links">${esc(it.linksLead ?? "")}${it.links.map((l) => `<a href="${esc(l.href)}" rel="noopener noreferrer" tabindex="-1"><code>${esc(l.label)}</code></a>`).join(", ")}</p>`
        : "") +
      (it.href ? `<p class="np-more"><a class="np-open" href="${esc(it.href)}" tabindex="-1">Open →</a></p>` : "") +
      `</div>`,
  );
  return (
    `<div class="np-slot" id="np-${esc(key)}">` +
    `<div class="np-panel" data-open="false">` +
    `<button type="button" class="np-close" aria-label="Close the details" tabindex="-1">×</button>` +
    entries.join("") +
    `<p class="np-live" aria-live="polite"></p>` +
    `</div></div>`
  );
}
