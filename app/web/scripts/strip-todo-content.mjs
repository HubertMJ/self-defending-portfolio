// Removes the owner's unwritten placeholder copy from the production build (FIX 2). The source keeps
// every `[TODO-CONTENT: …]` marker so `npm run todo-content` can list what is still to write and the
// dashed outline shows it while developing; the shipped page must never show a placeholder.
//
// The rule:
//   * every element carrying `data-todo-content` whose text still holds a `[TODO-CONTENT:` marker is
//     removed whole (it was never filled in);
//   * one whose text no longer holds a marker (the owner wrote real copy) stays, but loses its
//     `todo-content` class, its `data-todo-content` attribute and any leftover HTML comment, so no
//     placeholder styling or note ships;
//   * an element carrying `data-todo-section` that those removals left with nothing but its heading is
//     removed too (e.g. a Projects section whose every card was still a placeholder).
//
// Plain string surgery, no HTML parser (no dependency reaches the build, ADR 0019). The input is this
// repository's own `src/index.html`, whose structure is known; the matcher walks balanced tags of the
// one element it is removing and touches nothing else.

const VOID_TAGS = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"]);
const PLACEHOLDER = /\[TODO-CONTENT:/;

/** The end index (exclusive) of the element whose opening tag starts at `open`, matching nested tags. */
function elementEnd(html, open) {
  const nameMatch = /^<([a-zA-Z][\w-]*)/.exec(html.slice(open));
  if (!nameMatch) return -1;
  const tag = nameMatch[1].toLowerCase();
  const openTagEnd = html.indexOf(">", open);
  if (openTagEnd === -1) return -1;
  if (VOID_TAGS.has(tag) || html[openTagEnd - 1] === "/") return openTagEnd + 1;
  const re = new RegExp(`<${tag}(?=[\\s/>])|</${tag}\\s*>`, "gi");
  re.lastIndex = openTagEnd + 1;
  let depth = 1;
  for (let m; (m = re.exec(html)); ) {
    depth += m[0][1] === "/" ? -1 : 1;
    if (depth === 0) return m.index + m[0].length;
  }
  return -1;
}

/** Text content of an HTML fragment (tags and comments dropped): enough to test for a marker. */
function textOf(fragment) {
  return fragment.replace(/<!--[\s\S]*?-->/g, "").replace(/<[^>]*>/g, "");
}

/** Removes an element and the blank line it sat on, so the output has no orphaned whitespace. */
function cut(html, start, end) {
  let from = start;
  let to = end;
  while (from > 0 && (html[from - 1] === " " || html[from - 1] === "\t")) from--;
  if (html[to] === "\n") to++;
  if (from > 0 && html[from - 1] === "\n") from--;
  return html.slice(0, from) + html.slice(to);
}

/** Drops the `todo-content` class token, the `data-todo-content` attribute and inner comments. */
function cleanSurvivor(element) {
  return element
    .replace(/\sdata-todo-content="[^"]*"/i, "")
    .replace(/(\sclass="[^"]*?)\btodo-content\b\s?([^"]*")/i, (_, a, b) => `${a}${b}`.replace(/\s+"/, '"'))
    .replace(/<!--[\s\S]*?-->\s*/g, "");
}

function stripOnce(html, attr, shouldRemove, transform) {
  const re = new RegExp(`<[a-zA-Z][\\w-]*[^>]*\\s${attr}(?:=|[\\s>])`, "i");
  const m = re.exec(html);
  if (!m) return null;
  const start = m.index;
  const end = elementEnd(html, start);
  if (end === -1) return null;
  const element = html.slice(start, end);
  if (shouldRemove(element)) return cut(html, start, end);
  return html.slice(0, start) + transform(element) + html.slice(end);
}

export function stripTodoContent(html) {
  // Placeholder elements: remove or clean, one at a time until none is left (each pass rewrites one).
  for (let out = stripOnce(html, "data-todo-content", (el) => PLACEHOLDER.test(textOf(el)), cleanSurvivor); out !== null; out = stripOnce(html, "data-todo-content", (el) => PLACEHOLDER.test(textOf(el)), cleanSurvivor)) {
    html = out;
  }
  // Sections left with nothing but a heading: remove. A heading is the section's <header>…</header>.
  const isEmpty = (el) => textOf(el.replace(/<header[\s\S]*?<\/header>/i, "")).trim() === "";
  for (let out = stripOnce(html, "data-todo-section", isEmpty, (el) => el.replace(/\sdata-todo-section/i, "")); out !== null; out = stripOnce(html, "data-todo-section", isEmpty, (el) => el.replace(/\sdata-todo-section/i, ""))) {
    html = out;
  }
  return html;
}
