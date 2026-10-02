// Removes the owner's unwritten placeholder copy from the production build (FIX 2). The source keeps
// every `[TODO-CONTENT: …]` marker so `npm run todo-content` can list what is still to write and the
// dashed outline shows it while developing; the shipped page must never show a placeholder.
//
// The rule:
//   * every element carrying `data-todo-content` whose text still holds a `[TODO-CONTENT:` marker is
//     removed whole (it was never filled in);
//   * one whose text no longer holds a marker (the owner wrote real copy) stays, but loses its
//     `todo-content` class, its `data-todo-content` attribute and any leftover HTML comment;
//   * an element carrying `data-todo-section` that those removals left with nothing but its heading is
//     removed too (e.g. a Projects section whose every card was still a placeholder).
//
// Plain string surgery, no HTML parser (no dependency reaches the build, ADR 0019). It is strict: if
// it meets a tag it cannot balance (an unclosed element, a stray closing tag) it throws, so the build
// fails loudly rather than silently shipping whatever placeholders came after the point it gave up.

const VOID_TAGS = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"]);
const PLACEHOLDER = /\[TODO-CONTENT:/;
// Matches an attribute with a double-quoted, single-quoted, unquoted or absent value.
const attrRe = (name) => new RegExp(`\\s${name}(?:\\s*=\\s*(?:"[^"]*"|'[^']*'|[^\\s"'>]+))?`, "i");

/** The end index (exclusive) of the element whose opening tag starts at `open`. Throws if unbalanced. */
function elementEnd(html, open) {
  const nameMatch = /^<([a-zA-Z][\w-]*)/.exec(html.slice(open));
  if (!nameMatch) throw new Error(`strip-todo-content: not an element start at index ${open}`);
  const tag = nameMatch[1].toLowerCase();
  const openTagEnd = html.indexOf(">", open);
  if (openTagEnd === -1) throw new Error(`strip-todo-content: unterminated <${tag}> tag`);
  if (VOID_TAGS.has(tag) || html[openTagEnd - 1] === "/") return openTagEnd + 1;
  // Walk forward, skipping comments, counting only this tag's own open/close tags.
  const re = new RegExp(`<!--|<${tag}(?=[\\s/>])|</${tag}\\s*>`, "gi");
  re.lastIndex = openTagEnd + 1;
  let depth = 1;
  for (let m; (m = re.exec(html)); ) {
    if (m[0] === "<!--") {
      const close = html.indexOf("-->", re.lastIndex);
      if (close === -1) throw new Error("strip-todo-content: unterminated comment");
      re.lastIndex = close + 3;
      continue;
    }
    depth += m[0][1] === "/" ? -1 : 1;
    if (depth === 0) return m.index + m[0].length;
  }
  throw new Error(`strip-todo-content: <${tag}> at index ${open} is never closed`);
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
    .replace(attrRe("data-todo-content"), "")
    .replace(/(\sclass\s*=\s*"[^"]*?)\btodo-content\b\s?([^"]*")/i, (_, a, b) => `${a}${b}`.replace(/\s+"/, '"'))
    // A class that held only `todo-content` is now empty: drop the attribute entirely.
    .replace(/\sclass\s*=\s*"\s*"/i, "")
    .replace(/<!--[\s\S]*?-->\s*/g, "");
}

/**
 * Applies `handle` to each element carrying `attr`, left to right. `handle(element)` returns the
 * element's replacement text (possibly ""), which must no longer carry `attr` so the scan advances.
 */
function processAll(html, name, handle) {
  const find = attrRe(name);
  let from = 0;
  for (;;) {
    const rest = html.slice(from);
    const m = find.exec(rest);
    if (!m) return html;
    // Back up to the start of the tag that holds the attribute.
    const attrAt = from + m.index;
    const start = html.lastIndexOf("<", attrAt);
    if (start === -1) throw new Error(`strip-todo-content: ${name} outside any tag`);
    const end = elementEnd(html, start);
    const replacement = handle(html.slice(start, end));
    if (new RegExp(`\\s${name}\\b`, "i").test(replacement)) {
      throw new Error(`strip-todo-content: ${name} not cleared by handler`);
    }
    if (replacement === "") {
      html = cut(html, start, end);
      from = Math.max(0, start - 1);
    } else {
      html = html.slice(0, start) + replacement + html.slice(end);
      from = start + replacement.length;
    }
  }
}

export function stripTodoContent(html) {
  // Placeholder elements: remove the ones that still hold a marker, clean the ones the owner filled in.
  html = processAll(html, "data-todo-content", (el) => (PLACEHOLDER.test(textOf(el)) ? "" : cleanSurvivor(el)));
  // Sections left with nothing but a heading (its <header>…</header>): remove; otherwise drop the attr.
  html = processAll(html, "data-todo-section", (el) => {
    const bodyEmpty = textOf(el.replace(/<header[\s\S]*?<\/header>/i, "")).trim() === "";
    return bodyEmpty ? "" : el.replace(attrRe("data-todo-section"), "");
  });
  return html;
}
