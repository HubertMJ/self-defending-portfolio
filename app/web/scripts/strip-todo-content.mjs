// Removes the owner's unwritten placeholder copy from the production build (FIX 2). The source keeps
// every `[TODO-CONTENT: …]` marker so `npm run todo-content` can list what is still to write and the
// dashed outline shows it while developing; the shipped page must never show a placeholder.
//
// The rule:
//   * an element carrying `data-todo-content` with nothing written in it — only `[TODO-CONTENT: …]`
//     markers, comments and separators — is removed whole;
//   * one the owner has partly written keeps what is written: each child element still holding a
//     marker is removed (the About block's second paragraph, a project card's tag line), and the rest
//     stays, cleaned like a fully written one;
//   * a fully written one stays, but loses its `todo-content` class, its `data-todo-content`
//     attribute and any leftover HTML comment;
//   * an element carrying `data-todo-section` that those removals left with nothing but its heading is
//     removed too (an About not yet written, a Projects section whose every card was a placeholder),
//     and so is the navigation link to it.
//
// Plain string surgery, no HTML parser (no dependency reaches the build, ADR 0019). It is strict, and
// throws — failing the build — rather than ship or silently drop anything it cannot handle: a tag it
// cannot balance, a marker in the same run of text as written copy, a written child that also holds
// a marker, a single-quoted `class='… todo-content'`, a link left pointing at a removed section, and
// any marker or `todo-content` class still in the output (one outside a marked element, say).

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

/** Whether text holds written copy: a letter or a digit once the markers are taken out. */
const written = (text) => /[\p{L}\p{N}]/u.test(text.replace(/\[TODO-CONTENT:[^\]]*\]/g, ""));

/** The direct child elements of an element (start, end), and its own text outside them. */
function childrenOf(el) {
  const open = el.indexOf(">") + 1;
  const close = el.lastIndexOf("</");
  const kids = [];
  let own = "";
  for (let i = open; i < close; ) {
    if (el.startsWith("<!--", i)) {
      const end = el.indexOf("-->", i);
      if (end === -1) throw new Error("strip-todo-content: unterminated comment");
      i = end + 3;
    } else if (/^<[a-zA-Z]/.test(el.slice(i, i + 2))) {
      const end = elementEnd(el, i);
      kids.push([i, end]);
      i = end;
    } else {
      own += el[i];
      i++;
    }
  }
  return { kids, own };
}

/** What a `data-todo-content` element becomes: "" (nothing written), or what is written, cleaned. */
function settle(el) {
  if (!PLACEHOLDER.test(textOf(el))) return cleanSurvivor(el);
  if (!written(textOf(el))) return "";
  const { kids, own } = childrenOf(el);
  if (PLACEHOLDER.test(own)) throw new Error(`strip-todo-content: written copy and a placeholder in the same text: ${el.slice(0, 120)}`);
  let out = el;
  for (const [start, end] of kids.reverse()) {
    const kid = el.slice(start, end);
    if (!PLACEHOLDER.test(textOf(kid))) continue;
    if (written(textOf(kid))) throw new Error(`strip-todo-content: written copy and a placeholder in one element: ${kid.slice(0, 120)}`);
    out = cut(out, start, end);
  }
  return cleanSurvivor(out);
}

/** Removes an element and the blank line it sat on, so the output has no orphaned whitespace. */
function cut(html, start, end) {
  let from = start;
  let to = end;
  while (from > 0 && (html[from - 1] === " " || html[from - 1] === "\t")) from--;
  // An element alone on its line takes the line with it; otherwise only its own indentation goes.
  if ((from === 0 || html[from - 1] === "\n") && html[to] === "\n") to++;
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
  const single = /\sclass\s*=\s*'[^']*\btodo-content\b/i.exec(html);
  if (single) throw new Error(`strip-todo-content: write the todo-content class in double quotes: ${single[0]}`);
  // Placeholder elements: removed when nothing is written, reduced to what is written otherwise.
  html = processAll(html, "data-todo-content", settle);
  // Sections left with nothing but a heading (its <header>…</header>): remove, with the navigation
  // link to it; otherwise drop the attribute.
  const removed = [];
  html = processAll(html, "data-todo-section", (el) => {
    const bodyEmpty = textOf(el.replace(/<header[\s\S]*?<\/header>/i, "")).trim() === "";
    if (!bodyEmpty) return el.replace(attrRe("data-todo-section"), "");
    const id = /^<[^>]*\sid\s*=\s*"([^"]+)"/.exec(el)?.[1];
    if (id) removed.push(id);
    return "";
  });
  for (const id of removed) {
    const esc = id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    let m;
    while ((m = new RegExp(`<li>\\s*<a href="#${esc}">[^<]*</a>\\s*</li>`).exec(html))) html = cut(html, m.index, m.index + m[0].length);
    if (html.includes(`href="#${id}"`)) throw new Error(`strip-todo-content: a link still points at the removed section #${id}`);
  }
  const left = /todo-content/i.exec(html);
  if (left) throw new Error(`strip-todo-content: a placeholder is left in the output: …${html.slice(Math.max(0, left.index - 80), left.index + 60)}…`);
  return html;
}
