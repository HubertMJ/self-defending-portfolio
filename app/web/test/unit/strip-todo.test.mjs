import { describe, expect, it } from "vitest";
import { stripTodoContent } from "../../scripts/strip-todo-content.mjs";

describe("stripTodoContent (FIX 2, ADR 0033 review item 25)", () => {
  it("removes an element that still holds a marker", () => {
    const out = stripTodoContent('<p class="todo-content" data-todo-content="x"><!-- TODO-CONTENT: note -->[TODO-CONTENT: intro]</p><footer>keep</footer>');
    expect(out).toBe("<footer>keep</footer>");
  });

  it("keeps a filled-in element, dropping its placeholder class, attribute and comment", () => {
    const out = stripTodoContent('<p class="hero__lead--sub todo-content" data-todo-content="hero-intro"><!-- TODO-CONTENT: note -->I build secure platforms.</p>');
    expect(out).toBe('<p class="hero__lead--sub">I build secure platforms.</p>');
  });

  it("drops an emptied class attribute entirely", () => {
    const out = stripTodoContent('<p class="todo-content" data-todo-content="x">Written.</p>');
    expect(out).toBe("<p>Written.</p>");
  });

  it("handles single-quoted and valueless attributes without looping", () => {
    // The data-todo-content attribute is dropped whatever its quoting; the element survives with content.
    const single = stripTodoContent("<span class=\"todo-content\" data-todo-content='c'>done</span>");
    expect(single).toContain("done");
    expect(single).not.toContain("data-todo-content");
    expect(single).not.toContain("todo-content");
    // A valueless attribute on a placeholder element: the element is removed.
    expect(stripTodoContent("<span data-todo-content>[TODO-CONTENT: x]</span>after")).toBe("after");
  });

  it("removes a section left with only its heading, and clears data-todo-section otherwise", () => {
    const empty = '<section data-todo-section><header><h2>Projects</h2></header><ul><li class="todo-content" data-todo-content="p"><h3>[TODO-CONTENT: name]</h3></li></ul></section><footer>f</footer>';
    expect(stripTodoContent(empty)).toBe("<footer>f</footer>");
    const kept = '<section data-todo-section=""><header><h2>Projects</h2></header><ul><li>real</li><li class="todo-content" data-todo-content="p">[TODO-CONTENT: name]</li></ul></section>';
    const out = stripTodoContent(kept);
    expect(out).toContain("<section>");
    expect(out).toContain("<li>real</li>");
    expect(out).not.toContain("data-todo-section");
    expect(out).not.toContain("TODO-CONTENT");
  });

  it("does not lose a written sibling paragraph when another is still a placeholder", () => {
    // Each paragraph carries its own marker, so only the unwritten one is removed.
    const html =
      '<div><p class="todo-content" data-todo-content="a">Written paragraph.</p><p class="todo-content" data-todo-content="b">[TODO-CONTENT: more]</p></div>';
    expect(stripTodoContent(html)).toBe("<div><p>Written paragraph.</p></div>");
  });

  it("fails loudly on an element it cannot balance, rather than shipping later placeholders", () => {
    // An unclosed element of the attribute's own tag cannot be balanced.
    expect(() => stripTodoContent('<div data-todo-content="x"><div>[TODO-CONTENT: a]</div>')).toThrow();
    expect(() => stripTodoContent('<div data-todo-content="x">[TODO-CONTENT: a]')).toThrow();
  });

  it("is a no-op when there is nothing to strip", () => {
    const html = '<main><h1>Hi</h1><p>All real content.</p></main>';
    expect(stripTodoContent(html)).toBe(html);
  });
});
