import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { stripTodoContent } from "../../scripts/strip-todo-content.mjs";

// The page itself, as the production build gets it.
const page = readFileSync(join(process.cwd(), "src", "index.html"), "utf8");

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

  it("fails on a marker in the same text as written copy, and on a written child that holds one", () => {
    expect(() => stripTodoContent('<p class="todo-content" data-todo-content="x">I build platforms. [TODO-CONTENT: more]</p>')).toThrow(/same text/);
    expect(() => stripTodoContent('<div class="todo-content" data-todo-content="x"><p>Written.</p><p>Also written [TODO-CONTENT: more]</p></div>')).toThrow(/one element/);
  });

  it("fails on a single-quoted todo-content class and on a marker outside any marked element", () => {
    expect(() => stripTodoContent("<p class='todo-content' data-todo-content=\"x\">Written.</p>")).toThrow(/double quotes/);
    expect(() => stripTodoContent("<main><p>Hello [TODO-CONTENT: stray]</p></main>")).toThrow(/left in the output/);
    expect(() => stripTodoContent("<main><!-- TODO-CONTENT: a note --><p>Hi</p></main>")).toThrow(/left in the output/);
  });

  it("fails rather than leave a link to a section it removed", () => {
    const html = '<a href="#about">read about me</a><section id="about" data-todo-section><header><h2>About</h2></header><p class="todo-content" data-todo-content="a">[TODO-CONTENT: x]</p></section>';
    expect(() => stripTodoContent(html)).toThrow(/#about/);
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

describe("stripTodoContent on src/index.html (review 2, item 9)", () => {
  const sectionIds = (html) => [...html.matchAll(/<section[^>]*\sid="([^"]+)"/g)].map((m) => m[1]);
  const navLinks = (html) => [...html.matchAll(/<nav[\s\S]*?<\/nav>/g)].flatMap((n) => [...n[0].matchAll(/href="#([^"]+)"/g)].map((m) => m[1]));

  it("ships no placeholder, and no About section or About link while nothing of it is written", () => {
    const out = stripTodoContent(page);
    expect(out).not.toMatch(/todo-content/i);
    expect(sectionIds(out)).not.toContain("about");
    expect(navLinks(out)).not.toContain("about");
    // Everything else stays: the sections, the skills list, the real project card, every other link.
    // ADR 0035: the evidence and the verify panel come right after the hero, before the posture.
    expect(sectionIds(out)).toEqual(["top", "evidence", "verify", "posture", "attack", "console", "how", "skills", "projects"]);
    expect(navLinks(out)).toEqual(["posture", "attack", "how"]);
    expect(out).toContain("<li>Kubernetes (k3s)</li>");
    expect(out).toContain("self-defending-portfolio</a></h3>");
    expect(out).not.toContain("[TODO");
  });

  it("keeps a written About paragraph when the other is still a placeholder, and the section with its link", () => {
    const out = stripTodoContent(page.replace("<p>[TODO-CONTENT: background and current focus]</p>", "<p>I build and harden platforms.</p>"));
    expect(out).toContain("<p>I build and harden platforms.</p>");
    expect(out).not.toContain("what kind of work or role");
    expect(sectionIds(out)).toContain("about");
    expect(navLinks(out)).toContain("about");
    expect(out).not.toMatch(/todo-content/i);
  });

  it("keeps a project card's written lines and drops its unwritten tag line", () => {
    const out = stripTodoContent(
      page.replace("<h3>[TODO-CONTENT: project name]</h3>\n          <p>[TODO-CONTENT: what it does and what you did]</p>", "<h3>edge-proxy</h3>\n          <p>A proxy I wrote.</p>"),
    );
    expect(out).toContain("<h3>edge-proxy</h3>");
    expect(out).toContain("<p>A proxy I wrote.</p>");
    expect(out).not.toMatch(/todo-content|TODO-CONTENT/i);
  });
});

describe("stripTodoContent, two unwritten children of one written element (final review, item 5)", () => {
  it("removes both and keeps the written one", () => {
    const html = '<div class="todo-content" data-todo-content="x"><p>[TODO-CONTENT: a]</p><p>Written.</p><p>[TODO-CONTENT: b]</p></div>';
    expect(stripTodoContent(html)).toBe("<div><p>Written.</p></div>");
  });
});
