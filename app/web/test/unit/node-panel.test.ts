import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, test } from "vitest";
import { mountNodePanels } from "../../src/node-panel";
import { panelMarkup } from "../../src/node-panel/markup";

// src/node-panel is one module copied into every repository that serves a page of the site (as
// src/ascii is). This file is identical in each of them too: it pins the copies' fingerprint, and where
// another repository's checkout sits beside this one it compares the two byte for byte.

const root = resolve(__dirname, "..", "..");
const FILES = ["index.ts", "markup.ts", "node-panel.css"];
const fingerprint = (dir: string) => createHash("sha256").update(FILES.map((f) => `${f}\n${readFileSync(join(dir, f), "utf8")}`).join("\n--\n")).digest("hex");
/** Change the module in one repository, copy it to the others, and update this line in each. */
const PINNED = "acbbe8acff4d5335bb0634f54058572cb48be591d32fc61410625a1f0aa0d9eb";

describe("the shared module", () => {
  test("is the copy every repository carries", () => {
    expect(fingerprint(join(root, "src", "node-panel"))).toBe(PINNED);
  });

  test("matches a sibling checkout's copy byte for byte, where one is beside this one", () => {
    // The web apps sit at different depths of their repositories (detection-lab's in web/), so the
    // neighbours are looked for from a few levels up.
    const peers = ["site-ascii", "hubertjablon.ski", "work-mockups", "detlab-b4/web", "detection-lab/web", "sdp-labfix/app/web", "self-defending-portfolio/app/web"];
    const dirs = [1, 2, 3].flatMap((up) => peers.map((peer) => resolve(root, ...Array(up).fill(".."), ...peer.split("/"), "src", "node-panel")));
    for (const dir of new Set(dirs)) {
      if (dir === join(root, "src", "node-panel") || !existsSync(dir)) continue;
      for (const f of FILES) expect(readFileSync(join(dir, f), "utf8"), `${dir}/${f}`).toBe(readFileSync(join(root, "src", "node-panel", f), "utf8"));
    }
  });
});

describe("the panel", () => {
  const items = [
    { id: "a", title: "Box <A>", sub: "sub", text: 'Says "hello" & more.', role: "path" },
    { id: "b", title: "Box B", text: "Leads somewhere.", role: "lab", href: "/b/" },
  ];
  const page = () => {
    document.body.replaceChildren();
    const fig = document.createElement("figure");
    const NS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(NS, "svg");
    const g = document.createElementNS(NS, "g");
    g.setAttribute("data-node", "a");
    g.append(document.createElementNS(NS, "rect"));
    const a = document.createElementNS(NS, "a");
    a.setAttribute("href", "/b/");
    a.setAttribute("data-node", "b");
    a.append(document.createElementNS(NS, "rect"));
    svg.append(g, a);
    fig.append(svg);
    fig.insertAdjacentHTML("beforeend", panelMarkup("t", items));
    document.body.append(fig);
    mountNodePanels();
    const panel = fig.querySelector<HTMLElement>(".np-panel")!;
    const on = () => [...fig.querySelectorAll<HTMLElement>(".np-item")].filter((i) => i.dataset.on === "true").map((i) => i.dataset.for);
    return { fig, g, a, panel, on };
  };
  const pointer = (type: string, pointerType: string) => Object.assign(new Event(type, { bubbles: true, cancelable: true }), { pointerType });

  test("holds every entry from the start, escaped, closed", () => {
    const html = panelMarkup("t", items);
    expect(html).toContain("Box &lt;A&gt;");
    expect(html).toContain("Says &quot;hello&quot; &amp; more.");
    expect(html.match(/class="np-item"/g)).toHaveLength(2);
    expect(html).toContain('<a class="np-open" href="/b/" tabindex="-1">Open →</a>');
    expect(html).toContain('aria-live="polite"');
    const linked = panelMarkup("t", [{ id: "c", title: "C", text: "t", role: "record", links: [{ href: "https://example.org/a", label: "repo/a" }], linksLead: "On GitHub: " }]);
    expect(linked).toContain('<p class="np-links">On GitHub: <a href="https://example.org/a" rel="noopener noreferrer" tabindex="-1"><code>repo/a</code></a></p>');
    const { panel, on } = page();
    expect(panel.dataset.open).toBe("false");
    expect(on()).toEqual([]);
  });

  test("a box that is not a link becomes a button; focus or Enter shows its entry, Escape closes", () => {
    const { g, panel, on, fig } = page();
    expect(g.getAttribute("role")).toBe("button");
    expect(g.getAttribute("tabindex")).toBe("0");
    g.dispatchEvent(new Event("focus"));
    expect(panel.dataset.open).toBe("true");
    expect(on()).toEqual(["a"]);
    expect(panel.dataset.role).toBe("path");
    expect(fig.querySelector(".np-live")?.textContent).toBe('Box <A> sub: Says "hello" & more.');
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    expect(panel.dataset.open).toBe("false");
    g.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    expect(on()).toEqual(["a"]);
  });

  test("a mouse's hover shows an entry and moving on swaps it; leaving keeps it; × closes", () => {
    const { g, a, panel, on, fig } = page();
    g.dispatchEvent(pointer("pointerenter", "mouse"));
    a.dispatchEvent(pointer("pointerenter", "mouse"));
    expect(on()).toEqual(["b"]);
    expect(panel.dataset.role).toBe("lab");
    a.dispatchEvent(pointer("pointerleave", "mouse"));
    expect(on()).toEqual(["b"]);
    fig.querySelector<HTMLButtonElement>(".np-close")!.click();
    expect(panel.dataset.open).toBe("false");
  });

  test("a link opens on a mouse's click, but a tap shows its details first", () => {
    const { a, on } = page();
    const click = () => {
      const e = new MouseEvent("click", { bubbles: true, cancelable: true });
      a.dispatchEvent(e);
      return e.defaultPrevented;
    };
    a.dispatchEvent(pointer("pointerdown", "touch"));
    expect(click()).toBe(true);
    expect(on()).toEqual(["b"]);
    a.dispatchEvent(pointer("pointerdown", "touch"));
    expect(click()).toBe(false);
    a.dispatchEvent(pointer("pointerdown", "mouse"));
    expect(click()).toBe(false);
  });
});
