import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Posture } from "../../src/lib/contract";
import { h } from "../../src/lib/dom";
import { posture } from "../../src/lib/fixtures";
import { mountPosture } from "../../src/ui/posture";
import { mountSections, sectionTitle } from "../../src/ui/sections";

// ADR 0035, amended 2026-10-05: every section below the hero folds under its heading, the choice is
// kept per section, a link into a folded section opens it, and a folded section's panels stop drawing.

/** A page shaped like src/index.html: the hero, then sections with a head and a body. */
function page(): void {
  const section = (id: string, title: string, ...body: Node[]) =>
    h(
      "section",
      { class: "section", id, "aria-labelledby": `${id}-title` },
      h(
        "div",
        { class: "wrap" },
        h("header", { class: "section__head" }, h("p", { class: "eyebrow" }, id), h("h2", { id: `${id}-title` }, title), h("p", { class: "section__lead" }, "lead")),
        h("div", { class: "section__body", id: `${id}-body` }, ...body),
      ),
    );
  document.body.replaceChildren(
    h(
      "main",
      { id: "main" },
      h("section", { class: "hero", id: "top" }, h("h1", {}, "Hubert"), h("a", { href: "#verify-panel", id: "to-panel" }, "panel"), h("a", { href: "#posture", id: "to-posture" }, "posture")),
      section("attack", "Your hands on the pod", h("p", {}, "terminal")),
      section("posture", "Live security posture", h("div", { id: "posture-panel" })),
      section("verify", "Verify it yourself", h("div", { id: "verify-panel" })),
    ),
  );
}

const toggle = (id: string) => document.querySelector(`#${id}-title button`) as HTMLButtonElement;
const body = (id: string) => document.getElementById(`${id}-body`) as HTMLElement;

describe("mountSections", () => {
  beforeEach(() => {
    localStorage.clear();
    history.replaceState(null, "", "/");
    // jsdom has no layout: scrolling is only recorded.
    Element.prototype.scrollIntoView = vi.fn();
    page();
  });
  afterEach(() => vi.restoreAllMocks());

  it("turns each section's h2 into a disclosure button, open by default; the hero has none", () => {
    mountSections();
    const btn = toggle("posture");
    expect(btn.type).toBe("button");
    expect(btn.getAttribute("aria-expanded")).toBe("true");
    expect(btn.getAttribute("aria-controls")).toBe("posture-body");
    expect(btn.querySelector(".section__chevron")?.getAttribute("aria-hidden")).toBe("true");
    // The heading keeps its id (the section's aria-labelledby) and its text, now the button's name.
    expect(document.getElementById("posture-title")?.textContent).toBe("Live security posture");
    expect(sectionTitle(document.getElementById("posture-title") as HTMLElement).textContent).toBe("Live security posture");
    expect(body("posture").hidden).toBe(false);
    expect(document.querySelectorAll(".section__toggle")).toHaveLength(3);
    expect(document.querySelector("#top button")).toBeNull();
  });

  it("a click folds the body, flips aria-expanded, reports the change and keeps the choice per section", () => {
    const changes: [string, boolean][] = [];
    mountSections((id, open) => changes.push([id, open]));
    toggle("posture").click();
    expect(toggle("posture").getAttribute("aria-expanded")).toBe("false");
    expect(body("posture").hidden).toBe(true);
    expect(document.getElementById("posture")?.classList.contains("section--collapsed")).toBe(true);
    expect(body("attack").hidden).toBe(false);
    expect(localStorage.getItem("sdp:collapsed:posture")).toBe("1");
    toggle("posture").click();
    expect(body("posture").hidden).toBe(false);
    expect(localStorage.getItem("sdp:collapsed:posture")).toBeNull();
    expect(changes).toEqual([
      ["posture", false],
      ["posture", true],
    ]);
  });

  it("a folded section stays folded on the next visit, and its panels are told at mount", () => {
    localStorage.setItem("sdp:collapsed:verify", "1");
    const changes: [string, boolean][] = [];
    mountSections((id, open) => changes.push([id, open]));
    expect(toggle("verify").getAttribute("aria-expanded")).toBe("false");
    expect(body("verify").hidden).toBe(true);
    expect(body("posture").hidden).toBe(false);
    expect(changes).toEqual([["verify", false]]);
  });

  it("works, unremembered, when storage throws", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("SecurityError");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("QuotaExceededError");
    });
    expect(() => mountSections()).not.toThrow();
    expect(() => toggle("attack").click()).not.toThrow();
    expect(body("attack").hidden).toBe(true);
  });

  it("a link to a folded section, or to anything inside one, opens it first", () => {
    localStorage.setItem("sdp:collapsed:verify", "1");
    localStorage.setItem("sdp:collapsed:posture", "1");
    mountSections();
    (document.getElementById("to-panel") as HTMLAnchorElement).click();
    expect(body("verify").hidden).toBe(false);
    expect(toggle("verify").getAttribute("aria-expanded")).toBe("true");
    expect(localStorage.getItem("sdp:collapsed:verify")).toBeNull();
    (document.getElementById("to-posture") as HTMLAnchorElement).click();
    expect(body("posture").hidden).toBe(false);
  });

  it("a modified, non-primary or already handled click on a link opens nothing", () => {
    localStorage.setItem("sdp:collapsed:verify", "1");
    mountSections();
    const link = document.getElementById("to-panel") as HTMLAnchorElement;
    for (const init of [{ ctrlKey: true }, { metaKey: true }, { shiftKey: true }, { altKey: true }, { button: 1 }]) {
      link.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, ...init }));
      expect(body("verify").hidden).toBe(true);
    }
    const handled = (e: Event) => e.preventDefault();
    document.getElementById("top")?.addEventListener("click", handled);
    link.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
    expect(body("verify").hidden).toBe(true);
    document.getElementById("top")?.removeEventListener("click", handled);
    link.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
    expect(body("verify").hidden).toBe(false);
  });

  it("drops theme.ts's pre-paint stand-in once the sections are folded by their buttons", () => {
    localStorage.setItem("sdp:collapsed:posture", "1");
    document.documentElement.dataset.folded = "posture";
    mountSections();
    expect(document.documentElement.dataset.folded).toBeUndefined();
    expect(body("posture").hidden).toBe(true);
    toggle("posture").click();
    expect(body("posture").hidden).toBe(false);
  });

  it("on a reload the browser's own scroll position stands: no jump to the hash unless a folded section was opened", () => {
    localStorage.setItem("sdp:collapsed:attack", "1");
    history.replaceState(null, "", "/#verify-panel");
    vi.spyOn(performance, "getEntriesByType").mockReturnValue([{ type: "reload" } as unknown as PerformanceEntry]);
    mountSections();
    expect(Element.prototype.scrollIntoView).not.toHaveBeenCalled();
    page();
    localStorage.setItem("sdp:collapsed:verify", "1");
    mountSections();
    expect(body("verify").hidden).toBe(false);
    expect(Element.prototype.scrollIntoView).toHaveBeenCalledTimes(1);
  });

  it("a hash change and a page opened at a hash open the section they name", () => {
    localStorage.setItem("sdp:collapsed:attack", "1");
    localStorage.setItem("sdp:collapsed:verify", "1");
    history.replaceState(null, "", "/#attack");
    mountSections();
    expect(body("attack").hidden).toBe(false);
    expect(Element.prototype.scrollIntoView).toHaveBeenCalled();
    expect(body("verify").hidden).toBe(true);
    history.replaceState(null, "", "/#verify-panel");
    window.dispatchEvent(new HashChangeEvent("hashchange"));
    expect(body("verify").hidden).toBe(false);
  });
});

describe("folded at first paint (theme.ts, styles.css)", () => {
  afterEach(() => {
    localStorage.clear();
    delete document.documentElement.dataset.folded;
  });

  it("theme.ts names the stored folded sections in html[data-folded], and nothing else", async () => {
    localStorage.setItem("sdp:collapsed:posture", "1");
    localStorage.setItem("sdp:collapsed:verify", "1");
    localStorage.setItem("sdp:collapsed:how", "0");
    localStorage.setItem("sdp:collapsed:Bad Id", "1");
    localStorage.setItem("collapsed:skills", "1");
    vi.resetModules();
    await import("../../src/theme");
    expect((document.documentElement.dataset.folded ?? "").split(" ").sort()).toEqual(["posture", "verify"]);
  });

  it("sets nothing with no section folded, and survives storage that throws", async () => {
    vi.resetModules();
    await import("../../src/theme");
    expect(document.documentElement.dataset.folded).toBeUndefined();
    vi.spyOn(Storage.prototype, "key").mockImplementation(() => {
      throw new Error("SecurityError");
    });
    vi.resetModules();
    await expect(import("../../src/theme")).resolves.toBeDefined();
    vi.restoreAllMocks();
  });

  it("the stylesheet's stand-in covers every foldable section of index.html", () => {
    const html = readFileSync(join(process.cwd(), "src", "index.html"), "utf8");
    const css = readFileSync(join(process.cwd(), "src", "styles.css"), "utf8");
    const ids = [...html.matchAll(/<section class="section[ "][^>]*\sid="([^"]+)"/g)].map((m) => m[1]);
    expect(ids.length).toBe(9);
    for (const id of ids) expect(css.split(`html[data-folded~="${id}"] #${id}`).length - 1, id).toBe(3);
  });
});

describe("a folded section's panels stop drawing", () => {
  afterEach(() => vi.useRealTimers());

  it("posture: fetched and passed on while folded, drawn only once unfolded", async () => {
    vi.useFakeTimers();
    const root = document.createElement("div");
    const seen: Posture[] = [];
    const value = posture();
    const handle = mountPosture(root, { posture: async () => ({ ok: true as const, value }) } as never, (p) => seen.push(p));
    handle.setActive(false);
    await vi.advanceTimersByTimeAsync(0);
    expect(seen).toHaveLength(1);
    expect(root.dataset.state).toBe("live");
    expect(root.querySelector(".tile")).toBeNull();
    handle.setActive(true);
    expect(root.querySelector(".tile")).not.toBeNull();
    // Drawn with its live region off: unfolding does not read the whole panel aloud; then polite again.
    expect(root.getAttribute("aria-live")).toBe("off");
    await vi.advanceTimersByTimeAsync(300);
    expect(root.getAttribute("aria-live")).toBe("polite");
  });
});
