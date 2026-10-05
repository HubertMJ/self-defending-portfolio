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
    expect(localStorage.getItem("collapsed:posture")).toBe("1");
    toggle("posture").click();
    expect(body("posture").hidden).toBe(false);
    expect(localStorage.getItem("collapsed:posture")).toBeNull();
    expect(changes).toEqual([
      ["posture", false],
      ["posture", true],
    ]);
  });

  it("a folded section stays folded on the next visit, and its panels are told at mount", () => {
    localStorage.setItem("collapsed:verify", "1");
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
    localStorage.setItem("collapsed:verify", "1");
    localStorage.setItem("collapsed:posture", "1");
    mountSections();
    (document.getElementById("to-panel") as HTMLAnchorElement).click();
    expect(body("verify").hidden).toBe(false);
    expect(toggle("verify").getAttribute("aria-expanded")).toBe("true");
    expect(localStorage.getItem("collapsed:verify")).toBeNull();
    (document.getElementById("to-posture") as HTMLAnchorElement).click();
    expect(body("posture").hidden).toBe(false);
  });

  it("a hash change and a page opened at a hash open the section they name", () => {
    localStorage.setItem("collapsed:attack", "1");
    localStorage.setItem("collapsed:verify", "1");
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
  });
});
