import { describe, expect, it } from "vitest";
import { Grid, walk } from "../../src/ascii/grid";
import { fromSvg, wrap } from "../../src/ascii/svg";
import { bigText } from "../../src/ascii";

const rows = (g: Grid): string[] => {
  const pre = document.createElement("pre");
  g.render(pre);
  return (pre.textContent ?? "").split("\n").slice(0, g.rows);
};

describe("ASCII mode: the character grid", () => {
  it("walks an orthogonal line and draws its corners and arrowhead", () => {
    const g = new Grid(6);
    g.path([[0, 0], [0, 3], [2, 3], [2, 5]], "x");
    expect(rows(g)).toEqual(["───┐  ", "   │  ", "   └─▶"]);
  });

  it("crossing lines make a ┼, and a line passes behind a zone's title", () => {
    const g = new Grid(5);
    g.path([[1, 0], [1, 4]], "x", false);
    g.path([[0, 2], [2, 2]], "x", false);
    expect(rows(g)[1]).toBe("──┼──");
    const z = new Grid(8);
    z.put(0, 1, " ZONE ", "z-t");
    z.path([[0, 0], [0, 7]], "x", false);
    expect(rows(z)[0]).toBe("─ ZONE ─");
  });

  it("walk keeps one cell per step and the direction each was entered by", () => {
    expect(walk([[0, 0], [0, 2], [1, 2]]).map(([r, c, dr, dc]) => `${r}${c}${dr}${dc}`)).toEqual(["0001", "0101", "0201", "1210"]);
  });

  it("boxes centre their words and cut what does not fit", () => {
    const g = new Grid(10);
    g.box("a", 0, 0, 10, 4, "b", ["Title", "a very long line"]);
    expect(rows(g)).toEqual(["┌────────┐", "│ Title  │", "│a very l│", "└────────┘"]);
    expect(g.boxAt(2, 5)?.id).toBe("a");
    expect(g.boxAt(5, 5)).toBeUndefined();
  });

  it("wraps words at the middle dots and spaces", () => {
    expect(wrap("Security Analytics · beacon monitor", 20)).toEqual(["Security Analytics ·", "beacon monitor"]);
    expect(wrap("short", 20)).toEqual(["short"]);
  });

  it("block letters: five rows, every row the same width", () => {
    const b = bigText("Lab 2");
    expect(b).toHaveLength(5);
    expect(new Set(b.map((l) => [...l].length)).size).toBe(1);
    expect(bigText("Jabłoński")).toEqual(bigText("JABLONSKI"));
  });
});

describe("ASCII mode: reading an SVG diagram", () => {
  const svg = (inner: string): SVGSVGElement => {
    const d = document.createElement("div");
    d.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 100">${inner}</svg>`;
    return d.querySelector("svg") as SVGSVGElement;
  };
  const two = svg(`
    <g class="ld-node ld-role--entry" data-node="a"><rect x="0" y="20" width="120" height="60"/><text>Visitor</text><text>browser</text></g>
    <g class="ld-node ld-role--detect" data-node="b"><rect x="280" y="20" width="120" height="60"/><text>Rules</text></g>
    <g class="ld-edge" data-edge="a-b"><path class="ld-line" d="M120,50 L280,50"/><path class="ld-glow" d="M120,50 L280,50"/></g>`);

  it("draws each node as a box with its words, coloured by its role", () => {
    const { g, nodes } = fromSvg(two, 80);
    expect([...g.boxes.keys()]).toEqual(["a", "b"]);
    expect(g.boxes.get("a")?.k).toBe("b-entry");
    expect(g.boxes.get("b")?.k).toBe("b-detect");
    expect(nodes.get("a")?.getAttribute("data-node")).toBe("a");
    const text = rows(g).join("\n");
    expect(text).toContain("Visitor");
    expect(text).toContain("browser");
  });

  it("one line per edge (not its glow), trimmed at both boxes, ending in an arrow into the target", () => {
    const { g, edges } = fromSvg(two, 80);
    expect(edges).toHaveLength(1);
    expect(edges[0].to).toBe("b");
    expect(edges[0].k).toBe("r-detect");
    const [r, c] = edges[0].cells[edges[0].cells.length - 1];
    expect(rows(g)[r][c]).toBe("▶");
    for (const [rr, cc] of edges[0].cells) expect(g.boxAt(rr, cc)).toBeUndefined();
  });

  it("never wider than asked", () => {
    expect(fromSvg(two, 30).g.w).toBeLessThanOrEqual(32);
  });
});
