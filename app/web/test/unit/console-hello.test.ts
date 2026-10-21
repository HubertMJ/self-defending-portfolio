import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, test, vi } from "vitest";
import { banner, helloCalls, sayHello } from "../../src/console-hello";

// src/console-hello is one module copied into every repository that serves a page of the site (as
// src/ascii and src/node-panel are). This file is identical in each of them too: it pins the copies'
// fingerprint, and where another repository's checkout sits beside this one it compares the two.

const root = resolve(__dirname, "..", "..");
const FILES = ["index.ts"];
const fingerprint = (dir: string) => createHash("sha256").update(FILES.map((f) => `${f}\n${readFileSync(join(dir, f), "utf8")}`).join("\n--\n")).digest("hex");
/** Change the module in one repository, copy it to the others, and update this line in each. */
const PINNED = "c41575f370b81ba479902c0981a1d9180135cbf38675e47638040fd625895d5f";

describe("the shared module", () => {
  test("is the copy every repository carries", () => {
    expect(fingerprint(join(root, "src", "console-hello"))).toBe(PINNED);
  });

  test("matches a sibling checkout's copy byte for byte, where one is beside this one", () => {
    // The web apps sit at different depths of their repositories (detection-lab's in web/, the cluster
    // page's in app/web/), so the neighbours are looked for from a few levels up.
    const peers = ["site-ascii", "hubertjablon.ski", "work-mockups", "detlab-b4/web", "detection-lab/web", "sdp-labfix/app/web", "self-defending-portfolio/app/web"];
    const dirs = [1, 2, 3].flatMap((up) => peers.map((peer) => resolve(root, ...Array(up).fill(".."), ...peer.split("/"), "src", "console-hello")));
    for (const dir of new Set(dirs)) {
      if (dir === join(root, "src", "console-hello") || !existsSync(dir)) continue;
      for (const f of FILES) expect(readFileSync(join(dir, f), "utf8"), `${dir}/${f}`).toBe(readFileSync(join(root, "src", "console-hello", f), "utf8"));
    }
  });
});

describe("the greeting", () => {
  test("the site's name in block letters, five rows", () => {
    const rows = banner("hubertjablon.ski");
    expect(rows).toHaveLength(5);
    expect(rows.every((r) => /^[█ ]+$/.test(r))).toBe(true);
  });

  test("every %c has its style; the lines say what they should, in 10 to 15 lines in all", () => {
    const calls = helloCalls({ repo: "work-mockups" }, "0123456789abcdef");
    for (const [format, ...styles] of calls) expect(format.split("%c").length - 1, format).toBe(styles.length);
    const all = calls.map((c) => c[0]).join("\n");
    expect(all).toContain("You opened the console, so you are my kind of visitor.");
    expect(all).toContain("%cascii%c");
    expect(all).toContain("?ascii=1");
    expect(all).toContain("https://github.com/HubertMJ/work-mockups");
    expect(all).toContain("Built from commit 0123456.");
    expect(all.split("\n").length).toBeGreaterThanOrEqual(10);
    expect(all.split("\n").length).toBeLessThanOrEqual(15);
    // The mark is a picture the console paints from a data: URL; the banner has its own dark ground.
    expect(calls[0][1]).toMatch(/background: url\("data:image\/svg\+xml,/);
    expect(calls[1][1]).toMatch(/background: #0c0e12/);
    expect(helloCalls({}).map((c) => c[0]).join("\n")).not.toContain("Built from");
  });

  afterEach(() => {
    delete (window as unknown as Record<string, unknown>).__hubertjablonskiHello;
    vi.restoreAllMocks();
  });

  test("prints once per page load, never under automation, and never throws", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    sayHello({ repo: "x" });
    const n = log.mock.calls.length;
    expect(n).toBe(helloCalls({ repo: "x" }).length);
    sayHello({ repo: "x" });
    expect(log.mock.calls.length).toBe(n);
    delete (window as unknown as Record<string, unknown>).__hubertjablonskiHello;
    Object.defineProperty(navigator, "webdriver", { configurable: true, get: () => true });
    sayHello();
    expect(log.mock.calls.length).toBe(n);
    delete (navigator as unknown as Record<string, unknown>).webdriver;
    vi.restoreAllMocks();
    vi.spyOn(console, "log").mockImplementation(() => {
      throw new Error("no console");
    });
    expect(() => sayHello()).not.toThrow();
  });
});
