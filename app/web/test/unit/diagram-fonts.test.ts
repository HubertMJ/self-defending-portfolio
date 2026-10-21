import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, test } from "vitest";

// src/diagram-fonts (the fonts every drawing sets its words in) and test/e2e/diagram-check.ts (what the
// drawings are measured against) are copied into every repository that serves a page of the site, as
// src/ascii is. This file is identical in each of them too: it pins the copies' fingerprint, and where
// another repository's checkout sits beside this one it compares the two byte for byte.

const root = resolve(__dirname, "..", "..");
const FILES = [
  "src/diagram-fonts/diagram-fonts.css",
  "src/diagram-fonts/LICENSE.txt",
  "src/diagram-fonts/labsans-bold.woff2",
  "src/diagram-fonts/labmono-regular.woff2",
  "src/diagram-fonts/labmono-bold.woff2",
  "test/e2e/diagram-check.ts",
];
const fingerprint = (base: string) => {
  const h = createHash("sha256");
  for (const f of FILES) h.update(`${f}\n`).update(readFileSync(join(base, f))).update("\n--\n");
  return h.digest("hex");
};
/** Change a file in one repository, copy it to the others, and update this line in each. */
const PINNED = "b17b37cfd57b62920f278556bcf9c708fb7d65887bef7dadb4c78490655fa0e2";

describe("the diagrams' fonts and their measure", () => {
  test("are the copies every repository carries", () => {
    expect(fingerprint(root)).toBe(PINNED);
  });

  test("match a sibling checkout's copies byte for byte, where one is beside this one", () => {
    const peers = ["site-ascii", "hubertjablon.ski", "work-mockups", "detlab-b4/web", "detection-lab/web", "sdp-labfix/app/web", "self-defending-portfolio/app/web"];
    const bases = [1, 2, 3].flatMap((up) => peers.map((peer) => resolve(root, ...Array(up).fill(".."), ...peer.split("/"))));
    for (const base of new Set(bases)) {
      if (base === root || !FILES.every((f) => existsSync(join(base, f)))) continue;
      for (const f of FILES) expect(readFileSync(join(base, f)).equals(readFileSync(join(root, f))), `${base}/${f}`).toBe(true);
    }
  });

  test("the stylesheet names the two families and points at files that are there", () => {
    const css = readFileSync(join(root, "src/diagram-fonts/diagram-fonts.css"), "utf8");
    for (const fam of ["LabDiagramSans", "LabDiagramMono"]) expect(css).toContain(`font-family: "${fam}"`);
    for (const [, url] of css.matchAll(/url\("\.\/([^"]+)"\)/g)) expect(existsSync(join(root, "src/diagram-fonts", url)), url).toBe(true);
    expect(css).toMatch(/--diagram-sans: "LabDiagramSans"/);
    expect(css).toMatch(/--diagram-mono: "LabDiagramMono"/);
  });
});
