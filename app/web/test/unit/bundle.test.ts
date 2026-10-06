import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { FIXTURE_MARKER } from "../../src/lib/fixtures";
import { MOCK_MARKER } from "../../src/lib/mock";

// The mock is dev/test only (ADR 0035): the production bundle must not contain it, and the grep that
// says so must be able to see it — so the same markers are looked for in a --mock build too, where
// every one of them has to be present.
const MARKERS = ["sdpMock", "mock-speed", "mock-stream-refuse", MOCK_MARKER, FIXTURE_MARKER];

const build = (dir: string, ...flags: string[]) => {
  execFileSync(process.execPath, ["scripts/build.mjs", "--outdir", dir, ...flags], { cwd: process.cwd(), stdio: "pipe" });
  const main = readdirSync(join(dir, "assets")).find((f) => /^main-.*\.js$/.test(f));
  if (!main) throw new Error(`no main-*.js in ${dir}`);
  return { js: readFileSync(join(dir, "assets", main), "utf8"), html: readFileSync(join(dir, "index.html"), "utf8") };
};

/** Every file of a build, as text: JS, CSS, HTML and the copied static files. */
const tree = (dir: string): { file: string; text: string }[] =>
  readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? tree(p) : [{ file: p.slice(dir.length), text: readFileSync(p, "utf8") }];
  });

// Nothing of the mock anywhere in dist/: the banner (markup, styles, the script that moves it), the
// two data markers, and the words the page uses only for the mock.
// (esbuild writes the "·" of the header's "mock ·" as \xB7.)
// The correlation fixture (src/lib/correlation-fixture.json, ADR 0036) carries no marker of its own:
// its first incident's id and first rule's Sigma id stand for it, values nothing real would carry.
const CORRELATION_FIXTURE = JSON.parse(readFileSync(join(process.cwd(), "src/lib/correlation-fixture.json"), "utf8"));
const CORRELATION_MARKERS: string[] = [CORRELATION_FIXTURE.correlation.incidents[0].id, CORRELATION_FIXTURE.rules.rules[0].id];
const TREE_MARKERS: (string | RegExp)[] = ["mock-banner", MOCK_MARKER, FIXTURE_MARKER, /mock (·|\\xB7)/, "Mock data", ...CORRELATION_MARKERS];
const has = (text: string, m: string | RegExp) => (typeof m === "string" ? text.includes(m) : m.test(text));

describe("the production bundle has no mock (ADR 0035)", () => {
  let tmp: string;
  let prod: { js: string; html: string };
  let prodDir: string;
  let mockDir: string;
  let mock: { js: string; html: string };

  beforeAll(() => {
    tmp = mkdtempSync(join(tmpdir(), "sdp-bundle-"));
    prodDir = join(tmp, "dist");
    mockDir = join(tmp, "dist-mock");
    prod = build(prodDir);
    mock = build(mockDir, "--mock");
  }, 60_000);

  afterAll(() => rmSync(tmp, { recursive: true, force: true }));

  it("main-*.js of the production build contains none of the mock's markers", () => {
    for (const m of MARKERS) expect(prod.js, m).not.toContain(m);
  });

  it("the production index.html has no mock banner", () => {
    expect(prod.html).not.toContain("mock-banner");
  });

  it("no file of the production build (JS, CSS, HTML, static) carries any trace of the mock", () => {
    const files = tree(prodDir);
    expect(files.some((f) => f.file.endsWith(".css"))).toBe(true);
    for (const { file, text } of files) for (const m of TREE_MARKERS) expect(has(text, m), `${file}: ${m}`).toBe(false);
  });

  it("the --mock build carries them, the banner's own stylesheet included", () => {
    const all = tree(mockDir).map((f) => f.text).join("\n");
    for (const m of TREE_MARKERS) expect(has(all, m), String(m)).toBe(true);
    expect(readFileSync(join(mockDir, "assets", "mock.css"), "utf8")).toContain(".mock-banner");
  });

  it("the --mock build contains every marker and the banner, so the grep above would catch them", () => {
    for (const m of MARKERS) expect(mock.js, m).toContain(m);
    expect(mock.html).toContain('id="mock-banner"');
  });
});
