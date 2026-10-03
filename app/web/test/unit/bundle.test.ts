import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
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

describe("the production bundle has no mock (ADR 0035)", () => {
  let tmp: string;
  let prod: { js: string; html: string };
  let mock: { js: string; html: string };

  beforeAll(() => {
    tmp = mkdtempSync(join(tmpdir(), "sdp-bundle-"));
    prod = build(join(tmp, "dist"));
    mock = build(join(tmp, "dist-mock"), "--mock");
  }, 60_000);

  afterAll(() => rmSync(tmp, { recursive: true, force: true }));

  it("main-*.js of the production build contains none of the mock's markers", () => {
    for (const m of MARKERS) expect(prod.js, m).not.toContain(m);
  });

  it("the production index.html has no mock banner", () => {
    expect(prod.html).not.toContain("mock-banner");
  });

  it("the --mock build contains every marker and the banner, so the grep above would catch them", () => {
    for (const m of MARKERS) expect(mock.js, m).toContain(m);
    expect(mock.html).toContain('id="mock-banner"');
  });
});
