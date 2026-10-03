import { existsSync } from "node:fs";
import { chromium, defineConfig, devices } from "@playwright/test";

// Smoke tests against the built site. By default they start scripts/serve.mjs on dist/ (same
// headers as the image's nginx). Set BASE_URL to run them against something else instead, e.g. the
// real image: `docker run --rm --read-only --tmpfs /tmp -p 8080:8080 <image>` and
// BASE_URL=http://127.0.0.1:8080.
//
// Browser: Playwright's own Chromium if installed; otherwise PW_CHROMIUM_PATH, or the preinstalled
// /opt/pw-browsers/chromium some CI images ship. If none exists the suite cannot run; see README.
const external = process.env.BASE_URL;
// The fallback is consulted only when Playwright's own browser is missing: a runner that happens to
// carry /opt/pw-browsers must still test with the Chromium this lockfile pins, which is what
// `npx playwright install chromium` (the CI step) puts in place.
const ownChromium = (() => {
  try {
    return existsSync(chromium.executablePath());
  } catch {
    return false;
  }
})();
const fallbackChromium = ownChromium ? undefined : ["/opt/pw-browsers/chromium"].find((p) => existsSync(p));
const executablePath = process.env.PW_CHROMIUM_PATH ?? fallbackChromium;

export default defineConfig({
  testDir: "test/e2e",
  timeout: 30_000,
  expect: { timeout: 10_000 },
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  // In CI the "github" reporter turns every failure into a check-run annotation with its message
  // and location. Annotations are readable through the public API without signing in; job logs
  // and the uploaded report are not, so without it a red build says only "exit code 1".
  reporter: process.env.CI
    ? [["list"], ...(process.env.GITHUB_ACTIONS ? [["github"] as ["github"]] : []), ["html", { open: "never", outputFolder: "playwright-report" }]]
    : "list",
  use: {
    baseURL: external ?? "http://127.0.0.1:4173",
    trace: "retain-on-failure",
    launchOptions: executablePath ? { executablePath } : {},
  },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"] } },
    { name: "phone", use: { ...devices["Pixel 7"] } },
  ],
  // The stub servers serve this checkout's dist/ whatever BASE_URL points at: they stand in for an
  // API, which a deployed image does not let a test choose.
  webServer: [
    ...(external
      ? []
      : [
          {
            command: "node scripts/serve.mjs --port 4173",
            url: "http://127.0.0.1:4173/",
            reuseExistingServer: !process.env.CI,
          },
        ]),
    // The same site with a real streaming /api/events (see serve.mjs --stub-events).
    {
      command: "node scripts/serve.mjs --port 4174 --stub-events",
      url: "http://127.0.0.1:4174/",
      reuseExistingServer: !process.env.CI,
    },
    // The same site in front of a stub of the API deployed today (serve.mjs --live-api).
    {
      command: "node scripts/serve.mjs --port 4175 --live-api",
      url: "http://127.0.0.1:4175/",
      reuseExistingServer: !process.env.CI,
    },
  ],
});
