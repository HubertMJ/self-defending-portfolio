import { existsSync } from "node:fs";
import { defineConfig, devices } from "@playwright/test";

// Smoke tests against the built site. By default they start scripts/serve.mjs on dist/ (same
// headers as the image's nginx). Set BASE_URL to run them against something else instead, e.g. the
// real image: `docker run --rm --read-only --tmpfs /tmp -p 8080:8080 <image>` and
// BASE_URL=http://127.0.0.1:8080.
//
// Browser: Playwright's own Chromium if installed; otherwise PW_CHROMIUM_PATH, or the preinstalled
// /opt/pw-browsers/chromium some CI images ship. If none exists the suite cannot run; see README.
const external = process.env.BASE_URL;
const fallbackChromium = ["/opt/pw-browsers/chromium"].find((p) => existsSync(p));
const executablePath = process.env.PW_CHROMIUM_PATH ?? fallbackChromium;

export default defineConfig({
  testDir: "test/e2e",
  timeout: 30_000,
  expect: { timeout: 10_000 },
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]] : "list",
  use: {
    baseURL: external ?? "http://127.0.0.1:4173",
    trace: "retain-on-failure",
    launchOptions: executablePath ? { executablePath } : {},
  },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"] } },
    { name: "phone", use: { ...devices["Pixel 7"] } },
  ],
  webServer: external
    ? undefined
    : [
        {
          command: "node scripts/serve.mjs --port 4173",
          url: "http://127.0.0.1:4173/",
          reuseExistingServer: !process.env.CI,
        },
        // The same site with a real streaming /api/events (see serve.mjs --stub-events).
        {
          command: "node scripts/serve.mjs --port 4174 --stub-events",
          url: "http://127.0.0.1:4174/",
          reuseExistingServer: !process.env.CI,
        },
      ],
});
