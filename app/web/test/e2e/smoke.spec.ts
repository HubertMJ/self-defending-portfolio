import { type ConsoleMessage, type Page, expect, test } from "@playwright/test";

/**
 * Fails the test on any CSP or Trusted Types violation and on any script error. Network errors
 * for /api are expected in the offline tests (there is no API behind the static server) and are
 * the only console errors tolerated.
 */
function guardConsole(page: Page): string[] {
  const problems: string[] = [];
  const expected = [/Failed to load resource.*404/, /EventSource's response has a MIME type/];
  page.on("console", (msg: ConsoleMessage) => {
    const text = msg.text();
    if (/Content Security Policy|Trusted Type|Refused to/i.test(text)) problems.push(`csp: ${text}`);
    else if (msg.type() === "error" && !expected.some((r) => r.test(text))) problems.push(`console: ${text}`);
  });
  page.on("pageerror", (err) => problems.push(`pageerror: ${err.message}`));
  return problems;
}

async function noHorizontalScroll(page: Page) {
  const [scroll, client] = await page.evaluate(() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]);
  expect(scroll, "page must not scroll horizontally").toBeLessThanOrEqual(client);
}

test.describe("security headers", () => {
  test("index and assets carry the CSP and the right cache policy; /api is not served", async ({ request }) => {
    const index = await request.get("/");
    expect(index.status()).toBe(200);
    const csp = index.headers()["content-security-policy"];
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("connect-src 'self'");
    expect(csp).toContain("require-trusted-types-for 'script'");
    expect(csp).not.toContain("unsafe-inline");
    expect(index.headers()["cache-control"]).toBe("no-cache");
    expect(index.headers()["x-content-type-options"]).toBe("nosniff");

    const html = await index.text();
    expect(html).not.toMatch(/<script>(?!<\/script>)|<script\s+(?![^>]*\bsrc=)[^>]*>|\son\w+=|style=/i);
    const asset = /\/assets\/(main-[\w-]+\.js)/.exec(html)?.[1];
    expect(asset).toBeTruthy();
    const js = await request.get(`/assets/${asset}`);
    expect(js.headers()["cache-control"]).toBe("public, max-age=31536000, immutable");

    const api = await request.get("/api/scenarios");
    expect(api.status()).toBe(404);
    expect(api.headers()["content-type"]).not.toContain("json");
  });
});

test.describe("API offline (nothing behind /api)", () => {
  test("the portfolio renders and every live panel shows an offline state", async ({ page }) => {
    const problems = guardConsole(page);
    await page.goto("/");
    await expect(page.getByRole("heading", { level: 1, name: "Hubert Jabłoński" })).toBeVisible();
    await expect(page.getByText("Live posture is unavailable")).toBeVisible();
    await expect(page.getByText("The attack launcher is offline")).toBeVisible();
    await expect(page.locator("#timeline-conn")).toHaveAttribute("data-state", /reconnecting|offline/);
    await expect(page.locator("#mock-banner")).toBeHidden();
    await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();
    await noHorizontalScroll(page);
    expect(problems).toEqual([]);
  });
});

test.describe("mock mode", () => {
  test("posture, scenarios and history render from fixtures", async ({ page }) => {
    const problems = guardConsole(page);
    await page.goto("/?mock=1");
    await expect(page.locator("#mock-banner")).toBeVisible();
    await expect(page.locator("#posture-panel .tile")).toHaveCount(4);
    await expect(page.getByRole("table", { name: /Kyverno policy reports/ })).toBeVisible();
    await expect(page.locator(".scenario")).toHaveCount(4);
    await expect(page.locator("#timeline-conn")).toHaveAttribute("data-state", "open");
    await expect(page.locator(".run")).toHaveCount(1);
    await noHorizontalScroll(page);
    expect(problems).toEqual([]);
  });

  test("launching an attack streams attack -> detection -> response into the timeline", async ({ page }) => {
    const problems = guardConsole(page);
    await page.goto("/?mock=1&mock-speed=0.5");
    const card = page.locator('.scenario[data-scenario="network-tool"]');
    const button = card.getByRole("button", { name: /Launch attack/ });
    await expect(button).toHaveAttribute("aria-disabled", "false");
    await button.click();

    await expect(page.locator("#launch-status")).toContainText("queued as run");
    // While the run is active every launch button is locked.
    await expect(page.locator('.scenario[data-scenario="shell-in-container"] button')).toHaveAttribute("aria-disabled", "true");

    const run = page.locator(".run").first();
    await expect(run.locator(".run__title")).toHaveText("Network reconnaissance tool");
    await expect(run.locator(".stage--detect")).toHaveAttribute("data-reached", "true");
    await expect(run.locator(".stage--detect .stage__delta")).toHaveText(/^\+\d/);
    await expect(run.locator(".stage--respond")).toHaveAttribute("data-reached", "true");
    await expect(run.locator(".chip--state")).toHaveText("Finished");
    await expect(page.locator("#timeline-live")).toContainText("finished");
    await expect(button).toHaveAttribute("aria-disabled", "false");

    await run.getByText("Raw events").click();
    await expect(run.locator(".run__events")).toContainText("kubernetes:label");
    expect(problems).toEqual([]);
  });

  test("a 429 locks the launcher with a countdown from Retry-After", async ({ page }) => {
    const problems = guardConsole(page);
    await page.goto("/?mock=1&mock-speed=0.1&mock-limit=1");
    const button = page.locator('.scenario[data-scenario="shell-in-container"] button');
    await button.click();
    await expect(page.locator(".run").first().locator(".chip--state")).toHaveText("Finished");
    await expect(button).toHaveAttribute("aria-disabled", "false");
    await button.click();
    await expect(page.locator("#launch-status")).toContainText("Rate limit reached");
    await expect(button).toHaveAttribute("aria-disabled", "true");
    await expect(button).toContainText("Rate limited");
    await expect(page.locator(".launcher__countdown")).toContainText(/Unlocks in \d+:\d\d/);
    expect(problems).toEqual([]);
  });
});

test.describe("event stream reconnects", () => {
  test("refused and stalled streams: one steady countdown per attempt, Retry-After honoured, then live", async ({ page }) => {
    test.setTimeout(60_000);
    const problems = guardConsole(page);
    await page.goto("/?mock=1&mock-stream-refuse=3&mock-stream-retry-after=2&mock-stream-stall=1");
    const conn = page.locator("#timeline-conn");
    const samples = new Map<string, number[]>();
    const deadline = Date.now() + 45_000;
    while (Date.now() < deadline && (await conn.getAttribute("data-state")) !== "open") {
      const retry = conn.locator(".conn__retry");
      if (await retry.count()) {
        const key = (await retry.getAttribute("data-deadline")) ?? "";
        const m = /next attempt in (\d+) s/.exec((await retry.textContent()) ?? "");
        if (key && m) samples.set(key, [...(samples.get(key) ?? []), Number(m[1])]);
      }
      await page.waitForTimeout(100);
    }
    await expect(conn).toHaveAttribute("data-state", "open");
    // At least the two refusals whose probe saw the 429 announced a countdown.
    expect(samples.size).toBeGreaterThanOrEqual(2);
    const firsts = [...samples.values()].map((v) => v[0]);
    // The first refusal's backoff is under a second; Retry-After (2 s) must win over it.
    expect(firsts[0]).toBeGreaterThanOrEqual(2);
    for (const values of samples.values()) {
      for (let i = 1; i < values.length; i++) expect(values[i]).toBeLessThanOrEqual(values[i - 1]);
    }
    // Live again: the replayed history run is on the timeline.
    await expect(page.locator(".run").first()).toBeVisible();
    expect(problems).toEqual([]);
  });
});

test.describe("accessibility basics", () => {
  test("skip link is the first stop and moves focus to main", async ({ page, isMobile }) => {
    test.skip(isMobile, "keyboard navigation is a desktop concern");
    await page.goto("/?mock=1");
    await page.keyboard.press("Tab");
    const skip = page.getByRole("link", { name: "Skip to content" });
    await expect(skip).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.locator("main")).toBeFocused();
  });

  test("theme toggle switches and persists", async ({ page }) => {
    await page.emulateMedia({ colorScheme: "dark" });
    await page.goto("/?mock=1");
    const toggle = page.locator("#theme-toggle");
    await expect(toggle).toHaveAttribute("aria-label", "Switch to light theme");
    await toggle.click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    expect(bg).toBe("rgb(245, 244, 239)");
    await page.reload();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  });

  test("reduced motion stops the animations", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto("/?mock=1");
    await expect(page.locator("#timeline-conn")).toHaveAttribute("data-state", "open");
    const anim = await page.locator("#timeline-conn .conn__dot").evaluate((el) => getComputedStyle(el).animationName);
    expect(anim).toBe("none");
  });
});
