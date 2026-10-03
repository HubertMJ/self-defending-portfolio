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

/** Every request the page made to the in-page mock (`?mock=1` never reaches the network). */
async function mockCalls(page: Page): Promise<string[]> {
  return page.evaluate(() => (window as unknown as { sdpMock: { calls: string[] } }).sdpMock.calls.slice());
}

async function noHorizontalScroll(page: Page) {
  const [scroll, client] = await page.evaluate(() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]);
  expect(scroll, "page must not scroll horizontally").toBeLessThanOrEqual(client);
}

/** Nothing inside `selector` reaches past the right edge (clipped by an overflow:hidden parent, say). */
async function nothingPastEdge(page: Page, selector: string) {
  const past = await page.locator(selector).evaluate((root) =>
    [...root.querySelectorAll("*")].filter((e) => e.getBoundingClientRect().width > 0 && e.getBoundingClientRect().right > document.documentElement.clientWidth + 1).map((e) => e.className),
  );
  expect(past, `${selector} must fit the screen`).toEqual([]);
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
    expect(js.status()).toBe(200);
    expect(js.headers()["cache-control"]).toBe("public, max-age=31536000, immutable");

    // A missing hashed asset (another release's, during a rollout) and a missing page are never
    // cacheable: a 404 with the immutable policy would be served by the CDN for a year.
    const missing = await request.get("/assets/main-NOTBUILT.js");
    expect(missing.status()).toBe(404);
    expect(missing.headers()["cache-control"]).toBe("no-store");
    const missingPage = await request.get("/no-such-page");
    expect(missingPage.status()).toBe(404);
    expect(missingPage.headers()["cache-control"]).toBe("no-store");

    const api = await request.get("/api/scenarios");
    expect(api.status()).toBe(404);
    expect(api.headers()["content-type"]).not.toContain("json");
  });
});

test.describe("production build has no placeholder copy (FIX 2)", () => {
  test("no TODO-CONTENT marker or dashed placeholder ships, real content stays", async ({ page, request }) => {
    const html = await (await request.get("/")).text();
    expect(html).not.toContain("TODO-CONTENT");
    expect(html).not.toContain("data-todo-content");
    expect(html).not.toMatch(/\btodo-content\b/);
    await page.goto("/");
    // The real content that sat next to the placeholders is still there.
    await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();
    await expect(page.getByRole("link", { name: "self-defending-portfolio" }).first()).toBeVisible();
    await expect(page.locator(".todo-content")).toHaveCount(0);
    // An About with nothing written is not shipped as a heading over nothing, nor linked to.
    await expect(page.locator("#about")).toHaveCount(0);
    await expect(page.locator('.site-nav a[href="#about"]')).toHaveCount(0);
    await expect(page.getByRole("heading", { name: "Skills shown in this repository" })).toBeVisible();
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
  test("the mock banner stays on screen when the page opens at #attack", async ({ page }) => {
    await page.goto("/?mock=1#attack");
    await expect.poll(() => page.evaluate(() => scrollY)).toBeGreaterThan(500);
    await expect(page.locator("#mock-banner")).toBeInViewport();
    await page.mouse.wheel(0, 3000);
    await expect(page.locator("#mock-banner")).toBeInViewport();
  });

  test("posture, scenarios and history render from fixtures", async ({ page }) => {
    const problems = guardConsole(page);
    await page.goto("/?mock=1");
    await expect(page.locator("#mock-banner")).toBeVisible();
    await expect(page.locator("#posture-panel .tile")).toHaveCount(4);
    await expect(page.getByRole("table", { name: /Kyverno policy reports/ })).toBeVisible();
    await expect(page.getByRole("table", { name: /Critical \+ high findings per image/ })).toBeVisible();
    await expect(page.locator(".posture-split")).toContainText("third-party images");
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
    await expect(page.locator('.scenario[data-scenario="shell-in-container"] .btn--attack')).toHaveAttribute("aria-disabled", "true");

    const run = page.locator(".run").first();
    await expect(run.locator(".run__title")).toHaveText("Download tool in a container");
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
    const button = page.locator('.scenario[data-scenario="shell-in-container"] .btn--attack');
    await button.click();
    await expect(page.locator(".run").first().locator(".chip--state")).toHaveText("Finished");
    await expect(button).toHaveAttribute("aria-disabled", "false");
    await button.click();
    await expect(page.locator("#launch-status")).toContainText("Rate limit reached");
    await expect(button).toHaveAttribute("aria-disabled", "true");
    await expect(button).toContainText("Rate limited");
    // The copy explains the limit is per network address, and the countdown lives in the same line.
    await expect(page.locator("#launch-status")).toContainText("per network address");
    await expect(page.locator("#launch-status .launch-status__countdown")).toContainText(/Unlocks in \d+:\d\d/);
    expect(problems).toEqual([]);
  });
});

test.describe("live run console (mock)", () => {
  test("a full run lights the pipeline, runs the kill-timer, shows the pod and the victim", async ({ page }) => {
    const problems = guardConsole(page);
    await page.goto("/?mock=1");
    const consoleEl = page.locator("#console");
    await page.locator('.scenario[data-scenario="shell-in-container"] .btn--attack').click();
    await expect(consoleEl).toHaveAttribute("data-state", "live");
    await expect(consoleEl.locator(".console__who")).toHaveText("Your run");
    // Before its first answer the shop is "booting", with the pod's phase from the pod watch.
    await expect(consoleEl.locator(".browser")).toContainText(/Shop booting · pod (Pending|ContainerCreating|Running)/);
    // The victim shop is up first, then defaced by the attack, then gone with its pod.
    await expect(consoleEl.locator(".browser")).toHaveAttribute("data-status", /fresh|defaced/);
    // The pre_exec defaces the shop before the shell Falco catches: defaced while nothing is detected.
    await expect(consoleEl.locator(".browser")).toHaveAttribute("data-status", "defaced");
    await expect(consoleEl.locator('.hop[data-hop="falco"]')).not.toHaveAttribute("data-state", "lit");
    await expect(consoleEl.locator(".killtimer")).toHaveAttribute("data-state", "running");
    await expect(consoleEl.locator(".browser")).toHaveAttribute("data-status", "gone", { timeout: 15_000 });
    await expect(consoleEl.locator(".hop[data-state=lit]")).toHaveCount(8, { timeout: 15_000 });
    await expect(consoleEl.locator(".killtimer")).toHaveAttribute("data-state", "stopped");
    await expect(consoleEl.locator(".killtimer__value")).toHaveText(/^0\.\d{3}$/);
    // FIX 3: it played in real time; the badge states how fast that was, next to something human.
    await expect(consoleEl.locator(".replay-badge")).toContainText(/Real time · real: \d+ ms from the detected syscall to pod deleted · (faster|about as fast|quicker|in under|in a couple)/);
    // One number, two places: the badge's real duration is the kill-timer's reading.
    const badgeMs = Number(/real: (\d+) ms/.exec((await consoleEl.locator(".replay-badge").textContent()) ?? "")?.[1]);
    expect(Number(await consoleEl.locator(".killtimer__value").textContent()) * 1000).toBeCloseTo(badgeMs, 0);
    // The slow replay is offered, not forced; clicking it runs the dwelled playback.
    const replayBtn = consoleEl.getByRole("button", { name: "Replay slowly" });
    await expect(replayBtn).toBeVisible();
    await replayBtn.click();
    await expect(consoleEl.locator(".replay-badge")).toContainText(/Replay(ing|ed) at 1\/\d+ speed/);
    // Talon logs after the API server acted; its hop shows the API server's time as a bound.
    await expect(consoleEl.locator('.hop[data-hop="talon"] .hop__t')).toHaveText(/^≤ \+\d+ ms$/);
    await expect(consoleEl.locator('.hop[data-hop="talon"] .hop__what')).toHaveText("Talon deleted the pod");
    await expect(consoleEl.locator(".phase")).toHaveCount(5);
    await expect(consoleEl.locator(".card--pod")).toContainText(/sha256:[0-9a-f]{12}/);
    // Two steps: the pre_exec that defaced the shop without a terminal, then the detected shell.
    await expect(consoleEl.locator(".card--exec .steps > li")).toHaveCount(2);
    await expect(consoleEl.locator(".card--exec .steps > li").first()).toContainText("mv .index index.html &&");
    await expect(consoleEl.locator(".card--exec .steps > li").nth(1)).toContainText("Attack, in an interactive terminal");
    await expect(consoleEl.locator(".card--exec a").first()).toHaveAttribute("href", /^https:\/\/github\.com\/HubertMJ\/self-defending-portfolio\/blob\/[0-9a-f]{7,40}\//);
    await consoleEl.getByText("Verify it yourself").click();
    await expect(consoleEl.locator(".verify")).toContainText("cosign verify ghcr.io/hubertmj/self-defending-portfolio/scenario@sha256:");
    await expect(consoleEl.locator(".verify")).toContainText("build-images.yml@refs/heads/main");
    await expect(consoleEl.locator(".utc tbody tr")).toHaveCount(8);
    await noHorizontalScroll(page);
    expect(problems).toEqual([]);
  });

  test("a quarantine shows the label, the cut network and the dropped packets", async ({ page }) => {
    const problems = guardConsole(page);
    await page.goto("/?mock=1&mock-speed=0.5");
    await page.locator('.scenario[data-scenario="network-tool"] .btn--attack').click();
    const consoleEl = page.locator("#console");
    await expect(consoleEl.locator(".browser")).toHaveAttribute("data-status", "unreachable");
    await expect(consoleEl.locator(".card--proof")).toContainText("sdp.hubertjablon.ski/quarantine: false → true");
    await expect(consoleEl.locator(".card--proof")).toContainText("Cilium dropped the probe");
    await expect(consoleEl.locator('.hop[data-hop="effect"] .hop__who')).toContainText("Cilium");
    await expect(consoleEl.locator('.hop[data-hop="effect"] .hop__what')).toHaveText("probe dropped");
    await expect(page.locator(".run").first().locator(".run__foot")).toContainText("including the time held in quarantine", { timeout: 15_000 });
    expect(problems).toEqual([]);
  });

  test("another visitor's run is shown read-only; missing details fail soft", async ({ page }) => {
    const problems = guardConsole(page);
    await page.goto("/?mock=1&mock-visitor=300&mock-details=0");
    const consoleEl = page.locator("#console");
    await expect(consoleEl.locator(".console__who")).toContainText("Another visitor’s run");
    await expect(consoleEl.locator(".browser__ro")).toHaveText("read-only");
    await expect(consoleEl.locator(".card--exec")).toContainText("does not publish scenario details");
    expect(problems).toEqual([]);
  });

  test("the history's Show button puts that run in the console", async ({ page }) => {
    await page.goto("/?mock=1&mock-speed=0.1");
    await page.locator('.scenario[data-scenario="sensitive-file-read"] .btn--attack').click();
    await expect(page.locator(".run")).toHaveCount(2);
    await expect(page.locator(".run").first().locator(".chip--state")).toHaveText("Finished");
    await page.locator('.run[data-run="a7c3e9f1b2d40658"] .run__show').click();
    await expect(page.locator("#console .console__scenario")).toHaveText("Shell in a container");
    await expect(page.locator("#console-title")).toBeFocused();
    await page.getByRole("button", { name: "Back to the latest run" }).click();
    await expect(page.locator("#console .console__scenario")).toHaveText("Read /etc/shadow");
  });

  test("on a phone, launching takes the visitor to the live run", async ({ page, isMobile }) => {
    test.skip(!isMobile, "the scroll matters where the console is below the fold");
    await page.goto("/?mock=1");
    const button = page.locator('.scenario[data-scenario="drop-and-execute"] .btn--attack');
    await button.click();
    await expect(page.locator("#console-title")).toBeFocused();
    await expect(page.locator("#console-title")).toBeInViewport();
    await noHorizontalScroll(page);
  });
});

test.describe("attacker's terminal (mock, ADR 0033)", () => {
  test("type, read real output, change the shop, reach an objective, then get killed", async ({ page }) => {
    const problems = guardConsole(page);
    await page.goto("/?mock=1&mock-speed=0.3");
    const term = page.locator("#terminal");
    await term.getByRole("button", { name: /Open the terminal/ }).click();
    await expect(term.locator("#term-input")).toBeVisible();

    // An unknown line is answered locally and never sent anywhere.
    await term.locator("#term-input").fill("rm -rf /");
    await term.locator(".term__send").click();
    await expect(term.locator(".term__out")).toContainText("not in this sandbox's catalogue");

    // A real recon command streams real output back.
    await term.getByRole("button", { name: "id", exact: true }).click();
    await expect(term.locator(".term__out")).toContainText("uid=10001");
    // Each output line is its own bidi paragraph: a right-to-left run cannot reorder it.
    expect(await term.locator(".term__cmdout .term__line").first().evaluate((e) => getComputedStyle(e).unicodeBidi)).toBe("plaintext");

    // Defacing the shop changes the window beside the terminal; no rule fires.
    await term.getByRole("button", { name: /^echo pwned>/ }).click();
    await expect(term.locator(".term__shop .browser")).toHaveAttribute("data-status", "defaced");

    // Reading the flag reaches an objective.
    await term.getByRole("button", { name: "cat /srv/shop/.flag" }).click();
    await expect(term.locator(".term__out")).toContainText(/SDP\{[0-9a-f]{16}\}/);
    await expect(term.locator(".term__objhead")).toContainText(/Objectives · [1-9]/);

    // A detected command ends the session; the summary and the defence-map result appear.
    await term.getByRole("button", { name: "cat /etc/shadow" }).click();
    await expect(term.locator(".term__summary")).toBeVisible({ timeout: 15_000 });
    await expect(term.locator(".term__sumtitle")).toHaveText("Session over");
    await expect(term.locator(".term__summary .deflayer")).toHaveCount(7);
    await expect(term.locator(".term__summary")).toContainText("Killed after your Enter");
    await expect(term.locator(".term__summary a", { hasText: "Open an issue" })).toHaveAttribute("href", /\/issues$/);
    await noHorizontalScroll(page);
    await nothingPastEdge(page, "#terminal");
    expect(problems).toEqual([]);
  });

  test("an unknown line is answered locally and never sent to the API", async ({ page }) => {
    const problems = guardConsole(page);
    await page.goto("/?mock=1&mock-speed=0.3");
    const term = page.locator("#terminal");
    await term.getByRole("button", { name: /Open the terminal/ }).click();
    await expect(term.locator("#term-input")).toBeEnabled({ timeout: 10_000 }); // enabled only once pod_ready
    await term.locator("#term-input").fill("sudo rm -rf /");
    await term.locator(".term__send").click();
    await expect(term.locator(".term__out")).toContainText("not in this sandbox's catalogue");
    // Nothing was sent: the mock answers in-page, so its own call log is the record of what was.
    const calls = await mockCalls(page);
    expect(calls).toContain("POST /api/attack/terminal"); // the log does record what is sent
    expect(calls.filter((c) => c.includes("/commands"))).toEqual([]);
    expect(problems).toEqual([]);
  });

  test("commands are offered only once the pod is ready", async ({ page }) => {
    await page.goto("/?mock=1&mock-speed=0.6");
    const term = page.locator("#terminal");
    await term.getByRole("button", { name: /Open the terminal/ }).click();
    // Before pod_ready the input is disabled and the status says starting.
    await expect(term.locator("#term-input")).toBeDisabled();
    await expect(term.locator(".term__status")).toContainText("starting the pod");
    await expect(term.locator("#term-input")).toBeEnabled({ timeout: 10_000 });
  });

  test("another visitor's terminal is read-only: no form, no chips, no POST", async ({ page }) => {
    const problems = guardConsole(page);
    await page.goto("/?mock=1&mock-speed=0.4&mock-term-visitor=300");
    const term = page.locator("#terminal");
    await expect(term.locator(".term__status")).toContainText("read-only", { timeout: 10_000 });
    await expect(term.locator(".term__out")).toContainText("uid=10001", { timeout: 10_000 });
    await expect(term.locator("#term-input")).toBeHidden();
    await expect(term.locator(".term__chips")).toBeHidden();
    expect((await mockCalls(page)).filter((c) => !c.startsWith("GET "))).toEqual([]);
    expect(problems).toEqual([]);
  });

  test("falls back to the one-click demo when the API has no terminal catalogue", async ({ page }) => {
    const problems = guardConsole(page);
    await page.goto("/?mock=1&mock-details=0");
    const term = page.locator("#terminal");
    await expect(term.locator(".term-fallback")).toContainText("one-click attacks");
    // The one-click scenarios still work as the main attack path.
    await expect(page.locator(".scenario")).toHaveCount(4);
    expect(problems).toEqual([]);
  });
});

test.describe("defence map and live stats (mock, ADR 0033)", () => {
  test("the How-it-works section is a seven-layer map with live posture evidence", async ({ page }) => {
    const problems = guardConsole(page);
    await page.goto("/?mock=1");
    await expect(page.locator("#defence-map .deflayer")).toHaveCount(7);
    await expect(page.locator('#defence-map .deflayer[data-layer="admission"]')).toContainText("admission checks passing");
    await expect(page.locator('#defence-map .deflayer[data-layer="runtime"]')).toContainText("Falco");
    expect(problems).toEqual([]);
  });

  test("the hero shows live counters and objectives, including ones never reached", async ({ page }) => {
    await page.goto("/?mock=1");
    const hero = page.locator("#hero-stats");
    await expect(hero).toBeVisible();
    await expect(hero.locator(".herostats__tile")).toHaveCount(4);
    await expect(hero).toContainText("attacks");
    await expect(hero).toContainText("detections answered");
    await expect(hero.locator('.herostats__obj[data-never="true"]').first()).toContainText("not reached yet");
    await expect(hero.locator("a", { hasText: "Open an issue" })).toHaveAttribute("href", /\/issues$/);
    // No escapes/"got out" counter (review item 18).
    await expect(hero).not.toContainText(/got out|call-home/i);
  });
});

test.describe("unguarded twin (mock, ADR 0033)", () => {
  test("one click runs with and without the response, side by side", async ({ page }) => {
    const problems = guardConsole(page);
    await page.goto("/?mock=1&mock-speed=0.4");
    await page.locator('.scenario[data-scenario="network-tool"] .scenario__twin').click();
    const twin = page.locator("#console .twin");
    await expect(twin).toBeVisible({ timeout: 8_000 });
    await expect(twin.locator(".twin__arm")).toHaveCount(2);
    // The guarded pod is cut off; the unguarded one stays compromised, with nothing answering.
    await expect(twin.locator(".twin__arm--guarded .browser")).toHaveAttribute("data-status", "unreachable", { timeout: 12_000 });
    await expect(twin.locator(".twin__arm--unguarded .browser")).toHaveAttribute("data-status", "compromised");
    await expect(twin).toContainText("nothing answered");
    await expect(twin).toContainText("attacker has held this pod");
    await noHorizontalScroll(page);
    expect(problems).toEqual([]);
  });
});

test.describe("narrow screens", () => {
  test("no horizontal scroll at 360 px with a finished run, Technical Mode and every panel open", async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 780 });
    await page.goto("/?mock=1&mock-speed=0.2");
    await page.locator("#tech-toggle").click();
    await page.locator('.scenario[data-scenario="network-tool"] .btn--attack').click();
    await expect(page.locator("#console .browser")).toHaveAttribute("data-status", "unreachable");
    await page.locator("#console .verify > summary").click();
    await page.locator("#console .rawlog > summary").click();
    await noHorizontalScroll(page);
  });
});

test.describe("technical mode", () => {
  test("toggles raw detail, is announced as a pressed button and persists", async ({ page }) => {
    const problems = guardConsole(page);
    await page.goto("/?mock=1");
    const toggle = page.locator("#tech-toggle");
    await expect(toggle).toHaveAttribute("aria-pressed", "false");
    await expect(page.locator("#console .console__raw")).toBeHidden();
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-pressed", "true");
    await expect(page.locator("html")).toHaveAttribute("data-tech", "on");
    await expect(page.locator("#console .console__raw")).toBeVisible();
    await expect(page.locator("#console .console__raw")).toContainText("Falco output fields");
    await expect(page.locator("#console .console__raw")).toContainText("kubernetes:terminate");
    await expect(page.locator("#limits-panel")).toContainText("attacks left per 10 min");
    await page.reload();
    await expect(page.locator("html")).toHaveAttribute("data-tech", "on");
    await expect(page.locator("#tech-toggle")).toHaveAttribute("aria-pressed", "true");
    await page.locator("#tech-toggle").click();
    await page.reload();
    await expect(page.locator("#tech-toggle")).toHaveAttribute("aria-pressed", "false");
    await expect(page.locator("#console .console__raw")).toBeHidden();
    await noHorizontalScroll(page);
    expect(problems).toEqual([]);
  });
});

test.describe("against the API deployed today (serve.mjs --live-api: JSON 404 on the new endpoints)", () => {
  test("the one-click scenarios are the attack section: no terminal, no twin, no stats, nothing sent", async ({ page }) => {
    test.setTimeout(40_000);
    const problems = guardConsole(page);
    const requests: string[] = [];
    page.on("request", (r) => {
      if (r.url().includes("/api/") && !r.url().includes("/api/events")) requests.push(`${r.method()} ${new URL(r.url()).pathname}`);
    });
    await page.goto("http://127.0.0.1:4175/");
    await expect(page.locator(".scenario")).toHaveCount(4);
    // The page learnt there is no terminal: the hero and the section say what is there instead.
    await expect(page.locator("#hero-cta")).toHaveText("Launch an attack");
    await expect(page.locator("#attack-title")).toHaveText("Launch a real attack");
    await expect(page.locator(".terminal-wrap")).toBeHidden();
    await expect(page.locator(".launcher__head")).toBeHidden();
    await expect(page.getByText("Open the terminal")).toHaveCount(0);
    await expect(page.locator("#how .section__lead")).not.toContainText("terminal", { useInnerText: true });
    // That API ignores ?compare=1 and would start an ordinary run: no twin is offered.
    await expect(page.locator(".scenario__twin")).toHaveCount(0);
    await expect(page.locator(".scenario .btn--attack")).toHaveCount(4);
    await expect(page.locator("#hero-stats")).toBeHidden();
    await page.waitForTimeout(3000);
    // Loading the page posts nothing, and asks for the missing endpoints once each, not on a loop.
    expect(requests.filter((r) => r.startsWith("POST"))).toEqual([]);
    expect(requests.filter((r) => r === "GET /api/stats").length).toBeLessThanOrEqual(1);
    expect(requests.filter((r) => r === "GET /api/scenarios/terminal/details").length).toBeLessThanOrEqual(1);
    expect(requests.filter((r) => r.startsWith("GET /api/runs/")).length).toBeLessThanOrEqual(1);
    await noHorizontalScroll(page);
    expect(problems).toEqual([]);
  });
});

test.describe("a terminal session replayed as the API publishes it (serve.mjs --terminal-api)", () => {
  for (const [label, base] of [["", "http://127.0.0.1:4176/"], [" (the catalogue answering after the replay)", "http://127.0.0.1:4177/"]]) {
  test(`joined mid-session: backfilled in order, watched read-only, summarised from the API's own events${label}`, async ({ page }) => {
    const problems = guardConsole(page);
    const backfills: string[] = [];
    const posts: string[] = [];
    page.on("request", (r) => {
      if (/\/api\/runs\/[0-9a-f]{16}$/.test(r.url())) backfills.push(r.url());
      if (r.method() !== "GET") posts.push(`${r.method()} ${r.url()}`);
    });
    await page.goto(base);
    const term = page.locator("#terminal");
    // The replay held only the run's later events; the page still knows it is a live terminal run.
    await expect(term.locator(".term__status")).toContainText("read-only");
    // The backfill fills in what came before, in the order the API published it.
    await expect(term.locator(".term__cmd[data-seq]")).toHaveCount(3, { timeout: 10_000 });
    expect(await term.locator(".term__cmd[data-seq]").evaluateAll((els) => els.map((e) => e.getAttribute("data-seq")))).toEqual(["1", "2", "3"]);
    await expect(term.locator('.term__cmd[data-seq="1"] .term__cmdout')).toContainText("Connection refused");
    // Then the session ends live: the summary is read from the run's own responses.
    const summary = term.locator(".term__summary");
    await expect(summary).toBeVisible({ timeout: 10_000 });
    await expect(summary.locator(".term__sumlead")).toContainText("Quarantined after wget");
    await expect(summary.locator(".term__sumlead")).toContainText("under them after cat /etc/shadow");
    const stat = (label: string) => summary.locator(".term__sumstats div", { has: page.locator("dt", { hasText: label }) }).locator("dd");
    await expect(stat("Quarantined after their Enter")).toHaveText("220 ms");
    await expect(stat("Killed after their Enter")).toHaveText("150 ms");
    await expect(stat("Falco to response")).toHaveText("110 ms");
    const ended = summary.locator(".deflayer__entry", { has: page.locator(".deflayer__ended") }).locator("code");
    await expect(ended).toHaveText(["cat /etc/shadow"]);
    expect(backfills).toHaveLength(1);
    expect(posts).toEqual([]); // a watcher sends nothing
    await expect(term.locator(".term__obj")).toHaveCount(5); // the catalogue's objectives, filled in
    await noHorizontalScroll(page);
    expect(problems).toEqual([]);
  });
  }
});

test.describe("real EventSource against a streaming server", () => {
  test("opens exactly one long-lived stream, keeps it open and shows the replay", async ({ page }) => {
    test.skip(!!process.env.BASE_URL, "needs the local --stub-events server");
    test.setTimeout(60_000);
    const stub = "http://127.0.0.1:4174";
    const requests: string[] = [];
    const failed: string[] = [];
    page.on("request", (r) => {
      if (r.url().includes("/api/events")) requests.push(r.resourceType());
    });
    page.on("requestfailed", (r) => {
      if (r.url().includes("/api/events")) failed.push(`${r.resourceType()} ${r.failure()?.errorText}`);
    });
    await page.goto(`${stub}/`);
    await expect(page.locator("#timeline-conn")).toHaveAttribute("data-state", "open");
    await expect(page.locator(".run").first()).toBeVisible();
    // The replayed run carries every extension event; the console renders them from the real stream,
    // and degrades (no details endpoint behind the stub) instead of breaking.
    const consoleEl = page.locator("#console");
    await expect(consoleEl.locator('.hop[data-hop="effect"]')).toHaveAttribute("data-state", "lit");
    await expect(consoleEl.locator(".phase")).toHaveCount(4);
    await expect(consoleEl.locator(".browser")).toHaveAttribute("data-status", "gone");
    await expect(consoleEl.locator(".card--exec")).toContainText("does not publish scenario details");
    await expect(page.locator("#header-conn")).toContainText("cluster live");
    await page.waitForTimeout(20_000);
    await expect(page.locator("#timeline-conn")).toHaveAttribute("data-state", "open");
    // Exactly one request from this page, made by the browser's EventSource (not a fetch), never
    // aborted. Counted per page: the desktop and phone projects share the stub server.
    expect(requests).toEqual(["eventsource"]);
    expect(failed).toEqual([]);
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
      // Key and text read in one evaluation: two separate reads could straddle a new attempt and
      // pair the old attempt's key with the new countdown.
      const sample = await conn.evaluate((el) => {
        const r = el.querySelector(".conn__retry");
        return r ? { key: r.getAttribute("data-deadline") ?? "", text: r.textContent ?? "" } : null;
      });
      if (sample) {
        const m = /next attempt in (\d+) s/.exec(sample.text);
        if (sample.key && m) samples.set(sample.key, [...(samples.get(sample.key) ?? []), Number(m[1])]);
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

  test("reduced motion skips the replay: hops light as their events arrive", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto("/?mock=1&mock-speed=0.3");
    await page.locator('.scenario[data-scenario="shell-in-container"] .btn--attack').click();
    const consoleEl = page.locator("#console");
    // At 0.3x the whole chain is ~0.3 s; a 600 ms dwell per hop would need several seconds.
    await expect(consoleEl.locator(".hop[data-state=lit]")).toHaveCount(8, { timeout: 2_500 });
    await expect(consoleEl.locator(".replay-badge")).toContainText("Real time");
    await expect(consoleEl.getByRole("button", { name: "Replay slowly" })).toBeHidden();
  });
});
