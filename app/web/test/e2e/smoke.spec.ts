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

/** Appends a wide fallback font to the page's stylesheet as it is served (see the credibility tests). */
async function wideFonts(page: Page) {
  const wide = '\n* { font-family: "DejaVu Sans", Verdana, sans-serif !important; letter-spacing: 0.03em !important; }\ncode, pre, kbd, samp, .term, .chip, .facts--mono, .btn--small, .brand { font-family: "DejaVu Sans Mono", monospace !important; }\n';
  await page.route(/\/assets\/styles-[^/]*\.css$/, async (route) => {
    const res = await route.fetch();
    await route.fulfill({ response: res, body: (await res.text()) + wide });
  });
}

/**
 * The hero shows no provenance data (ADR 0035, amended 2026-10-04): its copy has no commit, digest,
 * cosign or Rekor, and nothing in it (the evidence card included, which shows the attacked pod's own
 * image) names the api or web image or the commit they were built from. Nor does it link to #verify:
 * the owner moved that link to the footer, with the panel far down the page, above the skills.
 */
async function hasNoProvenance(page: Page) {
  const hero = page.locator("#top");
  const copy = hero.locator(".hero__copy");
  await expect(hero.locator("#verify-strip, .vstrip, .vimage, .verify-panel")).toHaveCount(0);
  await expect(copy).not.toContainText(/sha256:|cosign|Rekor|provenance|signed in CI/i);
  await expect(copy.locator('a[href*="/commit/"], a[href*="sigstore"], a[href*="/actions/runs/"], button.copy')).toHaveCount(0);
  // serve.mjs's provenance: commit 0448cff…, api sha256:bbbb…, web sha256:1111….
  await expect(hero).not.toContainText(/0448cff|sha256:b{8}|sha256:1{8}|self-defending-portfolio\/(api|web)@/);
  await expect(hero.locator('a[href="#verify"]')).toHaveCount(0);
}

/**
 * The page's sections in order (ADR 0035, amended 2026-10-05), as every build ships them: the console
 * is inside #attack.
 */
const PAGE_ORDER = ["top", "attack", "correlation", "how", "about", "evidence", "posture", "verify", "skills", "projects"];

/**
 * "All activity, last 24 h" chosen before the page loads (ADR 0035, amendment "this session first"):
 * for the tests of the whole history, console, ticker and board, which this session's view leaves out.
 */
async function allActivity(page: Page) {
  await page.addInitScript(() => localStorage.setItem("sdp:scope", "all"));
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
    // The written About ships, linked from the navigation.
    await expect(page.getByRole("heading", { name: "About me" })).toBeVisible();
    await expect(page.locator('.site-nav a[href="#about"]')).toHaveCount(1);
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

test.describe("layout (ADR 0035, amended 2026-10-05; ?mock=1)", () => {
  test("the attack, its response and the correlation come first; evidence, posture and verify sit above the skills", async ({ page }) => {
    await page.goto("/?mock=1");
    await expect(page.locator("#correlation")).toBeVisible();
    expect(await page.evaluate(() => [...document.querySelectorAll("main > section")].map((el) => el.id))).toEqual(PAGE_ORDER);
    // The live run is part of the attack section, before the correlation.
    expect(await page.evaluate(() => document.querySelector("#attack #console") !== null)).toBe(true);
    // The navigation follows the page; the one link to #verify is the footer's.
    // The SIEM's section is linked while it is shown (UX stage 1).
    expect(await page.locator(".site-nav a").evaluateAll((as) => as.map((a) => a.getAttribute("href")))).toEqual(["#attack", "#correlation", "#how", "#about", "#posture"]);
    await expect(page.locator('.site-nav a[href="#correlation"]')).toBeVisible();
    await expect(page.locator('a[href="#verify"]')).toHaveCount(1);
    await expect(page.locator('footer.site-footer a[href="#verify"]')).toHaveCount(1);
  });

  test("a section's heading folds it: the body hides, aria-expanded flips, the choice survives a reload; by keyboard too", async ({ page }) => {
    const problems = guardConsole(page);
    await page.goto("/?mock=1");
    const btn = page.locator("#posture-title > button.section__toggle");
    await expect(btn).toHaveAttribute("aria-expanded", "true");
    await expect(btn).toHaveAttribute("aria-controls", "posture-body");
    await expect(page.locator("#posture-panel .tile").first()).toBeVisible();
    await btn.click();
    await expect(btn).toHaveAttribute("aria-expanded", "false");
    await expect(page.locator("#posture-body")).toBeHidden();
    await expect(page.locator("#posture .section__lead")).toBeHidden();
    // Folded keeps the eyebrow (the section's number) and the title.
    await expect(page.locator("#posture .eyebrow")).toBeVisible();
    await expect(btn).toBeVisible();
    await page.reload();
    await expect(btn).toHaveAttribute("aria-expanded", "false");
    await expect(page.locator("#posture-body")).toBeHidden();
    await expect(page.locator("#how-body")).toBeVisible();
    // Unfolded, the posture that was fetched while folded is drawn.
    await btn.focus();
    await page.keyboard.press("Enter");
    await expect(btn).toHaveAttribute("aria-expanded", "true");
    await expect(page.locator("#posture-panel .tile").first()).toBeVisible();
    await page.keyboard.press("Space");
    await expect(btn).toHaveAttribute("aria-expanded", "false");
    await page.reload();
    await expect(page.locator("#posture-body")).toBeHidden();
    // The attack section folds and unfolds with its terminal intact.
    const attack = page.locator("#attack-title > button");
    await attack.click();
    await expect(page.locator("#terminal")).toBeHidden();
    await attack.click();
    await expect(page.locator("#terminal .term-start__btn")).toBeVisible();
    expect(problems).toEqual([]);
  });

  test("a link to a folded section opens it: the footer's #verify, the hero's #attack, a typed hash, a page opened at one", async ({ page }) => {
    const problems = guardConsole(page);
    await page.goto("/?mock=1");
    for (const id of ["verify", "attack", "evidence", "posture"]) await page.locator(`#${id}-title > button`).click();
    await page.reload();
    for (const id of ["verify", "attack", "evidence", "posture"]) await expect(page.locator(`#${id}-body`)).toBeHidden();
    // The page has its full height first: a smooth scroll does not follow the correlation appearing above it.
    await expect(page.locator("#correlation .corr-matrix")).toBeVisible();
    await expect(page.locator("#hero-stats .herostats__tile").first()).toBeVisible();
    await page.locator('footer.site-footer a[href="#verify"]').click();
    await expect(page.locator("#verify-title > button")).toHaveAttribute("aria-expanded", "true");
    await expect(page.locator("#verify-panel")).toBeVisible();
    await expect(page.locator("#verify-title")).toBeInViewport();
    await page.locator("#hero-cta").click();
    await expect(page.locator("#attack-body")).toBeVisible();
    await expect(page.locator("#attack-title")).toBeInViewport();
    await page.evaluate(() => (location.hash = "#evidence"));
    await expect(page.locator("#evidence-body")).toBeVisible();
    await expect(page.locator("#evidence-title")).toBeInViewport();
    await page.goto("/?mock=1#posture");
    await expect(page.locator("#posture-body")).toBeVisible();
    await expect(page.locator("#posture-title")).toBeInViewport();
    expect(problems).toEqual([]);
  });

  test("folded at first paint: with the module script held back, theme.ts and the stylesheet fold a folded section alone", async ({ page }) => {
    await page.goto("/?mock=1");
    await page.locator("#posture-title > button").click();
    await page.route(/\/assets\/main-[^/]*\.js$/, (route) => route.abort());
    await page.reload();
    expect(await page.evaluate(() => document.documentElement.dataset.folded)).toBe("posture");
    await expect(page.locator("#posture-body")).toBeHidden();
    await expect(page.locator("#posture .section__lead")).toBeHidden();
    await expect(page.locator("#posture-title")).toBeVisible();
    await expect(page.locator("#how-body")).toBeVisible();
  });

  test("a reload keeps the visitor's scroll position: no jump to the hash because a section above it is folded", async ({ page }) => {
    await page.goto("/?mock=1#posture");
    await expect(page.locator("#correlation .corr-matrix")).toBeVisible();
    await page.locator("#evidence-title > button").click();
    await expect(page.locator("#evidence-body")).toBeHidden();
    await page.evaluate(() => window.scrollTo(0, (document.getElementById("skills") as HTMLElement).getBoundingClientRect().top + scrollY - 200));
    const y = await page.evaluate(() => scrollY);
    await page.reload();
    await expect(page.locator("#evidence-body")).toBeHidden();
    await expect(page.locator("#correlation .corr-matrix")).toBeVisible();
    // theme.ts's stand-in is gone once the buttons fold the section themselves.
    expect(await page.evaluate(() => document.documentElement.dataset.folded)).toBeUndefined();
    // The browser restores what it can (the mock's panels arrive after the load, so it may fall short of
    // y), and the visitor is not left at #posture. The browser's restoration comes after the module here,
    // so the unit test (a reload faked) is what pins sections.ts's own decision.
    await page.waitForTimeout(1500);
    const at = await page.evaluate(() => ({ y: scrollY, posture: (document.getElementById("posture") as HTMLElement).getBoundingClientRect().top }));
    expect(at.y).toBeGreaterThan(0);
    expect(Math.abs(at.posture)).toBeGreaterThan(300);
    expect(y).toBeGreaterThan(0);
  });

  for (const wide of [false, true]) {
    const fonts = wide ? " (a wide font forced in)" : "";

    test(`the section toggles fit 360 and 320 px, open and folded${fonts}`, async ({ page }) => {
      if (wide) await wideFonts(page);
      const past = () =>
        page.evaluate(() =>
          [...document.querySelectorAll(".section__toggle, .section__toggle *")]
            .filter((e) => {
              const r = e.getBoundingClientRect();
              return r.width > 0 && (r.left < -1 || r.right > document.documentElement.clientWidth + 1);
            })
            .map((e) => e.closest("section")?.id),
        );
      for (const width of [360, 320]) {
        await page.setViewportSize({ width, height: 780 });
        await page.goto("/?mock=1");
        if (wide) expect(await page.evaluate(() => getComputedStyle(document.body).fontFamily)).toContain("DejaVu Sans");
        await expect(page.locator("#correlation")).toBeVisible();
        const toggles = page.locator(".section__toggle");
        await expect(toggles).toHaveCount(9);
        expect(await past()).toEqual([]);
        await noHorizontalScroll(page);
        // The jump bar's five links fit in one row ("How it works" says "How" this narrow); with a wider
        // font it scrolls sideways inside itself, never the page (noHorizontalScroll above).
        if (!wide) await nothingPastEdge(page, ".site-header");
        for (const t of await toggles.all()) await t.click();
        expect(await past()).toEqual([]);
        await noHorizontalScroll(page);
      }
    });
  }
});

test.describe("mock mode", () => {
  test("the mock banner stays on screen when the page opens at #attack", async ({ page }) => {
    await page.goto("/?mock=1#attack");
    // Landed at #attack, below the sticky header's height (scroll-padding-top).
    await expect.poll(() => page.evaluate(() => scrollY)).toBeGreaterThan(400);
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
    // The guarded pod alone: one run, one pod, as the timeline below reads it.
    const button = card.getByRole("button", { name: "Guarded pod only" });
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
    // The run's in-between states last a few hundred milliseconds (the kill-timer runs for about half
    // a second), shorter than an assertion's polling can be sure to see. Every state the console
    // passes through is recorded as it happens instead, and the sequence is checked afterwards.
    await page.evaluate(() => {
      const root = document.getElementById("console") as HTMLElement;
      const seen: { victim: string; text: string; falcoLit: boolean; timer: string; who: string }[] = [];
      const record = () => {
        const s = {
          victim: root.querySelector(".browser")?.getAttribute("data-status") ?? "",
          text: root.querySelector(".browser")?.textContent ?? "",
          falcoLit: root.querySelector('.hop[data-hop="falco"]')?.getAttribute("data-state") === "lit",
          timer: root.querySelector(".killtimer")?.getAttribute("data-state") ?? "",
          who: root.querySelector(".console__who")?.textContent ?? "",
        };
        const last = seen[seen.length - 1];
        if (!last || JSON.stringify(last) !== JSON.stringify(s)) seen.push(s);
      };
      new MutationObserver(record).observe(root, { subtree: true, childList: true, attributes: true, characterData: true });
      (window as unknown as { consoleStates: typeof seen }).consoleStates = seen;
    });
    await page.locator('.scenario[data-scenario="shell-in-container"] .scenario__alt').click();
    // The run takes the console over (live for its whole length), then ends.
    await expect(consoleEl).toHaveAttribute("data-state", "live");
    await expect(consoleEl).toHaveAttribute("data-state", "done", { timeout: 15_000 });
    await expect(consoleEl.locator(".browser")).toHaveAttribute("data-status", "gone");
    await expect(consoleEl.locator(".hop[data-state=lit]")).toHaveCount(8, { timeout: 15_000 });
    await expect(consoleEl.locator(".killtimer")).toHaveAttribute("data-state", "stopped");
    const states = await page.evaluate(() => (window as unknown as { consoleStates: { victim: string; text: string; falcoLit: boolean; timer: string; who: string }[] }).consoleStates);
    // Only what the console showed once this run had taken it over (before, it showed the history).
    const own = states.slice(states.findIndex((s) => s.who === "Your run"));
    const changes = (xs: string[]) => xs.filter((x, i) => x !== "" && x !== xs[i - 1]);
    expect(states.some((s) => s.who === "Your run")).toBe(true);
    // Before its first answer the shop is "booting", with the pod's phase from the pod watch.
    expect(own.some((s) => /Shop booting · pod (Pending|ContainerCreating|Running)/.test(s.text))).toBe(true);
    // The shop is up first, then defaced by the pre_exec — while nothing is detected yet — then gone.
    expect(changes(own.map((s) => s.victim))).toEqual(["waiting", "fresh", "defaced", "gone"]);
    expect(own.some((s) => s.victim === "defaced" && !s.falcoLit)).toBe(true);
    // The kill-timer waits, runs from the detected syscall, and stops at the response.
    expect(changes(own.map((s) => s.timer))).toEqual(["idle", "running", "stopped"]);
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
    // The one identity every image is verified against (lib/provenance.ts, scripts/verify-image.sh; ADR 0035).
    await expect(consoleEl.locator(".verify")).toContainText(String.raw`--certificate-identity-regexp '^https://github\.com/HubertMJ/self-defending-portfolio/\.github/workflows/(build-images|build-web)\.yml@refs/heads/main$'`);
    await expect(consoleEl.locator(".utc tbody tr")).toHaveCount(8);
    await noHorizontalScroll(page);
    expect(problems).toEqual([]);
  });

  test("a quarantine shows the label, the cut network and the dropped packets", async ({ page }) => {
    const problems = guardConsole(page);
    await page.goto("/?mock=1&mock-speed=0.5");
    await page.locator('.scenario[data-scenario="network-tool"] .scenario__alt').click();
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
    await expect(consoleEl.locator(".console__who")).toContainText("Someone else is attacking right now");
    await expect(consoleEl.locator(".browser__ro")).toHaveText("read-only");
    await expect(consoleEl.locator(".card--exec")).toContainText("does not publish scenario details");
    expect(problems).toEqual([]);
  });

  test("the history's Show button puts that run in the console", async ({ page }) => {
    await allActivity(page);
    await page.goto("/?mock=1&mock-speed=0.1");
    await page.locator('.scenario[data-scenario="sensitive-file-read"] .scenario__alt').click();
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
    // The summary shows the layers this session touched; all seven, lit, are in How it works (UX stage 1).
    await expect(term.locator(".term__summary .deflayer[data-state='detected']")).toHaveCount(1);
    await expect(term.locator(".term__summary a[href='#how']")).toHaveCount(1);
    await expect(page.locator("#defence-map .defmap__overlay")).toBeVisible();
    await expect(page.locator("#defence-map .deflayer")).toHaveCount(7);
    await expect(page.locator("#defence-map .deflayer[data-layer='runtime']")).toHaveAttribute("data-state", "detected");
    await expect(term.locator(".term__summary")).toContainText("Killed after your Enter");
    await expect(term.locator(".term__summary a", { hasText: "Open an issue" })).toHaveAttribute("href", /\/issues$/);
    await noHorizontalScroll(page);
    await nothingPastEdge(page, "#terminal");
    expect(problems).toEqual([]);
  });

  test("the bar counts down the 5-minute session and the 90 s idle limit without moving, and says why it ended", async ({ page }) => {
    const problems = guardConsole(page);
    await page.goto("/?mock=1");
    const term = page.locator("#terminal");
    await term.getByRole("button", { name: /Open the terminal/ }).click();
    const bar = term.locator(".term__bar");
    await expect(bar.locator(".term__clock")).toHaveAttribute("data-live", "true", { timeout: 10_000 });
    await expect(bar.locator(".term__left")).toHaveText(/^Session time: 4:5\d left$/);
    await expect(bar.locator(".term__idleleft")).toHaveText(/^Idle limit in idle 1:[23]\d$/);
    // A tick changes the numbers and nothing else: every item of the bar stays where it was.
    const boxes = () => bar.evaluate((b) => [...b.children].map((e) => JSON.stringify(e.getBoundingClientRect())));
    const before = { boxes: await boxes(), text: await bar.locator(".term__left").textContent() };
    await expect(bar.locator(".term__left")).not.toHaveText(before.text ?? "", { timeout: 2_500 });
    expect(await boxes()).toEqual(before.boxes);
    // The bar is dark in both themes; Leave reads on it in both.
    for (const scheme of ["light", "dark"] as const) {
      await page.emulateMedia({ colorScheme: scheme });
      const ratio = await bar.locator(".term__exit").evaluate((el) => {
        const lum = (c: string) => {
          const [r, g, b] = (c.match(/[\d.]+/g) ?? []).slice(0, 3).map(Number).map((x) => x / 255).map((x) => (x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4));
          return 0.2126 * r + 0.7152 * g + 0.0722 * b;
        };
        const [a, b] = [lum(getComputedStyle(el).color), lum(getComputedStyle(el.closest(".term__bar") as HTMLElement).backgroundColor)].sort((x, y) => y - x);
        return (a + 0.05) / (b + 0.05);
      });
      expect(ratio, scheme).toBeGreaterThanOrEqual(4.5);
    }
    await bar.getByRole("button", { name: "Leave" }).click();
    await expect(term.locator(".term__status")).toHaveText("session over — you left");
    await expect(term.locator(".term__sumlead")).toContainText("You left");
    await expect(bar.locator(".term__clock")).toBeHidden();
    expect(problems).toEqual([]);
  });

  test("a session left without a command ends at the idle limit, and the bar and the summary say so", async ({ page }) => {
    // At 0.03x the mock's 90 s idle limit is 2.7 s; the words come from the details, not the clock.
    await page.goto("/?mock=1&mock-speed=0.03");
    const term = page.locator("#terminal");
    await term.getByRole("button", { name: /Open the terminal/ }).click();
    await expect(term.locator(".term__status")).toHaveText("session over — ended after 90 s without a command", { timeout: 10_000 });
    await expect(term.locator(".term__sumlead")).toContainText("ended after 90 s without a command");
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
    await expect(hero).toContainText("detected runs answered");
    await expect(hero.locator('.herostats__obj[data-never="true"]').first()).toContainText("not reached yet");
    await expect(hero.locator("a", { hasText: "Open an issue" })).toHaveAttribute("href", /\/issues$/);
    // No escapes/"got out" counter (review item 18).
    await expect(hero).not.toContainText(/got out|call-home/i);
    // The never-reached count is readable in both themes: 4.5:1 against its row at least.
    for (const scheme of ["light", "dark"] as const) {
      await page.emulateMedia({ colorScheme: scheme });
      const ratio = await hero.locator('.herostats__obj[data-never="true"] .herostats__objcount').first().evaluate((el) => {
        const rgb = (c: string) => {
          const n = (c.match(/[\d.]+/g) ?? []).map(Number);
          return c.startsWith("color(") ? n.slice(0, 3).map((x) => x * 255) : n.slice(0, 3);
        };
        const lum = (c: number[]) => {
          const [r, g, b] = c.map((x) => x / 255).map((x) => (x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4));
          return 0.2126 * r + 0.7152 * g + 0.0722 * b;
        };
        let bg = el as HTMLElement;
        while (getComputedStyle(bg).backgroundColor === "rgba(0, 0, 0, 0)") bg = bg.parentElement as HTMLElement;
        const row = el.closest(".herostats__obj") as HTMLElement;
        const [a, b] = [lum(rgb(getComputedStyle(el).color)), lum(rgb(getComputedStyle(bg).backgroundColor))].sort((x, y) => y - x);
        return Number(getComputedStyle(row).opacity) * ((a + 0.05) / (b + 0.05));
      });
      expect(ratio, scheme).toBeGreaterThanOrEqual(4.5);
    }
  });
});

test.describe("unguarded twin (mock, ADR 0033)", () => {
  test("the card's main button runs with and without the response, side by side", async ({ page }) => {
    const problems = guardConsole(page);
    await page.goto("/?mock=1&mock-speed=0.4");
    const card = page.locator('.scenario[data-scenario="network-tool"]');
    // The main button runs both pods; the card says so, and offers the guarded pod alone beside it.
    await expect(card.locator(".btn--attack")).toHaveText(/Launch side by side/);
    await expect(card.locator(".scenario__alt")).toHaveText("Guarded pod only");
    await expect(card.locator(".scenario__launchnote")).toContainText("an unguarded twin where Falco sees it and nothing answers");
    await card.locator(".btn--attack").click();
    const twin = page.locator("#console .twin");
    await expect(twin).toBeVisible({ timeout: 8_000 });
    const posts = await page.evaluate(() => (window as unknown as { sdpMock: { calls: string[] } }).sdpMock.calls.filter((c) => c.startsWith("POST ")));
    expect(posts).toEqual(["POST /api/attack/network-tool?compare=1"]);
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
    await page.locator('.scenario[data-scenario="network-tool"] .scenario__alt').click();
    await expect(page.locator("#console .browser")).toHaveAttribute("data-status", "unreachable");
    await page.locator("#console .verify > summary").click();
    await page.locator("#console .rawlog > summary").click();
    await noHorizontalScroll(page);
  });
});

test.describe("technical mode", () => {
  test("toggles raw detail, is announced as a pressed button and persists", async ({ page }) => {
    await allActivity(page);
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
    // That API ignores ?compare=1 and would start an ordinary run: the one plain button, no twin.
    await expect(page.locator(".scenario__alt")).toHaveCount(0);
    await expect(page.locator(".scenario__launchnote")).toHaveCount(0);
    await expect(page.locator(".scenario .btn--attack")).toHaveCount(4);
    await expect(page.locator(".scenario .btn--attack").first()).toHaveText(/Launch attack/);
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
    await allActivity(page);
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
    await page.locator('.scenario[data-scenario="shell-in-container"] .scenario__alt').click();
    const consoleEl = page.locator("#console");
    // At 0.3x the whole chain is ~0.3 s; a 600 ms dwell per hop would need several seconds.
    await expect(consoleEl.locator(".hop[data-state=lit]")).toHaveCount(8, { timeout: 2_500 });
    await expect(consoleEl.locator(".replay-badge")).toContainText("Real time");
    await expect(consoleEl.getByRole("button", { name: "Replay slowly" })).toBeHidden();
  });
});

test.describe("credibility on the production bundle (ADR 0035; serve.mjs --terminal-api, not ?mock)", () => {
  const CRED = "http://127.0.0.1:4176/";

  test("above the fold: the evidence card, no provenance data and no link to #verify in the hero, the panel far down and linked from the footer; on a phone the card follows the counters", async ({ page, isMobile }) => {
    const problems = guardConsole(page);
    if (!isMobile) await page.setViewportSize({ width: 1280, height: 720 });
    await page.goto(CRED);
    const card = page.locator("#evidence-card .evcard");
    // The provenance has arrived (the panel names the api's commit), and none of it is in the hero.
    await expect(page.locator('#verify-panel [data-image="api"]')).toContainText("0448cff");
    await expect(card).toBeVisible();
    await hasNoProvenance(page);
    await expect(card.locator(".evlist__item").first()).toContainText(/\d\d:\d\d:\d\d\.\d{3} CES?T/);
    await expect(page.locator("#hero-stats")).toBeVisible();
    // The card is never folded away.
    expect(await card.evaluate((el) => el.closest("details:not([open])") === null)).toBe(true);
    const box = await page.evaluate(() => {
      const r = (s: string) => (document.querySelector(s) as HTMLElement).getBoundingClientRect();
      return { scrollY: window.scrollY, card: r("#evidence-card").top, stats: r("#hero-stats").bottom, next: (document.querySelector("#hero-stats")?.parentElement?.nextElementSibling as HTMLElement | null)?.id };
    });
    expect(box.scrollY).toBe(0);
    if (!isMobile) {
      expect(box.card).toBeLessThan(720);
    } else {
      // Stacked: the card comes right after the copy, whose last child is #hero-stats.
      expect(box.next).toBe("evidence-card");
      expect(box.card).toBeGreaterThanOrEqual(box.stats);
      expect(box.card - box.stats).toBeLessThan(80);
    }
    // The order the owner asked for (ADR 0035, amended 2026-10-05): the attack, its response and the
    // correlation first; the evidence, the posture and the verify panel after How it works, above the
    // skills.
    expect(await page.evaluate(() => [...document.querySelectorAll("main > section")].map((el) => el.id))).toEqual(PAGE_ORDER);
    // The one way to it is a footer link.
    await expect(page.locator('a[href="#verify"]')).toHaveCount(1);
    const link = page.locator('footer.site-footer a[href="#verify"]');
    await expect(link).toHaveText("Verify the running images");
    await expect(page.locator("#verify-title")).not.toBeInViewport();
    await link.click();
    await expect(page.locator("#verify-title")).toBeInViewport();
    expect(problems).toEqual([]);
  });

  test("the server time follows the ticks; loading the page sends nothing but GETs", async ({ page }) => {
    await allActivity(page);
    test.setTimeout(40_000);
    const problems = guardConsole(page);
    const nonGet: string[] = [];
    page.on("request", (r) => {
      if (r.url().includes("/api/") && r.method() !== "GET") nonGet.push(`${r.method()} ${r.url()}`);
    });
    await page.goto(CRED);
    const server = page.locator("#liveness .liveness__server");
    await expect(server).toBeVisible();
    const first = await server.getAttribute("datetime");
    // The tick's `at`, rendered in Polish time: the attribute is the UTC instant, the text its Warsaw
    // wall clock with CET or CEST, whatever the zone of the browser or the host (ADR 0035, 2026-10-06).
    expect(first).toMatch(/Z$/);
    expect(Math.abs(Date.parse(first as string) - Date.now())).toBeLessThan(5000);
    await expect(server).toHaveText(/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d CES?T$/);
    const [iso, text] = await server.evaluate((el) => [(el as HTMLTimeElement).dateTime, el.textContent ?? ""]);
    const wall = new Intl.DateTimeFormat("sv-SE", { timeZone: "Europe/Warsaw", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" }).format(new Date(iso));
    const offsetH = Math.round((Date.parse(`${wall.replace(" ", "T")}Z`) - Math.floor(Date.parse(iso) / 1000) * 1000) / 3_600_000);
    expect(text).toBe(`${wall} ${offsetH === 2 ? "CEST" : "CET"}`);
    await expect.poll(() => server.getAttribute("datetime"), { timeout: 6000 }).not.toBe(first);
    await expect(page.locator("#liveness")).toContainText("API up");
    await expect(page.locator("#ticker .ticker__item").first()).toBeVisible();
    await expect(page.locator("#posture-panel .tile").first()).toContainText("stale config, nothing running violates");
    await page.waitForTimeout(10_000);
    expect(nonGet).toEqual([]);
    expect(problems).toEqual([]);
  });

  test("ticks without new events change no element of the ticker (nothing re-announced, focus kept)", async ({ page }) => {
    test.setTimeout(40_000);
    await page.goto(CRED);
    await expect(page.locator("#liveness .liveness__server")).toBeVisible();
    // The replayed session ends live about 2.5 s after the connect; after that only ticks arrive.
    await page.waitForTimeout(4000);
    await page.evaluate(() => {
      const w = window as unknown as { tickerMutations: number };
      w.tickerMutations = 0;
      new MutationObserver((records) => (w.tickerMutations += records.filter((r) => r.type === "childList").length)).observe(document.getElementById("ticker") as HTMLElement, { childList: true, subtree: true });
    });
    const server = page.locator("#liveness .liveness__server");
    const before = await server.getAttribute("datetime");
    await page.waitForTimeout(10_000);
    expect(await server.getAttribute("datetime")).not.toBe(before); // ticks did arrive
    expect(await page.evaluate(() => (window as unknown as { tickerMutations: number }).tickerMutations)).toBe(0);
  });

  // The site uses the visitor's system fonts, and a CI runner's (or a visitor's) can be much wider
  // than the ones this suite usually runs with. The same invariants hold with a deliberately wide
  // fallback forced in: DejaVu Sans (Verdana, else the default sans) with extra letter spacing,
  // appended to the stylesheet on its way in (an injected <style> would break the page's CSP).
  for (const wide of [false, true]) {
    const fonts = wide ? " (a wide font forced in)" : "";

    test(`no horizontal scroll at 360 and 320 px with the live policy names${fonts}`, async ({ page }) => {
      await allActivity(page);
      if (wide) await wideFonts(page);
      for (const width of [360, 320]) {
        await page.setViewportSize({ width, height: 780 });
        await page.goto(CRED);
        if (wide) expect(await page.evaluate(() => getComputedStyle(document.body).fontFamily)).toContain("DejaVu Sans");
        await expect(page.locator("#posture-panel table", { hasText: "autogen-validate-registries" })).toBeAttached();
        await expect(page.locator("#evidence-card .evcard")).toBeVisible();
        await expect(page.locator("#console .hop").first()).toBeVisible();
        await noHorizontalScroll(page);
      }
    });

    test(`the evidence card is above the fold at 1280x720, the hero carries no provenance${fonts}`, async ({ page, isMobile }) => {
      test.skip(isMobile, "a desktop viewport");
      if (wide) await wideFonts(page);
      await page.setViewportSize({ width: 1280, height: 720 });
      await page.goto(CRED);
      if (wide) expect(await page.evaluate(() => getComputedStyle(document.body).fontFamily)).toContain("DejaVu Sans");
      await expect(page.locator('#verify-panel [data-image="api"]')).toContainText("0448cff");
      await expect(page.locator("#evidence-card .evcard")).toBeVisible();
      await hasNoProvenance(page);
      const m = await page.evaluate(() => ({
        scrollY: window.scrollY,
        card: (document.getElementById("evidence-card") as HTMLElement).getBoundingClientRect().top,
        titleLines: Math.round((document.getElementById("hero-title") as HTMLElement).getBoundingClientRect().height / parseFloat(getComputedStyle(document.getElementById("hero-title") as HTMLElement).lineHeight)),
      }));
      expect(m.scrollY).toBe(0);
      expect(m.card).toBeLessThan(720);
      expect(m.titleLines, "the name stays on one line").toBe(1);
    });
  }

  test("?mock=1 on the production bundle is an ordinary query: no banner, no mock, the real header", async ({ page }) => {
    await page.goto(`${CRED}?mock=1`);
    await expect(page.locator("#header-conn")).toContainText("cluster");
    await expect(page.locator("#mock-banner")).toHaveCount(0);
    expect(await page.evaluate(() => (window as unknown as { sdpMock?: unknown }).sdpMock === undefined)).toBe(true);
    expect(await page.evaluate(() => document.documentElement.dataset.mock)).toBeUndefined();
  });

  for (const [label, base] of [["the interactive API before ADR 0035 (--terminal-api --no-cred)", "http://127.0.0.1:4178/"], ["the API deployed before the terminal (--live-api)", "http://127.0.0.1:4175/"]]) {
    test(`degrades on ${label}: provenance unavailable, liveness without server time, posture as before`, async ({ page }) => {
      const problems = guardConsole(page);
      await page.goto(base);
      await expect(page.locator("#verify-panel")).toContainText("API provenance unavailable");
      await hasNoProvenance(page);
      await expect(page.locator("#posture-panel .tile")).toHaveCount(4);
      await expect(page.locator("#posture-panel .tile__list")).toHaveCount(0);
      await expect(page.locator("#posture-panel")).toContainText("Runtime, last 24 h");
      // No tick from an older API: the line appears 3 s after the stream opened, without a server time.
      await expect(page.locator("#liveness")).toContainText("posture refreshed", { timeout: 8000 });
      await expect(page.locator("#liveness")).not.toContainText("server time");
      await expect(page.locator("#evidence-card .evcard")).toBeVisible();
      expect(problems).toEqual([]);
    });
  }
});

test.describe("a side-by-side run, contained with the twin still held (serve.mjs --terminal-api --twin)", () => {
  test("the card says contained, names the guarded pod and labels each event by pod; the history and the console name the pod", async ({ page }) => {
    await allActivity(page);
    const problems = guardConsole(page);
    await page.goto("http://127.0.0.1:4179/");
    const pod = "scenario-network-tool-7e57aaaaaa";
    const card = page.locator("#evidence-card .evcard");
    // The chip says contained and the run is still going (the twin is held): the header agrees with the chip.
    await expect(card.locator(".evcard__head .chip")).toHaveText("Contained");
    await expect(card.locator(".evcard__eyebrow")).toHaveText("Attack contained");
    // The twin's Falco event (sandbox-unguarded) does not take the pod's name off the card.
    await expect(card.locator(".evcard__facts > div", { has: page.locator("dt", { hasText: /^Pod$/ }) }).locator("dd")).toHaveText(pod);
    await expect(card.locator(".evlist__item")).toHaveCount(3);
    await expect(card.locator(".evlist__item .tag--arm")).toHaveText(["guarded", "twin, unguarded", "guarded"]);
    await expect(card.locator(".evlist__item").nth(1)).toHaveAttribute("data-type", "falco");
    await expect(page.locator("#evidence .evdetail .tag--arm")).toHaveText(["guarded", "twin, unguarded", "guarded"]);
    const attack = page.locator('#timeline .run[data-run="7e57aaaaaaaaaaaa"] .stage--attack');
    await expect(attack).toContainText(pod);
    await expect(attack).not.toContainText("not a sandbox pod");
    await expect(page.locator("#console .twin")).toBeVisible();
    await expect(page.locator("#console .console__sub")).toContainText(`pod ${pod}`);
    await expect(page.locator("#console .card--pod dd").first()).toHaveText(pod);
    await noHorizontalScroll(page);
    expect(problems).toEqual([]);
  });
});

test.describe("correlation (ADR 0036; serve.mjs --terminal-api --siem / --no-siem, the production bundle)", () => {
  const SIEM = "http://127.0.0.1:4180/";
  const NO_SIEM = "http://127.0.0.1:4181/";
  const section = (page: Page) => page.locator("#correlation");
  /**
   * The sections the stylesheet numbers, in order: its counter counts the eyebrows that are rendered
   * (a hidden section's is not), and a pseudo-element's counter value cannot be read from a script.
   */
  const numbered = (page: Page) =>
    page.evaluate(() => [...document.querySelectorAll("main > .section > .wrap > .section__head > .eyebrow")].filter((e) => e.getClientRects().length > 0).map((e) => e.closest("section")?.id));

  test("the section after the attack: health, SOC metrics, the incident board with its evidence timeline, the rule library; GETs only", async ({ page }) => {
    await allActivity(page);
    test.setTimeout(45_000);
    const problems = guardConsole(page);
    const nonGet: string[] = [];
    page.on("request", (r) => {
      if (r.url().includes("/api/") && r.method() !== "GET") nonGet.push(`${r.method()} ${r.url()}`);
    });
    await page.goto(SIEM);
    const s = section(page);
    await expect(s).toBeVisible();
    expect(await page.evaluate(() => [...document.querySelectorAll("main > section")].map((el) => el.id))).toEqual(PAGE_ORDER);
    // "02 · Correlation", and How it works becomes 03.
    expect((await numbered(page)).slice(0, 5)).toEqual(["attack", "correlation", "how", "about", "evidence"]);
    await expect(s.locator(".section__head .eyebrow")).toHaveText("Correlation");

    // The SIEM scenario first (UX stage 1), then the board; the health line is folded, its summary all ok.
    await expect(s.locator(".corr-scenario__title")).toHaveText("Make the SIEM catch what Falco cannot.");
    await expect(s.locator(".corr-scenario__state")).toHaveText("not run yet");
    await expect(s.locator(".corr-healthfold summary")).toContainText("every check ok");
    await expect(s.locator(".corr-health")).toBeHidden();
    await s.locator(".corr-healthfold summary").click();
    // The health line (decision D1): the applied commit linked, each check named.
    const health = s.locator(".corr-health");
    await expect(health.locator(".corr-health__rules")).toContainText("rules applied at commit a7cc041");
    await expect(health.locator('.corr-health__rules a[href="https://github.com/HubertMJ/self-defending-portfolio/commit/a7cc041e5d2b9f30c1a4e6b8d0f2a3c5e7f9b1d3"]')).toHaveCount(1);
    await expect(health).toContainText("ingest ok");
    await expect(health).toContainText("evidence not rewritten");
    await expect(health).toContainText("disk ok");
    await expect(health.locator(".corr-health__checked time")).toHaveText(/\d\d:\d\d:\d\d CES?T \(.+ ago\)/);

    // SOC metrics: the API's medians, the page's p95 saying what it is over.
    const tiles = s.locator(".corr-metrics .tile");
    await expect(tiles).toHaveCount(5);
    await expect(tiles.nth(1)).toContainText("Time to detect");
    await expect(tiles.nth(1).locator(".tile__value")).toHaveText("840 ms");
    await expect(tiles.nth(2).locator(".tile__value")).toHaveText("212 ms");
    await expect(tiles.nth(2)).toContainText("p95 1.8 s over the 3 contained intrusions listed");
    await expect(tiles.nth(3).locator(".tile__value")).toHaveText("1 min 1 s");
    await expect(tiles.nth(4).locator(".tile__value")).toHaveText("2");
    await expect(s.locator(".corr-lag")).toContainText("falco 1.2 s · talon 860 ms · k8s-audit 2.1 s · hubble 3.4 s · api 610 ms · host –");

    // The board, newest first: the dns-exfil incident with no Falco event and the flag matched.
    const incidents = s.locator(".incident");
    await expect(incidents).toHaveCount(6);
    const dns = incidents.first();
    await expect(dns).toHaveAttribute("data-kind", "dns-exfil");
    await expect(dns.locator(".incident__facts")).toContainText("Falcono event");
    await expect(dns.locator(".incident__facts")).toContainText("matched the run's flag");
    await expect(dns.locator('a[href="https://attack.mitre.org/techniques/T1048/003/"]')).toHaveCount(1);
    await expect(dns.locator('a[href="/api/runs/7e57000000000001"]')).toHaveCount(1);
    const steps = dns.locator(".corr-step");
    await expect(steps).toHaveCount(3);
    await expect(steps.first().locator("time")).toHaveText(/^\d\d:\d\d:\d\d\.\d{3} CES?T$/);
    await expect(steps.first().locator("time")).toHaveAttribute("datetime", /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
    // A command line without a finding has no rule; the hubble finding's rule links to its Sigma file at
    // the API's commit (serve.mjs's provenance: 0448cff…).
    await expect(steps.first()).toContainText("command read-flag (T1552.001, credentials) started on sandbox/terminal-7e57000001");
    await expect(steps.first().locator("strong")).toHaveCount(0);
    await expect(steps.nth(2).locator(".tag--src")).toHaveText("hubble");
    await expect(steps.nth(2).locator('a[href="https://github.com/HubertMJ/self-defending-portfolio/blob/0448cff5a1b2c3d4e5f60718293a4b5c6d7e8f90/siem/rules/dns-exfil-label.yml#L1"]')).toHaveCount(1);
    // Pinned first, the most severe leading: caught by correlation, not by Falco (UX stage 1).
    await expect(s.locator(".corr-tier--pinned .incident")).toHaveCount(4);
    expect(await s.locator(".corr-tier--pinned .incident").evaluateAll((es) => es.map((e) => e.getAttribute("data-severity")))).toEqual(["critical", "high", "medium", "medium"]);
    // The three contained intrusions are one closed fold with a summary line, one row each.
    const contained = s.locator("details.corr-contained");
    await expect(contained.locator("summary")).toHaveText("Contained automatically by Falco + Talon (3)");
    await expect(s.locator('.incident[data-incident="c0a1b2c3d4e5f607"]')).toHaveCount(0);
    await contained.locator("summary").click();
    await expect(contained.locator(".corr-contained__line")).toContainText(/^3 intrusions caught and ended · median [\d.]+ (ms|s) to detect · [\d.]+ (ms|s) to isolate/);
    await expect(contained.locator('li[data-incident="c0a1b2c3d4e5f607"]')).toBeVisible();
    // Nine valid incidents: four pinned, three folded, two others in full; the two malformed ones are dropped.
    await expect(s.locator(".corr-older")).toHaveCount(0);
    // The live test suites' two exec incidents (three sessions), the newest of the board among them, are
    // folded into one line, closed, and listed when it is opened (ADR 0036 amendment 2026-10-06).
    const optests = s.locator("details.corr-optests");
    await expect(optests.locator("summary")).toHaveText("3 operator test-suite execs in the last 24 h");
    await expect(s.locator('.incident[data-incident^="0b5e7a10c0ffee"]')).toHaveCount(0);
    // The leaky exec incident is no test run: it stays on the board in full.
    await expect(s.locator('.incident[data-kind="exec-outside-api"]')).toHaveCount(1);
    await expect(optests.locator('[data-incident="0b5e7a10c0ffee01"]')).toBeHidden();
    await optests.locator("summary").click();
    await expect(optests.locator(".corr-older__item")).toHaveCount(2);
    await expect(optests.locator('[data-incident="0b5e7a10c0ffee01"]')).toContainText("Operator test run: exec into sandbox/sc-network-tool-0a1b2c (2 sessions)");
    await expect(optests.locator('[data-incident="0b5e7a10c0ffee02"]')).toBeVisible();

    // What the page withholds although the API sent it (ADR 0021): the title and two details of the leaky incident.
    const leaky = s.locator('[data-incident="e8ec0a7e1de0b0b0"]');
    await expect(leaky).toContainText("Exec outside the API");
    await expect(leaky.locator(".corr-step__detail--withheld")).toHaveCount(2);
    await expect(leaky).toContainText("get pods/exec on sandbox/terminal-7e57000005 not by the API, response 101");
    await expect(s).not.toContainText(/kube-system|coredns|10\.43\.|serviceaccount|k3s01|siem01/i);

    // The rule library: the coverage matrix and every rule's YAML at the commit.
    const matrix = s.locator(".corr-matrix");
    await expect(matrix.locator("thead th")).toHaveText(["Technique", "falco", "talon", "k8s-audit", "hubble", "api", "Incidents"]);
    await expect(matrix.locator('tr[data-technique="T1048.003"] td[data-n="1"]')).toHaveCount(2);
    await expect(matrix.locator('tr[data-technique="T1552.001"] .corr-cell--gap')).toHaveText("1, no rule");
    await s.locator(".corr-rulelist summary").click();
    await expect(s.locator(".corr-rule")).toHaveCount(8);
    await expect(s.locator('.corr-rule a', { hasText: "Sigma YAML" }).first()).toHaveAttribute("href", /^https:\/\/github\.com\/HubertMJ\/self-defending-portfolio\/blob\/0448cff5a1b2c3d4e5f60718293a4b5c6d7e8f90\/siem\/rules\/[a-z-]+\.yml#L1$/);

    // Links only from validated values: the repository, MITRE, the API's own JSON.
    const hrefs = await s.locator("a").evaluateAll((as) => as.map((a) => a.getAttribute("href") ?? ""));
    for (const href of hrefs) expect(href).toMatch(/^(https:\/\/github\.com\/HubertMJ\/self-defending-portfolio\/(blob|commit)\/[0-9a-f]{40}[\w./#-]*|https:\/\/attack\.mitre\.org\/techniques\/T\d{4}\/(\d{3}\/)?|\/api\/runs\/[0-9a-f]{16}|\/api\/correlation)$/);

    // The verify panel lists the two endpoints while they answer.
    await expect(page.locator("#verify-panel .vraw")).toContainText("curl -s https://hubertjablon.ski/api/correlation/rules");
    await page.waitForTimeout(10_000);
    expect(nonGet).toEqual([]);
    expect(problems).toEqual([]);
  });

  for (const wide of [false, true]) {
    const fonts = wide ? " (a wide font forced in)" : "";

    test(`with the section shown, the evidence card stays above the fold at 1280x720${fonts}`, async ({ page, isMobile }) => {
      test.skip(isMobile, "a desktop viewport");
      if (wide) await wideFonts(page);
      await page.setViewportSize({ width: 1280, height: 720 });
      await page.goto(SIEM);
      await expect(section(page)).toBeVisible();
      await expect(page.locator("#evidence-card .evcard")).toBeVisible();
      await hasNoProvenance(page);
      const m = await page.evaluate(() => ({ scrollY: window.scrollY, card: (document.getElementById("evidence-card") as HTMLElement).getBoundingClientRect().top }));
      expect(m.scrollY).toBe(0);
      expect(m.card).toBeLessThan(720);
    });

    test(`no horizontal scroll at 360 and 320 px with the section open${fonts}`, async ({ page }) => {
      await allActivity(page);
      if (wide) await wideFonts(page);
      for (const width of [360, 320]) {
        await page.setViewportSize({ width, height: 780 });
        await page.goto(SIEM);
        if (wide) expect(await page.evaluate(() => getComputedStyle(document.body).fontFamily)).toContain("DejaVu Sans");
        const s = section(page);
        await expect(s.locator(".corr-matrix")).toBeVisible();
        await s.locator(".corr-contained summary").click();
        await s.locator(".corr-healthfold summary").click();
        await s.locator(".corr-rulelist summary").click();
        await nothingPastEdge(page, "#correlation .corr-scenario");
        await nothingPastEdge(page, "#correlation .corr-contained");
        await expect(s.locator(".corr-rule").first()).toBeVisible();
        await noHorizontalScroll(page);
        await nothingPastEdge(page, "#correlation .corr-tier--pinned");
        await nothingPastEdge(page, "#correlation .corr-incidents--other");
        await nothingPastEdge(page, "#correlation .corr-health");
        await nothingPastEdge(page, "#correlation .corr-rulelist");
        await expect(s.locator(".corr-lag")).toBeVisible();
        await nothingPastEdge(page, "#correlation .corr-metrics");
        await nothingPastEdge(page, "#correlation .corr-lag");
      }
    });
  }

  test("hidden while the SIEM says available:false; nothing else is shown, the numbering has no gap", async ({ page }) => {
    const problems = guardConsole(page);
    const asked: string[] = [];
    page.on("response", (r) => {
      if (r.url().endsWith("/api/correlation")) asked.push(String(r.status()));
    });
    await page.goto(NO_SIEM);
    await expect.poll(() => asked).toEqual(["200"]);
    await expect(page.locator("#verify-panel [data-image=\"api\"]")).toContainText("0448cff");
    await expect(section(page)).toBeHidden();
    await expect(section(page).locator(".incident, .tile")).toHaveCount(0);
    expect((await numbered(page)).slice(0, 4)).toEqual(["attack", "how", "about", "evidence"]);
    await expect(page.locator("#verify-panel")).not.toContainText("/api/correlation");
    expect(problems).toEqual([]);
  });

  test("hidden on an API without the endpoint (a JSON 404)", async ({ page }) => {
    const problems = guardConsole(page);
    const asked = page.waitForResponse((r) => r.url().endsWith("/api/correlation"));
    await page.goto("http://127.0.0.1:4176/");
    expect((await asked).status()).toBe(404);
    await expect(page.locator("#evidence-card .evcard")).toBeVisible();
    await expect(section(page)).toBeHidden();
    expect(problems).toEqual([]);
  });

  for (const [label, body, type] of [
    ["not JSON", "<!doctype html><p>not the API</p>", "text/html"],
    ["not an object", "[1, 2, 3]", "application/json"],
    ["available as a string", JSON.stringify({ available: "true", incidents: [] }), "application/json"],
    ["truncated JSON", '{"available": true, "incidents": [', "application/json"],
  ] as const) {
    test(`hidden on a malformed answer (${label})`, async ({ page }) => {
      const problems = guardConsole(page);
      await page.route(/\/api\/correlation$/, (route) => route.fulfill({ status: 200, contentType: type, body }));
      const asked = page.waitForResponse((r) => r.url().endsWith("/api/correlation"));
      await page.goto(SIEM);
      await asked;
      await expect(page.locator("#evidence-card .evcard")).toBeVisible();
      await expect(section(page)).toBeHidden();
      expect(problems).toEqual([]);
    });
  }

  test("?mock=1: the section from the fixtures, hidden with &mock-siem=0", async ({ page }) => {
    await page.goto("/?mock=1");
    await expect(section(page).locator(".incident").first()).toBeVisible();
    expect(await mockCalls(page)).toContain("GET /api/correlation/rules");
    await page.goto("/?mock=1&mock-siem=0");
    await expect.poll(async () => (await mockCalls(page)).includes("GET /api/correlation")).toBe(true);
    await expect(section(page)).toBeHidden();
  });
});

test.describe("the visitor's run, told back (mock, ADR 0035 amendment: UX stage 1)", () => {
  // The mock's SIEM files a run's incidents mock-siem-delay ms (× the speed) after the event; the page
  // asks every 1.5 s while one is awaited.
  const URL = "/?mock=1&mock-speed=0.3&mock-siem-delay=3000";

  test("the strip says each step: ready, waiting for the SIEM, Talon's delete, then the SIEM's catch; Open it pulses the card", async ({ page, isMobile }) => {
    test.setTimeout(60_000);
    const problems = guardConsole(page);
    await page.goto(URL);
    const term = page.locator("#terminal");
    const strip = term.locator(".run-strip");
    const msg = strip.locator(".run-strip__msg");
    await term.getByRole("button", { name: /Open the terminal/ }).click();
    await expect(msg).toHaveText("Pod ready. uid 10001, no network, read-only root. Type a command.", { timeout: 10_000 });
    // The banner's ready moment: "Pod starting" does not stay at the top of the output.
    await expect(term.locator(".term__out")).not.toContainText("Pod starting");
    // One polite live line outside the strip speaks each message; the strip itself is not live.
    await expect(page.locator(".run-status-live")).toHaveAttribute("aria-live", "polite");
    await expect(page.locator(".run-status-live")).toHaveText("Pod ready. uid 10001, no network, read-only root. Type a command.");
    expect(await strip.locator("[aria-live]").count()).toBe(0);

    await term.getByRole("button", { name: "nslookup sdp-<flag>.x.exfil.sdp.test." }).click();
    await expect(msg).toHaveText("Waiting for the SIEM (usually 1–3 min)…");
    // The terminal's own explanation is whole now: the sentence that points at the SIEM.
    await expect(term.locator(".term__explain").last()).toContainText("tying it to this run is the SIEM's job");
    await expect(page.locator("#correlation .corr-scenario__state")).toHaveText("waiting for the SIEM (≈2 min)…");
    await expect(term.locator('.thisrun__row[data-row="siem"] dd')).toHaveText("waiting… (usually 1–3 min)");

    await term.getByRole("button", { name: "cat /etc/shadow" }).click();
    await expect(msg).toHaveText(/^Talon deleted the pod \d+ ms later\. Session over\.$/);
    await expect(strip.getByRole("button", { name: "Watch the kill timeline" })).toBeVisible();
    await expect(strip.getByRole("button", { name: "Run again" })).toBeVisible();
    // The objective the kill paid for is amber, not a green win.
    await expect(term.locator(".term__line--costly")).toHaveText("✓ objective reached: Steal credentials — and it cost you the pod");
    await expect(term.locator('.thisrun__row[data-row="response"] dd')).toContainText("Talon: deleted the pod");

    await expect(msg).toHaveText("The SIEM caught your DNS exfil — CRITICAL. Falco never saw it.", { timeout: 15_000 });
    await expect(term.locator('.thisrun__row[data-row="siem"] dd')).toHaveText("CRITICAL — DNS exfiltration ↓");
    await expect(page.locator("#correlation .corr-scenario__state")).toContainText("found it");
    // The visitor's own incidents have their own heading above the correlation-only tier.
    const own = page.locator('#correlation .corr-tier--own .incident--own[data-kind="dns-exfil"]');
    await expect(own).toHaveCount(1);
    await expect(page.locator("#correlation .corr-tier--own .corr-tier__title")).toHaveText("From your run on this page");
    await expect(page.locator("#correlation .corr-tier--pinned .incident--own")).toHaveCount(0);

    // Away from the terminal and the board, the toast says the same, one slim line on a phone.
    await page.evaluate(() => document.getElementById("how")?.scrollIntoView({ behavior: "instant" }));
    const toast = page.locator(".run-toast");
    await expect(toast).toBeVisible();
    await expect(toast.locator(".run-toast__msg strong")).toHaveText("The SIEM caught your DNS exfil — CRITICAL.");
    expect(await toast.locator("[aria-live]").count()).toBe(0);
    if (isMobile) {
      await expect(toast.locator(".run-toast__text")).toBeHidden();
      await expect(toast.getByRole("button", { name: "Run again" })).toBeHidden();
    } else {
      await expect(toast.locator(".run-toast__msg")).toHaveText("The SIEM caught your DNS exfil — CRITICAL. Falco never saw it.");
    }
    // Its "Open it" lands on the card with its badge and title below the sticky header, pulses it,
    // and the toast has done its job.
    await toast.getByRole("link", { name: "Open it ↓" }).click();
    await expect(own).toBeInViewport();
    await expect(own).toHaveClass(/is-pulsing/);
    await expect.poll(() => page.evaluate(() => (document.querySelector(".incident--own") as HTMLElement).getBoundingClientRect().top - (document.querySelector(".site-header") as HTMLElement).getBoundingClientRect().bottom)).toBeGreaterThanOrEqual(0);
    await expect(toast).toBeHidden();
    // Followed, it stays away for that message, also away from the board again.
    await page.evaluate(() => document.getElementById("how")?.scrollIntoView({ behavior: "instant" }));
    await page.waitForTimeout(300);
    await expect(toast).toBeHidden();
    await noHorizontalScroll(page);

    // "Run again" starts the next session at once (it costs one run).
    const starts = async () => (await mockCalls(page)).filter((c) => c === "POST /api/attack/terminal").length;
    expect(await starts()).toBe(1);
    await strip.getByRole("button", { name: "Run again" }).click();
    await expect.poll(starts).toBe(2);
    await expect(term.locator("#term-input")).toBeEnabled({ timeout: 10_000 });
    expect(problems).toEqual([]);
  });

  test("the SIEM scenario's button opens the terminal with the DNS exfil picked; Enter runs it and the chip follows to 'found it'", async ({ page }) => {
    test.setTimeout(45_000);
    await page.goto(URL);
    const scenario = page.locator("#correlation .corr-scenario");
    await expect(scenario.locator(".corr-scenario__state")).toHaveText("not run yet");
    await scenario.getByRole("button", { name: "Run it in the terminal ↑" }).click();
    const term = page.locator("#terminal");
    await expect(term).toBeInViewport();
    await expect(term.locator("#term-input")).toHaveValue("nslookup sdp-<flag>.x.exfil.sdp.test.", { timeout: 10_000 });
    await expect(term.locator('.term__chip[data-id="dns-exfil"]')).toHaveAttribute("data-suggested", "true");
    await term.locator("#term-input").press("Enter");
    await expect(scenario.locator(".corr-scenario__state")).toHaveText("waiting for the SIEM (≈2 min)…");
    await expect(scenario.locator(".corr-scenario__state")).toHaveText("found it: the CRITICAL incident is below ↓", { timeout: 15_000 });
    await expect(scenario.locator(".corr-scenario__state a")).toHaveAttribute("href", /^#incident-d[0-9a-f]{15}$/);
    // The chip's link lands on the card, its top below the sticky header: followed from the top of the
    // page (a DOM click, so nothing scrolls the board into view first).
    await page.evaluate(() => window.scrollTo({ top: 0, behavior: "instant" }));
    await scenario.locator(".corr-scenario__state a").evaluate((a) => (a as HTMLAnchorElement).click());
    const card = page.locator("#correlation .corr-tier--own .incident").first();
    await expect(card).toBeInViewport();
    await expect.poll(() => card.evaluate((e) => e.getBoundingClientRect().top - (document.querySelector(".site-header") as HTMLElement).getBoundingClientRect().bottom)).toBeGreaterThanOrEqual(0);
  });

  test("layout: beside the terminal only this run, never taller than the terminal; the palette full width with its legend; on a phone one card above the input", async ({ page, isMobile }) => {
    await page.goto(URL);
    const term = page.locator("#terminal");
    await term.getByRole("button", { name: /Open the terminal/ }).click();
    await expect(term.locator("#term-input")).toBeEnabled({ timeout: 10_000 });
    await expect(term.locator(".deflayer")).toHaveCount(0);
    await expect(term.locator(".term__legend li")).toHaveText(["allowed", "Falco answers", "prevented", "only the SIEM sees it"]);
    const box = async (sel: string) => (await term.locator(sel).first().boundingBox()) as { x: number; y: number; width: number; height: number };
    const grid = await box(".term__grid");
    const palette = await box(".term__palette");
    expect(palette.y).toBeGreaterThanOrEqual(grid.y + grid.height - 1);
    expect(Math.abs(palette.width - grid.width)).toBeLessThan(2);
    if (isMobile) {
      const [out, side, form] = [await box(".term__out"), await box(".thisrun"), await box(".term__form")];
      expect(side.y).toBeGreaterThanOrEqual(out.y + out.height - 1);
      expect(side.y + side.height).toBeLessThanOrEqual(form.y + 1);
      await expect(term.locator(".thisrun__body")).toBeHidden();
      await term.getByRole("button", { name: "Details" }).click();
      await expect(term.locator(".thisrun__body")).toBeVisible();
    } else {
      const [pane, side] = [await box(".term__pane"), await box(".thisrun")];
      expect(side.x).toBeGreaterThan(pane.x + pane.width - 1);
      expect(side.y + side.height).toBeLessThanOrEqual(pane.y + pane.height + 1);
      expect(await term.locator(".term__out").evaluate((e) => e.getBoundingClientRect().height)).toBeGreaterThanOrEqual(300);
      // A panel that scrolls says so: the shop folds first, and a fade marks more below.
      const st = await term.locator(".thisrun").evaluate((e) => ({ over: e.scrollHeight > e.clientHeight + 1, atEnd: e.getAttribute("data-at-end"), shop: (e.querySelector(".thisrun__shop") as HTMLDetailsElement).open }));
      if (st.over) {
        expect(st.shop).toBe(false);
        expect(st.atEnd).toBe("false");
      }
    }
  });

  test("on a phone the header carries a jump bar; nothing scrolls sideways at 360 and 320 px with a session and the verify details open", async ({ page }) => {
    await allActivity(page);
    for (const width of [360, 320]) {
      await page.setViewportSize({ width, height: 760 });
      await page.goto("/?mock=1&mock-speed=0.2");
      const nav = page.locator(".site-nav");
      await expect(nav).toBeVisible();
      await expect(nav.locator("a:visible")).toHaveText(["Attack it", "SIEM", "How", "About", "Posture"], { useInnerText: true });
      await page.locator("#terminal").getByRole("button", { name: /Open the terminal/ }).click();
      await expect(page.locator("#term-input")).toBeEnabled({ timeout: 10_000 });
      for (const d of await page.locator("#console details.verify").all()) await d.evaluate((e) => ((e as HTMLDetailsElement).open = true));
      await noHorizontalScroll(page);
      await nothingPastEdge(page, "#terminal");
      // The console's URL bar ends in an ellipsis inside its box; what must fit is the verify body.
      await nothingPastEdge(page, "#console .verify__body");
      await nothingPastEdge(page, ".site-header");
      await nav.getByRole("link", { name: "SIEM" }).click();
      await expect(page.locator("#correlation-title")).toBeInViewport();
    }
  });

  test("reduced motion: the pulse is a steady outline, no animation", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto("/?mock=1");
    await expect(page.locator("#correlation .incident").first()).toBeVisible();
    // Re-queried inside the page: the board may have redrawn since the locator resolved.
    const style = await page.evaluate(() => {
      const e = document.querySelector("#correlation .incident") as HTMLElement;
      e.classList.add("is-pulsing");
      const cs = getComputedStyle(e);
      return { name: cs.animationName, outline: cs.outlineStyle };
    });
    expect(style).toEqual({ name: "none", outline: "solid" });
  });

  test("opened at #correlation or #attack, the page lands there once the live parts have rendered", async ({ page }) => {
    await page.goto("/?mock=1#correlation");
    await expect(page.locator("#correlation-title")).toBeInViewport({ timeout: 10_000 });
    await page.waitForTimeout(1500);
    await expect(page.locator("#correlation-title")).toBeInViewport();
    await page.goto("/?mock=1#attack");
    await page.waitForTimeout(1500);
    await expect(page.locator("#attack-title")).toBeInViewport();
  });
});

test.describe("this session first (mock, ADR 0035 amendment 2026-10-06)", () => {
  const HISTORY_RUN = "a7c3e9f1b2d40658";
  const EXAMPLE = "d15e0f17a1b2c3d4";
  const hist = (page: Page) => page.locator("#timeline-panel");
  const board = (page: Page) => page.locator("#correlation-board");

  test("by default: the prompt and one labelled example in each list; the visitor's own run once launched", async ({ page }) => {
    const problems = guardConsole(page);
    await page.goto("/?mock=1&mock-speed=0.2");
    await expect(page.locator('.scope__opt[data-scope="session"][aria-pressed="true"]')).toHaveCount(3);
    // The run history: the prompt to the terminal, then exactly one earlier visitor's run, labelled.
    await expect(hist(page).locator(".scope-empty")).toHaveText("Nothing from you yet — launch an attack.");
    await expect(hist(page).locator(".scope-empty a")).toHaveAttribute("href", "#attack");
    await expect(hist(page).locator(".run")).toHaveCount(1);
    await expect(hist(page).locator('.run[data-who="example"]')).toHaveAttribute("data-run", HISTORY_RUN);
    await expect(hist(page).locator(".run__who")).toHaveText("Example: an earlier visitor’s run");
    // The hero's card is the same example, after the same prompt.
    await expect(page.locator("#evidence-card .evcard")).toHaveAttribute("data-whose", "example");
    await expect(page.locator("#evidence-card .evcard__prompt")).toHaveText("Nothing from you yet — launch an attack.");
    await expect(page.locator("#evidence-card .evcard__eyebrow")).toHaveText("Example: an earlier visitor’s attack");
    // The board: the prompt, the one example (the critical DNS exfil), the rest counted behind the filter.
    await expect(board(page).locator(".scope-empty")).toContainText("Nothing from you yet");
    await expect(board(page).locator(".incident")).toHaveCount(1);
    await expect(board(page).locator(".corr-tier--example .corr-tier__title")).toHaveText("Example: from an earlier visitor’s run");
    await expect(board(page).locator(".corr-tier--example .incident")).toHaveAttribute("data-incident", EXAMPLE);
    await expect(board(page).locator(".scope-hidden")).toHaveText(/^\d+ more incidents by other visitors: show all activity, last 24 h$/);
    // The aggregates say whose they are.
    await expect(page.locator("#correlation .corr-metrics__title")).toHaveText("SOC figures · last 24 h, all visitors");
    await expect(page.locator("#hero-stats .herostats__label")).toContainText("all visitors, not only yours");
    // No earlier visitor's run on the console or the ticker.
    await expect(page.locator("#console .console__run")).toHaveCount(0);
    await expect(page.locator("#ticker .ticker__item")).toHaveCount(0);
    await expect(page.locator("#ticker .scope-empty")).toHaveText("Nothing from you yet — launch an attack.");

    await page.locator('.scenario[data-scenario="sensitive-file-read"] .btn--attack').click();
    const mine = hist(page).locator('.run[data-who="own"]');
    await expect(mine).toHaveCount(1);
    await expect(mine.locator(".run__who")).toHaveText("Your run");
    await expect(hist(page).locator('.run[data-who="example"]')).toHaveCount(0);
    await expect(hist(page).locator(".scope-empty")).toHaveCount(0);
    await expect(hist(page).locator(".scope-hidden")).toHaveText("1 run by other visitors: show all activity, last 24 h");
    await expect(mine.locator(".chip--state")).toHaveText("Finished", { timeout: 15_000 });
    await expect(page.locator("#evidence-card .evcard")).toHaveAttribute("data-whose", "own");
    await expect(page.locator("#evidence-card .evcard__eyebrow")).toHaveText("Your latest attack, as recorded");
    await expect(page.locator("#console .console__run")).toHaveAttribute("data-run", (await mine.getAttribute("data-run")) ?? "");
    await expect(page.locator("#ticker .ticker__item").first()).toBeVisible();
    // Only the visitor's run is on the ticker.
    expect(await page.locator("#ticker .ticker__text").allTextContents()).toEqual(expect.arrayContaining([expect.stringMatching(/^sensitive-file-read: /)]));
    expect((await page.locator("#ticker .ticker__text").allTextContents()).some((t) => t.startsWith("shell-in-container"))).toBe(false);
    // The tab keeps the id, for a reload.
    const id = await mine.getAttribute("data-run");
    expect(await page.evaluate(() => JSON.parse(sessionStorage.getItem("sdp:own-runs") ?? "[]"))).toEqual([id]);
    // The SIEM has nothing for it yet: the board says so and still shows its one example.
    await expect(board(page).locator(".scope-empty")).toContainText("Nothing filed for your runs yet");
    await expect(board(page).locator(".incident")).toHaveCount(1);
    expect(problems).toEqual([]);
  });

  test("All activity, last 24 h: every copy of the control moves, the history is back, and the choice is kept over a reload", async ({ page }) => {
    await page.goto("/?mock=1");
    await expect(hist(page).locator('.run[data-who="example"]')).toHaveCount(1);
    await page.locator('#correlation .scope__opt[data-scope="all"]').click();
    await expect(page.locator('.scope__opt[data-scope="all"][aria-pressed="true"]')).toHaveCount(3);
    expect(await page.evaluate(() => localStorage.getItem("sdp:scope"))).toBe("all");
    const check = async () => {
      await expect(hist(page).locator(".run")).toHaveCount(1);
      await expect(hist(page).locator(".run[data-who]")).toHaveCount(0);
      await expect(hist(page).locator(".scope-empty, .scope-hidden")).toHaveCount(0);
      await expect(page.locator("#correlation .corr-tier--pinned .incident")).toHaveCount(3);
      await expect(page.locator("#correlation .corr-tier--example")).toHaveCount(0);
      await expect(page.locator("#ticker .ticker__item").first()).toBeVisible();
      await expect(page.locator("#evidence-card .evcard__eyebrow")).toHaveText("Latest attack, as recorded");
      await expect(page.locator("#console .console__run")).toHaveAttribute("data-run", HISTORY_RUN);
    };
    await check();
    await page.reload();
    await expect(page.locator('.scope__opt[data-scope="all"][aria-pressed="true"]')).toHaveCount(3);
    await check();
    // And back: the default view again, the key removed.
    await page.locator('#evidence .scope__opt[data-scope="session"]').click();
    await expect(hist(page).locator('.run[data-who="example"]')).toHaveCount(1);
    await expect(page.locator("#correlation .corr-tier--pinned")).toHaveCount(0);
    expect(await page.evaluate(() => localStorage.getItem("sdp:scope"))).toBeNull();
  });

  test("another visitor's live run shows labelled, then drops out of the default view when it ends", async ({ page }) => {
    test.setTimeout(60_000);
    await page.goto("/?mock=1&mock-visitor=500&mock-speed=0.3");
    const live = hist(page).locator('.run[data-who="live"]');
    await expect(live).toHaveCount(1);
    await expect(live.locator(".run__who")).toHaveText("Someone else is attacking right now");
    const id = await live.getAttribute("data-run");
    expect(id).not.toBe(HISTORY_RUN);
    await expect(hist(page).locator('.run[data-who="example"]')).toHaveCount(0);
    await expect(page.locator("#console .console__who")).toHaveText("Someone else is attacking right now · you are watching it live");
    await expect(page.locator("#evidence-card .evcard__eyebrow")).toHaveText("Someone else is attacking right now");
    await expect(page.locator("#evidence-card .evcard")).toHaveAttribute("data-run", id ?? "");
    // Its events are on the ticker while it runs.
    await expect(page.locator("#ticker .ticker__item").first()).toBeVisible();
    // It ends: no longer live, no longer on the console; the list is back to the prompt and one example.
    await expect(live).toHaveCount(0, { timeout: 30_000 });
    await expect(page.locator("#console .console__run")).toHaveCount(0);
    await expect(hist(page).locator(".scope-empty")).toBeVisible();
    await expect(hist(page).locator(".run")).toHaveCount(1);
    await expect(hist(page).locator('.run[data-who="example"]')).toHaveCount(1);
    await expect(page.locator("#evidence-card .evcard")).toHaveAttribute("data-whose", "example");
  });

  test("after the visitor's terminal session the live run panel points to the terminal, not 'no run of yours'", async ({ page }) => {
    await page.goto("/?mock=1&mock-speed=0.2");
    await expect(page.locator("#console .empty")).toContainText("No run of yours yet");
    await page.locator("#terminal").getByRole("button", { name: /Open the terminal/ }).click();
    await expect(page.locator("#term-input")).toBeEnabled({ timeout: 10_000 });
    await expect(hist(page).locator('.run[data-who="own"]')).toHaveCount(1);
    await expect(page.locator("#console .empty")).toHaveText("Your terminal session is told beside the terminal above; one-click attacks play out here, hop by hop.");
    await expect(page.locator("#console")).not.toContainText("No run of yours yet");
  });

  test("'show all activity' in a hidden-count line makes the choice and focuses that section's control", async ({ page }) => {
    await page.goto("/?mock=1");
    const btn = board(page).locator('.scope-hidden button[data-scope-set="all"]');
    await expect(btn).toHaveText("show all activity, last 24 h");
    await btn.click();
    await expect(page.locator('.scope__opt[data-scope="all"][aria-pressed="true"]')).toHaveCount(3);
    await expect(page.locator('#correlation .scope__opt[data-scope="all"]')).toBeFocused();
    await expect(page.locator("#correlation .corr-tier--pinned .incident")).toHaveCount(3);
    await expect(page.locator(".scope-live")).toHaveText("Showing all activity of the last 24 hours, every visitor's.");
  });

  test("on a phone the history's connection line is a dot and 'live', on one line", async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 760 });
    await page.goto("/?mock=1");
    const conn = page.locator("#timeline-conn");
    await expect(conn).toHaveAttribute("data-state", "open");
    await expect(conn.locator(".conn__text")).toContainText("live");
    const [dot, text] = await Promise.all([conn.locator(".conn__dot").boundingBox(), conn.locator(".conn__text").boundingBox()]);
    expect(dot && text && Math.abs(dot.y + dot.height / 2 - (text.y + text.height / 2))).toBeLessThan(6);
  });

    test("a reload keeps the tab's own runs: their incidents under the own tier, no example; a bad id is ignored", async ({ page }) => {
    await page.addInitScript(() => sessionStorage.setItem("sdp:own-runs", JSON.stringify(["7e57000000000001", "<img src=x>", 42])));
    await page.goto("/?mock=1");
    await expect(board(page).locator(".corr-tier--own .corr-tier__title")).toHaveText("From your run on this page");
    await expect(board(page).locator(".corr-tier--own .incident")).toHaveCount(3);
    expect(await board(page).locator(".incident").evaluateAll((es) => es.every((e) => e.closest(".corr-tier--own")))).toBe(true);
    await expect(board(page).locator(".corr-tier--example, .scope-empty")).toHaveCount(0);
    // The scenario chip still finds this tab's DNS exfil.
    await expect(page.locator("#correlation .corr-scenario__state")).toHaveAttribute("data-phase", "found");
  });

  for (const width of [360, 320]) {
    test(`the SIEM evidence is one line of counts, its ids folded as chips; nothing scrolls sideways at ${width} px`, async ({ page }) => {
      await page.setViewportSize({ width, height: 760 });
      await page.goto("/?mock=1");
      const ev = board(page).locator(`.incident[data-incident="${EXAMPLE}"] details.incident__evidence`);
      await expect(ev.locator("summary")).toHaveText("Evidence: 1 finding · 1 document show IDs");
      await expect(ev.locator(".idchip").first()).toBeHidden();
      await expect(page.locator("#correlation")).not.toContainText("SIEM evidence:");
      await ev.locator("summary").click();
      await expect(ev.locator(".idchip code")).toHaveText(["8f0e6c1e-0d6b-4f7e-9a51-2b7f3c4d5e6f", "Zx3kQ5gBf2mP0aL1rT9e"]);
      await expect(ev.locator('a[href="/api/correlation"]')).toBeVisible();
      await noHorizontalScroll(page);
      await nothingPastEdge(page, "#correlation .incident__evidence");
      for (const s of await page.locator(".scope").all()) await expect(s).toBeVisible();
      await nothingPastEdge(page, "#attack .scope");
      await nothingPastEdge(page, "#correlation .scope");
      await nothingPastEdge(page, "#evidence .scope");
    });
  }
});
