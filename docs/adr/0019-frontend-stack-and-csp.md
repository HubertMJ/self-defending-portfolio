# ADR 0019: Frontend stack and Content Security Policy: vanilla TypeScript + esbuild, no third-party origins, Trusted Types

Date: 2026-10-01 · Status: accepted

## Context
Phase 6 replaces the one-page placeholder in `app/web` with the real site: the portfolio, a live
posture dashboard (`GET /api/posture`), a scenario launcher (`POST /api/attack/{id}`) and a live
timeline fed by Server-Sent Events (`GET /api/events`). The page is the public face of a project
whose subject is security, so it must hold to the same standard as the cluster under it: a strict
CSP, no third-party requests, nothing that cannot be reviewed and pinned, and an image that keeps the
phase 3 properties (nginx-unprivileged pinned by digest, non-root, read-only root filesystem,
Trivy-gated, SBOM'd, keyless-signed by the image workflow, ADR 0011 and ADR 0016).

The page also renders text that an attacker shapes: Falco's `output` field contains the command line
of the process that triggered the rule. A visitor chooses which scenario runs, and a future scenario
or a compromise of the sandbox could put arbitrary strings into that field. The timeline is
therefore an XSS surface by design, not by accident.

Options considered for the stack: a framework (React/Preact/Svelte with Vite), a no-build page of
hand-written ES modules, and plain TypeScript bundled by esbuild. For the CSP: the existing policy in
the HTTPRoute (`script-src 'none'; style-src 'self' 'unsafe-inline'`), a nonce-based policy, and a
`'self'`-only policy with Trusted Types.

## Decision

**Plain TypeScript, bundled by esbuild, no runtime dependencies.** The UI is four panels that
re-render from small pieces of state; a framework's component model would cost more in supply chain
(a runtime dependency tree shipped to every visitor, and its build plugins in CI) than it saves in
code. esbuild is a single pinned binary that compiles TypeScript and CSS and emits content-hashed
file names. Dev-only tools (TypeScript, Vitest, Playwright, jsdom) are pinned exactly in
`package.json` and locked with integrity hashes in `package-lock.json`; none of them is in the
image. A no-build page was rejected because it gives up type checking of the API contract and hashed
file names, which the cache policy below depends on.

**Two-stage image.** `app/web/Dockerfile` gains a `node` builder stage (pinned by tag and digest,
ADR 0008) that runs `npm ci --ignore-scripts`, the type check, the DOM-sink check and the unit tests,
then builds. Only `dist/` is copied into the unchanged nginx-unprivileged stage, so the shipped image
has no Node, no `node_modules` and no sources; Trivy, the SBOM and the signature cover the same kind
of artefact as before. Because the build happens inside the Dockerfile, the image workflow
(`build-images.yml`, ADR 0016) needs nothing web-specific beyond the browser end-to-end gate.

**Every byte from our own origin.** No CDN, no web fonts (system font stacks), no analytics, no
third-party images. The only external links are plain `<a>` navigations (GitHub, MITRE ATT&CK).

**CSP, served by nginx from `app/web/security-headers.conf`:**

```
default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self';
connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none';
frame-ancestors 'none'; object-src 'none'; require-trusted-types-for 'script'; trusted-types 'none'
```

- `default-src 'none'` and an explicit allow-list: anything not named is refused.
- `script-src 'self'` with no `'unsafe-inline'` and no nonce: the HTML contains no inline script or
  event handler, and a Playwright check fails if one appears. Nonces were rejected because
  they need a per-response template step in nginx for no benefit when nothing is inline.
- `style-src 'self'`, no `'unsafe-inline'`: the placeholder page's inline `<style>` is gone; dynamic
  values (bar widths) are set through CSSOM custom properties, which CSP does not restrict.
- `connect-src 'self'`: the API, including the SSE stream, is same-origin (`/api/*` routed by the
  Gateway to the API service), so nothing else may be fetched.
- **Trusted Types enforced** (`require-trusted-types-for 'script'; trusted-types 'none'`): every DOM
  write goes through `src/lib/dom.ts`, which only creates elements and text nodes. Assigning a
  string to `innerHTML` or any other script sink throws in Chromium-based browsers instead of
  parsing it. `scripts/check-dom-sinks.mjs` fails `npm run lint` (and the image build) if such a sink
  appears in `src/`, so the guard holds in browsers without Trusted Types too.
- `frame-ancestors 'none'` plus `X-Frame-Options: DENY` for older browsers; `base-uri` and
  `form-action` closed.

The other response headers (`nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP, CORP) are
set alongside it. **HSTS is not set by nginx**: TLS terminates at the Cloudflare edge and again at
the Gateway, which both already send `Strict-Transport-Security`; the pod only ever speaks plain
HTTP inside the cluster.

**Headers in the image and at the Gateway.** ADR 0010 put the headers in the HTTPRoute so they apply
to every backend. That stays, but the HTTPRoute's `ResponseHeaderModifier` uses `set`, so its CSP
replaces nginx's in the cluster, and its current value (`script-src 'none'`) would block this page
outright. The HTTPRoute's CSP is therefore the policy above, character for character, changed in the
same commit that points hello at this image; `scripts/check-web-csp.sh` (`make validate`, CI) fails
if the two ever differ. The route keeps its own CSP rather than dropping it, so any other backend
attached to the Gateway still gets a policy (ADR 0010). Setting the headers in nginx as well
means the image is safe on its own — in `docker run`, in the Playwright suite, behind any other
proxy — and the suite tests the policy the page will actually get. `scripts/serve.mjs` (the local
and test server) parses `security-headers.conf`, so the policy has one source in `app/web`.

**Caching.** `/assets/*` names carry a content hash and are served
`Cache-Control: public, max-age=31536000, immutable`; everything else (`index.html`, favicon,
robots.txt) is `no-cache` (revalidated via ETag), so a deploy reaches every returning visitor on
their next load.

**nginx never serves `/api`.** `location ^~ /api/` answers a plain-text 404 (and POSTs get the
server-wide 405). If the Gateway's `/api` route is ever missing, the page sees a non-JSON answer and
shows its offline state; nginx can never be mistaken for the API.

**Graceful degradation and mock mode.** The portfolio content is static HTML and renders without
JavaScript. Each live panel fails independently into an explicit offline state with a retry button;
the SSE client reconnects with capped exponential backoff and full jitter (EventSource gives up for
good on a non-200 response, which is exactly what happens while the API is down), resets the
backoff only after a connection has stayed up, drops events the server replays on reconnect, and
disconnects while the tab has been hidden for a minute. `?mock=1` swaps the fetch function and the
EventSource factory for an in-page fake that follows the contract (including 409 and 429 with
`Retry-After`) and is announced by a banner; it is how the page is developed and how Playwright
exercises it without a cluster.

## Consequences
- The CSP is stricter than the placeholder's (no `'unsafe-inline'` styles) while allowing the
  scripts the site now needs, and an HTML-injection bug in the timeline becomes a thrown exception
  rather than an XSS in current Chromium.
- One more base image to pin and bump (`node` builder). It never ships, but a compromised builder
  could alter `dist/`; the digest pin and `npm ci` against a lockfile with integrity hashes are the
  controls, and Renovate will propose bumps once enabled (ADR 0008).
- With the phase 3 route CSP this image would render the static content but no live panels (scripts
  blocked), so the route's CSP and hello's digest change in one commit, and the CSP check keeps them
  from drifting apart afterwards.
- The image build now runs the unit tests; the Playwright suite needs a browser and runs as a
  step of `build-images.yml` before the image is built (ADR 0016), or locally (`npm run test:e2e`).
- Mock mode ships in the production bundle (a few KB minified). It cannot reach the API and is visibly
  labelled, so it adds no capability a visitor did not already have.

## Amendment 2026-10-01: an error is never cacheable, and what a rollout may still show

**What happened.** The first rollout of a new web digest left the live page without JavaScript.
During the rolling update (two replicas, `maxSurge: 1`) a visitor got the new `index.html` from a
new pod and then asked an old pod for the new `/assets/main-<hash>.js`, which it does not have. nginx
answered 404 - with `Cache-Control: public, max-age=31536000, immutable`, because the `/assets/`
location added that header with `always`, which applies it to every status. The Cloudflare edge
cached that 404 for a year and served it to every visitor until the URL was purged by hand.

**Decision.**
- `Cache-Control` is chosen by status (`map $status` in `nginx.conf`): the long-lived immutable
  policy for a 200 or 304 under `/assets/`, `no-cache` for a 200 or 304 of a page, and `no-store`
  for every other status in both locations. The dev server (`scripts/serve.mjs`) does the same, the
  Playwright suite asserts it, and `test/image-smoke.sh` asserts it on the real image; the image
  workflow runs that smoke test after the push and before signing (ADR 0016), so an image that would
  cache an error is never admitted.
- Version skew during a rollout is accepted rather than engineered away. With errors uncacheable and
  `index.html` revalidated on every load, the worst a visitor can see is one page view without the
  live panels during the seconds both versions serve, and a reload fixes it; the static portfolio
  content renders without JavaScript anyway. Considered and not done: shipping the previous release's
  hashed assets in each image (needs the previous digest at build time, a second image as a build
  input, and a policy for how many releases to keep), and `strategy: Recreate` for hello (a visible
  outage on every deploy, which is worse than the skew it removes).
- The edge gets one manual rule (docs/bootstrap.md, 7.3): caching of `/assets/*` follows the origin's
  `Cache-Control` and never applies to 4xx/5xx, so a future origin mistake cannot be amplified for a
  year either.
