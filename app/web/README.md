# app/web — the site at hubertjablon.ski

Static frontend: the portfolio itself, a live security-posture dashboard, the attack-scenario
launcher and the live timeline (attack → Falco detection → Talon response). TypeScript compiled by
esbuild into content-hashed files, served by nginx-unprivileged from a read-only image. Stack and
CSP rationale: [ADR 0019](../../docs/adr/0019-frontend-stack-and-csp.md).

```
src/index.html         the page (static portfolio content; works without JavaScript)
src/styles.css         all styles, system fonts, dark + light tokens
src/main.ts            wires the live panels
src/theme.ts           tiny blocking script: applies a stored theme before first paint
src/lib/contract.ts    API types and runtime guards (phase 5/6/8 contract: runs, terminal, twin, stats)
src/lib/api.ts         HTTP client: timeouts, 202/404/409/429 + Retry-After; terminal + stats endpoints
src/lib/sse.ts         reconnecting EventSource: backoff + jitter, replay dedup
src/lib/timeline.ts    event log -> runs with latencies, pod/victim/command events, compare arms
src/lib/pipeline.ts    a run's eight pipeline hops, the replay schedule (600 ms dwell) and the kill-timer
src/lib/mock.ts        in-page fake API for ?mock=1, dev and tests (one-click, terminal, twin, stats)
src/lib/fixtures.ts    fixture data incl. the terminal catalogue and stats (shape follows the contract)
src/ui/console.ts      the live run console: pipeline, kill-timer, pod, what was executed, proof, verify
src/ui/terminal.ts     the attacker's terminal (ADR 0033): type commands, stream output, objectives, summary
src/ui/defencemap.ts   the seven-layer defence map; also the terminal's result view
src/ui/twin.ts         the unguarded twin: two shop windows side by side for a ?compare=1 run
src/ui/stats.ts        the hero's live counters and objectives (GET /api/stats)
src/ui/victim.ts       the victim app as a browser window, drawn from the probe's fields (text only)
src/ui/tech.ts         Technical Mode (html[data-tech], .tech-only) and the rate-limit panel
src/lib/dom.ts         the only DOM builder: text nodes, never HTML strings
scripts/strip-todo-content.mjs  removes unwritten [TODO-CONTENT] copy from the production build (FIX 2)
static/                copied verbatim (favicon, robots.txt)
nginx.conf             server config; security-headers.conf is included in every location
test/unit/             vitest (jsdom)
test/e2e/              Playwright smoke tests against the built site
```

## Develop

```sh
npm ci
npm run build && npm run serve    # http://127.0.0.1:4173/?mock=1  (fixture data, simulated runs)
                                  # http://127.0.0.1:4173/         (no API: offline states)
npm run dev                       # rebuild on change (index.html changes need a restart)
```

Mock mode is also available on the live site with `?mock=1` and is announced by a banner; it never
calls the API. Extra knobs: `&mock-speed=0.2` (faster runs), `&mock-limit=1` (hit the 429 sooner),
`&mock-stream-refuse=3&mock-stream-retry-after=2` (the event stream is refused with 429 first),
`&mock-stream-stall=1` (the first accepted stream delivers nothing and dies), `&mock-visitor=500`
(another visitor starts a quarantine run after 500 ms, watched read-only), `&mock-term-visitor=500`
(another visitor starts a *terminal* run, watched read-only) and `&mock-details=0`
(no /api/scenarios/{id}/details, as an API without the extension). `serve.mjs --stub-events` replays
one full run with every event type over a real event stream.

The terminal, the unguarded twin (the "With & without the response" button on a one-click card) and
the hero's live counters are all simulated in mock mode from `src/lib/fixtures.ts`, so the whole
interactive front end runs without a cluster.

## Check

```sh
npm run lint        # tsc --noEmit + no HTML/code DOM sinks in src/
npm test            # unit tests
npm run test:e2e    # build + Playwright (Chromium) against scripts/serve.mjs
npm run todo-content  # placeholder copy still to be written (add --strict to fail on it)
```

Playwright uses its own Chromium if `npx playwright install chromium` was run, otherwise
`PW_CHROMIUM_PATH` or `/opt/pw-browsers/chromium`. To test the real image instead of the Node
server:

```sh
docker build -t sdp-web:local app/web
docker run --rm -d --name sdp-web --read-only --tmpfs /tmp --user 101 --cap-drop ALL -p 8080:8080 sdp-web:local
BASE_URL=http://127.0.0.1:8080 npx playwright test
```

The image build runs `npm run lint` and `npm test` in its first stage, so a failing unit test fails
the build in CI too.
