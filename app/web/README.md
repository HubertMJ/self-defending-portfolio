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
src/lib/mock.ts        in-page fake API for ?mock=1, dev and tests only (one-click, terminal, twin, stats)
src/lib/mock-hook.ts   the page's only way to the mock; the production build swaps in mock-hook.prod.ts (null)
src/lib/fixtures.ts    fixture data: scenarios, posture, stats, what each terminal command prints in the mock
src/lib/terminal-catalogue.json  the mock's terminal catalogue, generated from the cluster's scenarios.yaml
src/lib/backfill.ts    when to fetch a run's history from /api/runs/{id} (mid-session join, reconnect)
src/ui/console.ts      the live run console: pipeline, kill-timer, pod, what was executed, proof, verify
src/ui/terminal.ts     the attacker's terminal (ADR 0033): type commands, stream output, objectives, summary
src/ui/defencemap.ts   the seven-layer defence map; also the terminal's result view
src/ui/twin.ts         the unguarded twin: two shop windows side by side for a ?compare=1 run
src/ui/stats.ts        the hero's live counters and objectives (GET /api/stats)
src/ui/victim.ts       the victim app as a browser window, drawn from the probe's fields (text only)
src/ui/tech.ts         Technical Mode (html[data-tech], .tech-only) and the rate-limit panel
src/lib/dom.ts         the only DOM builder: text nodes, never HTML strings
scripts/strip-todo-content.mjs  removes unwritten [TODO-CONTENT] copy from the production build (FIX 2)
scripts/terminal-catalogue.mjs  writes src/lib/terminal-catalogue.json from scenarios.yaml (--check: drift)
static/                copied verbatim (favicon, robots.txt)
nginx.conf             server config; security-headers.conf is included in every location
test/unit/             vitest (jsdom)
test/e2e/              Playwright smoke tests against the built site
```

## Develop

```sh
npm ci
npm run build:mock && npm run serve -- --dir dist-mock   # http://127.0.0.1:4173/?mock=1  (fixture data, simulated runs)
                                                         # http://127.0.0.1:4173/         (no API: offline states)
npm run build && npm run serve                           # the production bundle (dist/, no mock)
npm run dev                       # rebuild the mock build on change (index.html changes need a restart)
```

The mock is dev/test only (ADR 0035). `npm run build` (dist/, what the image ships) does not contain
it: the build resolves `src/lib/mock-hook.ts` to a stub that returns null and cuts the mock banner
from index.html, and `test/unit/bundle.test.ts` fails if any of the mock's markers reach the
production bundle. `npm run build:mock` writes the same page with the mock into dist-mock/, where
`?mock=1` turns it on, announced by a banner; it never calls the API. Extra knobs: `&mock-speed=0.2` (faster runs), `&mock-limit=1` (hit the 429 sooner),
`&mock-stream-refuse=3&mock-stream-retry-after=2` (the event stream is refused with 429 first),
`&mock-stream-stall=1` (the first accepted stream delivers nothing and dies), `&mock-visitor=500`
(another visitor starts a quarantine run after 500 ms, watched read-only), `&mock-term-visitor=500`
(another visitor starts a *terminal* run, watched read-only), `&mock-no-response=1` (Talon never
answers a terminal command, so `sh -i` runs into its 10 s bound) and `&mock-details=0`
(no /api/scenarios/{id}/details, as an API without the extension). `serve.mjs --stub-events` replays
one full run with every event type over a real event stream; `--live-api` answers like the API
deployed today (a JSON 404 for the terminal and `/api/stats`, `?compare=1` ignored); `--terminal-api` replays another
visitor's terminal session joined mid-way, exactly as the interactive API publishes it (with
`--slow-details`, its catalogue answers 1.5 s late).

The terminal, the unguarded twin (a one-click card's main button, "Launch side by side", whenever the
API knows `?compare=1`; "Guarded pod only" beside it runs the one defended pod) and
the hero's live counters are all simulated in mock mode from `src/lib/fixtures.ts`, so the whole
interactive front end runs without a cluster.

## Check

```sh
npm run lint        # tsc --noEmit + no HTML/code DOM sinks in src/
npm test            # unit tests
npm run test:e2e    # both builds + Playwright (Chromium) against scripts/serve.mjs: the ?mock suite on
                    # dist-mock/ (port 4173), the stub-API suites on the production dist/ (4174-4177)
npm run todo-content  # placeholder copy still to be written (add --strict to fail on it)
npm run catalogue -- <path to cluster/infra/sandbox/scenarios/scenarios.yaml>   # regenerate the mock catalogue
SDP_SCENARIOS_YAML=<that path> npm test                                         # ...and fail if it drifted
```

Playwright uses its own Chromium if `npx playwright install chromium` was run, otherwise
`PW_CHROMIUM_PATH` or `/opt/pw-browsers/chromium`. To test the real image instead of the Node
server:

```sh
docker build -t sdp-web:local app/web
docker run --rm -d --name sdp-web --read-only --tmpfs /tmp --user 101 --cap-drop ALL -p 8080:8080 sdp-web:local
BASE_URL=http://127.0.0.1:8080 npx playwright test
```

The image has no mock, so against it the `?mock` tests fail by design; the stub-API tests still run
against this checkout's dist/.

The image build runs `npm run lint` and `npm test` in its first stage, so a failing unit test fails
the build in CI too.
