# Integration review of `interactive-web` (e727a1f) — fixes for the WEB session

Locally: `npm ci` (0 vulnerabilities), lint clean (no DOM sinks), 109 unit and 46 e2e tests green, production build
without placeholders. Found sound: no HTML or code sink anywhere in the new code, only catalogue ids reach the
API, the token lives in memory only, CSP/Trusted Types/nginx untouched, guards hold against the real API's
payloads, FIX 2 and FIX 3 delivered, the one-click scenarios kept.

The terminal, twin and stats were only ever exercised against the mock, and the mock differs from the real API
exactly where the defects below are. The other two branches are now pushed: before you fix anything, read them
(`git fetch origin interactive-api interactive-cluster`):
- real catalogue: `origin/interactive-cluster:cluster/infra/sandbox/scenarios/scenarios.yaml`, scenario `terminal`
  (5 objectives: recon, tamper, credentials, execution, exfiltration; 14 commands);
- real API: `origin/interactive-api:app/api/internal/{server,runner,stats}`; ADRs 0029, 0030.
**Make the mock behave like that API and its fixture be that catalogue**, then fix on `interactive-web`, same rules
as before (owner authorship, no AI attribution, no PR, small commits). Every fix needs a test that fails before it.

## Wrong against the real API (the mock hides each of these)
1. **The session summary is wrong whenever Talon kills the pod.** For `cat /etc/shadow` the real API emits
   `exited` (exit 0, `achieved: true`) — `cat` finishes before the delete — and only then `responded` and
   `finished` with `detail: "killed"`; `drop-run` and probably `sh -i` do the same. The mock emits a `killed`
   command state for every terminate command. Result live: "The session ended.", no "Killed after your Enter".
   Decide the outcome from the run's `detail` and its `responded` events, not from a `killed` command state, and
   compute "killed N ms after your Enter" as the contract says: time of the response (run `responded`, or the
   talon event carrying `command_seq`) minus the `started` of the command it belongs to; show Falco-to-response
   next to it. `command_seq` is parsed today and used nowhere.
2. **Commands are offered before the pod is ready.** The session UI (focused input, live chips, "Connected to a
   fresh pod") appears at the 202, i.e. at `queued`; the API answers 409 until `pod_ready`, so every visitor's
   first tap prints "a command is still running, or the session is over". Show a starting state until the run's
   `pod_ready`, then enable; a 409 before that is not an error to print.
3. **Chip groups are out of order**: the API sends `"objective": ""` for commands without one; `?? "other"` keeps
   `""`, `indexOf` is -1, and "Other moves" sorts first. Treat an empty objective as none.
4. **Twin counter**: "attacker has held this pod N s" does not tick (the panel re-renders only on a victim status
   change, and the real API publishes victim events on change only) and freezes about a second in. Tick it from a
   timer between the unguarded arm's first non-`up` victim event and the run's end. The API will end a compare run
   only when both arms are gone, so `finished` is the stop.
5. **Compare runs mix the two arms**: `falco[0]` may be the unguarded pod's alert (the kill-timer then pairs the
   unguarded syscall with the guarded response), `created`/`running` may come from the unguarded pod, and `addPod`
   overwrites UID, container and image with whichever arm reported last. Pipeline, kill-timer and pod panel use
   events with `arm: "guarded"` (or no arm) only; the unguarded arm feeds only its own window.
6. **Hop 8 and the proof card take the first `unreachable` of the run**, not the first after the quarantine label
   (`pipeline.ts:65`, `console.ts:555`); a transient probe timeout before the label lights hop 8 before hop 7.
7. **Objective counts**: the page prints "reached by {achieved} of {attempts} runs that tried"; the API will count
   each objective once per run, with `attempts` = runs that tried it. Keep the wording true to that, and show an
   objective nobody reached as "0 of N", not hidden.
8. **Joining mid-session shows nothing**: the stream replays a limited number of events, so a visitor who arrives
   during a long terminal run gets `command` events for a run the page never saw start (they go to `unmatched`),
   and output lost across a reconnect of one's own session is never recovered. On events for an unknown `run_id`,
   and after a reconnect during a session, backfill from `/api/runs/{id}` (dedupe by `seq` and event id).

## State and lifecycle
9. **A second watched session renders blank**: `renderedSeq` and `endedShown` are reset only in `start()`, not in
   `renderSessionReadOnly`; after watching run A (3 commands), run B's first three commands are never drawn and
   its summary never appears. Key all per-session state by run id.
10. **DELETE is never sent** (`api.leaveRun` has no caller) although ADR 0033 says leaving ends the run: a closed
    tab holds the single global slot until the 30 s idle timeout. Add an explicit "exit" (typed and a button), and
    send DELETE on `pagehide` (`fetch` with `keepalive`). If `attackTerminal` times out on the client after the
    server accepted, the visitor is left watching their own run read-only: say so plainly instead.
11. After the session ends, chips and Run stay active and print 409/404 lines; a line typed during a running
    command is cleared and its error lands under the still-streaming block; the idle start button never refreshes
    its blocked state and a blocked click does nothing; `launcherState.cooldownUntil` is never set, so a 429
    cooldown is not shown; a 429 from the request limiter says "you have run too many commands", 400/403 say
    "the API is not reachable". Fix each.
12. A watcher's page jumps: `renderSummary` calls `scrollIntoView` when someone else's session ends. Scroll only
    for the visitor's own session.
13. `run_id` from the 202 is used in a URL unvalidated (`..` would redirect the Bearer header to another same-origin
    path): require the id pattern the API uses. `parseCommands` de-duplicates by id only: reject a catalogue where
    an `input` or alias is claimed twice, and inputs that are empty or not printable ASCII. `stats.ts:32` reads
    `s.objectives[id]` without an own-property check ("constructor" prints "undefined of undefined").
14. Polling: stats are fetched every 60 s forever, even after a 404, and the terminal details with them; posture
    is fetched three times on load. Back off after a 404 and fetch once.

## What the visitor sees (from screenshots of mock mode, light and dark, desktop and phone)
15. **The session summary is unreadable in the light theme**: the four result tiles ("3 of 6", "5.8 s",
    "240 ms") and the titles of the layer cards are light text on a light panel. Check every new component in
    both themes.
16. **The defence map in the summary attributes commands wrongly**: "Runtime — detected — ended the session"
    lists the defacement and the flag read (both allowed), "Pod security — prevented" lists `id`. Show each
    command under its own layer with its own verdict; "ended the session" only for the command that did; a
    quarantine does not end the session. Badges and titles wrap mid-word in the narrow cards ("prevente d",
    "Admissio n").
17. **Layers light only in the end-of-session summary.** The contract: every finished command lights its layer
    with the verdict and the control text. Light the map as each command finishes, during the session.
18. **The hero tile "3 of 412 call-homes that got out — the rest were cut off by Cilium" must go**: the contract
    rules out an escapes counter, `runs - responded` counts timeouts, and the call-home command fails on loopback
    by connection refused, not by Cilium. Use the objectives ("Phone home: reached in 0 of N sessions") and
    `unanswered` as defined by the API. `ui-ext.test.ts:55` asserts the wrong wording. The fourth tile wraps alone
    onto a second row at 1360 px. The hero must also show the last real run (scenario, when, response time), not
    only `response_ms.last`.
19. `.term` is defined twice (`styles.css:1921` and `:2807`): the console's "what was executed" block and the
    cosign block inherit the terminal's grid, the terminal root inherits the old dark box. Rename the new one.
20. Against the current live API (no new endpoints) the main section shows "The terminal is not available … HTTP
    404 · Retry now" under the heading "Your hands on the pod" and the hero button "Open the terminal", and
    "With & without the response" silently runs an ordinary run. When the API lacks the terminal or compare, do
    not offer them: fall back to the one-click scenarios as the main section.
21. "120-second deadline" is hard-coded (the API will send `timeout_seconds` in the details); "You are uid 10001…"
    shows even when watching someone else; a terminal run in the history shows "detected after N s" that is the
    visitor's dwell time, and its "Show" button does nothing.

## Accessibility
22. **The output log floods screen readers**: `.term__out` is `role="log" aria-live="polite"` and every SSE event
    of any kind rebuilds the last command block, re-announcing the whole command; the status line is rewritten on
    every event; this continues after the session ends. Append only new text; change nothing when nothing changed.
    `#hero-stats` is a live region replaced every 60 s: not live.
23. The input's accessible name is only its placeholder; Tab is captured whenever the text matches a completion,
    so a full match traps focus; completion hints are not announced.

## Hardening
24. `stripControl` keeps CR and does not remove bidi overrides/isolates, zero-width characters or the tail of an
    ANSI sequence, though its comment and ADR 0033 say it mirrors the API's scrub; `.term__line` has no
    `unicode-bidi: isolate`. Match the API's rule and isolate each line.
25. **`scripts/strip-todo-content.mjs`**: it removes a whole element when any marker remains inside it, so an
    About block with one paragraph written and one not loses the written one, silently; it loops forever on
    `data-todo-content` with no value or a single-quoted value (the build hangs); it stops silently, shipping
    later placeholders, at an implicitly closed `<p>` or a tag inside a comment; it turns `data-todo-section=""`
    into `<section="">`; today's build ships "About me" as a heading with nothing under it. Remove only the
    elements that still are placeholders, fail the build loudly on anything it cannot parse, drop a section whose
    content is all gone, and unit-test these cases.
26. `?mock=1` on production shows fixture counters under "Live, across every visitor" next to "cluster live", and
    `/?mock=1#attack` scrolls past the banner. In mock mode the header must say mock, the stats label must not say
    live, and the banner must stay in view.

## Tests
27. No unit test covers `mountTerminal`, `timeline.addCommand`, `isCommandEvent`, `parseCommands`, `parseStats`,
    `stripControl`, `renderTwin` or the stripper. "Unknown input never calls the API" is asserted only by the
    local message: assert that no request was made. "Output is text" is tested with static strings only: feed
    markup-like and control-character output through to `.term__out`. Read-only watching checks only that the
    input is hidden: assert no chips, no form, no POST. Add an e2e run against a server that answers like the
    current live API (JSON 404 on the new endpoints) and one that replays real-API-shaped event sequences
    (exited-then-killed-run, 409 before `pod_ready`, quarantine then terminate, compare with both arms).

Run `npm run lint`, `npm test`, `npm run test:e2e`, look at screenshots in both themes and at phone width, and
report per item above: done or not done and why.
