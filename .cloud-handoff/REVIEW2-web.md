# Second review of `interactive-web` (d31d638) — remaining fixes

Locally: lint clean, 126 unit and 52 e2e tests green. Of the 27 items in REVIEW-web.md: 9 fixed, 14 partly, 4 not
fixed. Each point below was reproduced by driving `mountTerminal` with the real API's event sequences or by
running the stripper. Same rules as before (owner authorship, no AI attribution, no PR, small commits). The API is
at `origin/interactive-api` (fetch it again: it has been revised), the catalogue at
`origin/interactive-cluster:cluster/infra/sandbox/scenarios/scenarios.yaml`.

ADR 0033's review amendment claims three things the code does not do (the twin counter ticks; the mock catalogue
is the real one; the new components are covered by tests). Make the code do them, then keep the sentences.

## Defects
1. **Quarantine then terminate gives the wrong summary** (terminal.ts:500-501, 562). `enderSeqOf` and `respAt`
   take the first guarded Talon event and `run.states.responded` is the earliest. Sequence: `wget` (exit 1) ->
   talon label `command_seq=1` -> `responded quarantine`; later `cat /etc/shadow` exits 0 -> talon terminate
   `command_seq=2` -> `finished killed`. Shown: `wget` "ended the session", `cat /etc/shadow` not, and "Killed
   after your Enter 800 ms" is the quarantine's latency. The session is ended by the response that terminates:
   the last `responded` whose action is terminate (run events now carry `command_seq`, which `contract.ts:488`
   drops — read it), matched to its own command; the quarantine is its own line. With no `command_seq`, fall back
   to the last command started before that response, and never print 0 ms.
2. **`exited` without `exit_code` counts as unfinished** (terminal.ts:441, 487). The API sends that when a command
   hit its 5 s timeout, on leave, and at the deadline under a TTY shell. The page waits for `exitCode` or
   `killed`: no footer, no explanation, layer never lit. Treat `exited` as finished; say "timed out" or "ended
   with the session" when there is no code.
3. **Backfill duplicates and loses output** (terminal.ts:433-436): `appendCommand` appends
   `stdout.slice(previousLength)`, assuming output only grows at the end. A backfilled middle chunk turns
   `AAA CCC` into `AAA CCC CCC` and `BBB` never shows; a wholly missing command is appended after later ones.
   Order output by the event's stream id (dedupe by id, not by payload: ui/timeline.ts:223) and rebuild a command
   block when its history changed.
4. **The twin counter still does not tick** (twin.ts:22-24 computes `now` only when rendered; console.ts:710
   re-renders only on a victim key change). Item 4 of the first review, untouched.
5. **The idle panel is rebuilt on every SSE event** (terminal.ts:624-627): the start button is replaced each time,
   so keyboard focus is lost and the "Rate limit reached" / "Another run is in progress" notes vanish on the next
   event; nothing refreshes the label when a cooldown ends on a quiet page. The hero stats also redraw on every
   event (main.ts:141-148). Render only on change.
6. **A mid-session join is missed when the replay holds any event of that run** (timeline.ts:175, 234): with
   `responded` but no `queued`/`started` the run has start 0, reads as inactive, its commands are attributed to it
   (so nothing is `unmatched` and no backfill fires): no watcher view, launcher not locked. Backfill whenever a
   run lacks its start. After a failed backfill (404, network) do not refetch on every render (main.ts:124): once,
   then back off. A tab hidden for 60 s and shown again reports "connecting", not "reconnecting", so no backfill
   is due (main.ts:180, sse.ts:159): backfill then too.
7. **Input locks if `exited` arrives before the 202** (terminal.ts:348, 398-404): `pendingSeq` is set after the
   POST resolves and cleared only by a later event; with nothing else arriving the lock holds until the idle
   timeout. Resolve it when either arrives.
8. **Against an API without the new endpoints nothing changed** (item 20): "Your hands on the pod" and the hero's
   "Open the terminal" stay (index.html:69, 103) above a "not available" note, and "With & without the response"
   still silently starts an ordinary run (scenarios.ts untouched). Offer the terminal and compare only when the
   API has them; otherwise the one-click scenarios are the main section and the hero button says so.
9. **The production build still ships an empty About** ("About me" followed by nothing) and the stripper still
   drops a written paragraph from a block that has one written and one not, silently; its only unit test uses
   per-paragraph markers, a structure `src/index.html` does not have. Test it on the real file's structure. A
   section with no content left is removed together with its nav link; a single-quoted `class='todo-content'`
   and a stray `[TODO-CONTENT:` outside an attribute must fail the build.
10. **Mock and fixtures still differ from the real API and catalogue**: `deface` input is "deface the shop"
    instead of the real 80-character line, and its victim payload has a title and banner the real `state.json`
    lacks (check the shop window renders sensibly without them); `caps`, `touch-bin`, `chown-root` have other
    `control`/`explain` text; run `detected`/`responded` carry no `command_seq`; no `exited` without a code; the
    unguarded arm sends a same-status probe at 6000 ms the real API would not (it hides item 4); leave after the
    end answers 202 (real: 409); the stats fixture contradicts per-run counting (recon attempts 121 with 37
    terminal runs; execution 0 achieved although `drop-run` exits 0). Generate the fixture catalogue from the
    cluster branch's file instead of retyping it.
11. **Tests**: the two "no POST" e2e assertions cannot fail (mock mode answers through an in-page `mock.fetch`, so
    `page.on("request")` sees nothing): assert on the mock's own call log or use the stub server. Still missing:
    any unit test of `mountTerminal` and the summary (single terminate; quarantine then terminate; left, idle,
    deadline; exited without a code), `renderTwin` with a ticking clock, markup-like and control-character output
    rendered into `.term__out`, and the deferred e2e runs against a server that answers like the current live API
    (JSON 404 on the new endpoints) and one that replays real-API event sequences. The `parseStats` own-property
    test is tautological.

## Smaller
12. Hop 8 and the `gone` hop are not filtered by arm (pipeline.ts:69-70). Typing `exit` is still "not in
    catalogue". After a client timeout on a start the server accepted, the page says "watching another visitor"
    with no explanation. A 429 from the request limiter still says "the most commands a session allows" (the two
    429s differ only in the body: read it). A click on a blocked start button does nothing. Leave stays active
    after the end; `pagehide` sends DELETE after the end and again after a bfcache restore. Chips are not disabled
    before `pod_ready` or after the end, and a chip clicked before the 202 sends a second POST. Watchers see
    second-person wording and the "You are uid 10001" banner; `failed`/`timeout` show "The session ended." with no
    reason. "Survived" counts from pod creation, not from `pod_ready`.
13. Stats still poll forever after a failure and the terminal details are fetched on every refresh; with no last
    run, tiles 1 and 2 both show `s.runs`; the herostats grid is unchanged, so the fourth tile still wraps alone;
    the objectives line says "tries" where the API counts runs.
14. Tab is trapped on a complete spelling that is also a prefix (`ps`, `wget`); the hint toggles `aria-live` in
    the same tick as its text. `unicode-bidi: isolate` on a block `<p>` does nothing: use `plaintext` or `dir`.
    `runEvents` builds its URL from an unvalidated `run_id`. A `__proto__` key in stats rewrites the parsed
    object's prototype. `/?mock=1#attack` still scrolls past the mock banner.

## One cross-side point to state on the page, not to change
The API counts an objective as reached when its command exits 0. `cat /etc/shadow` and the dropped binary exit 0
before the kill, so "Steal credentials" and "Run your own code" will show as reached on nearly every attempt.
That is the truth the terminal already teaches (detection is not prevention): make the objectives line say what
"reached" means and pair it with how long the attacker kept the pod afterwards.

Run lint, unit and e2e; look at the summary, the twin and the hero in both themes at desktop and phone width;
report per item: done or not done and why.
