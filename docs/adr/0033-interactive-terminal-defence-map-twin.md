# ADR 0033: The front end becomes interactive: an attacker's terminal, a defence map, an unguarded twin and live stats

Date: 2026-10-02 · Status: accepted

## Context
The live demo (ADR 0019, 0021, 0022) let a visitor press one of four buttons and watch a timeline.
The owner's verdict was that it "does not click": the visitor only watches; the four scenarios look
the same; the attack is a hidden `echo`; the climax is a 33 ms event shown as a slow replay; only one
defence layer is playable; and the defender always wins at once, so nothing shows what the defence is
worth. Four defects were logged against the running site (FIX 1–3 below, plus placeholder copy on
production).

This ADR covers the web side (`app/web`) of the "you are the attacker" work. The API and cluster
sides are ADRs 0029–0032; the wire formats between the three are the shared contract in
`.cloud-handoff/`. The web page ships independently of the API and must render today's API (no
`command` events, no `/api/stats`, no compare) as well as the one this work targets, degrading one
feature at a time rather than breaking.

Constraints carried from ADR 0019 unchanged: no third-party origins, a strict CSP with Trusted Types,
every DOM write through `src/lib/dom.ts` (text nodes only), keyboard and screen-reader access,
`prefers-reduced-motion`, a phone layout, and `?mock=1` fixtures so everything is testable without a
cluster.

## Decision

### A — the attacker's terminal (`src/ui/terminal.ts`)
A new interactive scenario, `terminal`, is the page's centrepiece. The visitor opens a throwaway pod
and types commands into it, reading the real output stream back while the shop window changes beside
them, until the cluster ends the session. The catalogue comes from
`GET /api/scenarios/{terminal}/details` (`objectives[]`, `commands[]`, `idle_seconds`); the visitor's
input is resolved against it **locally**, and only a known command **id** is ever sent
(`POST /api/runs/{id}/commands`, Bearer token from the 202 of `POST /api/attack/terminal`). An unknown
line is answered on the page ("not in this sandbox's catalogue") and goes nowhere — no free text from
a visitor reaches the cluster. Output arrives as `command` events on the shared SSE stream and is
rendered as text only; the page strips any control character that survived the API's own scrubber, so
output can never be anything but a text node. Completion is Tab in the text box and the same commands
as chips grouped by objective for touch screens; another visitor's run is shown read-only.

### D — the defence map (`src/ui/defencemap.ts`)
The static "How it works" list becomes a diagram of the seven layers (edge, host, network, supply
chain, admission, pod security, runtime), each with its one-line controls. It doubles as the
terminal's result view: every finished command lights the layer that answered it, with the verdict
(allowed / prevented / detected) and the control text. The four layers a visitor in a pod can never
reach (edge, host, supply chain, admission) are shown as exactly that, with their standing evidence
from `GET /api/posture`, so the map is honest about what the terminal does and does not exercise.

### C — the unguarded twin (`src/ui/twin.ts`)
A one-click catalogue attack can be run `?compare=1`: the same attack in two pods at once, one in
`sandbox` and one in `sandbox-unguarded` where Falco detects but nothing responds. The console shows
two shop windows side by side — the guarded one dies or goes dark, the unguarded one stays
compromised with "Falco saw it. Nothing answered." and a timer of how long the attacker has held it.
Both windows are drawn from the probe's structured fields as text, tagged by the event's `arm`.

### E+F — live stats and objectives (`src/ui/stats.ts`)
The hero shows a band from `GET /api/stats`: the counters across every visitor's runs (with the
window they cover), the last real response time next to a human comparison, the honest "call home"
number, and each objective with how many runs reached it — including, by name, the ones no one has.
A line invites anyone who gets further than the page says is possible to open an issue.

### The three FIXes
- **FIX 1** — a quarantine's cut now lights hop 8 from the first `unreachable` victim event after the
  label, labelled "probe dropped" with source "API probe". There are no Hubble flow events and none
  are planned; the proof panel and the pipeline no longer depend on them.
- **FIX 2** — the production build (`scripts/strip-todo-content.mjs`, wired into `build.mjs`) removes
  every `data-todo-content` element with nothing written in it, keeps what is written in a partly
  written one (each child element still holding a `[TODO-CONTENT: …]` marker goes), and removes a
  `data-todo-section` left with nothing but its heading together with its navigation link; the
  stylesheet numbers the sections, so a removed one leaves no gap. The watch build keeps everything
  and `npm run todo-content` still lists the placeholders from source, so the owner's unwritten copy
  never ships but is never lost.
- **FIX 3** — a live run plays in real time first (every hop lights as its event arrives), so the
  visitor sees how fast the cluster actually is; when it is over the console states the real duration
  next to something human ("about as fast as a blink") and offers the slowed, dwelled replay on a
  button. `prefers-reduced-motion` never animates either way.

### Contract typing and degradation (`src/lib/contract.ts`)
Every new wire shape (the `command` event, the catalogue fields, `arm`/`command_seq`/`pods` on
existing events, `/api/stats`, the terminal and command accept bodies) is typed with a runtime guard,
additive and optional, so an older API drops cleanly to the page it always rendered: no catalogue →
the terminal says it is unavailable and the one-click demo still works; no `/api/stats` → the hero
band hides; no compare → no twin button. How the page meets today's API is in the second amendment below.

## Consequences
- The page now drives a stateful session (a per-run token it holds only in memory, one command at a
  time), not just a fire-and-forget launch. The token is never put in an event, in `localStorage` or
  in `/api/runs/{id}`; leaving the page ends the run (`DELETE`), as do idle, deadline and a kill.
- Mock mode (`src/lib/mock.ts`, `src/lib/fixtures.ts`) simulates the terminal, the twin and the stats
  end to end, including the detect→respond chain, the quarantine that keeps the run going and the
  terminate that ends it, so the whole front end is exercised by `npm test` and `npm run test:e2e`
  without a cluster. The mock's terminal catalogue is not written here: `scripts/terminal-catalogue.mjs`
  generates `src/lib/terminal-catalogue.json` from the cluster's `scenarios.yaml`. The drift check is
  opt-in, not part of CI: that file is not in this side's tree, so the unit test that compares the two
  runs only when `SDP_SCENARIOS_YAML` points at a copy of it (as does the script's `--check`).
- One more image is not added; the bundle grows by the new modules (a few KB) and mock mode still
  ships, visibly labelled, reaching nothing a visitor could not already reach.
- What the web session could not verify, and integration must: the live API actually emitting
  `command` events with the scrubbing and caps the contract specifies; the real terminal catalogue
  matching the schema the page parses; `?compare=1` producing per-`arm` events; `/api/stats` matching
  the shape above; and label-to-isolation actually landing inside the window the quarantine proof
  now reads from the probe (ADR 0032).

## Amendment 2026-10-02: aligned with the real API and its integration review

The terminal, twin and stats were first built against the mock alone; once the API (ADR 0029, 0030)
and the catalogue (ADR 0032) were pushed, the mock and the page were corrected to match them, and the
integration review of this branch was worked item by item.

- **The mock is the real API's shape.** The `?mock=1` fixture catalogue is the live `terminal`
  scenario's own (five objectives, fourteen commands); a terminate command `exits` first (its own
  process finishes — `cat /etc/shadow` reaches its objective) and the *run* then ends `killed`, while
  only a TTY shell is `killed` mid-command; commands are refused with 409 until `pod_ready`; `leave`
  answers 202 while the run is live and 409 once it is over.
- **Summary from the run, not a command state.** "Killed N ms after your Enter" is the time of the
  run's last `responded` with action `terminate` minus the start of the command it names
  (`command_seq`; without one, the last command started before it), with Falco-to-response beside it;
  a quarantine earlier in the run is its own line; a time that is not positive is left out; the
  outcome line reads from the run's `detail`.
- **Compare never mixes arms.** The pipeline, kill-timer, pod panel and proof use only `arm:"guarded"`
  (or unarmed) events; the unguarded arm's pods are kept apart and feed only its own window, whose
  "held for" counter ticks every second from that pod's first compromise until the API deletes it.
- **Hop 8 and the proof** take the guarded pod's first `unreachable` *after* the quarantine label,
  never an earlier transient timeout and never the twin's probe.
- **The defence map lights during the session**, each command under its own layer with its own
  verdict, "ended the session" only on the command that did; it is legible in both themes.
- **The terminal degrades**: no catalogue → the one-click scenarios become the attack section (see
  the second amendment); mid-session joins and reconnects backfill from `/api/runs/{id}`, deduped so
  nothing counts twice; leaving (an explicit button, `exit`, and `pagehide`) ends the run at once.
- **Honesty and hardening**: the hero drops the escapes/"got out" tile for the objective counters and
  the last real run; output is appended (never re-announced) and matches the API's control/format-char
  scrub, each line its own bidi paragraph (`unicode-bidi: plaintext`); `run_id` is validated before it
  reaches a URL; `parseCommands` rejects a catalogue with a duplicate or unusable spelling; the
  placeholder stripper fails the build on anything it cannot handle. The new components are covered by
  unit tests that drive them with the API's own event sequences and by end-to-end runs (below).

## Amendment 2026-10-03: second review

The second review drove the terminal with the real API's event sequences and found the page wrong
exactly where the mock had differed from the API. The mock now emits those sequences, and each fix
has a test that fails without it.

- **The mock is the API's sequence, not a likeness of it.** Every event carries the hub's id (on the
  stream and in `/api/runs/{id}`); run events always carry `detail`, and a terminal run's
  `detected`/`responded` carry `command_seq`; a command the API cut short (its 5 s limit, a leave, the
  run's end) `exited` with no code; a victim event is published only when the probe's view changes, so
  the held twin sends nothing until the API deletes it 12 s after the guarded response, and only then
  does the run finish; the per-run 429 says "too many commands in this run"; the stats fixture counts
  objectives per run, as the API does.
- **Output in publication order.** A command's output is kept by event id and the timeline drops a
  duplicate by id with its payload, so two identical lines both show; a block whose history changed (a
  backfilled chunk, a command the live feed missed) is rebuilt in seq order, not appended at the end.
- **A code-less exit is an end.** It frees the input, lights its layer and says why: timed out (a
  command gets 5 s, one with a terminal 10 s), or stopped by the session's end, told by the run's own
  reason rather than a time window.
- **One command at a time, whichever comes first.** The lock clears when the sent command has ended,
  whether its end or its 202 arrives first; a second tap before the 202 sends nothing; chips, Run and
  Leave rest before `pod_ready` and after the end; `pagehide` sends one DELETE, never after the end.
- **What the visitor reads.** Watchers get a third-person banner and summary; a failed or timed-out
  run says why; "Survived" counts from `pod_ready`; the two 429s are told apart by their body; a start
  that timed out explains the read-only run that may follow; each reached objective says the pod was
  deleted N later, and the hero says what "reached" means (the command exited 0 — detection is not
  prevention) next to the median session length; objectives are counted in runs.
- **Mid-session joins.** A run the feed shows without `queued`/`started` takes its earliest state as
  its start, so it is the live run (watcher view, launcher locked), and is backfilled; a backfill the
  run store answers with a 404 is final, another failure waits 30 s, then twice as long each time
  (`src/lib/backfill.ts`); reopening the stream after a hidden-tab stop backfills the active run; a
  history the store cut short (`truncated`) is said in the terminal. A catalogue that arrives after a
  watched run is already on screen fills that view in rather than replacing it.
- **Against today's API** (its JSON 404 for the terminal's catalogue; no `/api/stats`, no compare):
  the hero button reads
  "Launch an attack", the attack section is the one-click scenarios, and nothing offers or mentions the
  terminal; the twin button appears only when the scenarios carry `interactive` (the field the
  interactive API added, and the sign that `?compare=1` is understood); `/api/stats` is not asked again
  after a 404 and the hero takes the objectives from the terminal's catalogue instead of fetching it.
  Any other failure to load the catalogue (the network, a 5xx, the request limiter's 429) is passing:
  the terminal shows an offline state that retries, and the page is not degraded.
- **Quiet updates.** The start panel and the hero band are patched only when they change, so focus and
  notes survive the feed; a cooldown unlocks the start button on its own; a blocked press says why;
  Tab completes only when it changes the line; hints reach a screen reader through a region that is
  always live.
- **Tests that can fail.** Unit tests drive `mountTerminal`, `renderTwin` (with a ticking clock) and
  the stripper on `src/index.html`; the e2e suite reads the mock's own call log for "nothing was sent"
  (an in-page mock never reaches the network), runs the page against `serve.mjs --live-api` (today's
  API) and against `serve.mjs --terminal-api`, which replays a session joined mid-way exactly as the
  API publishes it, backfill included — also with the catalogue answering after the replay
  (`--slow-details`). The console's run is checked from the sequence of states it went through,
  recorded as they happen, not by polling windows shorter than a second.
- **Wording.** The hero's tiles say what they count ("detected runs answered", runs that "ran out of
  time with a detection unanswered", one response-time figure); in the summary each time says where
  it counts from (after the Enter, after the exit); every layer of the result map has a status pill;
  long command lines wrap after `/` and `;`.

## Amendment 2026-10-03: session limits on screen, the staleness bound, pagehide, compare by default

The API now gives the terminal scenario `timeout_seconds: 300` and `idle_seconds: 90` and sends both
in `GET /api/scenarios/terminal/details` (ADR 0029 and 0032 amendments). The page follows.

- **Countdown.** The terminal's bar shows two countdowns from the details' values, as text in the
  bar's monospaced face, ticked once a second with nothing around them moving: session time left (the
  API's deadline runs from the run's start, before the pod exists) and idle time left (from
  `pod_ready`, then from each command's `started`: the API's idle timer restarts when a command
  arrives, not when it ends). They appear at `pod_ready`, are shown to watchers of another visitor's
  run as well, and read the API's clock, not the visitor's: the offset is the least lag seen between an
  event's `at` and its arrival. When the session ends, the bar and the summary name the reason from
  the run's `detail` — "ended after 90 s without a command" (`idle`), "the 5-minute session limit"
  (`deadline`), "you left" / "the visitor left" (`left`), "the cluster deleted the pod" (`killed`).
  The 30 s / 120 s fallbacks are gone: an API that sends no limits gets no countdowns and words
  without numbers.
- **Staleness bound.** A run without an end event counts as running for its scenario's
  `timeout_seconds` (from its details, as the terminal and the console load them) plus 60 s; with no
  details, the contract's 300 s ceiling plus 60 s; and a terminal run never less than 300 + 60 s. The
  fixed 180 s bound would have declared a live five-minute session over at three minutes: the
  terminal closed its input and showed the summary, and the launcher unlocked. The launcher's own
  lock follows the same bound.
- **pagehide.** The leave `DELETE` goes out only when the page is really unloading
  (`event.persisted === false`). A page put into the back/forward cache keeps its run, so a visitor
  who comes back finds their session; if they never do, the API's idle timer frees the slot.
- **Compare as the default.** When the API knows `?compare=1` (its scenarios carry `interactive`), a
  one-click card's main button, "Launch side by side", runs the attack in both pods, guarded and
  unguarded, and a small "Guarded pod only" button beside it runs the defended pod alone; the card
  says what each does. Against an API without compare the card keeps its one "Launch attack" button.
- **Mock.** `?mock=1` follows all of it: its catalogue is regenerated from `scenarios.yaml` (300 s,
  idle 90 s), its terminal ends on those limits, and its one-click cards launch side by side.
