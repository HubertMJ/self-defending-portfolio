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
  every element whose `data-todo-content` text is still a `[TODO-CONTENT: …]` placeholder, and a
  `data-todo-section` left with nothing but its heading. The watch build keeps them and
  `npm run todo-content` still lists them from source, so the owner's unwritten copy never ships but
  is never lost.
- **FIX 3** — a live run plays in real time first (every hop lights as its event arrives), so the
  visitor sees how fast the cluster actually is; when it is over the console states the real duration
  next to something human ("about as fast as a blink") and offers the slowed, dwelled replay on a
  button. `prefers-reduced-motion` never animates either way.

### Contract typing and degradation (`src/lib/contract.ts`)
Every new wire shape (the `command` event, the catalogue fields, `arm`/`command_seq`/`pods` on
existing events, `/api/stats`, the terminal and command accept bodies) is typed with a runtime guard,
additive and optional, so an older API drops cleanly to the page it always rendered: no catalogue →
the terminal says it is unavailable and the one-click demo still works; no `/api/stats` → the hero
band hides; no compare → the twin button simply never produces a twin.

## Consequences
- The page now drives a stateful session (a per-run token it holds only in memory, one command at a
  time), not just a fire-and-forget launch. The token is never put in an event, in `localStorage` or
  in `/api/runs/{id}`; leaving the page ends the run (`DELETE`), as do idle, deadline and a kill.
- Mock mode (`src/lib/mock.ts`, `src/lib/fixtures.ts`) simulates the terminal, the twin and the stats
  end to end, including the detect→respond chain, the quarantine that keeps the run going and the
  terminate that ends it, so the whole front end is exercised by `npm test` and `npm run test:e2e`
  without a cluster. The terminal catalogue fixture follows the contract's schema; the real catalogue
  is written by the cluster side.
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
  answers 202.
- **Summary from the run, not a command state.** "Killed N ms after your Enter" is the response time
  (the guarded Talon action, by `command_seq`) minus the start of the command it acted on, with
  Falco-to-response beside it; the outcome line reads from the run's `detail`.
- **Compare never mixes arms.** The pipeline, kill-timer, pod panel and proof use only `arm:"guarded"`
  (or unarmed) events; the unguarded arm's pods are kept apart and feed only its own window, whose
  "held for" timer ticks from its first compromise to the run's end.
- **Hop 8 and the proof** take the first `unreachable` *after* the quarantine label, never an earlier
  transient timeout.
- **The defence map lights during the session**, each command under its own layer with its own
  verdict, "ended the session" only on the command that did; it is legible in both themes.
- **The terminal degrades**: no catalogue → a quiet pointer to the one-click demo (not a loud error);
  mid-session joins and reconnects backfill from `/api/runs/{id}`, deduped so nothing counts twice;
  leaving (an explicit button, and `pagehide`) ends the run at once.
- **Honesty and hardening**: the hero drops the escapes/"got out" tile for the objective counters and
  the last real run; output is appended (never re-announced) and matches the API's control/format-char
  scrub with bidi isolation; `run_id` is validated before it reaches a URL; `parseCommands` rejects a
  catalogue with a duplicate or unusable spelling; the placeholder stripper fails the build loudly on
  anything it cannot balance. The new components are covered by unit and end-to-end tests.
