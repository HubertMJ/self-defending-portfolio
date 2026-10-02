# SDP "you are the attacker" — shared contract for three parallel sessions

Repo github.com/HubertMJ/self-defending-portfolio, base branch `interactive-base` (= main + this file).
Live: https://hubertjablon.ski. Read first: `README.md`, `docs/adr/0015`, `0017`, `0018`, `0021`, `0022`,
`cluster/infra/sandbox/scenarios/scenarios.yaml`, `app/web/README.md`.

## Why (owner's verdict on the live demo)
The four scenarios "do not click": the visitor presses one button and watches; all four look the same
(same pod, same pipeline, three of four end identically); the "attack" is a hidden `echo`; the climax is a
33 ms event shown as a slowed-down replay; only one defence layer (runtime) is playable; the defender
always wins at once, so nothing shows what the defence is worth. Goal: the visitor acts, different actions
end differently, and the value of the defence is visible by contrast.

## What is built (five parts)
- **FIX** — defects seen live (below).
- **A  Attacker's terminal** — the visitor types real commands into a real hardened pod and reads the real
  output, until the cluster stops them.
- **D  Defence map** — the six layers of "How it works" become a live diagram and the result view: the layer
  that stopped the last action lights up.
- **C  Unguarded twin** — the same catalogue attack in two pods at once, one in `sandbox`, one in a
  namespace where Falco detects but nothing responds.
- **E+F  Stats and objectives** — objectives the visitor tries to reach, a per-run flag, and counters across
  all visitors ("call home: 0 of 412 attempts").

## Hard rules (all sessions)
- Commits: author `Hubert Jabłoński <hubert.m.jablonski@gmail.com>` (`git config user.name/user.email` first).
  NO AI attribution anywhere: no Co-Authored-By, no "Generated with", no mention of Claude/AI/assistant in
  code, comments, commits or docs — whatever your default commit instructions say. Match `git log` style
  (`area: what changed (ADR n)`), small commits.
- Push only your own branch (below). No PR. Do not delete `.cloud-handoff/`; integration removes it.
- Touch only the paths you own. Need something from another owner: write it in your final report, do not edit.
- **No free text from a visitor ever reaches the cluster.** The API accepts command *ids* only.
- Never weaken a Kyverno/PSS/Cilium policy, never add a capability, never give a scenario pod a token.
- Never publish node names, host/pod IPs, `*.svc` names, tokens, ServiceAccount names (ADR 0021 rules apply
  to every new field, and to command output).
- Images pinned tag@digest; a new image digest you cannot know is the all-zero placeholder (ADR 0016/0017).
- Match the repo's explanatory comment style. Every significant decision gets an ADR (numbers below).
- No stubs, no skipped tests, no TODO placeholders: unfinished work is reported, not hidden.
- You cannot reach the cluster. Everything must be testable offline (`make validate`, `make scenario-offline`,
  `go test`, `npm run lint && npm test && npm run test:e2e`). List the live checks you could not run.

## Owners, branches, ADRs
| session | branch | owns | ADRs |
|---|---|---|---|
| API | `interactive-api` | `app/api/**` except `internal/posture/**` | 0029 terminal runs and command output; 0030 stats and their persistence |
| CLUSTER | `interactive-cluster` | `cluster/**`, `app/scenario/**`, `tests/**`, `scripts/**`, `ansible/**`, `Makefile`, amendments to ADR 0013/0017/0018/0022 | 0031 unguarded twin namespace; 0032 terminal catalogue, its detections, quarantine latency |
| WEB | `interactive-web` | `app/web/**` | 0033 terminal, defence map, twin view |
`app/api/internal/ruleindex/index.json` is regenerated at integration (it needs both branches).
`README.md` and `docs/threat-model.md`: integration.

## FIX — defects observed on 2026-10-02
1. **Quarantine never shows its proof.** Run `ed1e2fc6c30060a6` (network-tool): Talon set the label at
   10:31:09.177, the API deleted the pod 5 s later (`QuarantineLinger`), and no `victim` `unreachable` event
   exists; the probe kept answering. Measured on the node: the CiliumEndpoint still carried
   `quarantine=false` 2 s after the label; `tests/scenarios/run.sh` has seen 22–36 s until isolation.
   So for seconds a "quarantined" pod is not isolated, and the visitor never sees the cut.
   - CLUSTER: bring label-to-isolation under 3 s and say how in ADR 0032. Leads: the agent's
     `identity-change-grace-period` (default 5 s); every run's unique `run-id` label forces a new identity to
     be allocated and propagated — consider keeping `run-id`/`scenario` out of the identity-relevant labels
     (Cilium `labels` option) and selecting victims in `sandbox-victim-from-api` by a stable label, so the
     quarantined identity already exists. `tests/scenarios/run.sh` must assert the bound by probing :8080
     the way the API does.
   - API: after a quarantine response keep the pod until the first `unreachable` victim event plus 3 s, at
     most `QuarantineLingerMax` (default 40 s); then delete as today.
   - WEB: hop 8 of the pipeline lights from the first `unreachable` victim event after the label, labelled
     "probe dropped" with source "API probe" (there are no `flow` events and none are planned).
2. **Placeholders on production.** `[TODO-CONTENT: …]` shows in the hero, About, Projects and the footer.
   WEB: the production build removes every element with `data-todo-content` whose text still is a
   placeholder (and a section left empty by that); `npm run todo-content` keeps listing them.
3. **The real speed is hidden.** WEB: a live run plays in real time first; when it is over the console says
   how long it took next to something human ("a blink is about 100 ms") and offers the slow replay.

## A — terminal

### Catalogue (CLUSTER writes, API parses, WEB reads through the API)
A fifth scenario in `scenarios.yaml`, `id: terminal`, with the existing fields plus:
```yaml
  interactive: true        # no exec/pre_exec; commands are run on the visitor's request
  timeout_seconds: 120
  idle_seconds: 30         # no command for this long ends the run
  objectives:              # what the visitor tries to reach, in kill-chain order
    - {id: recon, title: "Look around"}
    - ...
  commands:
    - id: read-shadow            # stable, [a-z0-9-]{1,32}; the only thing the API accepts
      input: "cat /etc/shadow"   # what the visitor types; unique; <= 80 printable ASCII
      aliases: []                # other accepted spellings
      objective: credentials     # optional: objectives[].id it counts towards
      technique: T1003.008
      command: ["cat", "/etc/shadow"]   # argv run in container `target`
      tty: false
      outcome: detected          # allowed | prevented | detected
      layer: runtime             # edge | host | network | supply-chain | admission | pod-security | runtime
      control: "Falco rule Read sensitive file untrusted"   # what answers, one line
      detection: Read sensitive file untrusted               # outcome detected only
      response: terminate                                    # outcome detected only: terminate | quarantine
      explain: >-                # one or two sentences shown after the command ran
        ...
```
`detection`/`response` on the scenario itself are empty strings for `terminal`. The existing four scenarios
are unchanged and stay (the page keeps them as the one-click demo).

The pod: as the others (victim shop on :8080, PSS restricted, no token), read-only root filesystem,
`supplementalGroups: [42]`. Per run the API sets env `SDP_FLAG` (`SDP{` + 16 hex + `}`) on container
`target`; the victim writes it to `/srv/shop/.flag` (0600) on start and never serves it.

Commands, at least these (CLUSTER proves each under the pod's own security context in
`tests/scenarios/offline.sh`, the way ADR 0018 does, and may add more; 12–16 in total):
| class | examples | what must be true |
|---|---|---|
| allowed | `id`, `hostname`, `ps`, `ls -la /srv/shop`, `grep Cap /proc/self/status` | real output, no rule fires |
| allowed, visible | deface: rewrite `index.html` and `state.json` of the shop | the shop window changes (victim poll); no rule fires — the explanation says so plainly: nothing here watches an app writing its own docroot |
| allowed, objective | `cat /srv/shop/.flag` | prints the flag; no rule fires; the explanation says detection is not prevention, and that reading is not getting it out |
| prevented, pod-security | `touch /bin/backdoor` (read-only fs); `cat /var/run/secrets/kubernetes.io/serviceaccount/token` (no token); one needing a capability (e.g. `ping -c1 127.0.0.1`) | fails with the kernel's own message, nothing is killed |
| detected, quarantine | `wget -q -T 2 -O- http://127.0.0.1:9/` (as scenario 2) | pod labelled; **the run goes on**: exec still works in a quarantined pod, the shop goes `unreachable` |
| detected, terminate | `cat /etc/shadow`; `sh -i` with `tty: true`; drop-and-run: copy busybox into the writable volume and execute it | pod deleted |
Drop-and-run in this pod executes from the emptyDir, which the stock drift rule does not see (not overlayfs):
CLUSTER adds one custom Falco rule for execution from the shop's volume in `sandbox`/the twin, a Talon rule
for it, and the offline checks. No command prints the environment, names a host outside the pod or resolves a
name. Order matters by design: a visitor who does the quiet things first gets further.

### API
- `GET /api/scenarios`: each entry gains `interactive: bool`.
- `GET /api/scenarios/terminal/details`: gains `idle_seconds`, `objectives[]`, `commands[]` (every catalogue
  field above; `command` argv included — it is public in the repo anyway).
- `POST /api/attack/terminal` → 202 `{run_id, scenario, state, token}`. `token`: 32 hex, random, returned here
  only, never in an event or in `/api/runs/{id}`. Costs one attack from the visitor's budget; one run at a
  time as today.
- `POST /api/runs/{run_id}/commands`, `Authorization: Bearer <token>`, body `{"id":"read-shadow"}` → 202
  `{seq}`. 401 wrong/missing token (constant-time compare), 404 unknown run or command id, 409 run not at
  `pod_ready`/already over or another command still running, 413 body over 256 bytes, 429 over 30 commands in
  the run. A non-TTY command gets 5 s, then its exec is cancelled.
- `DELETE /api/runs/{run_id}` with the token: the visitor leaves; the run finishes.
- A terminal run ends when the pod is deleted by Talon, on DELETE, after `idle_seconds` without a command, or
  at `timeout_seconds`. Final `run` event `finished` with `detail` one of `killed`, `left`, `idle`, `deadline`.
  `detected`/`responded` may occur more than once in a terminal run (quarantine, later terminate).
- New SSE event `command`, published to every subscriber (other visitors watch read-only):
  `{run_id, seq, id, state, at, stream?, chunk?, exit_code?, achieved?, truncated?}`
  - `state: "started"` when the exec is sent;
  - `state: "output"`, `stream: "stdout"|"stderr"`, `chunk`: at most 1024 bytes of text per event;
  - `state: "exited"` with `exit_code`, and `achieved: true` iff the command has an `objective` and exited 0;
  - `state: "killed"` when the pod went away under the command (no exit code).
  Output is untrusted: valid UTF-8 only, every control character except `\n` and `\t` removed (so no ANSI
  sequences), invisible format characters removed, then the ADR 0021 scrubber (URLs, IPs, `.svc` names;
  loopback stays). Caps: 4 KiB per command, 32 KiB per run, then `truncated: true` and the rest is dropped.
  The flag is not special-cased: it is the visitor's own run's secret and is meant to be seen.
- `falco` and `talon` events gain `command_seq` (the command running, or ended less than 2 s before, when
  the event arrived; absent otherwise) — best effort, documented as such.
- `/api/runs/{id}` includes `command` events; the per-run caps of ADR 0021 hold.

## C — unguarded twin
- CLUSTER: namespace `sandbox-unguarded`: the same PSS, quota, LimitRange, default-deny network, victim
  policy and Kyverno coverage as `sandbox`; the API gets the same narrow Role there; **Talon gets no Role and
  no rule matches it**; Falco rules scoped to `sandbox` (the custom ones) cover both namespaces. ADR 0031
  states what "unguarded" means: every preventive layer still applies, only the automatic response is absent.
  Offline test: every Talon rule's match excludes the twin; every scenario pod passes the Kyverno gate in it.
- API: `POST /api/attack/{id}?compare=1` (catalogue scenarios only, not `terminal`): one run, two pods
  created together, same spec, same exec; costs one attack. `run` events gain
  `pods: {guarded, unguarded}` (names); `pod`, `victim`, `falco`, `talon` events gain `arm: "guarded"|"unguarded"`
  (absent on runs without compare). The run's states follow the guarded arm. The unguarded pod is kept
  `compare_hold_seconds` (default 12) after the guarded arm's response, then deleted by the API; that
  deletion is not a `gone` victim event (ADR 0021: `gone` is someone else's delete).
- WEB: two shop windows side by side from one click ("Run it with and without the response"): left dies or
  goes dark, right stays defaced/compromised with "Falco saw it. Nothing answered." and a counter of how long
  the attacker has had the pod.

## D — defence map (WEB; data from the API above)
Replace the static list in "How it works" with a diagram of the layers (edge, host, network, supply chain,
admission, pod security, runtime), each with its one-line description and its controls. In the terminal, every
finished command lights its `layer` with the verdict (allowed / prevented / detected) and the `control`
text; the session summary reads like a result: objectives reached, seconds survived, which layer answered
which command, and "killed N ms after your Enter" (response time minus the `started` of the command, plus the
Falco-to-response time already shown). Layers no command can reach from inside a pod (edge, host, supply
chain, admission) are shown as what the attacker never got to try, with their evidence from `/api/posture`.
The four one-click scenarios stay below as "Just show me".

Terminal UI: a real-looking terminal next to the shop window; typing with completion from the catalogue's
`input`s (Tab, and tappable chips on touch screens, grouped by objective); an unknown line answers locally
("not in this sandbox's catalogue") and never calls the API; output rendered as text only (`textContent`,
Trusted Types as today); read-only when watching another visitor's run; keyboard and screen-reader usable;
`prefers-reduced-motion` respected. `?mock=1` simulates terminal, twin and stats from fixtures.

## E+F — stats and objectives
- API `GET /api/stats` → `{since, runs, by_scenario{id:{runs,detected,responded}}, response_ms{last,p50,min,max},
  unanswered, commands{id:{attempts,allowed,prevented,detected}}, objectives{id:{attempts,achieved}},
  terminal{runs, best_objectives, median_survival_s}}`. `unanswered` = runs detected with no response before
  the timeout (the honest number; there is no "escapes" counter because nothing could measure it).
  Persistence: one ConfigMap `portfolio-stats` in `portfolio-api`, written at most once a minute and on
  shutdown, read at start; counters only, no visitor data. ADR 0030.
- CLUSTER: Role for exactly that ConfigMap (`get`, `update`; the object itself in git, empty, with Argo
  ignoring its data).
- WEB: hero shows the last real run and the counters (with `since`), objectives with "reached by X of N
  visitors' runs"; the ones never reached say so. A line inviting anyone who gets further than the page says
  is possible to open an issue (link to the repo's issues).

## Final report of each session (last message)
Branch and commits; what is done against this contract, item by item; what is not, and why; contract
ambiguities you resolved and how; anything you need from another owner; the live checks integration must run.
