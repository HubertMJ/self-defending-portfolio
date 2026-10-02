# Integration review of `interactive-api` (2fd639d) — fixes for the API session

Locally: gofmt clean, `go build`, `go vet`, `go test -race -count=3 ./...` all green. Two independent reviews
(security, contract/correctness) found the points below; each was reproduced with a probe test. What they found
sound: no visitor text reaches the cluster (command ids only), the token (crypto/rand, constant-time compare,
never published), limits, compare refused for interactive scenarios at the server, labels and deadline on both
pods, orphan sweep in both namespaces, no visitor data in stats.

Fix on `interactive-api`, same rules as before (owner authorship, no AI attribution, no PR, small commits). Every
fix needs a test that fails before it. Before you start, read the other two branches so your fixtures match them:
`git fetch origin interactive-cluster interactive-web`; the real catalogue is
`origin/interactive-cluster:cluster/infra/sandbox/scenarios/scenarios.yaml` (scenario `terminal`).

## Output sink (runner/terminal.go) — rewrite the chunking, it is wrong in four ways
1. **Infinite loop.** `runeBoundary` returns 0 when bytes 1..1024 of the pending buffer are all UTF-8
   continuation bytes (0x80-0xBF): `add` then buffers without bound (and rescans it, O(n²)), and `flush` loops
   forever holding `s.mu`. The run slot is never released: every later attack gets 409 until the API restarts.
   Probe: 2 MiB of `\x80`. Pod output is untrusted by this code's own premise, so this must be impossible, not
   unlikely: always make progress, bound `pending`.
2. **The 1024-byte cap per event is not enforced.** `cutPoint` emits everything up to the last newline in one
   event (one 3000-byte write = one 3000-byte chunk), and sanitising after the cut can grow a chunk (the scrubber's
   replacements are longer than what they replace: 1200 bytes of `a.svc ` became 1704).
3. **The scrubber runs per chunk**, so a cut inside a long line splits an IP, URL or `.svc` name and both halves
   pass (`10.` + `42.17.203`). Scrub before cutting and never cut inside a token the scrubber could match — simplest:
   sanitise and scrub whole lines (bounded line length; an over-long line is scrubbed as one unit and then split
   only at a point that cannot be inside a match), then split the result into chunks of at most 1024 bytes on rune
   boundaries.
4. **Output after `exited`, and a data race.** client-go's SPDY path returns on context cancel without waiting for
   its stream goroutine, so late writes reach the sink after `flush()`; `sink.truncated` is read without the lock
   (terminal.go:233). After the command's end state is published the sink must drop writes, under its lock.
   Tests: chunk size never over 1024 for arbitrary write sizes; the per-command 4 KiB and per-run 32 KiB caps;
   stderr; split IP across writes and across a would-be chunk boundary; the `\x80` case returns.

## Terminal run lifecycle (runner/terminal.go)
5. **DELETE and the idle timer are ignored while a command runs**; with a TTY command (`sh -i`, empty stdin on a
   TTY gets no EOF) the run ends only at the deadline, with detail `deadline` instead of `left`, and the visitor
   holds the global slot for up to 120 s. `leave`, pod gone and the run deadline must each end a running command;
   a TTY command needs its own bound as well.
6. **A command can get 202 + seq and never run** (the request lands in the buffered channel while the loop picks
   `leave`/`idle`/`gone`); `running` stays true and no `started` follows. The `default:` branch there is
   unreachable and its comment is wrong. Make accept-and-run atomic with the run's end.
7. **`responded` can be published before `detected`** in a terminal run (the one-shot path backfills, the terminal
   path does not); stats then record a response with no detection.
8. **After a run has ended**, commands and DELETE get 404 once the run leaves `byID`; the contract says 409 for
   "already over". Keep ended runs recognisable (the run log knows the last 50).
9. Falco firing on an `allowed`/`prevented` command publishes `detected` with an empty detail: put the rule name
   in the detail. A non-TTY command killed by the 5 s timeout reports `exit_code: -1`: publish it as its own
   state or without `exit_code`, and document it, so the web does not show -1 as an exit status.
10. `detail` of the final `finished` can become "pod cleanup failed", overwriting `killed|left|idle|deadline`:
    those four are the only values the contract allows; log the cleanup failure instead.

## FIX 1 linger (runner/runner.go:667-684, victim.go:240)
11. The wait does not watch `rn.gone`: a pod deleted during the wait still costs the full cap (40 s).
12. With no victim, or a poller that never started, every quarantine run waits the full 40 s (it was 5 s). Wait for
    `unreachable` only when a poller is running; otherwise keep a short fixed linger.
13. `firstUnreachable` is closed by any `unreachable`, including one before the response; the contract says the
    first `unreachable` after the label. Count only those at or after the response.

## Compare (runner/compare.go)
14. `executeArm` stops its watch right after deleting the twin, so on a real API server the twin's
    `pod deleted=true` event is dropped (the guarded path waits `DeleteWait`); and the run publishes `finished`
    about 12 s before the twin is gone, so the web has no end signal for the right-hand window. Wait for the
    twin's deletion like the guarded path, and end the run only when both arms are gone (or publish a clear
    per-arm end).
15. `StartCompare` itself must refuse an interactive scenario (today only the HTTP handler does).
16. `executeArm` duplicates `execute`'s pod lifecycle; item 14 came from that. Share the lifecycle.
17. Pod lookups by name only (`ObserveFalco`/`ObserveTalon`, `CommandSeqFor`, `ArmFor`) now span two namespaces:
    key them by namespace and name.

## Stats (internal/stats)
18. **`unanswered`** counts every run that ended detected-and-not-responded, including terminal runs that ended
    `left`/`idle`/`killed` and API shutdown, and a visitor can inflate it (detected command, then DELETE before
    Talon's webhook is correlated). Contract: detected with no response before the timeout. Also
    `terminalResponded` drops a response that arrives more than 2 s after the command ended: attribute it to the
    run anyway (only `command_seq` is best effort).
19. **`objectives.achieved` counts command exits, not runs**: one run reaching `recon` three times gives
    attempts 3, achieved 3 with terminal.runs 1. The web says "reached by X of N visitors' runs": count each
    objective once per run, and make `attempts` the number of runs that tried it.
20. **A corrupt ConfigMap value panics every `/api/stats`** (`{"ByScenario":{"x":null}}` -> nil dereference at
    stats.go:288); negative counters and oversized sample arrays are accepted. Validate on load; on anything
    invalid start from zero and log it.
21. `response_ms.min` treats 0 as unset (samples 0 then 900 give min 900).
22. **Persistence loses updates**: `TakeDirty()` clears the flag before `Save`, so a failed Update is not retried;
    the shutdown flush runs when the signal context is cancelled, before `run.Shutdown` publishes the last events,
    and `main` does not wait for it. Retry on conflict (Get + Update with resourceVersion), restore the dirty flag
    on failure, flush last and wait for it (bounded).
23. The hub tap does file I/O under the hub lock: `stats.Record` calls `scenarios.Store.Get` (an `os.Stat`, and a
    full re-parse when the file changed) for every `run` and `command` event, including each output chunk. Resolve
    the catalogue once per run. `Collector.pods` is written and never read; ADR 0030 says counts are derived from
    falco/talon events and the code ignores them: make code and ADR agree.
24. Events published after `finished` (a late webhook) create an `active` stats entry that is never removed.

## Catalogue validation (internal/scenarios)
25. These load and then misbehave: an argv element that is `""`; `tty: true` on a command whose outcome is not
    `detected`; title/control/explain/technique/objective titles with no length or printability bound; an
    `SDP_FLAG` env already present with `valueFrom` (setEnv sets `Value` without clearing it). `Container()` for an
    interactive scenario returns the first container, not `target`. `aliases` serialises as `null` instead of `[]`.
    Validate the real `terminal` entry from the cluster branch in a test.

## Tests that pass without proving their claim
26. `TestTerminalIdleEndsRun` accepts `deadline` (never exercises idle); `TestQuarantineLingersFromUnreachable`
    would pass if the signal were ignored; `TestTerminalDetectedTerminateKillsRun` never reaches the `killed`
    command state; `TestCompareFallsBackWithoutTwin` fails about 1 in 20 under -race because the test deletes the
    pod while `waitReady` does its first Get (a test ordering bug, not the fake clientset). Missing altogether:
    409 (busy, not ready, over), 413, 429, concurrent POSTs, DELETE during a command, the 5 s timeout, the token
    absent from every event and from `/api/runs/{id}`, repeated detected/responded (quarantine then terminate,
    with commands still working after the quarantine), the twin's delete not reported as victim `gone`.

## Smaller
27. Stale comments: exec.go:20,28 ("sandbox only", "Output is discarded"); runner.go:243; the comment at
    runner.go:745-748 that one visitor cannot read another's flag (it is broadcast once read; say so);
    "ends promptly" on `QuarantineLingerMax`.
28. `compare_hold_seconds` is a global Config value not settable from the environment: make it an env setting and
    say in ADR 0031's API notes that it is not a catalogue field.
29. SSE capacity: a burst of more than 64 `output` events drops slow subscribers and the replay ring holds 100;
    state in ADR 0029 what a viewer who joins mid-session sees, and make sure the final `run` event of a terminal
    run cannot fall out of `/api/runs/{id}` (500-event cap keeps the first events).

Run gofmt, `go vet`, `go test -race -count=5 ./...` and golangci-lint; report real output and, per item above,
done or not done and why.
