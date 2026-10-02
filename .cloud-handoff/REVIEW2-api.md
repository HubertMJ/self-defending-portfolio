# Second review of `interactive-api` (2b77cc8) — remaining fixes

Locally: gofmt, `go vet`, `go test -race -count=5/10 ./...` green. Of the 33 items in REVIEW-api.md most are fixed
(sink progress, the 1024-byte chunk cap, late writes, accept-and-run atomicity, linger on gone, the twin's end,
namespace-keyed lookups, objectives once per run, `pod_ready` gating, the real catalogue loads). Each point below
was confirmed with a probe test or a mutation. Same rules as before (owner authorship, no AI attribution, no PR,
small commits). Every fix needs a test that fails without it — four tests of the last round still pass when the
fix they were written for is removed.

## Defects
1. **Scrubber bypass at the 8 KiB line cut** (terminal.go:406, 472-473). A line with no newline is cut at exactly
   8192 bytes and each half is scrubbed on its own; bytes the sanitiser drops (NUL, 0x80, ESC, CR) keep the first
   half under the 4 KiB cap, so the second half is published. Probes published `10.42.17.203`,
   `https://kube-api.example.internal/x`, `kube-dns.kube-system.svc` and an IPv6 prefix unscrubbed, on one stream
   and across stdout/stderr. The same cut also destroys a valid rune split across it (`\xc3` | `\xa9`). Never
   scrub a cut-off unit on its own: carry the tail that could still be part of a token (and an incomplete rune)
   into the next unit, or stop publishing that line. The `cmdSink` doc comment says a cut cannot split a token:
   make it true.
2. **`/api/runs/{id}` can lose the final `run` event, and the rewrite made it more likely** (item 29, not fixed;
   ADR 0029 now claims the opposite). The sink emits one `output` event per line: 4096 newlines in one write gave
   4096 events, 30 such commands 32768; with the real hub and run log, 8 commands of 60 lines left the run at 500
   events, truncated, with no `finished`, and an idle SSE subscriber was dropped. Batch lines into chunks of up to
   1024 bytes per event, bound events per command and per run, and make the run log always keep a run's
   terminal-state events (reserve room) whatever the volume.
3. **Process crash**: `StartCompare` hands an interactive scenario to `Start` (compare.go:29), whose run has nil
   `cmds`, `leave`, `loopDone`; terminal.go:198 then panics with `close of nil channel`. Only the HTTP handler's
   400 stands in the way. `StartCompare` and `Start` must return an error for a scenario they cannot run.
4. **`responded` without `detected`** when Falco's alert arrives more than 2 s after the command ended
   (terminal.go:330 drops it; 356-379 then publish Talon's response alone). Stats then hold
   `{Runs:1 Detected:0 Responded:1}`. A Falco alert for the run's pod always becomes `detected`; only
   `command_seq` is best effort.
5. **`response_ms` can be inflated by a visitor**: stats measure from the run's first `detected` to its first
   `responded` even when they belong to different commands (an unanswered detection at 2 s and a 400 ms response
   at 102 s recorded 100400 ms as last, p50, min and max). Pair a response with the detection of the same command
   (or the same rule), and record nothing when there is no pair.
6. **`killed` is reported as `exited` with code 137**: terminal.go:278-299 waits for the pod watch only when the
   exec returned an error, but the production `ExecStream` turns a SIGKILL into `(137, nil)`. When the exec
   returns before the watch reports the deletion the command ends `exited(137)` (20 of 20) while the run ends
   `killed`. After any exec return, check for the pod's deletion (bounded wait) before choosing the state.
7. **A TTY command holds the global slot until the run's deadline** (probe: idle 1 s, deadline 4 s -> finished
   `deadline` after 4 s): the idle timer never ends a running command and a TTY command has no bound of its own.
   The ADR now calls this intended; it is not. Bound a TTY command (for example 10 s after its start with no pod
   deletion) and let idle apply from its start.
8. **A failed read at start wipes the persisted counters**: configmap.go:46-51 logs any `Get` error and starts
   from zero, and the next `Save` overwrites the stored totals. Distinguish "not found / invalid" (start from
   zero) from "could not read" (do not write until a read has succeeded).
9. **Stats load validation is still open**: negative `RespMin/Max/Last` and samples, a `Since` in year 9999,
   `Runs = MaxInt64` (the next increment overflows, and the next load rejects the blob and resets everything),
   any `BestObjectives`. A blob saved before `RespCount` existed loads with count 0, so an old min of 200 followed
   by a 900 ms response gives min 900: derive the count from the samples on load.
10. **Quarantine linger**: the drain-then-wait at runner.go:729-733 replaced "count only an `unreachable` at or
    after the response"; if the cut is seen before the webhook is correlated the run waits the full 40 s. Record
    the time of each `unreachable` and compare with the response time instead of draining.

## Tests that still prove nothing (found by mutation)
11. `wasTerminal` always false -> `TestTerminalEndedRunIs409` passes. 429 mapped to 409 ->
    `TestTerminalCommandLimitsAndTokenSecrecy` passes (its loop just ends at the deadline). `finished` published
    before the twin is deleted -> `TestCompareTwoArms` passes. No linger without a poller ->
    `TestQuarantineNoVictimShortLinger` passes (upper bound only). `TestQuarantineLingersFromUnreachable` catches a
    broken signal only because its cap equals the helper's timeout. No test at all for: the `\x80` input, the
    1024-byte chunk limit under random write sizes, a split IP/URL/.svc name (chunk boundary and line cut),
    stderr, the per-run cap, any persistence path (conflict retry, dirty flag restored, flush at shutdown, failed
    read at start), concurrent POSTs, 409 busy and not-ready, the token absent from SSE events, the twin's delete
    not reported as victim `gone`, the length bounds and `valueFrom` in catalogue validation. The "real entry"
    test uses a hand-written 6-command fixture: load the cluster branch's file
    (`git show origin/interactive-cluster:cluster/infra/sandbox/scenarios/scenarios.yaml` into testdata).

## Smaller
12. `Leave` during cleanup returns 202 instead of 409. A write between `flush()` and `close()`
    (terminal.go:263-264) is lost without setting `truncated`. One huge write re-copies quadratically while
    holding `s.mu` (16 MiB took 2 s): cap what a single write may add. The scenario title and `detection` are
    unbounded in validation. `executeArm` still duplicates create, wait-ready and exec. A narrow `Run`/`Flush`
    race at shutdown can mark the counters dirty after `Flush` checked the flag.
13. ADR 0029 still says a cut-short exec reports `-1`, that "each chunk is forced to valid UTF-8", and the
    mid-session event-count claims; the `podVisible` comment is wrong about who reads it. `COMPARE_HOLD_SECONDS` is
    documented in ADR 0029 because ADR 0031 is not on this branch: fine, say so in one line.
14. A terminal run never counts as `unanswered` now. State in ADR 0030 what `unanswered` means for terminal runs
    (a detected command whose response never came before the run ended by deadline) and count that.

Run gofmt, `go vet`, `go test -race -count=10 ./...` and golangci-lint; report real output and, per item, done or
not done and why.
