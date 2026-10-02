# ADR 0029: The attacker's terminal: interactive runs where the visitor types command ids and reads the real output

Date: 2026-10-02 · Status: accepted

## Context
The four one-click scenarios (ADR 0017, 0018) run a fixed script and the visitor only watches. The owner's
verdict on the live demo was that it "does not click": the visitor presses a button, all four scenarios look
the same, and the attack is something that happens *to* a pod rather than something the visitor does. The
interactive contract adds a fifth scenario, `terminal`: the pod is created and kept alive, and the visitor
runs catalogue commands into it one at a time, reading the real output as it streams, until the cluster stops
them. This ADR records what the API does for that, and how the untrusted output is handled. The catalogue
itself (which commands, their detections and Talon rules, the per-run flag the victim writes) is ADR 0032
(cluster); the terminal UI, defence map and twin view are ADR 0033 (web).

Two constraints frame every choice, both from the contract's hard rules. **No free text from a visitor ever
reaches the cluster**: the API accepts command *ids* only, resolved against the catalogue before anything is
exec'd. And **command output is attacker-controlled**: it is whatever runs in the pod printed, so it is read
as hostile input, like the victim poller's body (ADR 0021).

## Decision

**A terminal scenario is `interactive: true` with a command catalogue, no scripted exec.** `scenarios.go`
gains the fields the contract fixes - `interactive`, `idle_seconds`, `objectives[]`, `commands[]` - and
validates the split: an interactive scenario carries no `exec`/`pre_exec` and its own `detection`/`response`
are empty (each command has its own), it has a container named `target` for the commands to run in, and every
command has a stable id `[a-z0-9-]{1,32}`, a unique printable-ASCII `input`, an `outcome` of
allowed/prevented/detected, a defence-map `layer`, and - only when detected - a `detection` and a
`terminate`/`quarantine` `response`. A command's `input` and `aliases` are display text for the web
terminal's completion; the API never matches them, so a malformed one is a catalogue error, not a visitor's
problem. The four scripted scenarios are unchanged and stay as the one-click demo.

**The run keeps its pod and runs commands on request.** `POST /api/attack/terminal` creates the pod as any
run does (`sandbox`, PSS restricted, no token, `activeDeadlineSeconds` = `timeout_seconds` ≤ 120 s) and
returns `202 {run_id, scenario, state, token}`. The **token** is 32 hex, random, returned only here - never in
an event or in `/api/runs/{id}` - and held in memory on the run; it is the capability to drive that run. Per
run the API sets env `SDP_FLAG` = `SDP{` + 16 hex + `}` on the `target` container (the victim writes it to
`/srv/shop/.flag`, 0600, and never serves it); it is the run's own secret, overriding any value the catalogue
pins, so one visitor cannot read another's and the catalogue cannot fix it to a known string.

**Commands.** `POST /api/runs/{run_id}/commands`, `Authorization: Bearer <token>`, body `{"id":"read-shadow"}`
→ `202 {seq}`. The token is compared in constant time. `401` wrong/missing token, `404` unknown run or command
id, `409` the run is not ready or is over or a command is already running (one at a time), `413` body over 256
bytes, `429` over 30 commands in the run. A non-TTY command's exec is cancelled after 5 s; a TTY command (an
interactive shell) runs until the pod is killed or the run ends. `DELETE /api/runs/{run_id}` with the token
ends the run ("the visitor left"). A terminal run ends when Talon deletes the pod (`killed`), on `DELETE`
(`left`), after `idle_seconds` with no command (`idle`), or at `timeout_seconds` (`deadline`); the final `run`
event is `finished` with that `detail`. `detected` and `responded` run events may occur more than once in a
terminal run (a quarantine command, then later a terminate command), unlike a scripted run where either ends
it.

**The `command` event**, published to every subscriber (other visitors watch read-only):
`{run_id, seq, id, state, at, stream?, chunk?, exit_code?, achieved?, truncated?}`. `state` is `started` when
the exec is sent, `output` with `stream` (stdout/stderr) and a `chunk` of at most 1024 bytes of text,
`exited` with `exit_code` and `achieved` (true iff the command has an `objective` and exited 0), or `killed`
when the pod went away under the command (no exit code). A non-zero exit is the command's own result (wget
fails by design), not an error; a cut-short exec reports `-1`.

**Output is scrubbed and capped.** Each chunk is forced to valid UTF-8, stripped of every control character
except newline and tab (so no ANSI escape sequences) and of invisible format characters, then run through the
ADR 0021 scrubber (URLs, IPv4/IPv6 and in-cluster service names replaced; loopback kept, because
`http://127.0.0.1:9/` is the evidence that nothing left the pod). Output is capped at 4 KiB per command and 32
KiB per run; past either, `truncated: true` and the rest is dropped. The flag is not special-cased: it is this
run's secret and is meant to be seen by the visitor who read it. Chunking keeps whole lines together where it
can and never splits a UTF-8 sequence.

**Correlation.** `falco` and `talon` events gain `command_seq`: the command that was running, or ended less
than 2 s before, when the alert arrived; absent otherwise. It is best effort (Falco's alert and the exec are
not transactionally linked) and set by the server from the runner. `/api/runs/{id}` includes `command` events
under the same per-run caps as ADR 0021, so a whole terminal session can be replayed and checked.

**FIX 1: a quarantine shows its cut.** The live demo deleted a quarantined pod on a fixed 5 s linger, which
beat Cilium's isolation, so the probe was still answering and no `unreachable` ever reached the page. The
runner now keeps a quarantined pod until the victim poller publishes its first `unreachable` event and then 3
s more, the whole wait bounded by `QuarantineLingerMax` (40 s) so a run that never goes unreachable still ends
promptly. The cluster's job is to make the isolation itself land under 3 s (ADR 0032); the API's job is to not
delete the pod before the cut is visible.

## Consequences
- An anonymous visitor can now exec into a `sandbox` pod - but only commands the catalogue lists, by id, one
  at a time, at most 30 per run, each non-TTY exec capped at 5 s, the whole run capped at 120 s, and only
  while holding a token the API handed to that one run. The RBAC is unchanged: `pods/exec create` in
  `sandbox`, which the scripted scenarios already needed.
- The API streams attacker-controlled bytes to every subscriber. The caps (1 KiB per event, 4 KiB per
  command, 32 KiB per run), the sanitiser (valid UTF-8, no control characters but newline/tab, no invisible
  format characters) and the ADR 0021 scrubber bound what that can carry; the renderer is text-only under the
  Trusted Types CSP (ADR 0019), so markup in the output is shown, not run.
- `detected`/`responded` are no longer terminal for a terminal run, and a run can be quarantined and then
  terminated; the run store and stats treat them as repeatable.
- The per-run flag is a new secret in the pod's environment. It is per run, overrides the catalogue, and is
  never published except as the visitor's own command output; the victim never serves it.
- Correlation between an alert and a command is best effort and documented as such: a 2 s window and the
  running command. A visitor doing several things quickly may see an alert attributed to the neighbouring
  command; the Falco event's own fields remain the ground truth.

## What a mid-session viewer sees, and the compare hold

The SSE hub replays its last 100 events to a client that joins mid-run, and `GET /api/runs/{id}`
keeps each run's full history up to 500 events and 256 KiB (ADR 0021). A terminal run stays well
inside both: at most 30 commands, each a `started`, a bounded burst of `output` (capped at 4 KiB per
command and 32 KiB per run, so a few dozen chunks for the whole run) and an end event, plus the pod
and victim events - a couple of hundred events in the worst case. So the run's final `finished`
event is always in `/api/runs/{id}`; a viewer who joins late sees the recent tail live and can fetch
the whole run from that endpoint. A viewer watching someone else's run sees the same `command`
events read-only (the run's token is never needed to watch, only to drive).

The unguarded twin's extra linger, `compare_hold_seconds` (default 12), is an API environment
setting (`COMPARE_HOLD_SECONDS`), not a catalogue field: it governs how the API runs a compare, not
what an attack is. It belongs to the twin mechanism recorded in ADR 0031; it is noted here because
the API owns the value.
