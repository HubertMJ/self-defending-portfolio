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

**The run keeps its pod and runs commands on request.** `POST /api/attack/terminal` creates the pod as any run
does (`sandbox`, PSS restricted, no token, `activeDeadlineSeconds` = `timeout_seconds` ≤ 120 s; 300 s since
the 2026-10-03 amendment below) and returns `202 {run_id, scenario, state, token}`. The **token** is 32 hex,
random, returned only here - never in an event or in `/api/runs/{id}` - and held in memory on the run; it is
the capability to drive that run. Per run the API sets env `SDP_FLAG` = `SDP{` + 16 hex + `}` on the `target`
container (the victim writes it to `/srv/shop/.flag`, 0600, and never serves it); it is the run's own secret,
overriding any value the catalogue pins, so one visitor cannot read another's and the catalogue cannot fix it
to a known string.

**Commands.** `POST /api/runs/{run_id}/commands`, `Authorization: Bearer <token>`, body `{"id":"read-shadow"}`
→ `202 {seq}`. The token is compared in constant time. `401` wrong/missing token, `404` unknown run or command
id, `409` the run is not ready or is over or a command is already running (one at a time), `413` body over 256
bytes, `429` over 30 commands in the run. A non-TTY command's exec is cancelled after 5 s, a TTY command's (an
interactive shell, which only a pod deletion is expected to end) after 10 s, so a shell nobody answers
cannot hold the run - and the one global slot - until the deadline. `DELETE /api/runs/{run_id}` with the
token ends the run ("the visitor left"); once the run is over, including while its pod is still being
deleted, both endpoints answer `409`. A terminal run ends when Talon deletes the pod (`killed`), on `DELETE`
(`left`), after `idle_seconds` with no command (`idle`), or at `timeout_seconds` (`deadline`); the final `run`
event is `finished` with that `detail`. Idle counts from the last command's *start*, not its end, and bounds
the command too: a command that hangs is not activity. `detected` and `responded` run events may occur more than once in a
terminal run (a quarantine command, then later a terminate command), unlike a scripted run where either ends
it.

**The `command` event**, published to every subscriber (other visitors watch read-only):
`{run_id, seq, id, state, at, stream?, chunk?, exit_code?, achieved?, truncated?}`. `state` is `started` when
the exec is sent, `output` with `stream` (stdout/stderr) and a `chunk` of at most 1024 bytes of text,
`exited` with `exit_code` and `achieved` (true iff the command has an `objective` and exited 0), or `killed`
when the pod went away under the command (no exit code). A non-zero exit is the command's own result (wget
fails by design), not an error. An exec cut short before the shell reported a status (its own bound, a leave,
a transport error) is `exited` with no `exit_code`, never a made-up `-1`. A kill can reach the API as a clean
exit: the exec stream reports a container killed under the command as status 137 (SIGKILL) or 143 (SIGTERM),
often before the pod watch has seen the deletion. So after a transport error or an exit status above 128 the
runner waits briefly for the deletion (3 s at most) before choosing between `killed` and `exited`; an
ordinary exit does not wait.

**Output is scrubbed as whole lines, then batched and capped.** The pod chooses every byte and every write
boundary, so the unit of scrubbing is not a write or a chunk but a complete line of one stream (the bytes
between two newlines, or the last bytes when the stream ends). Each line is forced to valid UTF-8, stripped of
every control character except newline and tab (so no ANSI escape sequences) and of invisible format
characters, then run through the ADR 0021 scrubber (URLs, IPv4/IPv6 and in-cluster service names replaced;
loopback kept, because `http://127.0.0.1:9/` is the evidence that nothing left the pod). None of the
scrubber's patterns can match across a newline, so a token always lies inside one line and is seen whole,
however the pod splits its writes or pads them with bytes the sanitiser drops. A line that does not end
within 2 KiB is not scrubbed in pieces - each piece would pass on its own - but dropped whole, with
`[line too long, not shown]` published in its place and `truncated: true` on the command's end event. Only
scrubbed text is cut into events, on a UTF-8 boundary, so an event boundary can fall inside a replacement such
as `[ip]` but never inside an address. The lines one write completes are published together, up to 1024 bytes
per `output` event, so a burst of short lines is a few events, not one per line. Output is capped per command
at 4 KiB and 64 `output` events, and per run at 32 KiB and 300 events - events are bounded as well as bytes,
since the stream's buffers and the run log count events; past any cap, `truncated: true` and the rest of that
command's output is dropped. A write that arrives after the command's end event is ignored. The flag is not
special-cased: it is this run's secret and is meant to be seen by the visitor who read it.

**Correlation.** `falco` and `talon` events gain `command_seq`: the command that was running, or ended less
than 2 s before, when the alert arrived; absent otherwise. It is best effort (Falco's alert and the exec are
not transactionally linked) and set by the server from the runner. Only the attribution is best effort: a
Falco alert for the run's pod is always a `detected` run event, its rule capped at 256 characters like any
Falco field. One that correlates to no command is published once per run without `command_seq`, unless the
run already detected the same rule - then it is that command's alert arriving late, not a new detection.
A `responded` run event is paired with the detection it answers, not with whatever command is running when
Talon's notification arrives (the visitor has often typed the next one by then): the most recent detection
with no response yet whose command's catalogue response is what Talon did (`kubernetes:label` is the
quarantine, `kubernetes:terminate` the terminate; Talon's notification names no Falco rule), published under
that detection's `command_seq`. No `detected` is ever made up at the moment of a response - one would read as
a 0 ms response and, on another command, as a detection nobody answered. If no detection is waiting (Talon
beat Falco's alert to the API), the response is published tied to the command running or just ended, and the
alert, when it comes, is taken as already answered; a repeat notification for something already answered
publishes nothing.
`/api/runs/{id}` includes `command` events under the per-run caps of ADR 0021, with room reserved for how
each command and the run ended (below), so a whole terminal session can be replayed and checked.

**FIX 1: a quarantine shows its cut.** The live demo deleted a quarantined pod on a fixed 5 s linger, which
beat Cilium's isolation, so the probe was still answering and no `unreachable` ever reached the page. The
runner now keeps a quarantined pod until the victim poller has published an `unreachable` event at or after
the response and then 3 s more, the whole wait bounded by `QuarantineLingerMax` (40 s) so a run that never goes
unreachable still ends promptly. "At or after" is decided by time - the poller records when each cut was
published, the runner when it observed Talon's response - not by draining a signal, because the cut is often
published between the webhook's arrival and the run reaching the linger. Without a victim poller there is no
cut to wait for, and a fixed 3 s stands in. The cluster's job is to make the isolation itself land under 3 s (ADR 0032); the API's job is to not
delete the pod before the cut is visible.

## Consequences
- An anonymous visitor can now exec into a `sandbox` pod - but only commands the catalogue lists, by id, one
  at a time, at most 30 per run, each non-TTY exec capped at 5 s, the whole run capped at 120 s (300 s since
  the 2026-10-03 amendment below), and only while holding a token the API handed to that one run. The RBAC is
  unchanged: `pods/exec create` in `sandbox`, which the scripted scenarios already needed.
- The API streams attacker-controlled bytes to every subscriber. The caps (1 KiB per event; 4 KiB and 64
  events per command; 32 KiB and 300 events per run; lines over 2 KiB dropped), the sanitiser (valid UTF-8, no
  control characters but newline/tab, no invisible format characters) and the ADR 0021 scrubber, applied to
  whole lines only, bound what that can carry; the renderer is text-only under the
  Trusted Types CSP (ADR 0019), so markup in the output is shown, not run.
- `detected`/`responded` are no longer terminal for a terminal run, and a run can be quarantined and then
  terminated; the run store and stats treat them as repeatable.
- The per-run flag is a new secret in the pod's environment. It is per run, overrides the catalogue, and is
  never published except as the visitor's own command output; the victim never serves it.
- Correlation between an alert and a command is best effort and documented as such: a 2 s window and the
  running command. A visitor doing several things quickly may see an alert attributed to the neighbouring
  command; the Falco event's own fields remain the ground truth.

## What a mid-session viewer sees, and the compare hold

A terminal run is the largest run the API publishes. Its own events are bounded: at most 300 `output`
events (the per-run cap), a `started` and an end event for each of at most 30 commands, its `run` states,
and the pod and victim events - about 400 in the worst case. Falco and Talon events about its pod are not
bounded by the API (a rule may fire in a loop).

- **Joining mid-session.** The SSE hub replays its last 100 events to a client that connects (ADR 0021).
  For a scripted run that is the whole run; for a busy terminal session it is the tail - it may begin in the
  middle of a command's output. The page gets the whole session from `GET /api/runs/{id}`. A viewer watching
  someone else's run sees the same `command` events read-only (the token is needed to drive a run, never to
  watch it).
- **Keeping up.** Each subscriber may fall 128 events behind before the hub drops it - room for one
  command's largest burst (`started`, 64 `output` events, its end, and the run, Falco and Talon events around
  it), so a reading client is not dropped by a momentary stall. A client that has stopped reading is dropped;
  EventSource reconnects with `Last-Event-ID` and gets what it missed if that is still among the last 100
  events, and otherwise reads the run from `GET /api/runs/{id}`.
- **The record.** `GET /api/runs/{id}` keeps up to 500 events and 256 KiB per run (ADR 0021), of which 50
  events and 32 KiB are reserved for terminal-state events: the final `run` event (`finished`, `failed`,
  `timeout`) and each command's `exited`/`killed`. Everything else stops at the rest, so however many alerts
  or output chunks a run produced, its record still says how each command ended and ends with the run's final
  state (31 such events at most, a few KiB). Past the caps the record is marked `truncated`.

The unguarded twin's extra linger, `compare_hold_seconds` (default 12), is an API environment
setting (`COMPARE_HOLD_SECONDS`), not a catalogue field: it governs how the API runs a compare, not
what an attack is. It belongs to the twin mechanism of ADR 0031, which is the cluster branch's and not on
this branch, so the API, which owns the value, records it here.

## Amendment 2026-10-03: a killed run waits for Talon's notification

Live, the pod watch reported Talon's delete 10 ms before Talon's own notification reached the API; the run
had already published `finished` and the `responded` that explains the kill was dropped, so the page could
not say how long after the visitor's Enter the pod died, and the stats recorded no response time for it. A
terminal run whose pod is deleted under it now waits, while a detection is still unanswered, up to
`ResponseWait` (2 s) for that answer before it ends. A kill with nothing left to answer ends at once.

## Amendment 2026-10-03: a terminal run lasts up to 300 s and goes idle after 90 s

The terminal's `timeout_seconds` is now 300 and its `idle_seconds` 90 (were 120 and 30; ADR 0032 amendment,
the bound itself in ADR 0017's). Visitors' runs, the owner's own included, ended `idle` while they were reading
the explanation of the command they had just run, and the 120 s cap left room for only a few moves. Nothing
in the runner changes: the deadline (`ctx`, from `Timeout()`) and the idle timer (from `Idle()`) were already
read from the catalogue, and the command bounds - 5 s per non-TTY command, 10 s for a TTY one, capped by the
idle time when that is shorter - do not depend on the session length, so they stay. Neither does the per-run
cap of 30 commands, nor the output caps. `GET /api/scenarios/terminal/details` sends the two values as before
(`timeout_seconds`, `idle_seconds`), now 300 and 90.

What changes is what the catalogue may say. The API's validation now refuses an entry whose `timeout_seconds`
is over the 300 s bound (it used to cap it silently) and an interactive entry whose idle time, defaults
included, is not below its timeout - an idle timer that can never fire would end every quiet run as `deadline`
instead of `idle`. Both are unit-tested (`TestTimeoutAndIdleBounds`), and the real catalogue's copy in
`testdata/` is checked to load with 300 and 90.

The cost, accepted by the owner: one run at a time for everyone (ADR 0015), so a visitor who arrives during
someone else's terminal session may wait up to five minutes, watching it read-only, before starting their own.
