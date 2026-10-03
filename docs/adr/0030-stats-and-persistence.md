# ADR 0030: Cross-visitor stats, and persisting them in one ConfigMap

Date: 2026-10-02 · Status: accepted

## Context
The interactive demo gives the visitor objectives to reach and a per-run flag (ADR 0029), and the owner
wanted the page to show the value of the defence by contrast: how many attacks have been run, how many were
detected and answered, how fast the response was, which terminal commands visitors run and which objectives
they actually reach - "call home: 0 of 412 attempts". That needs counters across all visitors, and they have
to survive the Deployment being rolled (the API is one replica with in-memory state, ADR 0015), or every
number resets to zero on each image bump and the page's "since" is meaningless.

Two things must stay true. The counters are **aggregate only** - no client address, no visitor's free text,
nothing that identifies a run to a person - so they are safe to write to a ConfigMap that is in a public git
repository's namespace. And persisting them must not widen the API's blast radius more than two numbers are
worth: no new cluster-wide grant, no new stateful workload.

## Decision

**A collector fed by the hub tap.** `internal/stats` accumulates the counters from the same event stream the
page sees: `events.Hub` already has a tap (the run store uses it), and the collector registers alongside it,
so it records exactly what was published and needs no extra API reads or RBAC. It derives everything from the
`run` and `command` events - the run states already encode every detection and response, so the raw
`falco`/`talon` events are not consumed: total `runs` and `by_scenario{runs, detected, responded}`;
`response_ms` (detection-to-response latency: `last`, `p50` over a bounded recent sample, all-time
`min`/`max`), where a response is measured only against the detection of the same command (`command_seq`;
a scripted run has one of each) - a terminal run may detect several commands, and an unanswered detection at
2 s followed by a 400 ms response to another command at 102 s is a 400 ms response, not a 100 s one; a
response that cannot be paired with a detection records no latency; `unanswered` (runs detected but not
responded to **before the scenario's time ran out** - a run the visitor left, let go idle, or that was killed
is not an escape: for a scripted run that is a `timeout` ending; a terminal run never ends `timeout`, so it is
unanswered when it ends `finished` with detail `deadline` while a detection has had no response - counted
once per run; detections and responses are matched by `command_seq` only, since the runner already
publishes a response under the seq of the detection it answers (ADR 0029), so a response tied to no
command answers only the detection tied to none); per
terminal command `{attempts, allowed, prevented, detected}`; per objective `{attempts, achieved}` counted once
per run ("tried / reached by X of N runs", not per keystroke); and
`terminal{runs, best_objectives, median_survival_s}`. A command's outcome and objective are read from the
catalogue once when the run is first seen (not per event, so Record does no file I/O under the hub lock), and
a late event for a run that already finished is ignored rather than resurrecting it. `GET /api/stats` renders
it; a scenario's interactive flag, command outcomes and objectives are looked up by id, never trusted from the
event.

**Persistence is one ConfigMap, `portfolio-stats` in `portfolio-api`.** It is committed empty in git with Argo
CD ignoring its `data` (so Argo never fights the API's writes), read at start, and written by a
background loop at most once a minute - only when the counters changed - and once more on shutdown.
**It is written only after it has been read.** A read that fails (the API server briefly unreachable at
start-up) is not "there are no counters": writing what was counted since would overwrite the persisted
totals. So until a read succeeds nothing is written, and the loop retries the read on each tick; when it
succeeds, the persisted totals and the runs counted in the meantime are added together. A missing object or
an unparseable or invalid blob is a successful read with nothing to keep. The final write on shutdown is
serialised with the loop, so a tick whose write fails as the process stops cannot re-queue the counters after
the final write has looked. The blob
is the serialised aggregate (totals and the bounded latency/survival sample rings, so `p50` and the median
survive a restart); it holds no per-run or per-visitor record. The RBAC is a Role in `portfolio-api` with
exactly `get` and `update` on that one object (owned by the cluster manifests, ADR 0032's sibling work): the
API updates the object the manifest ships, and never creates it, so it needs no `create` and a lost write
path can touch nothing else. A missing or unparseable ConfigMap, or no RBAC at all, starts the counters from
zero and logs it. A loaded blob is validated before it is used: every counter, latency and sample must be
between 0 and 2^40 (a counter at the integer limit would overflow on its next increment), `since` must not
be in the future, `best_objectives` must be reachable (at most the catalogue's command ceiling, and 0 with no
terminal runs), and min must not exceed max; a blob written before the response count existed has it derived
from its samples, so its min survives. An invalid blob counts as unparseable; the counters are never load-bearing for the service, and a nil client makes load and save
no-ops so the API runs the same without them.

## Consequences
- The page can show real cross-visitor numbers with a truthful "since", and they persist across a
  `kubectl rollout restart` instead of resetting. A burst right after a restart is still bounded by the
  sandbox quota and the single run slot (ADR 0015).
- The API gains `get`/`update` on exactly one ConfigMap in its own namespace. It reveals nothing (the object
  holds only aggregate counters) and cannot reach any other object; `create` is deliberately withheld, so the
  object must exist in git first.
- The counters are approximate by design: `p50` and the median are over the last few hundred samples, not all
  time, so memory and the ConfigMap stay small; `response_ms` is the detection-to-response latency, which for
  a run answered before detection (the response webhook racing the alert) is clamped at zero. `unanswered` is
  the only "did the defence miss" number, and it counts a detected run that ended without a response, which
  is what the page claims and no more.
- Like the 24 h counters and the run history, the stats are the API's own state; a restart keeps them only
  because of this ConfigMap, and a corrupted blob falls back to zero rather than failing start-up; an unreadable one is not overwritten. The
  earlier "in memory only" open item (ADR 0015) is narrowed: the cross-visitor counters now persist; the
  rate-limit windows and the per-run history still do not.

## Amendment 2026-10-03: hourly buckets for the 24 h window, and the last run's time (ADR 0035)

**Context.** The posture's 24 h Falco/Talon counters lived in memory (ADR 0015) and reset on every rollout,
next to this ADR's persisted totals, so the page contradicted itself. The hero's "last run" also came only
from the live feed, so after a restart it showed nothing although runs had happened.

**Decision.** The blob gains `Hourly` (one bucket per unix hour with runs, detected, responded, Falco
alerts and Talon actions), `WindowSince` (when this window started counting) and `LastRunAt` (the time of
the most recent `queued` run event; one timestamp, no identifier). `/api/stats` publishes `last_run_at` and
`last_24h` (`since` and the five sums over the current hour and the 23 before it); the posture's 24 h counts
read the same buckets, so the two pages cannot disagree beyond the documented in-flight exception (ADR
0035): a detection published before its Falco webhook, until the webhook arrives or, if it never does,
until the run's hour leaves the window. A run's runs, detected and responded are all counted in the
hour it was queued, so `runs >= detected >= responded` holds in every window; alerts and actions are
counted in the hour they arrive. A run event stamped in the future is counted as now, for its hour and for
`LastRunAt`. Buckets older than the window are pruned on every write; nothing else about writing changes (one
object, `get`/`update`, written only after a successful read, at most once a minute when dirty).

Loading **sanitises** the new fields instead of rejecting the blob: buckets outside
[current hour - 23, current hour + 1] are dropped, duplicate hours are summed, a future `WindowSince` or
`LastRunAt` is clamped to now. An hourly section still malformed after that (a negative count, a count
above 2^40, or more than 25 buckets in range) is discarded on its own - the window restarts at now - while
the all-time totals still load; only a malformed all-time section rejects the blob as invalid (and so as
unparseable), as before. A late first read sums
buckets by hour and keeps the earliest `WindowSince` and the latest `LastRunAt`. A blob written before this
amendment loads with every all-time field unchanged, no buckets and `WindowSince` = now.

**Consequences.** The 24 h numbers survive a rollout and are labelled with `since` (23 to 24 hours, hour
granularity). Rolling back to an API without these fields is safe for the totals - it ignores unknown
fields - but its next write drops `Hourly`, `WindowSince` and `LastRunAt`, so the window starts again when
the newer API returns. The blob grows by at most 25 small buckets. The open item narrows again: the
rate-limit windows and the per-run history are what remain in memory.
