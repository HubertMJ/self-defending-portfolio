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
`min`/`max`); `unanswered` (runs detected but not responded to **before the scenario timeout** - a run the
visitor left, let go idle, or that was killed is not an escape, so only a `timeout` ending counts); per
terminal command `{attempts, allowed, prevented, detected}`; per objective `{attempts, achieved}` counted once
per run ("tried / reached by X of N runs", not per keystroke); and
`terminal{runs, best_objectives, median_survival_s}`. A command's outcome and objective are read from the
catalogue once when the run is first seen (not per event, so Record does no file I/O under the hub lock), and
a late event for a run that already finished is ignored rather than resurrecting it. `GET /api/stats` renders
it; a scenario's interactive flag, command outcomes and objectives are looked up by id, never trusted from the
event.

**Persistence is one ConfigMap, `portfolio-stats` in `portfolio-api`.** It is committed empty in git with Argo
CD ignoring its `data` (so Argo never fights the API's writes), read once at start, and written by a
background loop at most once a minute - only when the counters changed - and once more on shutdown. The blob
is the serialised aggregate (totals and the bounded latency/survival sample rings, so `p50` and the median
survive a restart); it holds no per-run or per-visitor record. The RBAC is a Role in `portfolio-api` with
exactly `get` and `update` on that one object (owned by the cluster manifests, ADR 0032's sibling work): the
API updates the object the manifest ships, and never creates it, so it needs no `create` and a lost write
path can touch nothing else. A missing or unparseable ConfigMap, or no RBAC at all, starts the counters from
zero and logs it; the counters are never load-bearing for the service, and a nil client makes load and save
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
  because of this ConfigMap, and a corrupted blob falls back to zero rather than failing start-up. The
  earlier "in memory only" open item (ADR 0015) is narrowed: the cross-visitor counters now persist; the
  rate-limit windows and the per-run history still do not.
