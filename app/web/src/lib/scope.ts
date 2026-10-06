// What the page shows by default (ADR 0035, amendment 2026-10-06 "this session first"): the visitor's
// own runs and any run another visitor has in progress right now, labelled as theirs. Every other run
// and incident of the last 24 h is behind one control, "All activity, last 24 h", kept in localStorage
// (`sdp:scope`, beside the fold keys). The visitor's own run ids are kept for the tab in sessionStorage
// (`sdp:own-runs`), so a reload still knows which runs are "yours"; they are public ids (/api/runs),
// and only strings isRunId accepts are read back. Every function here is pure, or takes its storage.

import { type CorrelationIncident, isRunId } from "./contract";

export type Scope = "session" | "all";

export const SCOPE_KEY = "sdp:scope";
export const OWN_RUNS_KEY = "sdp:own-runs";
/** The tab remembers this many of its own runs, the newest. */
export const OWN_RUNS_MAX = 20;

/** The words of the one control, wherever it is drawn. */
export const SCOPE_WORD: Record<Scope, string> = { session: "This session", all: "All activity, last 24 h" };

type Store = Pick<Storage, "getItem" | "setItem" | "removeItem">;

/** The stored choice; "session" by default, and when storage is missing or throws. */
export function loadScope(storage: Store | undefined): Scope {
  try {
    return storage?.getItem(SCOPE_KEY) === "all" ? "all" : "session";
  } catch {
    return "session";
  }
}

export function saveScope(scope: Scope, storage: Store | undefined): void {
  try {
    if (scope === "all") storage?.setItem(SCOPE_KEY, "all");
    else storage?.removeItem(SCOPE_KEY);
  } catch {
    // Not persisted: the choice holds for this page view.
  }
}

/** The tab's own run ids, oldest first: valid run ids only, no repeats, at most OWN_RUNS_MAX. */
export function loadOwnRuns(storage: Store | undefined): string[] {
  try {
    const v: unknown = JSON.parse(storage?.getItem(OWN_RUNS_KEY) ?? "[]");
    if (!Array.isArray(v)) return [];
    return [...new Set(v.filter((x): x is string => typeof x === "string" && isRunId(x)))].slice(-OWN_RUNS_MAX);
  } catch {
    return [];
  }
}

export function saveOwnRuns(ids: readonly string[], storage: Store | undefined): void {
  try {
    storage?.setItem(OWN_RUNS_KEY, JSON.stringify(ids.filter(isRunId).slice(-OWN_RUNS_MAX)));
  } catch {
    // Not persisted: a reload forgets which runs were this tab's.
  }
}

/** What every scoped part of the page is told: the choice, and which runs are the visitor's. */
export interface Focus {
  all: boolean;
  own: ReadonlySet<string>;
}

/** Everything, as before this amendment: what a part shows until the page tells it otherwise. */
export const ALL: Focus = { all: true, own: new Set() };

/** Whose a run is, from this page: the visitor's, another visitor's in progress now, or an earlier one. */
export type Whose = "own" | "live" | "other";

export function whose(run: { runId: string; active: boolean }, own: ReadonlySet<string>): Whose {
  if (own.has(run.runId)) return "own";
  return run.active ? "live" : "other";
}

/** The runs a list shows: all of them, or the visitor's own and any run in progress now. */
export function scopedRuns<T extends { runId: string; active: boolean }>(runs: readonly T[], f: Focus): T[] {
  return f.all ? [...runs] : runs.filter((r) => f.own.has(r.runId) || r.active);
}

/**
 * The one run the hero's card and #evidence's full record show. Everything: the newest. This session:
 * the visitor's own run in progress, else another visitor's run in progress, else the visitor's newest,
 * else the newest run of anyone as a labelled example.
 */
export function focusRun<T extends { runId: string; active: boolean }>(runs: readonly T[], f: Focus): { run: T; whose: Whose | "example" } | undefined {
  if (f.all) return runs[0] ? { run: runs[0], whose: whose(runs[0], f.own) } : undefined;
  const own = runs.filter((r) => f.own.has(r.runId));
  const ownLive = own.find((r) => r.active);
  if (ownLive) return { run: ownLive, whose: "own" };
  const live = runs.find((r) => r.active);
  if (live) return { run: live, whose: "live" };
  if (own[0]) return { run: own[0], whose: "own" };
  return runs[0] ? { run: runs[0], whose: "example" } : undefined;
}

/** The incidents of the visitor's own runs and of the run in progress now (`live`). */
export function scopedIncidents(incidents: readonly CorrelationIncident[], own: ReadonlySet<string>, live?: string): CorrelationIncident[] {
  return incidents.filter((i) => !!i.run_id && (own.has(i.run_id) || i.run_id === live));
}

/**
 * The one incident shown as an example of an earlier visitor's run when the visitor has none: the
 * newest critical DNS exfil (the incident the SIEM exists for), else the newest critical, else the
 * newest; never an operator's test exec.
 */
export function exampleIncident(incidents: readonly CorrelationIncident[]): CorrelationIncident | undefined {
  const real = incidents.filter((i) => !i.operator_test);
  const newest = (list: CorrelationIncident[]) => [...list].sort((a, b) => Date.parse(b.last_at) - Date.parse(a.last_at))[0];
  return newest(real.filter((i) => i.kind === "dns-exfil" && i.severity === "critical")) ?? newest(real.filter((i) => i.severity === "critical")) ?? newest(real);
}
