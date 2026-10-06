// The visitor's own run, told back to them (ADR 0035, amendment 2026-10-06 "the visitor's run, told
// back"). Three things read the same facts: the status strip under the terminal (and its toast), the
// "This run" panel beside it, and the SIEM scenario block at the top of #correlation. The facts are
// the ones the page already has: the run's events from the stream (pod_ready, the Falco alert, the
// Talon response, the end) and the incidents GET /api/correlation publishes, which carry the run id
// (ADR 0036 §9, `run_id`, already public in /api/runs). Nothing here is fetched or invented; every
// function is pure (facts and a clock in, words out) so the state machines are unit tested.

import type { CatalogueCommand, CorrelationIncident, Severity } from "./contract";
import type { RunView } from "./timeline";
import { formatDuration, ts } from "./timeline";

/** The catalogue command only the SIEM catches: Falco has no rule for a name lookup. */
export const SIEM_COMMAND = "dns-exfil";
/** After this long without the incident, "waiting for the SIEM" says it is late instead. */
export const SIEM_WAIT_MS = 6 * 60_000;
/** The eager poll stops this long after it began, whatever the waits say (a hard cap on the page's side). */
export const EAGER_CAP_MS = 9 * 60_000;

/**
 * How long the page has waited for a filing of `kind` whose wait began at `apiSince` (the API's clock).
 * The page passes one timed on its own clock from the moment it first saw the expectation, so a
 * visitor's wrong clock moves nothing; without one, `now - apiSince` (both on the API's clock: tests).
 */
export type WaitClock = (kind: string, apiSince: number) => number;
const waitedFor = (f: { now: number; waited?: WaitClock }, kind: string, since: number): number => (f.waited ? f.waited(kind, since) : f.now - since);
/** The SIEM's incidents usually land this long after the event (ADR 0036): said, not measured. */
export const SIEM_USUAL = "usually 1–3 min";

/** What each incident kind means, in the page's words. A Map: a kind such as "constructor" finds nothing. */
const KINDS: ReadonlyMap<string, string> = new Map([
  ["staged-attack", "Staged attack"],
  ["contained-intrusion", "Contained intrusion"],
  ["dns-exfil", "DNS exfiltration"],
  ["policy-probing", "Policy probing"],
  ["prevented-not-detected", "Prevented, not detected"],
  ["detection-missing", "Detection missing"],
  ["exec-outside-api", "Exec outside the API"],
  ["twin-dwell", "Unguarded twin: dwell time"],
]);
/** An unknown kind (a newer API) reads as a plain "Incident": the page names only kinds it knows. */
export const kindLabel = (kind: string): string => KINDS.get(kind) ?? "Incident";

// ---------- the command palette ----------

/** A chip's colour: grey allowed, red Falco answers it, amber the pod's hardening prevents it, green only the SIEM sees it. */
export type PaletteTone = "allowed" | "detected" | "prevented" | "siem";

/** "siem": an allowed command whose control says the SIEM is what catches it (the catalogue's dns-exfil). */
export function paletteTone(c: Pick<CatalogueCommand, "outcome" | "control">): PaletteTone {
  if (c.outcome === "detected" || c.outcome === "prevented") return c.outcome;
  return /\bSIEM\b/.test(c.control) ? "siem" : "allowed";
}

// ---------- what the run's events say ----------

export interface RunAlert {
  rule: string;
  at: number;
  /** From the Enter of the command it is about (its `started`) to the alert; undefined when not positive. */
  afterEnterMs?: number;
}

export interface RunResponse {
  action: "terminate" | "quarantine";
  at: number;
  /** From the alert that caused it to the response; undefined when not positive. */
  afterAlertMs?: number;
}

/** The newest Falco alert on the run's (guarded) pod, with how long after its command's Enter. */
export function lastAlert(run: RunView): RunAlert | undefined {
  const alerts = run.falco.filter((f) => f.arm !== "unguarded");
  const a = alerts[alerts.length - 1];
  if (!a) return undefined;
  const at = ts(a.at);
  const cmd = a.command_seq !== undefined ? run.commands.find((c) => c.seq === a.command_seq) : [...run.commands].reverse().find((c) => c.startedAt !== undefined && c.startedAt <= at);
  const enter = cmd?.startedAt;
  return { rule: a.rule, at, afterEnterMs: enter !== undefined && at > enter ? at - enter : undefined };
}

/**
 * The newest response to the run: the API's `responded` (its detail names the action), else a guarded
 * Talon action of either kind; with how long after the alert that caused it (the alert about the same
 * command, else the last one before it).
 */
export function lastResponse(run: RunView): RunResponse | undefined {
  const kindOf = (s: string): RunResponse["action"] | undefined => (/terminate/i.test(s) ? "terminate" : /label|quarantine/i.test(s) ? "quarantine" : undefined);
  let pick: { action: RunResponse["action"]; at: number; seq?: number } | undefined;
  for (const r of run.responses) {
    const action = kindOf(r.action);
    if (action && (!pick || r.at >= pick.at)) pick = { action, at: r.at, seq: r.seq };
  }
  if (!pick) {
    for (const t of run.talon) {
      const action = t.arm === "unguarded" ? undefined : kindOf(`${t.actionner ?? ""} ${t.action}`);
      if (action && (!pick || ts(t.at) >= pick.at)) pick = { action, at: ts(t.at), seq: t.command_seq };
    }
  }
  if (!pick) return undefined;
  const at = pick.at;
  const seq = pick.seq;
  const alerts = run.falco.filter((f) => f.arm !== "unguarded");
  const alert = (seq !== undefined ? alerts.find((f) => f.command_seq === seq) : undefined) ?? [...alerts].reverse().find((f) => ts(f.at) <= at);
  const from = alert ? ts(alert.at) : undefined;
  return { action: pick.action, at, afterAlertMs: from !== undefined && at > from ? at - from : undefined };
}

// ---------- what the SIEM is expected to file ----------

export type SiemAvailability = "unknown" | "available" | "unavailable";

/** The visitor's own incidents, the most severe first, then the newest. */
export function incidentsFor(incidents: readonly CorrelationIncident[], runId: string | undefined): CorrelationIncident[] {
  if (!runId) return [];
  const rank: Record<Severity | "unknown", number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
  return incidents.filter((i) => i.run_id === runId).sort((a, b) => rank[b.severity] - rank[a.severity] || Date.parse(b.last_at) - Date.parse(a.last_at));
}

/** The run's dns-exfil command, the last one run, if any. */
function exfilCommand(run: RunView | undefined) {
  return run ? [...run.commands].reverse().find((c) => c.id === SIEM_COMMAND) : undefined;
}

/**
 * What the run should make the SIEM file, and since when: the DNS exfil once its command exited 0
 * (the question carried the flag), a contained intrusion once Falco alerted, a prevented command once
 * it ended. Each says when the wait began (the API's clock). The API files all three with the run's id
 * for a terminal run (app/api/internal/incidents: the run's own API records anchor a contained
 * intrusion; a prevented-not-detected alert's bucket key is the run's pod ref, mapped to its run).
 */
export function siemExpectations(run: RunView | undefined, commands: readonly CatalogueCommand[]): { kind: string; since: number }[] {
  if (!run) return [];
  const out: { kind: string; since: number }[] = [];
  const exfil = exfilCommand(run);
  if (exfil?.endedAt !== undefined && exfil.exitCode === 0) out.push({ kind: SIEM_COMMAND, since: exfil.endedAt });
  const alert = lastAlert(run);
  if (alert) out.push({ kind: "contained-intrusion", since: alert.at });
  const prevented = run.commands.find((c) => c.endedAt !== undefined && commands.find((x) => x.id === c.id)?.outcome === "prevented");
  if (prevented?.endedAt !== undefined) out.push({ kind: "prevented-not-detected", since: prevented.endedAt });
  return out;
}

// ---------- the SIEM scenario's state chip ----------

export type ScenarioPhase = "idle" | "running" | "failed" | "waiting" | "late" | "down" | "found";

export interface ScenarioState {
  phase: ScenarioPhase;
  /** "found": the incident's id and severity. */
  incidentId?: string;
  severity?: string;
}

/**
 * not run yet → running → waiting for the SIEM (≈2 min) → found it. The current session's dns-exfil
 * comes first; with none in it, an incident of an earlier session of this page view still counts.
 * The wait is timed by `waited` (the page's own clock) when given, else by `now` on the API's clock.
 */
export function scenarioState(f: { run?: RunView; incidents: readonly CorrelationIncident[]; ownRuns: readonly string[]; siem: SiemAvailability; now: number; waited?: WaitClock }): ScenarioState {
  const found = (runIds: readonly string[]): ScenarioState | undefined => {
    const i = f.incidents.filter((x) => x.kind === SIEM_COMMAND && runIds.includes(x.run_id)).sort((a, b) => Date.parse(b.last_at) - Date.parse(a.last_at))[0];
    return i ? { phase: "found", incidentId: i.id, severity: i.severity } : undefined;
  };
  const exfil = exfilCommand(f.run);
  if (f.run && exfil) {
    const mine = found([f.run.runId]);
    if (mine) return mine;
    if (exfil.endedAt === undefined) return { phase: "running" };
    if (exfil.exitCode !== 0) return { phase: "failed" };
    if (f.siem === "unavailable") return { phase: "down" };
    return { phase: waitedFor(f, SIEM_COMMAND, exfil.endedAt) > SIEM_WAIT_MS ? "late" : "waiting" };
  }
  return found(f.ownRuns) ?? { phase: "idle" };
}

// ---------- the "This run" panel's SIEM row ----------

export interface SiemRow {
  text: string;
  tone: "idle" | "pending" | "siem" | "neutral";
  incidentId?: string;
}

export function siemRow(f: { run?: RunView; commands: readonly CatalogueCommand[]; incidents: readonly CorrelationIncident[]; siem: SiemAvailability; now: number; waited?: WaitClock }): SiemRow {
  const mine = incidentsFor(f.incidents, f.run?.runId)[0];
  if (mine) return { text: `${mine.severity.toUpperCase()} — ${kindLabel(mine.kind)}`, tone: "siem", incidentId: mine.id };
  const expected = siemExpectations(f.run, f.commands);
  if (!expected.length) return { text: "nothing to correlate yet", tone: "idle" };
  if (f.siem === "unavailable") return { text: "unavailable right now", tone: "neutral" };
  const waited = Math.max(...expected.map((e) => waitedFor(f, e.kind, e.since)));
  return waited > SIEM_WAIT_MS ? { text: "nothing filed yet; the SIEM may be behind", tone: "pending" } : { text: `waiting… (${SIEM_USUAL})`, tone: "pending" };
}

/** Whether a filing for this run is still awaited: the page then asks the SIEM more often. */
export function siemPending(f: { run?: RunView; commands: readonly CatalogueCommand[]; incidents: readonly CorrelationIncident[]; now: number; waited?: WaitClock }): boolean {
  const kinds = new Set(incidentsFor(f.incidents, f.run?.runId).map((i) => i.kind));
  return siemExpectations(f.run, f.commands).some((e) => !kinds.has(e.kind) && waitedFor(f, e.kind, e.since) <= SIEM_WAIT_MS * 1.5);
}

// ---------- the status strip ----------

export type StripKind = "starting" | "ready" | "falco" | "killed" | "quarantined" | "over" | "siem-waiting" | "siem-late" | "siem-down" | "siem-found";
export type StripAction = "timeline" | "again" | "open";

export interface Strip {
  /** Identity of the message: a dismissed one stays away until the key changes. */
  key: string;
  kind: StripKind;
  tone: "info" | "detect" | "respond" | "siem" | "pending" | "neutral";
  lead: string;
  text: string;
  /** A second line: a SIEM wait still running under a newer message. */
  note?: string;
  actions: StripAction[];
  incidentId?: string;
  /** Worth the sticky toast when the strip is scrolled out of view (not "starting" or "ready"). */
  toast: boolean;
}

export interface StripFacts {
  /** The visitor's own session; undefined: none started in this page view. */
  runId?: string;
  run?: RunView;
  commands: readonly CatalogueCommand[];
  idleSeconds?: number;
  incidents: readonly CorrelationIncident[];
  siem: SiemAvailability;
  /** The API's clock, for the SIEM wait when no `waited` is given. */
  now: number;
  waited?: WaitClock;
}

/** Tie-break among messages first seen in the same update: the bigger news wins. */
const RANK: Record<StripKind, number> = { "siem-found": 9, killed: 8, over: 7, quarantined: 6, falco: 5, "siem-down": 4, "siem-late": 3, "siem-waiting": 2, ready: 1, starting: 0 };

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

function runMessage(run: RunView | undefined, idleSeconds: number | undefined): Strip {
  const base = { note: undefined, incidentId: undefined };
  if (!run || (run.active && run.states.pod_ready === undefined)) {
    return { ...base, key: "starting", kind: "starting", tone: "info", lead: "Pod starting…", text: " The input unlocks when it is ready, in a few seconds.", actions: [], toast: false };
  }
  const response = lastResponse(run);
  const later = (r: RunResponse) => (r.afterAlertMs !== undefined ? ` ${formatDuration(r.afterAlertMs)} later` : "");
  if (!run.active) {
    if (run.detail === "killed") {
      return response?.action === "terminate"
        ? { ...base, key: "killed", kind: "killed", tone: "respond", lead: "Talon deleted the pod", text: `${later(response)}. Session over.`, actions: ["timeline", "again"], toast: true }
        : { ...base, key: "killed", kind: "killed", tone: "respond", lead: "The cluster deleted the pod.", text: " Session over.", actions: ["timeline", "again"], toast: true };
    }
    const failed = run.current === "failed" || run.current === "timeout";
    const why = failed
      ? "it could not run"
      : run.detail === "left"
        ? "you left"
        : run.detail === "idle"
          ? `it ended after ${idleSeconds !== undefined ? `${idleSeconds} s` : "the idle limit"} without a command`
          : run.detail === "deadline"
            ? "it reached the session's time limit"
            : "it ended";
    return { ...base, key: `over:${run.detail ?? ""}`, kind: "over", tone: "neutral", lead: "Session over", text: ` — ${why}.`, actions: ["again"], toast: true };
  }
  const alert = lastAlert(run);
  if (response?.action === "quarantine" && (!alert || response.at >= alert.at)) {
    return { ...base, key: `quarantined:${response.at}`, kind: "quarantined", tone: "respond", lead: "Talon quarantined the pod", text: `${later(response)}. You keep the shell, but its network is cut both ways.`, actions: ["timeline"], toast: true };
  }
  if (alert) {
    return { ...base, key: `falco:${alert.at}`, kind: "falco", tone: "detect", lead: "Falco saw that", text: ` — ${alert.rule}${alert.afterEnterMs !== undefined ? ` at +${formatDuration(alert.afterEnterMs)}` : ""}`, actions: [], toast: true };
  }
  return { ...base, key: "ready", kind: "ready", tone: "info", lead: "Pod ready.", text: " uid 10001, no network, read-only root. Type a command.", actions: [], toast: false };
}

function siemMessages(f: StripFacts): Strip[] {
  const out: Strip[] = [];
  const over = f.run !== undefined && !f.run.active;
  const mine = incidentsFor(f.incidents, f.runId);
  for (const i of mine) {
    const sev = i.severity.toUpperCase();
    const exfil = i.kind === SIEM_COMMAND;
    out.push({
      key: `incident:${i.id}`,
      kind: "siem-found",
      tone: "siem",
      lead: exfil ? `The SIEM caught your DNS exfil — ${sev}.` : `The SIEM filed this as ${sev} — ${kindLabel(i.kind)}`,
      text: exfil ? " Falco never saw it." : "",
      actions: over ? ["open", "again"] : ["open"],
      incidentId: i.id,
      toast: true,
    });
  }
  const exfil = exfilCommand(f.run);
  const filed = mine.some((i) => i.kind === SIEM_COMMAND);
  if (exfil?.endedAt !== undefined && exfil.exitCode === 0 && !filed) {
    if (f.siem === "unavailable") {
      out.push({ key: "siem-down", kind: "siem-down", tone: "neutral", lead: "The SIEM is not reachable right now,", text: " so nothing on this page can tie your DNS query to this run.", actions: [], toast: true });
    } else if (waitedFor(f, SIEM_COMMAND, exfil.endedAt) > SIEM_WAIT_MS) {
      out.push({ key: "siem-late", kind: "siem-late", tone: "pending", lead: "The SIEM has not tied your DNS exfil to this run yet.", text: ` It is ${SIEM_USUAL}; the board below keeps asking.`, actions: [], toast: true });
    } else {
      out.push({ key: "siem-waiting", kind: "siem-waiting", tone: "pending", lead: "Waiting for the SIEM", text: ` (${SIEM_USUAL})…`, actions: [], toast: true });
    }
  }
  return out;
}

/**
 * The strip's state machine. Each message is remembered with the update it first appeared in; the
 * newest wins, so each event replaces the one before ("Falco saw that", then "Talon deleted the pod",
 * then "The SIEM caught your DNS exfil"), while a command Falco allows changes nothing (silence is the
 * point). Messages that first appear together (a replay, a backfill) are ranked by how big the news is.
 * A new session starts from nothing.
 */
export class StripTracker {
  private runId: string | undefined;
  private readonly seen = new Map<string, number>();
  private updates = 0;

  update(f: StripFacts): Strip | null {
    if (f.runId !== this.runId) {
      this.runId = f.runId;
      this.seen.clear();
    }
    if (!f.runId) return null;
    this.updates += 1;
    const candidates = [runMessage(f.run, f.idleSeconds), ...siemMessages(f)];
    for (const c of candidates) if (!this.seen.has(c.key)) this.seen.set(c.key, this.updates);
    const order = (s: Strip) => this.seen.get(s.key) ?? 0;
    const sev = (s: Strip) => (s.incidentId ? (SEV_RANK[f.incidents.find((i) => i.id === s.incidentId)?.severity ?? ""] ?? 0) : 0);
    let best = [...candidates].sort((a, b) => order(b) - order(a) || RANK[b.kind] - RANK[a.kind] || sev(b) - sev(a))[0];
    // Among the SIEM's filings for the run, a later, milder one does not replace a more severe one:
    // the CRITICAL DNS exfil stays the message when the HIGH contained intrusion lands after it.
    const found = candidates.filter((c) => c.kind === "siem-found");
    if (best.kind === "siem-found" && found.length > 1) {
      best = [...found].sort((a, b) => sev(b) - sev(a) || order(b) - order(a))[0];
      const more = found.length - 1;
      return { ...best, note: `The SIEM filed ${more} more incident${more === 1 ? "" : "s"} for this run on the board below.` };
    }
    const waiting = candidates.find((c) => c.kind === "siem-waiting");
    if (waiting && best !== waiting && !best.kind.startsWith("siem")) return { ...best, note: `Still waiting for the SIEM on your DNS exfil (${SIEM_USUAL})…` };
    return best;
  }
}

// ---------- the busy slot's end ----------

/**
 * How long until a run that holds the one slot must end, from its limits: the session deadline from
 * its start, and for the terminal the idle limit from pod_ready or the last command's start. undefined
 * without a start or a limit; never below zero.
 */
export function runEndsWithin(run: Pick<RunView, "states" | "commands" | "scenario">, now: number, timeoutSeconds?: number, idleSeconds?: number): number | undefined {
  const begun = run.states.queued ?? run.states.started;
  const ends: number[] = [];
  if (begun !== undefined && timeoutSeconds !== undefined) ends.push(begun + timeoutSeconds * 1000);
  const ready = run.states.pod_ready;
  if (run.scenario === "terminal" && ready !== undefined && idleSeconds !== undefined) ends.push(Math.max(ready, ...run.commands.map((c) => c.startedAt ?? 0)) + idleSeconds * 1000);
  return ends.length ? Math.max(0, Math.min(...ends) - now) : undefined;
}
