// Types and runtime guards for the portfolio API, mirroring the phase 5/6 contract
// (GET /api/scenarios, POST /api/attack/{id}, SSE /api/events, GET /api/posture).
//
// Everything that arrives from the network is checked here before the UI touches it. The checks are
// structural, not exhaustive: a field we do not render may be missing without breaking the page, but
// a field we do render must have the type we render it as, because Falco output in particular is
// text an attacker can influence and the UI must never be surprised by its shape.

export type ResponseAction = "terminate" | "quarantine";

export interface Scenario {
  id: string;
  title: string;
  summary: string;
  /** MITRE ATT&CK technique id, e.g. T1059.004 */
  technique: string;
  /** Falco rule name that is expected to fire */
  detection: string;
  response: ResponseAction | string;
}

export const RUN_STATES = [
  "queued",
  "started",
  "detected",
  "responded",
  "finished",
  "failed",
  "timeout",
] as const;
export type RunState = (typeof RUN_STATES)[number];
export const TERMINAL_STATES: ReadonlySet<RunState> = new Set(["finished", "failed", "timeout"]);

export interface AttackAccepted {
  run_id: string;
  scenario: string;
  state: "queued";
}

export interface RunEvent {
  run_id: string;
  scenario: string;
  state: RunState;
  at: string;
  detail?: string;
}

export interface FalcoEvent {
  at: string;
  rule: string;
  priority: string;
  namespace: string;
  pod: string;
  output: string;
}

export interface TalonEvent {
  at: string;
  action: string;
  namespace: string;
  pod: string;
  status: string;
}

export type StreamEvent =
  | { type: "run"; data: RunEvent }
  | { type: "falco"; data: FalcoEvent }
  | { type: "talon"; data: TalonEvent };

export interface KyvernoPolicy {
  name: string;
  pass: number;
  fail: number;
  warn: number;
}

export interface Posture {
  generated_at: string;
  kyverno: { policies: KyvernoPolicy[] };
  trivy: { images: number; critical: number; high: number; medium: number; low: number };
  kube_bench: { last_run: string | null; pass: number; fail: number; warn: number; info: number };
  falco: { alerts_24h: number };
  talon: { actions_24h: number };
}

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === "string";
const isCount = (v: unknown): v is number =>
  typeof v === "number" && Number.isFinite(v) && v >= 0;

function hasStrings(o: Obj, keys: readonly string[]): boolean {
  return keys.every((k) => isStr(o[k]));
}
function hasCounts(o: unknown, keys: readonly string[]): o is Obj {
  return isObj(o) && keys.every((k) => isCount(o[k]));
}

export function isScenario(v: unknown): v is Scenario {
  return isObj(v) && hasStrings(v, ["id", "title", "summary", "technique", "detection", "response"]);
}

export function parseScenarios(v: unknown): Scenario[] {
  if (!Array.isArray(v)) throw new TypeError("scenarios: expected an array");
  return v.filter(isScenario);
}

export function isAttackAccepted(v: unknown): v is AttackAccepted {
  return isObj(v) && hasStrings(v, ["run_id", "scenario"]) && v.state === "queued";
}

export function isRunEvent(v: unknown): v is RunEvent {
  return (
    isObj(v) &&
    hasStrings(v, ["run_id", "scenario", "at"]) &&
    (RUN_STATES as readonly unknown[]).includes(v.state) &&
    (v.detail === undefined || v.detail === null || isStr(v.detail))
  );
}

export function isFalcoEvent(v: unknown): v is FalcoEvent {
  return isObj(v) && hasStrings(v, ["at", "rule", "priority", "namespace", "pod", "output"]);
}

export function isTalonEvent(v: unknown): v is TalonEvent {
  return isObj(v) && hasStrings(v, ["at", "action", "namespace", "pod", "status"]);
}

/** Parses one SSE message into a typed event, or null if it does not match the contract. */
export function parseStreamEvent(type: string, raw: string): StreamEvent | null {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return null;
  }
  switch (type) {
    case "run":
      return isRunEvent(data) ? { type, data } : null;
    case "falco":
      return isFalcoEvent(data) ? { type, data } : null;
    case "talon":
      return isTalonEvent(data) ? { type, data } : null;
    default:
      return null;
  }
}

export function isPosture(v: unknown): v is Posture {
  if (!isObj(v) || !isStr(v.generated_at)) return false;
  const k = v.kyverno;
  if (!isObj(k) || !Array.isArray(k.policies)) return false;
  if (!k.policies.every((p) => hasCounts(p, ["pass", "fail", "warn"]) && isStr(p.name))) return false;
  if (!hasCounts(v.trivy, ["images", "critical", "high", "medium", "low"])) return false;
  const kb = v.kube_bench;
  if (!hasCounts(kb, ["pass", "fail", "warn", "info"])) return false;
  if (!(kb.last_run === null || isStr(kb.last_run))) return false;
  return hasCounts(v.falco, ["alerts_24h"]) && hasCounts(v.talon, ["actions_24h"]);
}
