// Types and runtime guards for the portfolio API, mirroring the phase 5/6 contract
// (GET /api/scenarios, POST /api/attack/{id}, SSE /api/events, GET /api/posture) and its "prove it is
// real" extension (pod/victim/flow events, extra Falco and Talon fields, GET /api/scenarios/{id}/details,
// GET /api/runs/{id}, GET /api/limits).
//
// Every field the extension added is optional here. The page ships independently of the API, so it
// must render the API that is deployed today (no `pod_ready`, no `fields`, no pod events) as well as
// the one that is coming; a newer field that is missing or malformed is dropped, never fatal.
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
  /** Extension: whether the scenario pod runs the victim app (absent from older APIs). */
  victim?: boolean;
}

export const RUN_STATES = [
  "queued",
  "started",
  // Extension: the scenario pod is Running and Ready, right before the exec. Detail: container id.
  "pod_ready",
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
  /** Extension: the scenario pod's name, from `started` on. */
  pod?: string;
}

/**
 * The Falco output fields the API passes through (an allow-list on the server, enforced again here):
 * what the page may show about the process that tripped the rule.
 */
export const FALCO_FIELDS = [
  "evt.type",
  "proc.name",
  "proc.cmdline",
  "proc.pname",
  "user.name",
  "user.uid",
  "container.id",
  "container.image.repository",
  "k8s.pod.name",
  "k8s.ns.name",
  "fd.name",
] as const;

export interface FalcoEvent {
  at: string;
  rule: string;
  priority: string;
  namespace: string;
  pod: string;
  output: string;
  /** Extension: allow-listed output_fields, every value as text. */
  fields?: Record<string, string>;
  /** Extension: when the API received the alert from Falcosidekick. */
  api_received_at?: string;
  run_id?: string;
}

export interface TalonEvent {
  at: string;
  /** The rule file's action name ("Terminate Pod"), or the actionner when Talon sent none. */
  action: string;
  namespace: string;
  pod: string;
  status: string;
  /** Extension: "kubernetes:terminate", "kubernetes:label", ... */
  actionner?: string;
  api_received_at?: string;
  /** Extension: Talon's own result text (capped at 300 by the API). */
  output?: string;
  run_id?: string;
}

/** Extension: one observation of the scenario pod by the API's single-pod watch. */
export interface PodEvent {
  run_id: string;
  pod: string;
  uid: string;
  /** Pending, ContainerCreating, Running, Terminating, Deleted (free text: shown, not interpreted). */
  phase: string;
  reason: string;
  /** 12 hex characters, or "" before the container exists. */
  container_id: string;
  /** repo@sha256:... */
  image: string;
  /** Labels added or changed since the previous observation; null means removed. */
  labels_delta: Record<string, string | null>;
  deleted: boolean;
  at: string;
}

export const VICTIM_STATUSES = ["up", "defaced", "compromised", "unreachable", "gone"] as const;
export type VictimStatus = (typeof VICTIM_STATUSES)[number];

/** Extension: what the API's probe of the victim app inside the scenario pod saw. */
export interface VictimEvent {
  run_id: string;
  pod: string;
  at: string;
  status: VictimStatus;
  title: string;
  banner: string;
  probe_ms: number;
  checksum: string;
}

/** Extension (optional on the server too): one Hubble flow verdict for the scenario pod, no addresses. */
export interface FlowEvent {
  run_id: string;
  pod: string;
  at: string;
  direction: string;
  l4: string;
  verdict: string;
  drop_reason: string;
}

export type StreamEvent =
  | { type: "run"; data: RunEvent }
  | { type: "falco"; data: FalcoEvent }
  | { type: "talon"; data: TalonEvent }
  | { type: "pod"; data: PodEvent }
  | { type: "victim"; data: VictimEvent }
  | { type: "flow"; data: FlowEvent };

export type StreamEventType = StreamEvent["type"];
export const STREAM_EVENT_TYPES: readonly StreamEventType[] = ["run", "falco", "talon", "pod", "victim", "flow"];

/** GET /api/scenarios/{id}/details: how the scenario runs, for the "what was executed" card. */
export interface SourceRef {
  name: string;
  file: string;
  line: number;
}

export interface ScenarioDetails {
  exec_command: string[];
  pod_security: {
    runAsUser?: number;
    runAsNonRoot?: boolean;
    readOnlyRootFilesystem?: boolean;
    allowPrivilegeEscalation?: boolean;
    capabilities_drop: string[];
    seccomp?: string;
    automountServiceAccountToken?: boolean;
  };
  resources: Record<string, string>;
  image: { ref: string; digest: string };
  falco_rule?: SourceRef;
  talon_rule?: SourceRef;
  policies: { kind: string; name: string; file: string }[];
  exec_tty?: boolean;
  /** The API build's git commit: file links point at exactly the code that ran. */
  commit: string;
  victim: boolean;
}

/** GET /api/limits */
export interface Limits {
  per_visitor: { limit: number; window_s: number; remaining: number; reset_in_s: number };
  global: { limit: number; window_s: number; remaining: number };
  active_run: boolean;
  stream_slots_remaining: number;
}

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

export function isPodEvent(v: unknown): v is PodEvent {
  return (
    isObj(v) &&
    hasStrings(v, ["run_id", "pod", "at"]) &&
    ["uid", "phase", "reason", "container_id", "image"].every((k) => v[k] === undefined || isStr(v[k])) &&
    (v.deleted === undefined || typeof v.deleted === "boolean") &&
    (v.labels_delta === undefined || v.labels_delta === null || isObj(v.labels_delta))
  );
}

export function isVictimEvent(v: unknown): v is VictimEvent {
  return (
    isObj(v) &&
    hasStrings(v, ["run_id", "pod", "at"]) &&
    (VICTIM_STATUSES as readonly unknown[]).includes(v.status)
  );
}

export function isFlowEvent(v: unknown): v is FlowEvent {
  return isObj(v) && hasStrings(v, ["run_id", "pod", "at", "verdict"]);
}

/** Caps a string the way the API promises to; the page must not trust the promise. */
export function cap(v: unknown, max: number): string {
  const s = isStr(v) ? v : "";
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

const optStr = (v: unknown, max: number): string | undefined => (isStr(v) ? cap(v, max) : undefined);

/** Only allow-listed keys, every value rendered as text, each capped. */
function sanitizeFields(v: unknown): Record<string, string> | undefined {
  if (!isObj(v)) return undefined;
  const out: Record<string, string> = {};
  for (const k of FALCO_FIELDS) {
    const x = v[k];
    if (isStr(x) || (typeof x === "number" && Number.isFinite(x)) || typeof x === "boolean") out[k] = cap(String(x), 512);
  }
  return Object.keys(out).length ? out : undefined;
}

function definedOnly<T extends object>(o: T): T {
  return Object.fromEntries(Object.entries(o).filter(([, x]) => x !== undefined)) as T;
}

/**
 * Normalises a payload that passed its guard: optional extension fields of the wrong type are dropped,
 * text is capped, and nothing the contract does not name is kept (the raw-event view in Technical Mode
 * shows exactly what the page uses).
 */
function normalise(ev: StreamEvent): StreamEvent {
  switch (ev.type) {
    case "run": {
      const d = ev.data;
      return { type: "run", data: definedOnly({ run_id: d.run_id, scenario: d.scenario, state: d.state, at: d.at, detail: optStr(d.detail, 300), pod: optStr(d.pod, 253) || undefined }) };
    }
    case "falco": {
      const d = ev.data;
      return {
        type: "falco",
        data: definedOnly({
          at: d.at, rule: cap(d.rule, 200), priority: cap(d.priority, 32), namespace: cap(d.namespace, 63), pod: cap(d.pod, 253),
          output: cap(d.output, 1024), fields: sanitizeFields(d.fields), api_received_at: optStr(d.api_received_at, 64), run_id: optStr(d.run_id, 64),
        }),
      };
    }
    case "talon": {
      const d = ev.data;
      return {
        type: "talon",
        data: definedOnly({
          at: d.at, action: cap(d.action, 100), namespace: cap(d.namespace, 63), pod: cap(d.pod, 253), status: cap(d.status, 32),
          actionner: optStr(d.actionner, 64), api_received_at: optStr(d.api_received_at, 64), output: optStr(d.output, 300), run_id: optStr(d.run_id, 64),
        }),
      };
    }
    case "pod": {
      const d = ev.data;
      const labels: Record<string, string | null> = {};
      if (isObj(d.labels_delta)) {
        for (const [k, x] of Object.entries(d.labels_delta).slice(0, 20)) {
          if (x === null || isStr(x)) labels[cap(k, 120)] = x === null ? null : cap(x, 63);
        }
      }
      return {
        type: "pod",
        data: {
          run_id: d.run_id, pod: cap(d.pod, 253), uid: cap(d.uid, 64), phase: cap(d.phase, 32), reason: cap(d.reason, 64),
          container_id: (typeof d.container_id === "string" ? d.container_id : "").slice(0, 12), image: cap(d.image, 300), labels_delta: labels, deleted: d.deleted === true, at: d.at,
        },
      };
    }
    case "victim": {
      const d = ev.data;
      const ms = typeof d.probe_ms === "number" && Number.isFinite(d.probe_ms) && d.probe_ms >= 0 ? d.probe_ms : -1;
      const sum = isStr(d.checksum) && /^[0-9a-f]{0,16}$/i.test(d.checksum) ? d.checksum.toLowerCase() : "";
      return {
        type: "victim",
        data: { run_id: d.run_id, pod: cap(d.pod, 253), at: d.at, status: d.status, title: cap(d.title, 80), banner: cap(d.banner, 120), probe_ms: ms, checksum: sum },
      };
    }
    case "flow": {
      const d = ev.data;
      return {
        type: "flow",
        data: { run_id: d.run_id, pod: cap(d.pod, 253), at: d.at, direction: cap(d.direction, 16), l4: cap(d.l4, 32), verdict: cap(d.verdict, 16), drop_reason: cap(d.drop_reason, 64) },
      };
    }
  }
}

/** Parses one SSE message into a typed event, or null if it does not match the contract. */
export function parseStreamEvent(type: string, raw: string): StreamEvent | null {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return null;
  }
  return toStreamEvent(type, data);
}

/** The same check for an already decoded payload (GET /api/runs/{id} returns them as JSON objects). */
export function toStreamEvent(type: string, data: unknown): StreamEvent | null {
  switch (type) {
    case "run":
      return isRunEvent(data) ? normalise({ type, data }) : null;
    case "falco":
      return isFalcoEvent(data) ? normalise({ type, data }) : null;
    case "talon":
      return isTalonEvent(data) ? normalise({ type, data }) : null;
    case "pod":
      return isPodEvent(data) ? normalise({ type, data }) : null;
    case "victim":
      return isVictimEvent(data) ? normalise({ type, data }) : null;
    case "flow":
      return isFlowEvent(data) ? normalise({ type, data }) : null;
    default:
      return null;
  }
}

const isBool = (v: unknown): v is boolean => typeof v === "boolean";
const isLine = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v) && v > 0;
/** A repository-relative path: no scheme, no "..", nothing that could turn a GitHub link into another URL. */
export const isRepoPath = (v: unknown): v is string =>
  isStr(v) && v.length <= 200 && /^[A-Za-z0-9_][A-Za-z0-9_./-]*$/.test(v) && !v.includes("..");
export const isCommit = (v: unknown): v is string => isStr(v) && /^[0-9a-f]{7,40}$/.test(v);

/** A rule reference. A stock rule (shipped in the Falco image, not in this repository) has file "". */
function sourceRef(v: unknown): SourceRef | undefined {
  if (!isObj(v) || !isStr(v.name) || !v.name) return undefined;
  const file = isRepoPath(v.file) ? v.file : "";
  return { name: cap(v.name, 200), file, line: file && isLine(v.line) ? v.line : 0 };
}

/**
 * GET /api/scenarios/{id}/details. Lenient by design: the card renders whatever part is valid, so a
 * field the API renames costs one line of the card, not the card.
 */
export function parseScenarioDetails(v: unknown): ScenarioDetails {
  if (!isObj(v)) throw new TypeError("details: expected an object");
  const ps = isObj(v.pod_security) ? v.pod_security : {};
  const img = isObj(v.image) ? v.image : {};
  const res: Record<string, string> = {};
  if (isObj(v.resources)) {
    // Either flat ({cpu_limit: "100m"}) or nested ({limits: {cpu: "100m"}}): flattened to "limits.cpu".
    for (const [k, x] of Object.entries(v.resources)) {
      if (isStr(x) || typeof x === "number") res[cap(k, 40)] = cap(String(x), 40);
      else if (isObj(x)) for (const [k2, y] of Object.entries(x)) if (isStr(y) || typeof y === "number") res[`${cap(k, 20)}.${cap(k2, 30)}`] = cap(String(y), 40);
    }
  }
  return {
    exec_command: Array.isArray(v.exec_command) ? v.exec_command.filter(isStr).slice(0, 20).map((a) => cap(a, 200)) : [],
    pod_security: definedOnly({
      runAsUser: typeof ps.runAsUser === "number" ? ps.runAsUser : undefined,
      runAsNonRoot: isBool(ps.runAsNonRoot) ? ps.runAsNonRoot : undefined,
      readOnlyRootFilesystem: isBool(ps.readOnlyRootFilesystem) ? ps.readOnlyRootFilesystem : undefined,
      allowPrivilegeEscalation: isBool(ps.allowPrivilegeEscalation) ? ps.allowPrivilegeEscalation : undefined,
      capabilities_drop: Array.isArray(ps.capabilities_drop) ? ps.capabilities_drop.filter(isStr).slice(0, 40).map((c) => cap(c, 40)) : [],
      seccomp: optStr(ps.seccomp, 60),
      automountServiceAccountToken: isBool(ps.automountServiceAccountToken) ? ps.automountServiceAccountToken : undefined,
    }),
    resources: res,
    image: { ref: cap(img.ref, 300), digest: isStr(img.digest) && /^sha256:[0-9a-f]{64}$/.test(img.digest) ? img.digest : "" },
    falco_rule: sourceRef(v.falco_rule),
    talon_rule: sourceRef(v.talon_rule),
    policies: Array.isArray(v.policies)
      ? v.policies
          .filter((p): p is Obj => isObj(p) && isStr(p.kind) && isStr(p.name))
          .slice(0, 30)
          .map((p) => ({ kind: cap(p.kind, 60), name: cap(p.name, 120), file: isRepoPath(p.file) ? p.file : "" }))
      : [],
    commit: isCommit(v.commit) ? v.commit : "",
    exec_tty: isBool(v.exec_tty) ? v.exec_tty : undefined,
    victim: v.victim === true,
  };
}

export function isLimits(v: unknown): v is Limits {
  return (
    isObj(v) &&
    hasCounts(v.per_visitor, ["limit", "window_s", "remaining", "reset_in_s"]) &&
    hasCounts(v.global, ["limit", "window_s", "remaining"]) &&
    isBool(v.active_run) &&
    isCount(v.stream_slots_remaining)
  );
}

/** GET /api/runs/{id}: either a bare array of {type, data} or {events: [...]}; invalid entries dropped. */
export function parseRunEvents(v: unknown): StreamEvent[] {
  const list = Array.isArray(v) ? v : isObj(v) && Array.isArray(v.events) ? v.events : null;
  if (!list) throw new TypeError("run: expected an event list");
  const out: StreamEvent[] = [];
  for (const e of list) {
    if (!isObj(e) || !isStr(e.type)) continue;
    const ev = toStreamEvent(e.type, e.data);
    if (ev) out.push(ev);
  }
  return out;
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
