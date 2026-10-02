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
  /** Extension (phase 8): the visitor drives this one by typing commands (the terminal scenario). */
  interactive?: boolean;
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

/** Extension (phase 8): a compare run has two pods; every per-pod event says which arm it is. */
export type Arm = "guarded" | "unguarded";

export interface RunEvent {
  run_id: string;
  scenario: string;
  state: RunState;
  at: string;
  detail?: string;
  /** Extension: the scenario pod's name, from `started` on. */
  pod?: string;
  /** Extension (phase 8): both pods of a compare run, named together when they are created. */
  pods?: { guarded: string; unguarded: string };
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
  /** Extension (phase 8): the terminal command that was running when the alert arrived (best effort). */
  command_seq?: number;
  /** Extension (phase 8): which pod of a compare run this alert names. */
  arm?: Arm;
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
  /** Extension (phase 8): the terminal command that was running when the action arrived (best effort). */
  command_seq?: number;
  /** Extension (phase 8): which pod of a compare run this action names. */
  arm?: Arm;
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
  /** Extension (phase 8): which pod of a compare run this observation is of. */
  arm?: Arm;
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
  /** Extension (phase 8): which pod of a compare run this probe is of. */
  arm?: Arm;
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

/** Extension (phase 8): where the API is in running one of the terminal's commands. */
export const COMMAND_STATES = ["started", "output", "exited", "killed"] as const;
export type CommandState = (typeof COMMAND_STATES)[number];

/**
 * Extension (phase 8): one slice of a terminal command's life. `started` once, then `output` events
 * carrying at most 1 KiB of already-scrubbed text each, then `exited` (with the code and whether it
 * reached its objective) or `killed` (the pod went away under it). Published to every subscriber, so
 * other visitors watch the same keystrokes read-only.
 */
export interface CommandEvent {
  run_id: string;
  seq: number;
  /** The catalogue command id the visitor ran. */
  id: string;
  state: CommandState;
  at: string;
  /** On `output`: which stream the chunk is from. */
  stream?: "stdout" | "stderr";
  /** On `output`: at most 1024 bytes of text, already scrubbed by the API (no control chars, no ANSI). */
  chunk?: string;
  /** On `exited`: the process exit code. */
  exit_code?: number;
  /** On `exited`: true iff the command has an objective and exited 0. */
  achieved?: boolean;
  /** The per-command or per-run output cap was hit; the rest was dropped. */
  truncated?: boolean;
}

/**
 * One event of the feed. `id` is the hub's sequence number for it — the SSE `id:` line, and the `id`
 * of each entry of GET /api/runs/{id} — so the same event read from the stream and from a backfill is
 * recognisably one event, and a run's output can be put back in the order it was published.
 */
export type StreamEvent = (
  | { type: "run"; data: RunEvent }
  | { type: "falco"; data: FalcoEvent }
  | { type: "talon"; data: TalonEvent }
  | { type: "pod"; data: PodEvent }
  | { type: "victim"; data: VictimEvent }
  | { type: "flow"; data: FlowEvent }
  | { type: "command"; data: CommandEvent }
) & { id?: number };

export type StreamEventType = StreamEvent["type"];
export const STREAM_EVENT_TYPES: readonly StreamEventType[] = ["run", "falco", "talon", "pod", "victim", "flow", "command"];

/** GET /api/scenarios/{id}/details: how the scenario runs, for the "what was executed" card. */
export interface SourceRef {
  name: string;
  file: string;
  line: number;
}

/** The six defence layers, in depth order (edge is outermost). The defence map and the catalogue share them. */
export const DEFENCE_LAYERS = ["edge", "host", "network", "supply-chain", "admission", "pod-security", "runtime"] as const;
export type DefenceLayer = (typeof DEFENCE_LAYERS)[number];
export const isDefenceLayer = (v: unknown): v is DefenceLayer => (DEFENCE_LAYERS as readonly unknown[]).includes(v);

export const COMMAND_OUTCOMES = ["allowed", "prevented", "detected"] as const;
export type CommandOutcome = (typeof COMMAND_OUTCOMES)[number];

/** Extension (phase 8): one thing the visitor tries to reach in the terminal, in kill-chain order. */
export interface Objective {
  id: string;
  title: string;
}

/**
 * Extension (phase 8): one command in the terminal scenario's catalogue. The API accepts only the
 * `id`; everything else is what the page shows and how it explains what happened. `command` (the argv
 * that runs in the pod) is public in the repository anyway.
 */
export interface CatalogueCommand {
  id: string;
  /** What the visitor types; unique, <= 80 printable ASCII. */
  input: string;
  /** Other accepted spellings. */
  aliases: string[];
  /** The objectives[].id this counts towards, if any. */
  objective?: string;
  technique: string;
  /** The argv run in container `target`. */
  command: string[];
  tty: boolean;
  outcome: CommandOutcome;
  layer: DefenceLayer;
  /** What answers, one line. */
  control: string;
  /** outcome "detected" only. */
  detection?: string;
  /** outcome "detected" only. */
  response?: ResponseAction | string;
  /** One or two sentences shown after the command ran. */
  explain: string;
}

export interface ScenarioDetails {
  /** Run to completion without a TTY before exec_command; [] when the scenario has none. */
  pre_exec_command: string[];
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
  /** Extension (phase 8): set on the terminal scenario's details. */
  interactive?: boolean;
  timeout_seconds?: number;
  idle_seconds?: number;
  objectives?: Objective[];
  commands?: CatalogueCommand[];
}

/** GET /api/limits */
export interface Limits {
  per_visitor: { limit: number; window_s: number; remaining: number; reset_in_s: number };
  global: { limit: number; window_s: number; remaining: number };
  active_run: boolean;
  stream_slots_remaining: number;
}

/** POST /api/attack/terminal → 202. `token` is returned here only, never in an event or /api/runs. */
export interface TerminalAccepted {
  run_id: string;
  scenario: string;
  state: "queued";
  token: string;
}

/** POST /api/runs/{run_id}/commands → 202. */
export interface CommandAccepted {
  seq: number;
}

/** GET /api/stats: counters across every visitor's runs, persisted in a ConfigMap (ADR 0030). */
export interface Stats {
  since: string;
  runs: number;
  by_scenario: Record<string, { runs: number; detected: number; responded: number }>;
  response_ms: { last: number; p50: number; min: number; max: number };
  /** Runs detected with no response before the timeout — the honest number. */
  unanswered: number;
  commands: Record<string, { attempts: number; allowed: number; prevented: number; detected: number }>;
  objectives: Record<string, { attempts: number; achieved: number }>;
  terminal: { runs: number; best_objectives: number; median_survival_s: number };
}

export interface KyvernoPolicy {
  name: string;
  pass: number;
  fail: number;
  warn: number;
}

/** Extension: one side of the own/third-party split of the Trivy totals. */
export interface TrivyGroup {
  images: number;
  critical: number;
  high: number;
  /** CRITICAL+HIGH findings that name a fixed version upstream. */
  fixable: number;
}

/** Extension: one row of the per-image breakdown, worst first. */
export interface ImageVulns {
  /** registry/repository:tag as the scanner recorded it - text from the cluster, rendered as text. */
  image: string;
  /** Built and signed by this repository (ghcr.io/hubertmj/self-defending-portfolio/*). */
  own: boolean;
  critical: number;
  high: number;
  fixable: number;
}

export interface PostureTrivy {
  images: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  /** Extension (absent from older APIs): the same totals, split. own + third_party == the totals. */
  own?: TrivyGroup;
  third_party?: TrivyGroup;
  by_image?: ImageVulns[];
}

export interface Posture {
  generated_at: string;
  kyverno: { policies: KyvernoPolicy[] };
  trivy: PostureTrivy;
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

export function isCommandEvent(v: unknown): v is CommandEvent {
  return (
    isObj(v) &&
    hasStrings(v, ["run_id", "id", "at"]) &&
    typeof v.seq === "number" &&
    Number.isFinite(v.seq) &&
    (COMMAND_STATES as readonly unknown[]).includes(v.state)
  );
}

/** Caps a string the way the API promises to; the page must not trust the promise. */
export function cap(v: unknown, max: number): string {
  const s = isStr(v) ? v : "";
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

const optStr = (v: unknown, max: number): string | undefined => (isStr(v) ? cap(v, max) : undefined);

const optArm = (v: unknown): Arm | undefined => (v === "guarded" || v === "unguarded" ? v : undefined);
const optSeq = (v: unknown): number | undefined => (typeof v === "number" && Number.isFinite(v) ? v : undefined);

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
      const pods =
        isObj(d.pods) && isStr(d.pods.guarded) && isStr(d.pods.unguarded)
          ? { guarded: cap(d.pods.guarded, 253), unguarded: cap(d.pods.unguarded, 253) }
          : undefined;
      return { type: "run", data: definedOnly({ run_id: d.run_id, scenario: d.scenario, state: d.state, at: d.at, detail: optStr(d.detail, 300), pod: optStr(d.pod, 253) || undefined, pods }) };
    }
    case "falco": {
      const d = ev.data;
      return {
        type: "falco",
        data: definedOnly({
          at: d.at, rule: cap(d.rule, 200), priority: cap(d.priority, 32), namespace: cap(d.namespace, 63), pod: cap(d.pod, 253),
          output: cap(d.output, 1024), fields: sanitizeFields(d.fields), api_received_at: optStr(d.api_received_at, 64), run_id: optStr(d.run_id, 64),
          command_seq: optSeq(d.command_seq), arm: optArm(d.arm),
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
          command_seq: optSeq(d.command_seq), arm: optArm(d.arm),
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
          ...definedOnly({ arm: optArm(d.arm) }),
        },
      };
    }
    case "victim": {
      const d = ev.data;
      const ms = typeof d.probe_ms === "number" && Number.isFinite(d.probe_ms) && d.probe_ms >= 0 ? d.probe_ms : -1;
      const sum = isStr(d.checksum) && /^[0-9a-f]{0,16}$/i.test(d.checksum) ? d.checksum.toLowerCase() : "";
      return {
        type: "victim",
        data: { run_id: d.run_id, pod: cap(d.pod, 253), at: d.at, status: d.status, title: cap(d.title, 80), banner: cap(d.banner, 120), probe_ms: ms, checksum: sum, ...definedOnly({ arm: optArm(d.arm) }) },
      };
    }
    case "flow": {
      const d = ev.data;
      return {
        type: "flow",
        data: { run_id: d.run_id, pod: cap(d.pod, 253), at: d.at, direction: cap(d.direction, 16), l4: cap(d.l4, 32), verdict: cap(d.verdict, 16), drop_reason: cap(d.drop_reason, 64) },
      };
    }
    case "command": {
      const d = ev.data;
      const stream = d.stream === "stdout" || d.stream === "stderr" ? d.stream : undefined;
      // The API has already scrubbed the chunk (valid UTF-8, no control chars but \n and \t, no ANSI,
      // ADR 0021 URL/IP scrubber). The page trusts nothing: strip any control char that slipped
      // through so output can only ever be a text node, and cap at the contract's 1 KiB.
      const chunk = isStr(d.chunk) ? cap(stripControl(d.chunk), 1024) : undefined;
      return {
        type: "command",
        data: definedOnly({
          run_id: d.run_id,
          seq: d.seq,
          id: cap(d.id, 32),
          state: d.state,
          at: d.at,
          stream,
          chunk,
          exit_code: optSeq(d.exit_code),
          achieved: typeof d.achieved === "boolean" ? d.achieved : undefined,
          truncated: d.truncated === true ? true : undefined,
        }),
      };
    }
  }
}

/**
 * Mirrors the API's output scrub (ADR 0029): keep only tab and newline among control characters —
 * drop every other C0/C1 control (carriage return included, so no ANSI) — and drop invisible format
 * characters (bidi overrides and isolates, zero-width spaces, BOM). A text node is then all that can
 * result; `.term__line` additionally isolates bidi so a right-to-left run cannot reorder the line.
 */
function stripControl(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g, "").replace(/\p{Cf}/gu, "");
}

/** The hub's event id: a positive integer (the SSE `id:` line is text, the runs endpoint's a number). */
function eventId(v: unknown): number | undefined {
  const n = typeof v === "string" && /^\d{1,15}$/.test(v) ? Number(v) : v;
  return typeof n === "number" && Number.isSafeInteger(n) && n > 0 ? n : undefined;
}

/** Parses one SSE message into a typed event, or null if it does not match the contract. */
export function parseStreamEvent(type: string, raw: string, id?: unknown): StreamEvent | null {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return null;
  }
  return toStreamEvent(type, data, id);
}

/** The same check for an already decoded payload (GET /api/runs/{id} returns them as JSON objects). */
export function toStreamEvent(type: string, data: unknown, id?: unknown): StreamEvent | null {
  const ev = typedEvent(type, data);
  const n = eventId(id);
  return ev && n !== undefined ? { ...ev, id: n } : ev;
}

function typedEvent(type: string, data: unknown): StreamEvent | null {
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
    case "command":
      return isCommandEvent(data) ? normalise({ type, data }) : null;
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

const isArgv = (v: unknown): v is string[] => Array.isArray(v) && v.every(isStr);

/** The terminal catalogue id: the only thing the API accepts, so the page validates it the same way. */
export const isCommandId = (v: unknown): v is string => isStr(v) && /^[a-z0-9-]{1,32}$/.test(v);

function parseObjectives(v: unknown): Objective[] {
  if (!Array.isArray(v)) return [];
  return v
    .filter((o): o is Obj => isObj(o) && isStr(o.id) && isStr(o.title))
    .slice(0, 40)
    .map((o) => ({ id: cap(o.id, 40), title: cap(o.title, 80) }));
}

function parseCommand(v: unknown): CatalogueCommand | null {
  if (!isObj(v) || !isCommandId(v.id) || !isStr(v.input)) return null;
  const outcome = (COMMAND_OUTCOMES as readonly unknown[]).includes(v.outcome) ? (v.outcome as CommandOutcome) : "allowed";
  return {
    id: v.id,
    input: cap(v.input, 80),
    aliases: Array.isArray(v.aliases) ? v.aliases.filter(isStr).slice(0, 8).map((a) => cap(a, 80)) : [],
    objective: isStr(v.objective) ? cap(v.objective, 40) : undefined,
    technique: isStr(v.technique) ? cap(v.technique, 20) : "",
    command: isArgv(v.command) ? v.command.slice(0, 20).map((a) => cap(a, 2000)) : [],
    tty: v.tty === true,
    outcome,
    layer: isDefenceLayer(v.layer) ? v.layer : "runtime",
    control: isStr(v.control) ? cap(v.control, 200) : "",
    detection: isStr(v.detection) ? cap(v.detection, 200) : undefined,
    response: isStr(v.response) ? cap(v.response, 40) : undefined,
    explain: isStr(v.explain) ? cap(v.explain, 400) : "",
  };
}

/** Printable ASCII, 1..80 chars: the shape the catalogue promises for a command's input/alias. */
const isTypable = (s: string): boolean => s.length > 0 && s.length <= 80 && /^[\x20-\x7e]+$/.test(s);

function parseCommands(v: unknown): CatalogueCommand[] {
  if (!Array.isArray(v)) return [];
  const out: CatalogueCommand[] = [];
  const ids = new Set<string>();
  // A spelling (input or alias) resolves to exactly one command, so a spelling claimed twice — or an
  // empty / non-printable one — would make resolution ambiguous or unmatchable: drop such a command.
  const spellings = new Set<string>();
  for (const c of v.slice(0, 64)) {
    const cmd = parseCommand(c);
    if (!cmd || ids.has(cmd.id)) continue;
    const words = [cmd.input, ...cmd.aliases].map((s) => s.toLowerCase());
    if (!isTypable(cmd.input) || cmd.aliases.some((a) => !isTypable(a))) continue;
    if (words.some((w) => spellings.has(w))) continue;
    ids.add(cmd.id);
    for (const w of words) spellings.add(w);
    out.push(cmd);
  }
  return out;
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
    pre_exec_command: Array.isArray(v.pre_exec_command) ? v.pre_exec_command.filter(isStr).slice(0, 20).map((a) => cap(a, 2000)) : [],
    exec_command: Array.isArray(v.exec_command) ? v.exec_command.filter(isStr).slice(0, 20).map((a) => cap(a, 2000)) : [],
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
    interactive: isBool(v.interactive) ? v.interactive : undefined,
    timeout_seconds: isCount(v.timeout_seconds) ? v.timeout_seconds : undefined,
    idle_seconds: isCount(v.idle_seconds) ? v.idle_seconds : undefined,
    objectives: v.objectives !== undefined ? parseObjectives(v.objectives) : undefined,
    commands: v.commands !== undefined ? parseCommands(v.commands) : undefined,
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

export function isTerminalAccepted(v: unknown): v is TerminalAccepted {
  return isObj(v) && hasStrings(v, ["run_id", "scenario", "token"]) && v.state === "queued" && /^[0-9a-f]{32}$/i.test(v.token as string);
}

export function isCommandAccepted(v: unknown): v is CommandAccepted {
  return isObj(v) && typeof v.seq === "number" && Number.isFinite(v.seq);
}

/** GET /api/stats. Lenient: a missing or malformed section becomes its empty shape, never a throw. */
export function parseStats(v: unknown): Stats {
  if (!isObj(v)) throw new TypeError("stats: expected an object");
  const count = (x: unknown): number => (isCount(x) ? x : 0);
  const byScenario: Stats["by_scenario"] = {};
  if (isObj(v.by_scenario)) {
    for (const [k, x] of Object.entries(v.by_scenario).slice(0, 64)) {
      if (isObj(x)) byScenario[cap(k, 40)] = { runs: count(x.runs), detected: count(x.detected), responded: count(x.responded) };
    }
  }
  const commands: Stats["commands"] = {};
  if (isObj(v.commands)) {
    for (const [k, x] of Object.entries(v.commands).slice(0, 64)) {
      if (isObj(x)) commands[cap(k, 32)] = { attempts: count(x.attempts), allowed: count(x.allowed), prevented: count(x.prevented), detected: count(x.detected) };
    }
  }
  const objectives: Stats["objectives"] = {};
  if (isObj(v.objectives)) {
    for (const [k, x] of Object.entries(v.objectives).slice(0, 40)) {
      if (isObj(x)) objectives[cap(k, 40)] = { attempts: count(x.attempts), achieved: count(x.achieved) };
    }
  }
  const rms = isObj(v.response_ms) ? v.response_ms : {};
  const term = isObj(v.terminal) ? v.terminal : {};
  return {
    since: isStr(v.since) ? v.since : "",
    runs: count(v.runs),
    by_scenario: byScenario,
    response_ms: { last: count(rms.last), p50: count(rms.p50), min: count(rms.min), max: count(rms.max) },
    unanswered: count(v.unanswered),
    commands,
    objectives,
    terminal: { runs: count(term.runs), best_objectives: count(term.best_objectives), median_survival_s: count(term.median_survival_s) },
  };
}

/** GET /api/runs/{id}: either a bare array of {type, data} or {events: [...]}; invalid entries dropped. */
export function parseRunEvents(v: unknown): StreamEvent[] {
  const list = Array.isArray(v) ? v : isObj(v) && Array.isArray(v.events) ? v.events : null;
  if (!list) throw new TypeError("run: expected an event list");
  const out: StreamEvent[] = [];
  for (const e of list) {
    if (!isObj(e) || !isStr(e.type)) continue;
    const ev = toStreamEvent(e.type, e.data, e.id);
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

/** The most rows of the per-image breakdown the page keeps; it shows fewer. */
export const MAX_IMAGE_ROWS = 100;

const isGroup = (v: unknown): v is TrivyGroup => hasCounts(v, ["images", "critical", "high", "fixable"]);

function isImageVulns(v: unknown): v is ImageVulns {
  return hasCounts(v, ["critical", "high", "fixable"]) && isStr(v.image) && typeof v.own === "boolean";
}

/**
 * GET /api/posture: the guard, then the extension fields normalised the way stream events are - a
 * malformed split or breakdown is dropped (the page then renders exactly what it did before the
 * extension), a malformed row is dropped, image names are capped. The five Trivy totals are never
 * touched: they are the true counts and the page shows them as given.
 */
export function parsePosture(v: unknown): Posture {
  if (!isPosture(v)) throw new TypeError("posture: response does not match the contract");
  const t = v.trivy as PostureTrivy & Obj;
  const trivy: PostureTrivy = { images: t.images, critical: t.critical, high: t.high, medium: t.medium, low: t.low };
  if (isGroup(t.own) && isGroup(t.third_party)) {
    trivy.own = { images: t.own.images, critical: t.own.critical, high: t.own.high, fixable: t.own.fixable };
    trivy.third_party = { images: t.third_party.images, critical: t.third_party.critical, high: t.third_party.high, fixable: t.third_party.fixable };
  }
  if (Array.isArray(t.by_image)) {
    trivy.by_image = t.by_image
      .filter(isImageVulns)
      .slice(0, MAX_IMAGE_ROWS)
      .map((r) => ({ image: cap(r.image, 200), own: r.own, critical: r.critical, high: r.high, fixable: r.fixable }));
  }
  return { ...v, trivy };
}
