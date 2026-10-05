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
  /**
   * Extension (phase 8): on a terminal run's `detected`/`responded`, the command it is about (the one
   * running, or ended less than 2 s before). Absent when the API could tie it to none.
   */
  command_seq?: number;
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
  /** Extension (ADR 0035): when the newest run was queued, persisted across restarts; absent from older APIs. */
  last_run_at?: string;
  /** Extension (ADR 0035): the persisted hourly window, 23-24 h, always shown with its `since`. */
  last_24h?: Last24h;
}

export interface Last24h {
  since: string;
  runs: number;
  detected: number;
  responded: number;
  falco_alerts: number;
  talon_actions: number;
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

/**
 * Extension (ADR 0035): the failing Kyverno results grouped by what they are about, never naming the
 * resource. `running`: true = a Pending/Running pod is the resource or is owned by it, false = such a
 * kind with no such pod (old ReplicaSet revisions scaled to 0), null = unknown.
 */
export interface KyvernoViolation {
  policy: string;
  rule: string;
  kind: string;
  namespace: string;
  count: number;
  running: boolean | null;
  /** The policy's file in the repository, "" when the API does not know it. */
  file: string;
}

/** Extension (ADR 0035): one failing kube-bench check, as kube-bench names it (scrubbed, capped by the API). */
export interface BenchCheck {
  id: string;
  title: string;
  remediation: string;
}

export interface Posture {
  generated_at: string;
  kyverno: {
    policies: KyvernoPolicy[];
    /** Extension (ADR 0035). */
    violations?: KyvernoViolation[];
    violations_truncated?: boolean;
    /** Set by the parser when a malformed group was dropped: the list no longer describes every failure. */
    violations_incomplete?: boolean;
  };
  trivy: PostureTrivy & { last_scan?: string };
  kube_bench: { last_run: string | null; pass: number; fail: number; warn: number; info: number; failing?: BenchCheck[] };
  falco: { alerts_24h: number; counted_since?: string };
  talon: { actions_24h: number };
}

/** GET /api/provenance (ADR 0035): what is running and what it was built from. */
export interface Provenance {
  generated_at?: string;
  api: { commit: string; ci_run_id: string; started_at?: string; images: string[] };
  web: { images: string[] };
  /** The last successful pod list; the images are as of then. */
  images_observed_at?: string;
}

/** GET /build.json, written into the web image at build time (ADR 0035). */
export interface BuildInfo {
  commit: string;
  ci_run_id: string;
}

/** One run of GET /api/runs (ADR 0035), newest first; no pod, no commands, no output. */
export interface RunSummary {
  run_id: string;
  scenario: string;
  state: RunState;
  /** Absent when the API sends null (a run it has no start time for): never rendered as a zero time. */
  started_at?: string;
  ended_at?: string;
  detected: boolean;
  responded: boolean;
  events: number;
  truncated: boolean;
}

/** The opt-in SSE heartbeat (`?tick=1`): the server's clock and the API's start, never a run event. */
export interface Tick {
  at: string;
  started_at?: string;
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
      return { type: "run", data: definedOnly({ run_id: d.run_id, scenario: d.scenario, state: d.state, at: d.at, detail: optStr(d.detail, 300), pod: optStr(d.pod, 253) || undefined, pods, command_seq: optSeq(d.command_seq) }) };
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

/** A run id the page will put in a URL: the API's are 16 hex; nothing that could leave the path. */
export const isRunId = (v: unknown): v is string => isStr(v) && /^[A-Za-z0-9_-]{1,64}$/.test(v);

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
  // Keyed by ids the API sends: built with Object.fromEntries, which makes even a `__proto__` key an
  // ordinary own property — an assignment would set the object's prototype instead.
  const table = <T>(o: unknown, max: number, keyCap: number, row: (x: Obj) => T): Record<string, T> =>
    Object.fromEntries(isObj(o) ? Object.entries(o).slice(0, max).filter((e): e is [string, Obj] => isObj(e[1])).map(([k, x]) => [cap(k, keyCap), row(x)]) : []);
  const byScenario = table(v.by_scenario, 64, 40, (x) => ({ runs: count(x.runs), detected: count(x.detected), responded: count(x.responded) }));
  const commands = table(v.commands, 64, 32, (x) => ({ attempts: count(x.attempts), allowed: count(x.allowed), prevented: count(x.prevented), detected: count(x.detected) }));
  const objectives = table(v.objectives, 40, 40, (x) => ({ attempts: count(x.attempts), achieved: count(x.achieved) }));
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
    ...definedOnly({ last_run_at: isTime(v.last_run_at) ? v.last_run_at : undefined, last_24h: parseLast24h(v.last_24h) }),
  };
}

/** A timestamp the page will render: a string Date.parse understands, of a sane length. */
export const isTime = (v: unknown): v is string => isStr(v) && v.length <= 40 && !Number.isNaN(Date.parse(v));

/** All or nothing: a window without its `since`, or with a bad count, is not shown at all. */
function parseLast24h(v: unknown): Last24h | undefined {
  if (!hasCounts(v, ["runs", "detected", "responded", "falco_alerts", "talon_actions"]) || !isTime(v.since)) return undefined;
  return { since: v.since, runs: v.runs as number, detected: v.detected as number, responded: v.responded as number, falco_alerts: v.falco_alerts as number, talon_actions: v.talon_actions as number };
}

/** GET /api/runs/{id}: either a bare array of {type, data} or {events: [...]}; invalid entries dropped. */
/** GET /api/runs/{id} with its `truncated` flag: the store hit its per-run cap and kept no more. */
export function parseRunHistory(v: unknown): { events: StreamEvent[]; truncated: boolean } {
  return { events: parseRunEvents(v), truncated: isObj(v) && v.truncated === true };
}

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
  const trivy: Posture["trivy"] = { images: t.images, critical: t.critical, high: t.high, medium: t.medium, low: t.low };
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
  if (isTime(t.last_scan)) trivy.last_scan = t.last_scan;
  const k = v.kyverno as Posture["kyverno"] & Obj;
  const kyverno: Posture["kyverno"] = { policies: k.policies };
  if (Array.isArray(k.violations)) {
    const rows = k.violations.slice(0, MAX_VIOLATIONS).map(parseViolation);
    kyverno.violations = rows.filter((r): r is KyvernoViolation => r !== null);
    kyverno.violations_truncated = k.violations_truncated === true || k.violations.length > MAX_VIOLATIONS;
    if (kyverno.violations.length < rows.length) kyverno.violations_incomplete = true;
  }
  const kb = v.kube_bench as Posture["kube_bench"] & Obj;
  const kube_bench: Posture["kube_bench"] = { last_run: kb.last_run, pass: kb.pass, fail: kb.fail, warn: kb.warn, info: kb.info };
  if (Array.isArray(kb.failing)) kube_bench.failing = kb.failing.slice(0, MAX_BENCH_CHECKS).map(parseBenchCheck).filter((c): c is BenchCheck => c !== null);
  const f = v.falco as Posture["falco"] & Obj;
  const falco: Posture["falco"] = { alerts_24h: f.alerts_24h };
  if (isTime(f.counted_since)) falco.counted_since = f.counted_since;
  return { generated_at: v.generated_at, kyverno, trivy, kube_bench, falco, talon: { actions_24h: v.talon.actions_24h } };
}

/** The API sends at most 50 of each; the page keeps no more whatever it is sent. */
const MAX_VIOLATIONS = 50;
const MAX_BENCH_CHECKS = 50;

function parseViolation(v: unknown): KyvernoViolation | null {
  if (!isObj(v) || !hasStrings(v, ["policy", "rule", "kind", "namespace"]) || !isCount(v.count)) return null;
  return {
    policy: cap(v.policy, 120),
    rule: cap(v.rule, 120),
    kind: cap(v.kind, 63),
    namespace: cap(v.namespace, 63),
    count: v.count,
    // Anything but a boolean is "unknown", which never earns the amber "nothing running" tone.
    running: typeof v.running === "boolean" ? v.running : null,
    file: isRepoPath(v.file) ? v.file : "",
  };
}

const BENCH_ID = /^[0-9]+(\.[0-9]+){1,3}$/;

function parseBenchCheck(v: unknown): BenchCheck | null {
  if (!isObj(v) || !isStr(v.id) || !BENCH_ID.test(v.id) || !isStr(v.title)) return null;
  return { id: v.id, title: cap(v.title, 200), remediation: cap(v.remediation, 300) };
}

const OWN_IMAGE = (repo: "api" | "web") => new RegExp(`^ghcr\\.io/hubertmj/self-defending-portfolio/${repo}@sha256:[0-9a-f]{64}$`);
const isRunNumber = (v: unknown): v is string => isStr(v) && /^[0-9]{1,20}$/.test(v);

/** Only this repository's own api/web images pinned by digest; anything else is dropped. */
function ownImages(v: unknown, repo: "api" | "web"): string[] {
  if (!Array.isArray(v)) return [];
  const re = OWN_IMAGE(repo);
  return [...new Set(v.filter((x): x is string => isStr(x) && re.test(x)))].slice(0, 10);
}

/** GET /api/provenance. Lenient: a bad commit or run id becomes "", a bad image is dropped. */
export function parseProvenance(v: unknown): Provenance {
  if (!isObj(v)) throw new TypeError("provenance: expected an object");
  const api = isObj(v.api) ? v.api : {};
  const web = isObj(v.web) ? v.web : {};
  return definedOnly({
    generated_at: isTime(v.generated_at) ? v.generated_at : undefined,
    api: definedOnly({
      commit: isCommit(api.commit) ? api.commit : "",
      ci_run_id: isRunNumber(api.ci_run_id) ? api.ci_run_id : "",
      started_at: isTime(api.started_at) ? api.started_at : undefined,
      images: ownImages(api.images, "api"),
    }),
    web: { images: ownImages(web.images, "web") },
    images_observed_at: isTime(v.images_observed_at) ? v.images_observed_at : undefined,
  });
}

/** GET /build.json: a full 40-hex commit and a numeric run id, else "". */
export function parseBuildInfo(v: unknown): BuildInfo {
  if (!isObj(v)) throw new TypeError("build.json: expected an object");
  return { commit: isStr(v.commit) && /^[0-9a-f]{40}$/.test(v.commit) ? v.commit : "", ci_run_id: isRunNumber(v.ci_run_id) ? v.ci_run_id : "" };
}

/** GET /api/runs: malformed entries dropped, at most 50 kept. */
export function parseRunList(v: unknown): RunSummary[] {
  if (!isObj(v) || !Array.isArray(v.runs)) throw new TypeError("runs: expected {runs: [...]}");
  const out: RunSummary[] = [];
  for (const r of v.runs.slice(0, 50)) {
    if (!isObj(r) || !isRunId(r.run_id) || !isStr(r.scenario) || !(RUN_STATES as readonly unknown[]).includes(r.state)) continue;
    out.push({
      run_id: r.run_id,
      scenario: cap(r.scenario, 40),
      state: r.state as RunState,
      // null (or anything not a time) is "unknown": dropped, so a zero time never reaches the page.
      ...definedOnly({ started_at: isRealTime(r.started_at) ? r.started_at : undefined, ended_at: isRealTime(r.ended_at) ? r.ended_at : undefined }),
      detected: r.detected === true,
      responded: r.responded === true,
      events: isCount(r.events) ? r.events : 0,
      truncated: r.truncated === true,
    });
  }
  return out;
}

/** A time that is not Go's zero time (0001-01-01T00:00:00Z) nor the Unix epoch's start. */
const isRealTime = (v: unknown): v is string => isTime(v) && Date.parse(v) > 0;

/** One `event: tick` frame; null if it is not one. It is a clock reading, never part of the run log. */
export function parseTick(raw: string): Tick | null {
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!isObj(v) || !isTime(v.at)) return null;
  return definedOnly({ at: v.at, started_at: isTime(v.started_at) ? v.started_at : undefined });
}

// ---------- correlation (ADR 0034 section "Correlation", ADR 0036) ----------
//
// GET /api/correlation and GET /api/correlation/rules: incidents the API correlated from the SIEM's
// evidence, the SOC metrics over them, the SIEM's health, and the rule library from git. Lenient like
// the stats: a malformed incident, step or rule is dropped, a malformed figure becomes "unknown", and
// only an answer that says `available: true` in so many words shows the section at all.
//
// The API builds every published field from an allow-list and scrubs free text (ADR 0021); the page
// checks again, because what it shows it vouches for: a text that still looks like an address, a
// cluster-internal name, a ServiceAccount, a pseudonym or a pod outside the sandbox namespaces is
// withheld here, never shown.

export const SEVERITIES = ["low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CORRELATION_SOURCES = ["falco", "talon", "hubble", "k8s-audit", "api"] as const;
export type CorrelationSource = (typeof CORRELATION_SOURCES)[number];

/** ADR 0036 §9: `document` is the `_id` of a stream document an incident is measured on (TTI, dwell). */
export const EVIDENCE_TYPES = ["finding", "alert", "correlation", "document"] as const;
export type EvidenceType = (typeof EVIDENCE_TYPES)[number];

export interface CorrelationStep {
  at: string;
  source: CorrelationSource;
  /** The rule's title. */
  rule: string;
  /** The Sigma rule's UUID, "" for a step no rule produced (a command document, an audited response). */
  rule_id: string;
  /** The terminal command this step belongs to, when the API could tie it to one. */
  command_seq: number | null;
  /** Scrubbed and capped by the API (200); "" when the page withheld it. */
  detail: string;
  /** Set by the parser when it withheld the detail (see `publishable`). */
  withheld?: true;
}

export interface CorrelationIncident {
  /** 16 hex. */
  id: string;
  kind: string;
  severity: Severity | "unknown";
  title: string;
  /** "" when the incident belongs to no run. */
  run_id: string;
  arm: Arm | "";
  first_at: string;
  last_at: string;
  /** ATT&CK technique ids, e.g. T1048.003. */
  attack: string[];
  /** null: not counted (an API that sends no number). */
  falco_events: number | null;
  /** dns-exfil only: true/false; null when the match is unavailable (the API restarted since the run). */
  flag_match: boolean | null;
  ttd_ms: number | null;
  tti_ms: number | null;
  steps: CorrelationStep[];
  /** What the incident is built from: Security Analytics finding, Alerting alert, SA correlation rule or stream document ids. */
  evidence: { type: EvidenceType; id: string }[];
}

export type RulesStatus = "applied" | "refused" | "failed" | "unknown";
export type IngestHealth = "ok" | "silent" | "unknown";
export type DiskHealth = "ok" | "high" | "unknown";

export interface CorrelationMetrics {
  since: string;
  incidents: number;
  median_ttd_ms: number | null;
  median_tti_ms: number | null;
  median_twin_dwell_ms: number | null;
  host_findings: number;
  /**
   * How far behind each source's newest document is when the API reads it, by source; null when the
   * source has sent nothing to measure. Absent from an API that does not publish it.
   */
  ingest_lag_ms?: [source: string, ms: number | null][];
}

export interface Correlation {
  available: boolean;
  checked_at: string;
  rules: { commit: string; applied_at: string | null; status: RulesStatus };
  /** evidence_rewritten: null when the API sent no boolean (unknown, never "fine"). */
  health: { ingest: IngestHealth; evidence_rewritten: boolean | null; disk: DiskHealth };
  metrics: CorrelationMetrics;
  incidents: CorrelationIncident[];
}

export interface SiemRule {
  id: string;
  title: string;
  level: string;
  status: string;
  source: string;
  attack: string[];
  file: string;
  line: number;
  /** The canary that proves the rule fires ("" when the index names none). */
  canary: string;
}

export interface SiemMonitor {
  name: string;
  file: string;
  canary: string;
}

export interface SiemCorrelationRule {
  name: string;
  file: string;
  canary: string;
}

export interface RuleIndex {
  rules: SiemRule[];
  monitors: SiemMonitor[];
  correlations: SiemCorrelationRule[];
}

/** The page keeps no more than the API promises to send. */
export const MAX_INCIDENTS = 200;
export const MAX_STEPS = 50;
const MAX_RULES = 300;

/** The namespaces whose pod names may be published (ADR 0021, 0031); lib/timeline.ts's SANDBOX_NAMESPACES. */
const SANDBOX_NS: ReadonlySet<string> = new Set(["sandbox", "sandbox-unguarded"]);

/**
 * Patterns ADR 0021 never publishes, as the API's leak test and redactions list them (P4 tests,
 * app/api/internal/incidents publish.go): an IPv4 address other than loopback, an IPv6 address, a
 * cluster-internal DNS name, the node names, a ServiceAccount, a token, a user pseudonym, a dns-exfil
 * query label, the flag, and a Kubernetes API path into a pod outside the sandbox namespaces.
 */
const NEVER_PUBLISHED: readonly RegExp[] = [
  // An address at the end of a sentence ("to 10.43.0.10.") is still one.
  /(?<![\d.])(?!127\.)(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)/,
  // IPv6, conservatively: eight groups, or a "::" with a group on its left (so "12:00:00" and "::1" are not).
  /(?<![\w:])(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}(?![\w:])/i,
  /(?<![\w:])(?:[0-9a-f]{1,4}:){1,6}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,5})?(?![\w:])/i,
  /\.svc\b|cluster\.local/i,
  /k3s01|siem01/i,
  /service[\s_-]?account/i,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+/,
  /bearer\s+\S{16,}/i,
  /hm1:/i,
  /sdp-[0-9a-f]{16}/i,
  /sdp\{/i,
  /namespaces\/(?!sandbox(?:-unguarded)?\/)[a-z0-9-]+\/pods\//i,
];

/**
 * `a/b` or `a_b` that does not start inside a path or a word ("/etc/shadow", "sdp_falco" are not one):
 * a candidate `<namespace>/<pod>`, or the SIEM's own `<namespace>_<pod>` (S0-#1).
 */
const SLASHED = /(?<![\w./-])([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)([/_])([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?![\w])/g;

/** The cluster's other namespaces (cluster/ manifests and the Kubernetes defaults): a ref into one is never shown. */
const CLUSTER_NS: ReadonlySet<string> = new Set(["argocd", "cert-manager", "cloudflared", "default", "falco", "falco-response", "gateway", "hello", "kube-bench", "kube-node-lease", "kube-public", "kube-system", "kyverno", "policy-reporter", "portfolio-api", "trivy-system"]);

/**
 * Whether a text from the SIEM path may be shown: none of the never-published patterns, and no
 * `<ns>/<pod>` reference outside the sandbox namespaces (ADR 0021: pod names only for the sandbox).
 * An `a/b` is taken for a pod reference when `a` is one of the cluster's namespaces or `b` looks like
 * a controller's pod name (it has a hyphen); "pods/exec" and "UDP/53", which the API's details carry,
 * are not.
 */
export function publishable(text: string): boolean {
  // Compatibility forms first: a fullwidth "ｋ３ｓ０１" or a ligature must not slip past an ASCII pattern.
  const s = text.normalize("NFKC");
  if (NEVER_PUBLISHED.some((re) => re.test(s))) return false;
  for (const [, ns, sep, pod] of s.matchAll(SLASHED)) {
    if (SANDBOX_NS.has(ns)) continue;
    // `ns_x` is a ref only with a controller's pod name ("default_value", "read_shadow" are words).
    if (sep === "/" ? CLUSTER_NS.has(ns) || pod.includes("-") : pod.includes("-")) return false;
  }
  return true;
}

const isTechnique = (v: unknown): v is string => isStr(v) && /^T\d{4}(?:\.\d{3})?$/.test(v);
const techniques = (v: unknown): string[] => (Array.isArray(v) ? [...new Set(v.filter(isTechnique))].slice(0, 20) : []);
const isSigmaId = (v: unknown): v is string => isStr(v) && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v);
const optMs = (v: unknown): number | null => (isCount(v) ? v : null);
const oneOf = <T extends string>(list: readonly T[], v: unknown, fallback: T): T => ((list as readonly unknown[]).includes(v) ? (v as T) : fallback);
/** Free text from the SIEM path: the whole text is checked before it is capped (a cap could cut a leak in half). */
const siemText = (v: unknown, max: number): string => {
  const s = isStr(v) ? stripControl(v) : "";
  return publishable(s) ? cap(s, max) : "";
};

function parseStep(v: unknown): CorrelationStep | null {
  if (!isObj(v) || !isTime(v.at) || !(CORRELATION_SOURCES as readonly unknown[]).includes(v.source)) return null;
  const full = isStr(v.detail) ? stripControl(v.detail) : "";
  const detail = publishable(full) ? cap(full, 200) : "";
  return {
    at: v.at,
    source: v.source as CorrelationSource,
    rule: siemText(v.rule, 200),
    rule_id: isSigmaId(v.rule_id) ? v.rule_id : "",
    command_seq: typeof v.command_seq === "number" && Number.isInteger(v.command_seq) && v.command_seq > 0 ? v.command_seq : null,
    detail,
    ...(full && !detail ? { withheld: true as const } : {}),
  };
}

function parseIncident(v: unknown): CorrelationIncident | null {
  if (!isObj(v) || !isStr(v.id) || !/^[0-9a-f]{16}$/.test(v.id) || !isStr(v.kind) || !/^[a-z][a-z-]{0,39}$/.test(v.kind)) return null;
  if (!isTime(v.first_at) || !isTime(v.last_at)) return null;
  const steps = Array.isArray(v.steps) ? v.steps.slice(0, MAX_STEPS).map(parseStep).filter((s): s is CorrelationStep => s !== null) : [];
  return {
    id: v.id,
    kind: v.kind,
    severity: oneOf<Severity | "unknown">(SEVERITIES, v.severity, "unknown"),
    title: siemText(v.title, 200),
    run_id: isRunId(v.run_id) ? v.run_id : "",
    arm: optArm(v.arm) ?? "",
    first_at: v.first_at,
    last_at: v.last_at,
    attack: techniques(v.attack),
    falco_events: isCount(v.falco_events) && Number.isInteger(v.falco_events) ? v.falco_events : null,
    flag_match: isBool(v.flag_match) ? v.flag_match : null,
    ttd_ms: optMs(v.ttd_ms),
    tti_ms: optMs(v.tti_ms),
    steps: steps.sort((a, b) => Date.parse(a.at) - Date.parse(b.at)),
    evidence: Array.isArray(v.evidence)
      ? v.evidence
          .filter((e): e is Obj => isObj(e) && (EVIDENCE_TYPES as readonly unknown[]).includes(e.type) && isStr(e.id) && /^[A-Za-z0-9_-]{1,64}$/.test(e.id) && publishable(e.id))
          .slice(0, 20)
          .map((e) => ({ type: e.type as EvidenceType, id: e.id as string }))
      : [],
  };
}

/**
 * metrics.ingest_lag_ms: source -> ms or null; a bad key or value is dropped, an empty or absent map is
 * undefined. A negative lag (clock skew between the hosts) is kept as the API publishes it (ADR 0036 §5).
 */
function ingestLag(v: unknown): CorrelationMetrics["ingest_lag_ms"] {
  if (!isObj(v)) return undefined;
  const rows = Object.entries(v)
    .filter((e): e is [string, number | null] => /^[a-z0-9-]{1,30}$/.test(e[0]) && (e[1] === null || (typeof e[1] === "number" && Number.isFinite(e[1]))))
    .slice(0, 12);
  return rows.length ? rows : undefined;
}

const EMPTY_METRICS: CorrelationMetrics = { since: "", incidents: 0, median_ttd_ms: null, median_tti_ms: null, median_twin_dwell_ms: null, host_findings: 0 };

/**
 * GET /api/correlation. Throws only when the answer is not an object; `available` is true only for a
 * literal `true`, and an unavailable answer carries nothing else (whatever the API sent with it).
 */
export function parseCorrelation(v: unknown): Correlation {
  if (!isObj(v)) throw new TypeError("correlation: expected an object");
  const checked_at = isTime(v.checked_at) ? v.checked_at : "";
  if (v.available !== true) {
    return { available: false, checked_at, rules: { commit: "", applied_at: null, status: "unknown" }, health: { ingest: "unknown", evidence_rewritten: null, disk: "unknown" }, metrics: EMPTY_METRICS, incidents: [] };
  }
  const r = isObj(v.rules) ? v.rules : {};
  const hl = isObj(v.health) ? v.health : {};
  const m = isObj(v.metrics) ? v.metrics : {};
  const seen = new Set<string>();
  const incidents = (Array.isArray(v.incidents) ? v.incidents.slice(0, MAX_INCIDENTS) : [])
    .map(parseIncident)
    .filter((i): i is CorrelationIncident => i !== null && !seen.has(i.id) && (seen.add(i.id), true))
    // Newest first by first_at, as the API orders them (ADR 0036 §9), whatever order arrived.
    .sort((a, b) => Date.parse(b.first_at) - Date.parse(a.first_at));
  return {
    available: true,
    checked_at,
    rules: {
      commit: isStr(r.commit) && /^[0-9a-f]{40}$/.test(r.commit) ? r.commit : "",
      applied_at: isTime(r.applied_at) ? r.applied_at : null,
      status: oneOf<RulesStatus>(["applied", "refused", "failed", "unknown"], r.status, "unknown"),
    },
    health: {
      ingest: oneOf<IngestHealth>(["ok", "silent", "unknown"], hl.ingest, "unknown"),
      evidence_rewritten: isBool(hl.evidence_rewritten) ? hl.evidence_rewritten : null,
      disk: oneOf<DiskHealth>(["ok", "high", "unknown"], hl.disk, "unknown"),
    },
    metrics: {
      since: isTime(m.since) ? m.since : "",
      incidents: isCount(m.incidents) ? m.incidents : incidents.length,
      median_ttd_ms: optMs(m.median_ttd_ms),
      median_tti_ms: optMs(m.median_tti_ms),
      median_twin_dwell_ms: optMs(m.median_twin_dwell_ms),
      host_findings: isCount(m.host_findings) ? m.host_findings : 0,
      ...definedOnly({ ingest_lag_ms: ingestLag(m.ingest_lag_ms) }),
    },
    incidents,
  };
}

const canaryOf = (v: unknown): string => (isStr(v) ? siemText(v, 80) : v === true ? "yes" : "");

/** GET /api/correlation/rules: the index generated from siem/ in git. Malformed entries dropped. */
export function parseRuleIndex(v: unknown): RuleIndex {
  if (!isObj(v) || !Array.isArray(v.rules)) throw new TypeError("rules: expected {rules: [...]}");
  const named = (x: unknown, max: number) =>
    (Array.isArray(x) ? x.slice(0, max) : [])
      .filter((o): o is Obj => isObj(o) && isStr(o.name) && o.name.length > 0)
      .map((o) => ({ name: siemText(o.name, 120), file: isRepoPath(o.file) ? o.file : "", canary: canaryOf(o.canary) }))
      .filter((o) => o.name);
  const seen = new Set<string>();
  return {
    rules: v.rules
      .slice(0, MAX_RULES)
      .filter((o): o is Obj => isObj(o) && isSigmaId(o.id) && isStr(o.title) && !seen.has(o.id) && (seen.add(o.id), true))
      .map((o) => ({
        id: o.id as string,
        title: siemText(o.title, 200),
        level: oneOf<string>(["informational", ...SEVERITIES], o.level, ""),
        status: isStr(o.status) && /^[a-z]{1,20}$/.test(o.status) ? o.status : "",
        source: isStr(o.source) && /^[a-z0-9-]{1,30}$/.test(o.source) ? o.source : "",
        attack: techniques(o.attack),
        file: isRepoPath(o.file) ? o.file : "",
        line: isRepoPath(o.file) && isLine(o.line) ? o.line : 0,
        canary: canaryOf(o.canary),
      }))
      .filter((r) => r.title),
    monitors: named(v.monitors, 100),
    correlations: named(v.correlations, 100),
  };
}
