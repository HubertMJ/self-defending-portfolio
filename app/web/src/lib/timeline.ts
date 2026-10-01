// Turns the flat SSE event log into what the timeline shows: one entry per run, with the Falco
// detection and Talon response that belong to it and the latencies between them.
//
// The view is rebuilt from the whole (bounded) log on every event rather than patched in place.
// Events can arrive in any order -- a replay after reconnect, a Falco alert that beats the API's
// own "detected" transition -- and a pure rebuild makes the result independent of arrival order,
// which is also what makes it easy to test.
//
// The extension events (pod lifecycle, victim probes, Hubble flows) carry a run_id and are attributed
// by it; Falco and Talon events do not, so they are attributed by pod name (known from the run's own
// `pod` field since the extension, otherwise from the first event that names one) and, failing that,
// by time window.

import {
  type FalcoEvent,
  type FlowEvent,
  type PodEvent,
  type RunEvent,
  type RunState,
  type StreamEvent,
  type TalonEvent,
  TERMINAL_STATES,
  type VictimEvent,
} from "./contract";

/** The quarantine label Talon sets (cluster/infra/falco-response/talon/rules.yaml). */
export const QUARANTINE_LABEL = "sdp.hubertjablon.ski/quarantine";

/** A run of identical victim observations, collapsed: the API probes every 500 ms. */
export interface VictimSpan extends VictimEvent {
  /** Timestamp (ms) of the last observation with this status and checksum. */
  until: number;
  count: number;
}

export interface RunView {
  runId: string;
  scenario: string;
  /** Timestamp (ms) of each state the run has reported. */
  states: Partial<Record<RunState, number>>;
  current: RunState;
  detail?: string;
  pod?: string;
  falco: FalcoEvent[];
  talon: TalonEvent[];
  /** Pod watch observations, oldest first. */
  pods: PodEvent[];
  /** Victim probe results, oldest first, consecutive repeats collapsed. */
  victim: VictimSpan[];
  flows: FlowEvent[];
  /** Every event attributed to this run, oldest first: the raw view of Technical Mode. */
  events: StreamEvent[];
  podUid?: string;
  image?: string;
  containerId?: string;
  /** When the quarantine label turned "true" (ms), if it did. */
  quarantinedAt?: number;
  timings: {
    /** started -> first detection (run "detected" or first Falco alert, whichever is earlier) */
    detectMs?: number;
    /** detection -> first response (run "responded" or first Talon action, whichever is earlier) */
    respondMs?: number;
    /** started -> terminal state */
    totalMs?: number;
  };
  active: boolean;
}

export interface TimelineView {
  runs: RunView[]; // newest first
  /** Falco/Talon events in the sandbox that no run claims (manual tests, a run outside our window). */
  unmatched: StreamEvent[];
  activeRun?: RunView;
}

/** A Falco or Talon event this long after a run ended still belongs to it (delivery lag). */
const GRACE_MS = 10_000;
const MAX_RUNS = 20;

const STATE_ORDER: Record<RunState, number> = {
  queued: 0,
  started: 1,
  pod_ready: 2,
  detected: 3,
  responded: 4,
  finished: 5,
  failed: 5,
  timeout: 5,
};

export function ts(iso: string): number {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? 0 : t;
}

function minDefined(...xs: (number | undefined)[]): number | undefined {
  const d = xs.filter((x): x is number => x !== undefined);
  return d.length ? Math.min(...d) : undefined;
}

/**
 * A run with no terminal state this long after it started is treated as over: scenario pods have a
 * 120 s deadline, so the API either lost the run or the terminal event was lost. Without this, one
 * dropped event would keep the launch buttons disabled until the page is reloaded.
 */
export const STALE_RUN_MS = 180_000;

export function buildTimeline(events: readonly StreamEvent[], now: number = Date.now()): TimelineView {
  const runs = new Map<string, RunView>();
  const runEvents = events.filter((e): e is { type: "run"; data: RunEvent } => e.type === "run");

  for (const { data } of runEvents) {
    let run = runs.get(data.run_id);
    if (!run) {
      run = {
        runId: data.run_id,
        scenario: data.scenario,
        states: {},
        current: data.state,
        falco: [],
        talon: [],
        pods: [],
        victim: [],
        flows: [],
        events: [],
        timings: {},
        active: true,
      };
      runs.set(data.run_id, run);
    }
    if (data.pod && !run.pod) run.pod = data.pod;
    const at = ts(data.at);
    const prev = run.states[data.state];
    if (prev === undefined || at < prev) run.states[data.state] = at;
    if (STATE_ORDER[data.state] >= STATE_ORDER[run.current]) {
      run.current = data.state;
      if (data.detail) run.detail = data.detail;
    }
  }

  const list = [...runs.values()];
  const start = (r: RunView) => r.states.started ?? r.states.queued ?? 0;
  const end = (r: RunView) => {
    const t = minDefined(r.states.finished, r.states.failed, r.states.timeout);
    return t === undefined ? Infinity : t + GRACE_MS;
  };

  const unmatched: StreamEvent[] = [];
  const byPod = new Map<string, RunView>();
  for (const r of list) if (r.pod) byPod.set(r.pod, r);
  const sorted = events.slice().sort((a, b) => ts(a.data.at) - ts(b.data.at));

  for (const ev of sorted) {
    if (ev.type === "run") {
      runs.get(ev.data.run_id)?.events.push(ev);
      continue;
    }
    const data = ev.data;
    const at = ts(data.at);
    // An explicit run id wins, then a pod already tied to a run, then the newest run whose window
    // contains the event.
    const runId = "run_id" in data ? data.run_id : undefined;
    let owner = runId ? runs.get(runId) : undefined;
    owner ??= byPod.get(data.pod);
    if (!owner) {
      owner = list
        .filter((r) => start(r) <= at && at <= end(r))
        .sort((a, b) => start(b) - start(a))[0];
    }
    if (!owner) {
      unmatched.push(ev);
      continue;
    }
    if (!owner.pod && data.pod) owner.pod = data.pod;
    if (data.pod && !byPod.has(data.pod)) byPod.set(data.pod, owner);
    owner.events.push(ev);
    switch (ev.type) {
      case "falco":
        owner.falco.push(ev.data);
        break;
      case "talon":
        owner.talon.push(ev.data);
        break;
      case "pod":
        addPod(owner, ev.data);
        break;
      case "victim":
        addVictim(owner, ev.data);
        break;
      case "flow":
        owner.flows.push(ev.data);
        break;
    }
  }

  for (const r of list) {
    r.active = !TERMINAL_STATES.has(r.current) && now - start(r) < STALE_RUN_MS;
    const started = r.states.started ?? r.states.queued;
    const detected = minDefined(r.states.detected, r.falco[0] && ts(r.falco[0].at));
    const responded = minDefined(r.states.responded, r.talon[0] && ts(r.talon[0].at));
    const finished = minDefined(r.states.finished, r.states.failed, r.states.timeout);
    if (started !== undefined && detected !== undefined) r.timings.detectMs = Math.max(0, detected - started);
    if (detected !== undefined && responded !== undefined) r.timings.respondMs = Math.max(0, responded - detected);
    if (started !== undefined && finished !== undefined) r.timings.totalMs = Math.max(0, finished - started);
  }

  list.sort((a, b) => start(b) - start(a));
  const recent = list.slice(0, MAX_RUNS);
  return {
    runs: recent,
    unmatched: unmatched.slice(-20).reverse(),
    activeRun: recent.find((r) => r.active),
  };
}

function addPod(run: RunView, p: PodEvent): void {
  run.pods.push(p);
  if (p.uid) run.podUid = p.uid;
  if (p.image) run.image = p.image;
  if (p.container_id) run.containerId = p.container_id;
  if (run.quarantinedAt === undefined && p.labels_delta[QUARANTINE_LABEL] === "true") run.quarantinedAt = ts(p.at);
}

function addVictim(run: RunView, v: VictimEvent): void {
  const last = run.victim[run.victim.length - 1];
  const at = ts(v.at);
  if (last && last.status === v.status && last.checksum === v.checksum && last.pod === v.pod) {
    last.until = at;
    last.count += 1;
    if (v.probe_ms >= 0) last.probe_ms = v.probe_ms;
    return;
  }
  run.victim.push({ ...v, until: at, count: 1 });
}

/** Human-readable duration: "840 ms", "2.4 s", "1 min 12 s". */
export function formatDuration(ms: number | undefined): string {
  if (ms === undefined || !Number.isFinite(ms)) return "–";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)} s`;
  const m = Math.floor(ms / 60_000);
  const s = Math.round((ms % 60_000) / 1000);
  return `${m} min ${s} s`;
}
