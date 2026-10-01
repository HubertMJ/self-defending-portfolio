// The detection pipeline of one run as eight hops, each with the real timestamp the cluster reported
// for it, and the schedule on which the page lights them.
//
//   kube-apiserver create -> containerd Running -> exec -> Falco (eBPF) -> Falcosidekick -> Talon
//     -> kube-apiserver delete | label -> kubelet gone | Cilium drop
//
// Why a schedule at all: the interesting part of a run happens in a few hundred milliseconds. Falco
// sees the syscall, Falcosidekick forwards it and Talon acts within tens of milliseconds of each other,
// and the events reach the page in one burst. Lighting them as they arrive would look like a single
// flash, which is indistinguishable from a mock-up. So every hop is held for at least MIN_DWELL_MS
// before the next one lights, and the page says so in plain words: "replayed at 1/N speed, real: X
// ms". The numbers on the hops are always the real ones; only the animation is slowed down. Under
// prefers-reduced-motion there is no replay: a hop lights when its event arrives.
//
// Everything here is pure (timestamps in, numbers out) so it can be unit tested without a DOM.

import type { RunView } from "./timeline";
import { QUARANTINE_LABEL, ts } from "./timeline";

export const MIN_DWELL_MS = 600;
/** In a replay, a long real gap (pod scheduling, image pull) is shortened to this. */
export const MAX_GAP_MS = 2500;

/** The kill-timer runs from the exec to the response taking effect in the API server. */
export const TIMER_START = 2;
export const TIMER_END = 6;

export type HopKey = "create" | "running" | "exec" | "falco" | "sidekick" | "talon" | "act" | "effect";
export type Stage = "attack" | "detect" | "respond";

export interface Hop {
  key: HopKey;
  stage: Stage;
  /** The component that did it, as it is called in the cluster. */
  who: string;
  /** What it did, in a few words. */
  what: string;
  /** Real timestamp (ms since epoch) reported for this hop, if any. */
  at?: number;
  /** The raw RFC 3339 timestamp, for the "verify it yourself" panel. */
  raw?: string;
  /** Where the timestamp comes from, for the same panel. */
  source?: string;
}

const first = <T>(xs: readonly T[], p: (x: T) => boolean): T | undefined => xs.find(p);

/** The eight hops of a run, from whatever events it has. Missing data leaves a hop without `at`. */
export function runHops(run: RunView): Hop[] {
  const quarantine = run.quarantinedAt !== undefined || run.talon.some((t) => /label|quarantine/i.test(`${t.actionner ?? ""} ${t.action}`));
  const created = first(run.pods, () => true);
  const running = first(run.pods, (p) => /^running$/i.test(p.phase) && !p.deleted);
  const falco = run.falco[0];
  const talon = run.talon[0];
  const terminating = first(run.pods, (p) => /terminating/i.test(p.phase) || p.deleted);
  const labelled = first(run.pods, (p) => p.labels_delta[QUARANTINE_LABEL] === "true");
  const deleted = first(run.pods, (p) => p.deleted || /^deleted$/i.test(p.phase));
  const dropped = first(run.flows, (f) => /drop/i.test(f.verdict));
  const unreachable = first(run.victim, (v) => v.status === "unreachable");
  const gone = first(run.victim, (v) => v.status === "gone");

  const hop = (h: Omit<Hop, "at" | "raw">, raw: string | undefined, fallback?: number): Hop => {
    const at = raw ? ts(raw) : fallback;
    return { ...h, at: at || undefined, raw };
  };
  const stateRaw = (s: keyof RunView["states"]): string | undefined => {
    const e = run.events.find((ev) => ev.type === "run" && ev.data.state === s);
    return e?.data.at;
  };

  // Exec: the API sends it right after the pod is Ready ("pod_ready"); an API without that state
  // reports "started" at the same moment instead.
  const execRaw = stateRaw("pod_ready") ?? stateRaw("started");
  return [
    hop({ key: "create", stage: "attack", who: "kube-apiserver", what: "pod created", source: created ? "pod watch" : "run: started" }, created?.at ?? stateRaw("started")),
    hop({ key: "running", stage: "attack", who: "containerd", what: "container running", source: running ? "pod watch" : "run: pod_ready" }, running?.at ?? stateRaw("pod_ready")),
    hop({ key: "exec", stage: "attack", who: "exec", what: "attack command starts", source: "run: pod_ready / started" }, execRaw),
    hop({ key: "falco", stage: "detect", who: "Falco · eBPF", what: falco ? falco.rule : "syscall matched a rule", source: "falco event time" }, falco?.at),
    hop({ key: "sidekick", stage: "detect", who: "Falcosidekick", what: "alert forwarded", source: "falco: api_received_at" }, falco?.api_received_at),
    hop({ key: "talon", stage: "respond", who: "Falco Talon", what: talon ? humanAction(talon.action, talon.actionner) : "response decided", source: "talon event time" }, talon?.at),
    quarantine
      ? hop({ key: "act", stage: "respond", who: "kube-apiserver", what: "quarantine label set", source: labelled ? "pod watch" : "run: responded" }, labelled?.at ?? stateRaw("responded"))
      : hop({ key: "act", stage: "respond", who: "kube-apiserver", what: "pod deleted", source: terminating ? "pod watch" : "run: responded" }, terminating?.at ?? stateRaw("responded")),
    quarantine
      ? hop({ key: "effect", stage: "respond", who: "Cilium", what: "traffic dropped", source: dropped ? "hubble flow" : "victim probe" }, dropped?.at ?? unreachable?.at)
      : hop({ key: "effect", stage: "respond", who: "kubelet", what: "pod gone", source: deleted ? "pod watch" : "victim probe" }, deleted?.at ?? gone?.at),
  ];
}

/** Talon's action in words a visitor understands; the raw names stay available in Technical Mode. */
export function humanAction(action: string, actionner?: string): string {
  const s = `${action} ${actionner ?? ""}`.toLowerCase();
  if (s.includes("terminate")) return "Talon deleted the pod";
  if (s.includes("label") || s.includes("quarantine")) return "Talon quarantined the pod";
  if (s.includes("networkpolicy")) return "Talon cut the pod's network";
  return `Talon ran “${action}”`;
}

export interface HopTiming {
  /** Real timestamp of the hop, from the cluster. */
  real?: number;
  /** Local time (ms) at which the page learned of it. */
  known?: number;
}

export interface Schedule {
  /** Local time at which each hop lights; undefined for a hop that has no data (yet). */
  lightAt: (number | undefined)[];
  /** Real time from the first to the last hop with data in the response chain (exec..effect). */
  realSpanMs?: number;
  /** How long the same stretch takes on screen. */
  shownSpanMs?: number;
  /** shownSpanMs / realSpanMs, rounded; 1 means real time. */
  slowdown: number;
}

/**
 * When each hop lights. A hop lights no earlier than the page knew of it and, unless `instant`, no
 * earlier than its predecessor plus the real gap between them clamped to [minDwell, maxGap]. A hop
 * without data does not hold the ones after it back: a later hop that has data lights in its turn and
 * the empty one is shown as "not reported".
 */
export function scheduleHops(
  hops: readonly HopTiming[],
  opts: { instant?: boolean; minDwellMs?: number; maxGapMs?: number; chainFrom?: number } = {},
): Schedule {
  const minDwell = opts.minDwellMs ?? MIN_DWELL_MS;
  const maxGap = Math.max(minDwell, opts.maxGapMs ?? MAX_GAP_MS);
  const lightAt: (number | undefined)[] = [];
  let prevLight: number | undefined;
  let prevReal: number | undefined;
  for (const h of hops) {
    if (h.real === undefined || h.known === undefined) {
      lightAt.push(undefined);
      continue;
    }
    let t = h.known;
    if (!opts.instant && prevLight !== undefined) {
      const gap = prevReal === undefined ? minDwell : Math.min(maxGap, Math.max(minDwell, h.real - prevReal));
      t = Math.max(t, prevLight + gap);
    }
    lightAt.push(t);
    prevLight = t;
    prevReal = h.real;
  }
  const from = opts.chainFrom ?? 2;
  const idx = hops.map((_, i) => i).filter((i) => i >= from && lightAt[i] !== undefined);
  let realSpanMs: number | undefined;
  let shownSpanMs: number | undefined;
  let slowdown = 1;
  if (idx.length >= 2) {
    const a = idx[0];
    const b = idx[idx.length - 1];
    realSpanMs = Math.max(0, (hops[b].real as number) - (hops[a].real as number));
    shownSpanMs = Math.max(0, (lightAt[b] as number) - (lightAt[a] as number));
    slowdown = realSpanMs > 0 ? Math.max(1, Math.round(shownSpanMs / realSpanMs)) : 1;
  }
  return { lightAt, realSpanMs, shownSpanMs, slowdown };
}

/**
 * The kill-timer's reading at local time `now`: real milliseconds since the attack started, as far
 * as the (possibly slowed-down) replay has got. Between two lit hops it runs from one real value to
 * the next; at the frontier it holds still until the next hop is scheduled. That keeps it monotonic
 * and never ahead of what the cluster actually reported.
 */
export function timerReading(
  hops: readonly HopTiming[],
  schedule: Schedule,
  startIndex: number,
  endIndex: number,
  now: number,
): number | undefined {
  const start = hops[startIndex]?.real;
  if (start === undefined || schedule.lightAt[startIndex] === undefined || (schedule.lightAt[startIndex] as number) > now) return undefined;
  let value = 0;
  let prevLight = schedule.lightAt[startIndex] as number;
  let prevReal = start;
  for (let i = startIndex + 1; i <= endIndex && i < hops.length; i++) {
    const light = schedule.lightAt[i];
    const real = hops[i].real;
    if (light === undefined || real === undefined) continue;
    const target = Math.max(value, real - start);
    if (now >= light) {
      value = target;
      prevLight = light;
      prevReal = real;
      continue;
    }
    const span = light - prevLight;
    const f = span > 0 ? Math.min(1, Math.max(0, (now - prevLight) / span)) : 1;
    return Math.max(value, prevReal - start + f * (target - (prevReal - start)));
  }
  return value;
}
