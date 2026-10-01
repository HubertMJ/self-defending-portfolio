// An in-page stand-in for the portfolio API, used by `?mock=1`, the dev server and the tests.
//
// It plugs in at the two seams the real client already has -- a fetch function and an EventSource
// factory -- so mock mode exercises the same client, parsing and rendering code as production. It
// also enforces the contract's rules (one run at a time -> 409, 3 attacks per 10 minutes -> 429 with
// Retry-After) so those paths can be seen and tested without a cluster.

import type { PodEvent, RunEvent, RunState, StreamEvent } from "./contract";
import type { FetchLike } from "./api";
import type { EventSourceLike } from "./sse";
import { SCENARIOS, SCENARIO_IMAGE, falcoFields, falcoOutput, posture, scenarioDetails, victimScript } from "./fixtures";

export interface MockOptions {
  /** Multiplies every delay in the simulated run; 0.1 makes a run take a fraction of a second. */
  speed?: number;
  /** Attacks allowed per window before 429 (contract: 3 per 10 minutes per IP). */
  limit?: number;
  windowMs?: number;
  /** Seed the replay buffer with one completed run, as a live server would have. */
  history?: boolean;
  /** Refuse this many stream connections first, as the API's stream cap does (429 + Retry-After). */
  streamRefusals?: number;
  /** Retry-After of those refusals, in seconds. */
  streamRetryAfter?: number;
  /** The first accepted stream opens and then stalls: no events, closed after a second. */
  streamStall?: boolean;
  /** Answer /api/scenarios/{id}/details with 404, as an API without the extension does. */
  noDetails?: boolean;
  /** Start a run "from another visitor" this long after the page loads, to watch it read-only. */
  visitorAfterMs?: number;
}

const REPLAY = 50;

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

class MockEventSource implements EventSourceLike {
  readyState = 0;
  onopen: ((ev: Event) => unknown) | null = null;
  onerror: ((ev: Event) => unknown) | null = null;
  private readonly listeners = new Map<string, ((ev: MessageEvent) => void)[]>();

  constructor(private readonly backend: MockBackend) {}

  addEventListener(type: string, listener: (ev: MessageEvent) => void): void {
    const list = this.listeners.get(type) ?? [];
    list.push(listener);
    this.listeners.set(type, list);
  }

  emit(ev: StreamEvent): void {
    if (this.readyState !== 1) return;
    const msg = new MessageEvent(ev.type, { data: JSON.stringify(ev.data) });
    for (const l of this.listeners.get(ev.type) ?? []) l(msg);
  }

  open(): void {
    this.readyState = 1;
    this.onopen?.(new Event("open"));
  }

  /** A refused or dead connection, as the browser reports it: CLOSED, then one error event. */
  fail(): void {
    this.readyState = 2;
    this.backend.detach(this);
    this.onerror?.(new Event("error"));
  }

  close(): void {
    this.readyState = 2;
    this.backend.detach(this);
  }
}

export class MockBackend {
  private readonly speed: number;
  private readonly limit: number;
  private readonly windowMs: number;
  private readonly buffer: StreamEvent[] = [];
  private readonly sources = new Set<MockEventSource>();
  private readonly attempts: number[] = [];
  private activeRun: string | null = null;
  private seq = 0;
  private streamRefusals: number;
  private readonly streamRetryAfter: number;
  private streamStall: boolean;
  private readonly noDetails: boolean;

  constructor(opts: MockOptions = {}) {
    this.speed = opts.speed ?? 1;
    this.limit = opts.limit ?? 3;
    this.windowMs = opts.windowMs ?? 10 * 60_000;
    this.streamRefusals = opts.streamRefusals ?? 0;
    this.streamRetryAfter = opts.streamRetryAfter ?? 2;
    this.streamStall = opts.streamStall ?? false;
    this.noDetails = opts.noDetails ?? false;
    if (opts.history ?? true) this.seedHistory();
    if (opts.visitorAfterMs !== undefined) {
      setTimeout(() => {
        if (this.activeRun) return;
        const runId = this.nextRunId();
        this.activeRun = runId;
        this.simulate(runId, "network-tool");
      }, opts.visitorAfterMs);
    }
  }

  readonly fetch: FetchLike = async (input, init) => {
    const path = new URL(input, "http://mock.invalid").pathname;
    const method = (init?.method ?? "GET").toUpperCase();
    await new Promise((r) => setTimeout(r, 120 * this.speed));

    if (method === "GET" && path === "/api/healthz") return json(200, { status: "ok" });
    // The probe EventStream sends after a refused connect.
    if (method === "GET" && path === "/api/events") {
      return this.streamRefusals > 0
        ? json(429, { error: "too many open event streams" }, { "Retry-After": String(this.streamRetryAfter) })
        : new Response("", { status: 200, headers: { "Content-Type": "text/event-stream" } });
    }
    if (method === "GET" && path === "/api/scenarios") return json(200, SCENARIOS);
    if (method === "GET" && path === "/api/posture") return json(200, posture());
    if (method === "GET" && path === "/api/limits") return json(200, this.limits());

    const details = /^\/api\/scenarios\/([^/]+)\/details$/.exec(path);
    if (method === "GET" && details) {
      const d = this.noDetails ? null : scenarioDetails(decodeURIComponent(details[1]));
      return d ? json(200, d) : json(404, { error: "not found" });
    }
    const runs = /^\/api\/runs\/([^/]+)$/.exec(path);
    if (method === "GET" && runs) {
      const id = decodeURIComponent(runs[1]);
      const events = this.buffer.filter((e) => "run_id" in e.data && e.data.run_id === id);
      const pods = new Set(events.map((e) => e.data.pod).filter(Boolean));
      const all = this.buffer.filter((e) => events.includes(e) || (!("run_id" in e.data) && pods.has(e.data.pod)));
      return all.length ? json(200, { run_id: id, events: all }) : json(404, { error: "unknown run" });
    }

    const m = /^\/api\/attack\/([^/]+)$/.exec(path);
    if (method === "POST" && m) {
      const id = decodeURIComponent(m[1]);
      const scenario = SCENARIOS.find((s) => s.id === id);
      if (!scenario) return json(404, { error: "unknown scenario" });
      if (this.activeRun) return json(409, { error: "another run is active" });
      const now = Date.now();
      while (this.attempts.length && now - this.attempts[0] > this.windowMs) this.attempts.shift();
      if (this.attempts.length >= this.limit) {
        const retry = Math.ceil((this.attempts[0] + this.windowMs - now) / 1000);
        return json(429, { error: "rate limited" }, { "Retry-After": String(retry) });
      }
      this.attempts.push(now);
      const runId = this.nextRunId();
      this.activeRun = runId;
      this.simulate(runId, scenario.id);
      return json(202, { run_id: runId, scenario: scenario.id, state: "queued" });
    }
    return json(404, { error: "not found" });
  };

  readonly eventSource = (url: string): EventSourceLike => {
    if (new URL(url, "http://mock.invalid").pathname !== "/api/events") {
      throw new Error(`mock: no stream at ${url}`);
    }
    const src = new MockEventSource(this);
    if (this.streamRefusals > 0) {
      this.streamRefusals -= 1;
      setTimeout(() => src.fail(), 30 * this.speed);
      return src;
    }
    if (this.streamStall) {
      this.streamStall = false;
      setTimeout(() => src.open(), 30 * this.speed);
      setTimeout(() => src.fail(), 1000);
      return src;
    }
    this.sources.add(src);
    setTimeout(() => {
      src.open();
      for (const ev of this.buffer) src.emit(ev);
    }, 60 * this.speed);
    return src;
  };

  detach(src: MockEventSource): void {
    this.sources.delete(src);
  }

  private nextRunId(): string {
    this.seq += 1;
    return `mock-${Date.now().toString(36)}-${this.seq}`;
  }

  private publish(ev: StreamEvent): void {
    this.buffer.push(ev);
    if (this.buffer.length > REPLAY) this.buffer.shift();
    for (const s of this.sources) s.emit(ev);
  }

  private limits() {
    const now = Date.now();
    const recent = this.attempts.filter((t) => now - t <= this.windowMs);
    return {
      per_visitor: {
        limit: this.limit,
        window_s: Math.round(this.windowMs / 1000),
        remaining: Math.max(0, this.limit - recent.length),
        reset_in_s: recent.length ? Math.ceil((recent[0] + this.windowMs - now) / 1000) : 0,
      },
      global: { limit: 30, window_s: 3600, remaining: 30 - Math.min(30, this.seq) },
      active_run: this.activeRun !== null,
      stream_slots_remaining: 64 - this.sources.size,
    };
  }

  /**
   * The event sequence a real run produces: [emit offset, event] pairs, both in ms from t0 before the
   * speed factor. Timestamps differ from emit offsets where the real system's do -- Falco stamps the
   * syscall, which happened before the alert reached the API -- so the page's latency maths sees the
   * same shape it sees live. Loosely modelled on the DoD test runs.
   */
  private script(runId: string, scenarioId: string, t0: number, speed: number): [number, StreamEvent][] {
    const scenario = SCENARIOS.find((s) => s.id === scenarioId) ?? SCENARIOS[0];
    const suffix = runId.replace(/[^a-z0-9]/g, "").slice(-5).padStart(5, "x");
    const pod = `scenario-${scenarioId}-${suffix}`;
    const uid = `7c1e${suffix}-3b2a-4f0e-9d61-${runId.length.toString(16).padStart(4, "0")}a4c09e1f`;
    const quarantine = scenario.response === "quarantine";
    const at = (ms: number) => new Date(t0 + ms * speed).toISOString();
    const run = (state: RunState, ms: number, detail?: string): StreamEvent => {
      const data: RunEvent = { run_id: runId, scenario: scenarioId, state, at: at(ms) };
      if (state !== "queued") data.pod = pod;
      if (detail) data.detail = detail;
      return { type: "run", data };
    };
    const podEv = (ms: number, phase: string, extra: Partial<PodEvent> = {}): StreamEvent => ({
      type: "pod",
      data: { run_id: runId, pod, uid, phase, reason: "", container_id: "", image: SCENARIO_IMAGE, labels_delta: {}, deleted: false, at: at(ms), ...extra },
    });
    const [up, hit] = victimScript(scenarioId);
    const victim = (ms: number, v: typeof up, probe = 3): StreamEvent => ({
      type: "victim",
      data: { run_id: runId, pod, at: at(ms), probe_ms: probe, ...v },
    });
    const cid = "4f1c2a9e8b7d";
    const end = quarantine ? 6400 : 3000;
    const events: [number, StreamEvent][] = [
      [0, run("queued", 0)],
      [80, run("started", 80)],
      [120, podEv(120, "Pending", { labels_delta: { "sdp.hubertjablon.ski/quarantine": "false" } })],
      [620, podEv(620, "ContainerCreating", { reason: "ContainerCreating" })],
      [1880, podEv(1880, "Running", { container_id: cid })],
      [1920, run("pod_ready", 1920, cid)],
      [2010, victim(2010, { ...up }, 4)],
      // The exec is sent at 1925; the victim app is hit and Falco sees the syscall almost at once.
      [2180, victim(2180, { ...hit }, 3)],
      [2240, {
        type: "falco",
        data: {
          at: at(2131),
          rule: scenario.detection,
          priority: quarantine ? "Warning" : scenarioId === "drop-and-execute" ? "Critical" : scenarioId === "shell-in-container" ? "Notice" : "Warning",
          namespace: "sandbox",
          pod,
          output: falcoOutput(scenario, pod).slice(0, 1024),
          fields: falcoFields(scenario, pod),
          api_received_at: at(2158),
        },
      }],
      [2250, run("detected", 2250, scenario.detection)],
      [2290, {
        type: "talon",
        data: {
          at: at(2186),
          action: quarantine ? "Quarantine Pod" : "Terminate Pod",
          actionner: quarantine ? "kubernetes:label" : "kubernetes:terminate",
          namespace: "sandbox",
          pod,
          status: "success",
          output: quarantine ? `the pod '${pod}' in the namespace 'sandbox' has been labeled` : `the pod '${pod}' in the namespace 'sandbox' has been terminated`,
          api_received_at: at(2201),
        },
      }],
    ];
    if (quarantine) {
      events.push(
        [2300, podEv(2214, "Running", { container_id: cid, labels_delta: { "sdp.hubertjablon.ski/quarantine": "true" } })],
        [2310, run("responded", 2310, "quarantine")],
        [2520, { type: "flow", data: { run_id: runId, pod, at: at(2512), direction: "ingress", l4: "TCP/8080", verdict: "DROPPED", drop_reason: "Policy denied" } }],
        [2820, victim(2820, { status: "unreachable", title: "", banner: "", checksum: "" }, 300)],
        [3320, victim(3320, { status: "unreachable", title: "", banner: "", checksum: "" }, 300)],
        [3540, { type: "flow", data: { run_id: runId, pod, at: at(3533), direction: "egress", l4: "UDP/53", verdict: "DROPPED", drop_reason: "Policy denied" } }],
        [6300, podEv(6300, "Terminating", { container_id: cid })],
        [6380, podEv(6380, "Deleted", { container_id: cid, deleted: true })],
      );
    } else {
      events.push(
        [2300, podEv(2203, "Terminating", { container_id: cid })],
        [2310, run("responded", 2310, "terminate")],
        [2380, podEv(2251, "Deleted", { container_id: cid, deleted: true })],
        [2700, victim(2700, { status: "gone", title: "", banner: "", checksum: "" }, 0)],
      );
    }
    events.push([end, run("finished", end)]);
    return events;
  }

  private simulate(runId: string, scenarioId: string): void {
    const t0 = Date.now();
    for (const [offset, ev] of this.script(runId, scenarioId, t0, this.speed)) {
      setTimeout(() => {
        this.publish(ev);
        if (ev.type === "run" && ev.data.state === "finished") this.activeRun = null;
      }, offset * this.speed);
    }
  }

  private seedHistory(): void {
    const t0 = Date.now() - 7 * 60_000;
    for (const [, ev] of this.script("mock-history-1", "shell-in-container", t0, 1)) this.buffer.push(ev);
    while (this.buffer.length > REPLAY) this.buffer.shift();
  }
}

/** Reads mock settings from the page URL: `?mock=1`, optional `&mock-speed=0.2&mock-limit=1`. */
export function mockOptionsFromUrl(search: string): MockOptions | null {
  const q = new URLSearchParams(search);
  const flag = q.get("mock");
  if (flag === null || flag === "0" || flag === "false") return null;
  const num = (k: string) => {
    const v = Number(q.get(k));
    return q.has(k) && Number.isFinite(v) && v >= 0 ? v : undefined;
  };
  return {
    speed: num("mock-speed"),
    limit: num("mock-limit"),
    streamRefusals: num("mock-stream-refuse"),
    streamRetryAfter: num("mock-stream-retry-after"),
    streamStall: q.get("mock-stream-stall") === "1",
    noDetails: q.get("mock-details") === "0",
    visitorAfterMs: num("mock-visitor"),
  };
}
