// An in-page stand-in for the portfolio API, used by `?mock=1`, the dev server and the tests.
//
// It plugs in at the two seams the real client already has -- a fetch function and an EventSource
// factory -- so mock mode exercises the same client, parsing and rendering code as production. It
// also enforces the contract's rules (one run at a time -> 409, 3 attacks per 10 minutes -> 429 with
// Retry-After) so those paths can be seen and tested without a cluster.

import type { RunEvent, RunState, StreamEvent } from "./contract";
import type { FetchLike } from "./api";
import type { EventSourceLike } from "./sse";
import { SCENARIOS, falcoOutput, posture } from "./fixtures";

export interface MockOptions {
  /** Multiplies every delay in the simulated run; 0.1 makes a run take a fraction of a second. */
  speed?: number;
  /** Attacks allowed per window before 429 (contract: 3 per 10 minutes per IP). */
  limit?: number;
  windowMs?: number;
  /** Seed the replay buffer with one completed run, as a live server would have. */
  history?: boolean;
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

  constructor(opts: MockOptions = {}) {
    this.speed = opts.speed ?? 1;
    this.limit = opts.limit ?? 3;
    this.windowMs = opts.windowMs ?? 10 * 60_000;
    if (opts.history ?? true) this.seedHistory();
  }

  readonly fetch: FetchLike = async (input, init) => {
    const path = new URL(input, "http://mock.invalid").pathname;
    const method = (init?.method ?? "GET").toUpperCase();
    await new Promise((r) => setTimeout(r, 120 * this.speed));

    if (method === "GET" && path === "/api/healthz") return json(200, { status: "ok" });
    if (method === "GET" && path === "/api/scenarios") return json(200, SCENARIOS);
    if (method === "GET" && path === "/api/posture") return json(200, posture());

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

  private runEvent(runId: string, scenario: string, state: RunState, at: number, detail?: string): StreamEvent {
    const data: RunEvent = { run_id: runId, scenario, state, at: new Date(at).toISOString() };
    if (detail) data.detail = detail;
    return { type: "run", data };
  }

  /** The event sequence a real run produces, with offsets (ms) loosely modelled on the DoD test. */
  private script(runId: string, scenarioId: string, t0: number): [number, StreamEvent][] {
    const scenario = SCENARIOS.find((s) => s.id === scenarioId) ?? SCENARIOS[0];
    const pod = `scenario-${scenarioId}-${runId.slice(-4)}`;
    const quarantine = scenario.response === "quarantine";
    return [
      [0, this.runEvent(runId, scenarioId, "queued", t0)],
      [700, this.runEvent(runId, scenarioId, "started", t0 + 700, `pod ${pod} ready`)],
      [1540, {
        type: "falco",
        data: {
          at: new Date(t0 + 1540).toISOString(),
          rule: scenario.detection,
          priority: quarantine ? "Warning" : "Notice",
          namespace: "sandbox",
          pod,
          output: falcoOutput(scenario, pod).slice(0, 300),
        },
      }],
      [1610, this.runEvent(runId, scenarioId, "detected", t0 + 1610, scenario.detection)],
      [1930, {
        type: "talon",
        data: {
          at: new Date(t0 + 1930).toISOString(),
          action: quarantine ? "kubernetes:label" : "kubernetes:terminate",
          namespace: "sandbox",
          pod,
          status: "success",
        },
      }],
      [1990, this.runEvent(runId, scenarioId, "responded", t0 + 1990, quarantine ? "pod labelled quarantine=true" : "pod terminated")],
      [2800, this.runEvent(runId, scenarioId, "finished", t0 + 2800, "scenario pod deleted")],
    ];
  }

  private simulate(runId: string, scenarioId: string): void {
    const t0 = Date.now();
    for (const [offset, ev] of this.script(runId, scenarioId, t0)) {
      setTimeout(() => {
        // Timestamps are re-stamped at emission so the displayed latencies are what actually happened.
        const at = new Date().toISOString();
        const stamped = { ...ev, data: { ...ev.data, at } } as StreamEvent;
        this.publish(stamped);
        if (ev.type === "run" && ev.data.state === "finished") this.activeRun = null;
      }, offset * this.speed);
    }
  }

  private seedHistory(): void {
    const t0 = Date.now() - 7 * 60_000;
    const runId = `mock-history-1`;
    for (const [, ev] of this.script(runId, "shell-in-container", t0)) this.buffer.push(ev);
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
  return { speed: num("mock-speed"), limit: num("mock-limit") };
}
