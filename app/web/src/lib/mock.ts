// An in-page stand-in for the portfolio API, used by `?mock=1`, the dev server and the tests.
//
// It plugs in at the two seams the real client already has -- a fetch function and an EventSource
// factory -- so mock mode exercises the same client, parsing and rendering code as production. It
// also enforces the contract's rules (one run at a time -> 409, 3 attacks per 10 minutes -> 429 with
// Retry-After) so those paths can be seen and tested without a cluster.
//
// The event sequences are the real API's (app/api/internal/runner: runner.go, terminal.go,
// compare.go): every event gets the hub's next id, a run event always carries `detail` ("" when
// none), a terminal run's `detected`/`responded` carry the command_seq they are about, a command the
// API cut short `exited` with no code, a victim event is published only when what the probe sees
// changes, and a compare run's unguarded pod is deleted compare_hold (12 s) after the guarded arm's
// response, after which the run finishes. Every call the page makes is kept in `calls`, so a test can
// check what was (and was not) sent.

import type { Arm, CommandEvent, PodEvent, RunEvent, RunState, StreamEvent, VictimStatus } from "./contract";
import type { FetchLike } from "./api";
import type { EventSourceLike } from "./sse";
import {
  SCENARIOS,
  SCENARIO_IMAGE,
  TERMINAL_COMMANDS,
  TERMINAL_OUTPUT,
  falcoFields,
  falcoOutput,
  posture,
  scenarioDetails,
  stats,
  terminalDetails,
  victimScript,
} from "./fixtures";

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
  /** Start a terminal run "from another visitor" this long after load, to watch it read-only. */
  termVisitorAfterMs?: number;
}

const REPLAY = 100;

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
    const msg = new MessageEvent(ev.type, { data: JSON.stringify(ev.data), lastEventId: String(ev.id ?? "") });
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

interface TerminalState {
  runId: string;
  token: string;
  pod: string;
  uid: string;
  flag: string;
  ready: boolean;
  over: boolean;
  /** The seq of the command running now (0: none), and what ends it early if the run ends first. */
  running: number;
  cutShort?: () => void;
  count: number;
  seq: number;
  quarantined: boolean;
  idleTimer?: ReturnType<typeof setTimeout>;
  deadlineTimer?: ReturnType<typeof setTimeout>;
}

/** The id of the finished run the mock's replay buffer starts with. */
export const MOCK_HISTORY_RUN = "a7c3e9f1b2d40658";

export class MockBackend {
  /** Every request the page made, as "METHOD /path?query", oldest first. */
  readonly calls: string[] = [];
  private eventId = 0;
  private readonly speed: number;
  private readonly limit: number;
  private readonly windowMs: number;
  private readonly buffer: StreamEvent[] = [];
  private readonly sources = new Set<MockEventSource>();
  private readonly attempts: number[] = [];
  private activeRun: string | null = null;
  private terminal: TerminalState | null = null;
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
    if (opts.termVisitorAfterMs !== undefined) {
      setTimeout(() => {
        if (this.activeRun) return;
        const runId = this.nextRunId();
        this.activeRun = runId;
        this.terminal = this.newTerminal(runId, this.newToken());
        this.startTerminal();
        // The other visitor types a quiet command, which this page sees stream in read-only.
        setTimeout(() => {
          const t = this.terminal;
          if (t && !t.over && !t.running) {
            t.running = ++t.seq;
            this.simulateCommand(t, "whoami", t.seq);
          }
        }, 1400 * this.speed);
      }, opts.termVisitorAfterMs);
    }
  }

  readonly fetch: FetchLike = async (input, init) => {
    const url = new URL(input, "http://mock.invalid");
    const path = url.pathname;
    const method = (init?.method ?? "GET").toUpperCase();
    this.calls.push(`${method} ${path}${url.search}`);
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
    if (method === "GET" && path === "/api/stats") return json(200, stats());

    const details = /^\/api\/scenarios\/([^/]+)\/details$/.exec(path);
    if (method === "GET" && details) {
      const id = decodeURIComponent(details[1]);
      const d = this.noDetails ? null : id === "terminal" ? terminalDetails() : scenarioDetails(id);
      return d ? json(200, d) : json(404, { error: "not found" });
    }

    const commands = /^\/api\/runs\/([^/]+)\/commands$/.exec(path);
    if (method === "POST" && commands) return this.runCommand(decodeURIComponent(commands[1]), init);
    const leave = /^\/api\/runs\/([^/]+)$/.exec(path);
    if (method === "DELETE" && leave) return this.leaveTerminal(decodeURIComponent(leave[1]), init);
    const runs = /^\/api\/runs\/([^/]+)$/.exec(path);
    if (method === "GET" && runs) {
      const id = decodeURIComponent(runs[1]);
      const events = this.buffer.filter((e) => "run_id" in e.data && e.data.run_id === id);
      const podOf = (e: StreamEvent): string | undefined => ("pod" in e.data ? e.data.pod : undefined);
      const pods = new Set(events.map(podOf).filter((p): p is string => !!p));
      const all = this.buffer.filter((e) => {
        if (events.includes(e)) return true;
        const p = podOf(e);
        return !("run_id" in e.data) && !!p && pods.has(p);
      });
      const scenario = events.find((e) => e.type === "run")?.data;
      // The run store keeps each event with the hub's own id, exactly as the stream sent it.
      return all.length
        ? json(200, { run_id: id, scenario: scenario && "scenario" in scenario ? scenario.scenario : "", events: all.map((e) => ({ id: e.id, type: e.type, data: e.data })), truncated: false })
        : json(404, { error: "unknown run (only the last 50 runs are kept)" });
    }

    const m = /^\/api\/attack\/([^/]+)$/.exec(path);
    if (method === "POST" && m) {
      const id = decodeURIComponent(m[1]);
      const scenario = SCENARIOS.find((s) => s.id === id);
      if (!scenario) return json(404, { error: "unknown scenario" });
      if (this.activeRun) return json(409, { error: "another attack is running; watch it on the live feed" });
      const rate = this.spendAttack();
      if (rate) return rate;
      const runId = this.nextRunId();
      this.activeRun = runId;
      if (scenario.interactive) {
        // The terminal: start the run, keep a token the caller must present for each command.
        const token = this.newToken();
        this.terminal = this.newTerminal(runId, token);
        this.startTerminal();
        return json(202, { run_id: runId, scenario: id, state: "queued", token });
      }
      const compare = url.searchParams.get("compare") === "1";
      if (compare) this.simulateCompare(runId, scenario.id);
      else this.simulate(runId, scenario.id);
      return json(202, { run_id: runId, scenario: id, state: "queued" });
    }
    return json(404, { error: "not found" });
  };

  /** The shared rate-limit check for starting any run; returns a 429 Response or null. */
  private spendAttack(): Response | null {
    const now = Date.now();
    while (this.attempts.length && now - this.attempts[0] > this.windowMs) this.attempts.shift();
    if (this.attempts.length >= this.limit) {
      const retry = Math.ceil((this.attempts[0] + this.windowMs - now) / 1000);
      return json(429, { error: "attack rate limit reached" }, { "Retry-After": String(retry) });
    }
    this.attempts.push(now);
    return null;
  }

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

  /** 16 hex, as the API's newRunID; the pod is named from its first 10 (podName). */
  private nextRunId(): string {
    this.seq += 1;
    return `${Date.now().toString(16)}${this.seq.toString(16).padStart(4, "0")}`.slice(-16).padStart(16, "0");
  }

  /** The hub: every published event gets the next id, which the stream and the run store both carry. */
  private publish(ev: StreamEvent): void {
    ev = { ...ev, id: ++this.eventId };
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
    const pod = `${scenarioId}-${runId.slice(0, 10)}`;
    const uid = `7c1e${runId.slice(0, 4)}-3b2a-4f0e-9d61-${runId.slice(4, 16)}`;
    const quarantine = scenario.response === "quarantine";
    const at = (ms: number) => new Date(t0 + ms * speed).toISOString();
    const run = (state: RunState, ms: number, detail = ""): StreamEvent => {
      const data: RunEvent = { run_id: runId, scenario: scenarioId, state, at: at(ms), detail };
      if (state !== "queued") data.pod = pod;
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
    const end = quarantine ? 6400 : 3400;
    const events: [number, StreamEvent][] = [
      [0, run("queued", 0)],
      [80, run("started", 80, "pod created")],
      // The first observation carries every label; later ones only what changed.
      [120, podEv(120, "Pending", { labels_delta: { "sdp.hubertjablon.ski/quarantine": "false", "sdp.hubertjablon.ski/run-id": runId } })],
      [620, podEv(620, "ContainerCreating", { reason: "ContainerCreating" })],
      [1880, podEv(1880, "Running", { container_id: cid })],
      [1920, run("pod_ready", 1920, cid)],
      [2010, victim(2010, { ...up }, 4)],
      // The exec is sent at 1925; Falco sees the syscall almost at once, the victim app changes a
      // moment later (a defacement lands just after the alert).
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
      [2790, {
        type: "talon",
        data: {
          // Talon stamps its event when it logs the result, after the API server has acted.
          at: at(2766),
          action: quarantine ? "Quarantine Pod" : "Terminate Pod",
          actionner: quarantine ? "kubernetes:label" : "kubernetes:terminate",
          namespace: "sandbox",
          pod,
          status: "success",
          output: quarantine ? `the pod '${pod}' in the namespace 'sandbox' has been labeled` : `the pod '${pod}' in the namespace 'sandbox' has been terminated`,
          api_received_at: at(2779),
        },
      }],
    ];
    if (quarantine) {
      // No flow events: the cut shows as the API's probe going unreachable after the label (FIX 1).
      events.push(
        [2730, podEv(2714, "Running", { container_id: cid, labels_delta: { "sdp.hubertjablon.ski/quarantine": "true" } })],
        [2740, run("responded", 2740, "quarantine")],
        [3180, victim(3180, { status: "unreachable", title: "", banner: "", checksum: "" }, 300)],
        [6300, podEv(6300, "Terminating", { container_id: cid })],
        [6380, podEv(6380, "Deleted", { container_id: cid, deleted: true })],
      );
    } else {
      events.push(
        [2730, podEv(2707, "Terminating", { container_id: cid })],
        [2740, run("responded", 2740, "terminate")],
        [2800, podEv(2758, "Deleted", { container_id: cid, deleted: true })],
        [3180, victim(3180, { status: "gone", title: "", banner: "", checksum: "" }, 0)],
      );
    }
    events.push([end, run("finished", end)]);
    // shell-in-container defaces the shop in a pre_exec and only then opens the shell Falco
    // detects: everything from the detection on happens ~1.5 s later, after the defacement.
    if (scenarioId === "shell-in-container") {
      const d = 1500;
      const later = (iso: string) => new Date(Date.parse(iso) + d * speed).toISOString();
      return events.map(([offset, ev]) => {
        if (offset < 2240) return [offset, ev];
        const data = { ...ev.data, at: later(ev.data.at) } as typeof ev.data & { api_received_at?: string };
        if (data.api_received_at) data.api_received_at = later(data.api_received_at);
        return [offset + d, { ...ev, data } as StreamEvent];
      });
    }
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
    for (const [, ev] of this.script(MOCK_HISTORY_RUN, "shell-in-container", t0, 1)) this.buffer.push({ ...ev, id: ++this.eventId });
    while (this.buffer.length > REPLAY) this.buffer.shift();
  }

  // ---------- terminal (ADR 0033) ----------

  private newToken(): string {
    let s = "";
    for (let i = 0; i < 32; i++) s += Math.floor(Math.random() * 16).toString(16);
    return s;
  }

  private newTerminal(runId: string, token: string): TerminalState {
    let flag = "";
    for (let i = 0; i < 16; i++) flag += Math.floor(Math.random() * 16).toString(16);
    const pod = `terminal-${runId.slice(0, 10)}`;
    const uid = `9d3f${runId.slice(0, 4)}-51c0-4b7e-8a2d-${runId.slice(4, 16)}`;
    return { runId, token, pod, uid, flag: `SDP{${flag}}`, ready: false, over: false, running: 0, count: 0, seq: 0, quarantined: false };
  }

  /** A run event of the terminal run, with the pod once it exists, as runner.publish/publishCmd send it. */
  private termRun(t: TerminalState, state: RunState, detail = "", seq?: number): StreamEvent {
    const data: RunEvent = { run_id: t.runId, scenario: "terminal", state, at: new Date().toISOString(), detail };
    if (state !== "queued") data.pod = t.pod;
    if (seq) data.command_seq = seq;
    return { type: "run", data };
  }

  private termPod(t: TerminalState, phase: string, extra: Partial<PodEvent> = {}): StreamEvent {
    return { type: "pod", data: { run_id: t.runId, pod: t.pod, uid: t.uid, phase, reason: "", container_id: "9b2e7c4d1a0f", image: SCENARIO_IMAGE, labels_delta: {}, deleted: false, at: new Date().toISOString(), ...extra } };
  }

  private termVictim(t: TerminalState, status: VictimStatus, probe = 3, shop?: { title: string; banner: string; checksum: string }): StreamEvent {
    return { type: "victim", data: { run_id: t.runId, pod: t.pod, at: new Date().toISOString(), status, title: "", banner: "", checksum: "", probe_ms: probe, ...shop } };
  }

  /** Publishes `make()` after ms (scaled), unless the terminal run it belongs to is over by then. */
  private later(t: TerminalState, ms: number, make: () => StreamEvent | null, evenIfOver = false): ReturnType<typeof setTimeout> {
    return setTimeout(() => {
      if (this.terminal !== t || (t.over && !evenIfOver)) return;
      const ev = make();
      if (ev) this.publish(ev);
    }, ms * this.speed);
  }

  private startTerminal(): void {
    const t = this.terminal;
    if (!t) return;
    this.publish(this.termRun(t, "queued"));
    this.later(t, 60, () => this.termRun(t, "started", "pod created"));
    this.later(t, 100, () => this.termPod(t, "Pending", { container_id: "", labels_delta: { "sdp.hubertjablon.ski/quarantine": "false", "sdp.hubertjablon.ski/run-id": t.runId, "sdp.hubertjablon.ski/scenario": "terminal" } }));
    this.later(t, 900, () => this.termPod(t, "Running"));
    // The run accepts commands from the moment pod_ready is on the wire (409 before), as the API does.
    this.later(t, 950, () => {
      t.ready = true;
      return this.termRun(t, "pod_ready", "9b2e7c4d1a0f");
    });
    this.later(t, 980, () => this.termVictim(t, "up", 4, { title: "SDP Shop", banner: "Open for business", checksum: "5e0c1a77d3b2f190" }));
    this.armIdle();
    t.deadlineTimer = setTimeout(() => this.endTerminal("deadline"), 120_000 * this.speed);
  }

  private armIdle(): void {
    const t = this.terminal;
    if (!t) return;
    clearTimeout(t.idleTimer);
    t.idleTimer = setTimeout(() => this.endTerminal("idle"), 30_000 * this.speed);
  }

  /**
   * The run's end (runTerminal returning): a command still running is cut short first (`exited`, no
   * code), then — unless Talon already deleted the pod — the API's own cleanup deletes it (no `gone`:
   * that is someone else's delete), then `finished` with the reason.
   */
  private endTerminal(detail: "killed" | "left" | "idle" | "deadline"): void {
    const t = this.terminal;
    if (!t || t.over) return;
    t.over = true;
    clearTimeout(t.idleTimer);
    clearTimeout(t.deadlineTimer);
    t.cutShort?.();
    if (detail !== "killed") {
      this.publish(this.termPod(t, "Terminating"));
      this.publish(this.termPod(t, "Deleted", { deleted: true }));
    }
    this.publish(this.termRun(t, "finished", detail));
    if (this.activeRun === t.runId) this.activeRun = null;
  }

  private bearer(init?: RequestInit): string | null {
    const h = init?.headers;
    const v = h instanceof Headers ? h.get("Authorization") : h ? (h as Record<string, string>)["Authorization"] : null;
    const m = /^Bearer\s+(.+)$/.exec(v ?? "");
    return m ? m[1] : null;
  }

  private leaveTerminal(runId: string, init?: RequestInit): Response {
    const t = this.terminal;
    if (!t || t.runId !== runId) return json(404, { error: "unknown run" });
    if (this.bearer(init) !== t.token) return json(401, { error: "wrong or missing token" });
    // A run that is over answers 409 ("already over"), as Runner.Leave does.
    if (t.over) return json(409, { error: "the run is not ready, is over, or a command is already running" });
    this.endTerminal("left");
    return json(202, { state: "finishing" });
  }

  private runCommand(runId: string, init?: RequestInit): Response {
    const t = this.terminal;
    if (!t || t.runId !== runId) return json(404, { error: "unknown run" });
    if (this.bearer(init) !== t.token) return json(401, { error: "wrong or missing token" });
    let id = "";
    try {
      id = (JSON.parse(typeof init?.body === "string" ? init.body : "{}") as { id?: string }).id ?? "";
    } catch {
      return json(400, { error: 'body must be {"id":"<command id>"}' });
    }
    const cmd = TERMINAL_COMMANDS.find((c) => c.id === id);
    if (!cmd) return json(404, { error: "unknown command" });
    // The API answers 409 until the pod is ready, while one command runs, and once the run is over.
    if (t.over || !t.ready || t.running) return json(409, { error: "the run is not ready, is over, or a command is already running" });
    if (t.count >= 30) return json(429, { error: "too many commands in this run" }, { "Retry-After": "1" });
    t.count += 1;
    t.running = ++t.seq;
    this.armIdle();
    this.simulateCommand(t, cmd.id, t.seq);
    return json(202, { seq: t.seq });
  }

  /**
   * One command as runCommand and the webhooks publish it: `started`, the output one line per event,
   * then `exited` with the code (`achieved` only when true: omitempty). A detected command trips Falco
   * (`falco` with command_seq, then the run's `detected` for that seq), then Talon (`talon`, then
   * `responded` with the command's response): a quarantine labels the pod and the probe goes
   * unreachable while the shell goes on; a terminate deletes the pod — a non-TTY command has exited
   * by then, a TTY shell is `killed` — and the run finishes `killed`.
   */
  private simulateCommand(t: TerminalState, id: string, seq: number): void {
    const cmd = TERMINAL_COMMANDS.find((c) => c.id === id);
    const out = TERMINAL_OUTPUT[id];
    if (!cmd || !out) {
      t.running = 0;
      return;
    }
    const timers: ReturnType<typeof setTimeout>[] = [];
    const at = (ms: number, make: () => StreamEvent | null, evenIfOver = false) => timers.push(this.later(t, ms, make, evenIfOver));
    const cmdEv = (state: CommandEvent["state"], extra: Partial<CommandEvent> = {}): StreamEvent => ({ type: "command", data: { run_id: t.runId, seq, id, state, at: new Date().toISOString(), ...extra } });
    const done = () => {
      if (t.running === seq) t.running = 0;
      t.cutShort = undefined;
    };
    // Leave, idle or the deadline while this command runs: its exec is cancelled, `exited` with no code.
    t.cutShort = () => {
      timers.forEach(clearTimeout);
      if (t.running === seq) this.publish(cmdEv("exited"));
      done();
    };

    this.publish(cmdEv("started"));
    let ms = 30;
    for (const [stream, text] of [["stdout", out.stdout], ["stderr", out.stderr]] as const) {
      for (const line of text ?? []) {
        const chunk = (line === "${FLAG}" ? t.flag : line) + "\n";
        at(ms, () => cmdEv("output", { stream, chunk }));
        ms += 15;
      }
    }
    const exited = () => {
      done();
      return cmdEv("exited", { exit_code: out.exit, ...(cmd.objective && out.exit === 0 ? { achieved: true } : {}) });
    };
    if (!cmd.tty) at(ms + 20, exited);

    // The deface rewrites state.json to {"status":"defaced"}: the probe sees no title, no banner, no
    // checksum. A quarantined pod's probe sees nothing at all.
    if (id === "deface" && !t.quarantined) at(ms + 400, () => this.termVictim(t, "defaced", 3));

    if (cmd.outcome !== "detected") return;
    const quarantine = cmd.response === "quarantine";
    const falcoMs = ms + 60;
    const talonMs = falcoMs + 160;
    const fields = { ...falcoFields(SCENARIOS[0], t.pod), "proc.name": cmd.command[0], "proc.cmdline": cmd.command.join(" "), "k8s.pod.name": t.pod };
    at(falcoMs, () => ({ type: "falco", data: { at: new Date(Date.now() - 25 * this.speed).toISOString(), rule: cmd.detection ?? "", priority: quarantine ? "Warning" : "Critical", namespace: "sandbox", pod: t.pod, output: `${cmd.detection} | command=${cmd.command.join(" ")} k8s_pod_name=${t.pod}`.slice(0, 1024), fields, api_received_at: new Date().toISOString(), command_seq: seq } }));
    at(falcoMs + 5, () => this.termRun(t, "detected", cmd.detection ?? "", seq));
    at(talonMs, () => ({ type: "talon", data: { at: new Date(Date.now() - 10 * this.speed).toISOString(), action: quarantine ? "Quarantine Pod" : "Terminate Pod", actionner: quarantine ? "kubernetes:label" : "kubernetes:terminate", namespace: "sandbox", pod: t.pod, status: "success", output: quarantine ? `the pod '${t.pod}' in the namespace 'sandbox' has been labeled` : `the pod '${t.pod}' in the namespace 'sandbox' has been terminated`, api_received_at: new Date().toISOString(), command_seq: seq } }));
    at(talonMs + 10, () => this.termRun(t, "responded", cmd.response ?? "", seq));
    if (quarantine) {
      at(talonMs - 5, () => {
        t.quarantined = true;
        return this.termPod(t, "Running", { labels_delta: { "sdp.hubertjablon.ski/quarantine": "true" } });
      });
      // The next probe after the label gets nothing back (probe interval + its 300 ms timeout).
      at(talonMs + 800, () => this.termVictim(t, "unreachable", 300));
      return;
    }
    // Terminate: the pod goes away under the run. A TTY shell never exits on its own: it is killed.
    at(talonMs + 20, () => this.termPod(t, "Terminating"));
    if (cmd.tty) at(talonMs + 40, () => (done(), cmdEv("killed")));
    at(talonMs + 60, () => this.termVictim(t, "gone", 0));
    at(talonMs + 120, () => this.termPod(t, "Deleted", { deleted: true }));
    at(talonMs + 140, () => {
      this.endTerminal("killed");
      return null;
    });
  }

  // ---------- compare / unguarded twin (ADR 0033) ----------

  private simulateCompare(runId: string, scenarioId: string): void {
    const t0 = Date.now();
    for (const [offset, ev] of this.compareScript(runId, scenarioId, t0, this.speed)) {
      setTimeout(() => {
        this.publish(ev);
        if (ev.type === "run" && ev.data.state === "finished") this.activeRun = null;
      }, offset * this.speed);
    }
  }

  private compareScript(runId: string, scenarioId: string, t0: number, speed: number): [number, StreamEvent][] {
    const scenario = SCENARIOS.find((s) => s.id === scenarioId) ?? SCENARIOS[0];
    const guarded = `${scenarioId}-${runId.slice(0, 10)}`;
    const unguarded = `${guarded}-u`;
    const pods = { guarded, unguarded };
    const quarantine = scenario.response === "quarantine";
    const at = (ms: number) => new Date(t0 + ms * speed).toISOString();
    const [up, hit] = victimScript(scenarioId);
    const cid = "4f1c2a9e8b7d";
    // Every run event of a compare run names both pods; `pod` (the guarded one) only once it exists.
    const run = (ms: number, state: RunState, detail = ""): [number, StreamEvent] => [ms, { type: "run", data: { run_id: runId, scenario: scenarioId, state, at: at(ms), detail, pods, ...(state === "queued" ? {} : { pod: guarded }) } }];
    const podEv = (ms: number, pod: string, arm: Arm, phase: string, extra: Partial<PodEvent> = {}): [number, StreamEvent] => [ms, { type: "pod", data: { run_id: runId, pod, uid: `7c1e-${arm}-${runId.slice(0, 8)}`, phase, reason: "", container_id: cid, image: SCENARIO_IMAGE, labels_delta: {}, deleted: false, at: at(ms), arm, ...extra } }];
    const vic = (ms: number, pod: string, arm: Arm, v: { status: VictimStatus; title: string; banner: string; checksum: string }, probe = 3): [number, StreamEvent] => [ms, { type: "victim", data: { run_id: runId, pod, at: at(ms), probe_ms: probe, arm, ...v } }];
    const none = { title: "", banner: "", checksum: "" };
    // The guarded arm's response, which starts the unguarded pod's compare_hold (12 s).
    const responded = 2740;
    const events: [number, StreamEvent][] = [
      run(0, "queued"),
      run(80, "started", "pod created"),
      podEv(120, guarded, "guarded", "Pending", { container_id: "", labels_delta: { "sdp.hubertjablon.ski/quarantine": "false", "sdp.hubertjablon.ski/run-id": runId } }),
      podEv(140, unguarded, "unguarded", "Pending", { container_id: "", labels_delta: { "sdp.hubertjablon.ski/quarantine": "false", "sdp.hubertjablon.ski/run-id": runId } }),
      podEv(1880, guarded, "guarded", "Running"),
      podEv(1900, unguarded, "unguarded", "Running"),
      run(1920, "pod_ready", cid),
      vic(2010, guarded, "guarded", { ...up }, 4),
      vic(2020, unguarded, "unguarded", { ...up }, 4),
      vic(2180, guarded, "guarded", { ...hit }),
      vic(2190, unguarded, "unguarded", { ...hit }),
      // Both pods trip Falco. Only the guarded namespace has a Talon rule.
      [2240, { type: "falco", data: { at: at(2131), rule: scenario.detection, priority: quarantine ? "Warning" : "Critical", namespace: "sandbox", pod: guarded, output: falcoOutput(scenario, guarded).slice(0, 1024), fields: falcoFields(scenario, guarded), api_received_at: at(2158), arm: "guarded" } }],
      [2260, { type: "falco", data: { at: at(2151), rule: scenario.detection, priority: quarantine ? "Warning" : "Critical", namespace: "sandbox-unguarded", pod: unguarded, output: falcoOutput(scenario, unguarded).slice(0, 1024), fields: falcoFields(scenario, unguarded), api_received_at: at(2178), arm: "unguarded" } }],
      run(2250, "detected", scenario.detection),
      [2790, { type: "talon", data: { at: at(2766), action: quarantine ? "Quarantine Pod" : "Terminate Pod", actionner: quarantine ? "kubernetes:label" : "kubernetes:terminate", namespace: "sandbox", pod: guarded, status: "success", output: quarantine ? `the pod '${guarded}' in the namespace 'sandbox' has been labeled` : `the pod '${guarded}' in the namespace 'sandbox' has been terminated`, api_received_at: at(2779), arm: "guarded" } }],
    ];
    if (quarantine) {
      // The label, the response, the cut; then the quarantine linger (the unreachable + 3 s) and the
      // API's own cleanup of the guarded pod (not a `gone`: that is someone else's delete).
      events.push(
        podEv(2730, guarded, "guarded", "Running", { labels_delta: { "sdp.hubertjablon.ski/quarantine": "true" } }),
        run(responded, "responded", "quarantine"),
        vic(3180, guarded, "guarded", { status: "unreachable", ...none }, 300),
        podEv(6200, guarded, "guarded", "Terminating"),
        podEv(6240, guarded, "guarded", "Deleted", { deleted: true }),
      );
    } else {
      events.push(
        podEv(2730, guarded, "guarded", "Terminating"),
        run(responded, "responded", "terminate"),
        vic(2760, guarded, "guarded", { status: "gone", ...none }, 0),
        podEv(2800, guarded, "guarded", "Deleted", { deleted: true }),
      );
    }
    // The unguarded pod keeps serving its compromised page — the probe reports nothing new, so no
    // event — until compare_hold after the guarded response, when the API deletes it. Only once both
    // pods are gone does the run finish.
    const hold = responded + 12_000;
    events.push(
      podEv(hold + 20, unguarded, "unguarded", "Terminating"),
      podEv(hold + 60, unguarded, "unguarded", "Deleted", { deleted: true }),
      run(hold + 80, "finished"),
    );
    if (scenarioId === "shell-in-container") {
      const d = 1500;
      const later = (iso: string) => new Date(Date.parse(iso) + d * speed).toISOString();
      return events.map(([offset, ev]) => {
        if (offset < 2240) return [offset, ev];
        const data = { ...ev.data, at: later(ev.data.at) } as typeof ev.data & { api_received_at?: string };
        if (data.api_received_at) data.api_received_at = later(data.api_received_at);
        return [offset + d, { ...ev, data } as StreamEvent];
      });
    }
    return events;
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
    termVisitorAfterMs: num("mock-term-visitor"),
  };
}
