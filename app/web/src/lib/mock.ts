// An in-page stand-in for the portfolio API, used by `?mock=1`, the dev server and the tests.
//
// It plugs in at the two seams the real client already has -- a fetch function and an EventSource
// factory -- so mock mode exercises the same client, parsing and rendering code as production. It
// also enforces the contract's rules (one run at a time -> 409, 3 attacks per 10 minutes -> 429 with
// Retry-After) so those paths can be seen and tested without a cluster.

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

interface TerminalState {
  runId: string;
  token: string;
  pod: string;
  flag: string;
  ready: boolean;
  over: boolean;
  running: boolean;
  count: number;
  seq: number;
  quarantined: boolean;
  idleTimer?: ReturnType<typeof setTimeout>;
  deadlineTimer?: ReturnType<typeof setTimeout>;
}

export class MockBackend {
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
        this.terminal = { runId, token: this.newToken(), pod: `scenario-terminal-${runId.replace(/[^a-z0-9]/g, "").slice(-5)}`, flag: this.newFlag(), ready: false, over: false, running: false, count: 0, seq: 0, quarantined: false };
        this.startTerminal();
        // The other visitor types a quiet command, which this page sees stream in read-only.
        setTimeout(() => {
          const t = this.terminal;
          if (t && !t.over) this.simulateCommand(t, "whoami", ++t.seq);
        }, 1400 * this.speed);
      }, opts.termVisitorAfterMs);
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
      return all.length
        ? json(200, { run_id: id, scenario: scenario && "scenario" in scenario ? scenario.scenario : "", events: all.map((e, i) => ({ id: i + 1, ...e })), truncated: false })
        : json(404, { error: "unknown run" });
    }

    const m = /^\/api\/attack\/([^/]+)$/.exec(path);
    if (method === "POST" && m) {
      const id = decodeURIComponent(m[1]);
      const scenario = SCENARIOS.find((s) => s.id === id);
      if (!scenario) return json(404, { error: "unknown scenario" });
      if (this.activeRun) return json(409, { error: "another run is active" });
      const rate = this.spendAttack();
      if (rate) return rate;
      const runId = this.nextRunId();
      this.activeRun = runId;
      if (scenario.interactive) {
        // The terminal: start the run, keep a token the caller must present for each command.
        const token = this.newToken();
        this.terminal = { runId, token, pod: `scenario-terminal-${runId.replace(/[^a-z0-9]/g, "").slice(-5)}`, flag: this.newFlag(), ready: false, over: false, running: false, count: 0, seq: 0, quarantined: false };
        this.startTerminal();
        return json(202, { run_id: runId, scenario: id, state: "queued", token });
      }
      const compare = new URL(input, "http://mock.invalid").searchParams.get("compare") === "1";
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
      return json(429, { error: "rate limited" }, { "Retry-After": String(retry) });
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
    for (const [, ev] of this.script("mock-history-1", "shell-in-container", t0, 1)) this.buffer.push(ev);
    while (this.buffer.length > REPLAY) this.buffer.shift();
  }

  // ---------- terminal (ADR 0033) ----------

  private newToken(): string {
    let s = "";
    for (let i = 0; i < 32; i++) s += Math.floor(Math.random() * 16).toString(16);
    return s;
  }

  private newFlag(): string {
    let s = "";
    for (let i = 0; i < 16; i++) s += Math.floor(Math.random() * 16).toString(16);
    return `SDP{${s}}`;
  }

  private startTerminal(): void {
    const t = this.terminal;
    if (!t) return;
    const image = SCENARIO_IMAGE;
    const uid = "7c1e-terminal-" + t.runId.replace(/[^a-z0-9]/g, "").slice(-6);
    const at = (ms: number) => new Date(Date.now() + ms * this.speed).toISOString();
    const emit = (ms: number, ev: StreamEvent) => setTimeout(() => this.publish(ev), ms * this.speed);
    emit(0, { type: "run", data: { run_id: t.runId, scenario: "terminal", state: "queued", at: at(0) } });
    emit(60, { type: "run", data: { run_id: t.runId, scenario: "terminal", state: "started", at: at(60), detail: "pod created", pod: t.pod } });
    emit(100, { type: "pod", data: { run_id: t.runId, pod: t.pod, uid, phase: "Pending", reason: "", container_id: "", image, labels_delta: { "sdp.hubertjablon.ski/quarantine": "false", "sdp.hubertjablon.ski/run-id": t.runId }, deleted: false, at: at(100) } });
    emit(900, { type: "pod", data: { run_id: t.runId, pod: t.pod, uid, phase: "Running", reason: "", container_id: "9b2e7c4d1a0f", image, labels_delta: {}, deleted: false, at: at(900) } });
    emit(950, { type: "run", data: { run_id: t.runId, scenario: "terminal", state: "pod_ready", at: at(950), detail: "9b2e7c4d1a0f", pod: t.pod } });
    // The run only accepts commands once it is ready (409 before that), as the real API does.
    setTimeout(() => {
      if (this.terminal === t && !t.over) t.ready = true;
    }, 950 * this.speed);
    emit(1000, { type: "victim", data: { run_id: t.runId, pod: t.pod, at: at(1000), status: "up", title: "SDP Shop", banner: "Open for business", probe_ms: 4, checksum: "5e0c1a77d3b2f190" } });
    this.armIdle();
    t.deadlineTimer = setTimeout(() => this.endTerminal("deadline"), 120_000 * this.speed);
  }

  private armIdle(): void {
    const t = this.terminal;
    if (!t) return;
    clearTimeout(t.idleTimer);
    t.idleTimer = setTimeout(() => this.endTerminal("idle"), 30_000 * this.speed);
  }

  private endTerminal(detail: "killed" | "left" | "idle" | "deadline"): void {
    const t = this.terminal;
    if (!t || t.over) return;
    t.over = true;
    clearTimeout(t.idleTimer);
    clearTimeout(t.deadlineTimer);
    this.publish({ type: "run", data: { run_id: t.runId, scenario: "terminal", state: "finished", at: new Date().toISOString(), detail, pod: t.pod } });
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
    if (this.bearer(init) !== t.token) return json(401, { error: "bad token" });
    this.endTerminal("left");
    return json(202, { state: "finishing" });
  }

  private runCommand(runId: string, init?: RequestInit): Response {
    const t = this.terminal;
    if (!t || t.runId !== runId) return json(404, { error: "unknown run" });
    if (this.bearer(init) !== t.token) return json(401, { error: "bad token" });
    let id = "";
    try {
      id = (JSON.parse(typeof init?.body === "string" ? init.body : "{}") as { id?: string }).id ?? "";
    } catch {
      return json(400, { error: "bad body" });
    }
    const cmd = TERMINAL_COMMANDS.find((c) => c.id === id);
    if (!cmd) return json(404, { error: "unknown command" });
    // The API answers 409 until the pod is ready, while one command runs, and once the run is over.
    if (t.over || !t.ready) return json(409, { error: "the run is not ready or is over" });
    if (t.running) return json(409, { error: "a command is already running" });
    if (t.count >= 30) return json(429, { error: "too many commands" }, { "Retry-After": "0" });
    t.count += 1;
    t.running = true;
    this.armIdle();
    const seq = ++t.seq;
    this.simulateCommand(t, cmd.id, seq);
    return json(202, { seq });
  }

  private simulateCommand(t: TerminalState, id: string, seq: number): void {
    const cmd = TERMINAL_COMMANDS.find((c) => c.id === id);
    const out = TERMINAL_OUTPUT[id];
    if (!cmd || !out) {
      t.running = false;
      return;
    }
    const base = Date.now();
    const at = (ms: number) => new Date(base + ms * this.speed).toISOString();
    const emit = (ms: number, ev: StreamEvent) => setTimeout(() => this.publish(ev), ms * this.speed);
    const cmdEv = (ms: number, data: Partial<CommandEvent> & { state: CommandEvent["state"] }) =>
      emit(ms, { type: "command", data: { run_id: t.runId, seq, id, at: at(ms), ...data } as CommandEvent });

    cmdEv(0, { state: "started" });
    let ms = 120;
    const lines = (text: string[] | undefined, stream: "stdout" | "stderr") => {
      for (const line of text ?? []) {
        const chunk = (line === "${FLAG}" ? t.flag : line) + "\n";
        cmdEv(ms, { state: "output", stream, chunk });
        ms += 40;
      }
    };

    if (cmd.outcome === "detected") {
      const quarantine = cmd.response === "quarantine";
      const fields = { ...falcoFields(SCENARIOS[0], t.pod), "proc.name": cmd.command[0], "proc.cmdline": cmd.input, "k8s.pod.name": t.pod };
      // Falco sees the syscall as the command runs; the alert reaches the API a moment later.
      emit(ms, { type: "falco", data: { at: at(ms), rule: cmd.detection ?? "", priority: quarantine ? "Warning" : "Critical", namespace: "sandbox", pod: t.pod, output: `${cmd.detection} | command=${cmd.input} k8s_pod_name=${t.pod}`.slice(0, 1024), fields, api_received_at: at(ms + 20), command_seq: seq } });
      this.publishAt(ms + 60, { type: "run", data: { run_id: t.runId, scenario: "terminal", state: "detected", at: at(ms + 60), detail: cmd.detection ?? "", pod: t.pod } });
      const talonMs = ms + 180;
      emit(talonMs, { type: "talon", data: { at: at(talonMs), action: quarantine ? "Quarantine Pod" : "Terminate Pod", actionner: quarantine ? "kubernetes:label" : "kubernetes:terminate", namespace: "sandbox", pod: t.pod, status: "success", output: quarantine ? `the pod '${t.pod}' has been labeled` : `the pod '${t.pod}' has been terminated`, api_received_at: at(talonMs + 15), command_seq: seq } });

      if (quarantine) {
        // The command finishes (connection refused), then the label lands and the probe goes dark.
        // The run continues — the shell still works in a quarantined pod.
        lines(out.stdout, "stdout");
        lines(out.stderr, "stderr");
        cmdEv(ms + 60, { state: "exited", exit_code: out.exit, achieved: cmd.objective ? out.exit === 0 : false });
        t.quarantined = true;
        emit(talonMs, { type: "pod", data: { run_id: t.runId, pod: t.pod, uid: "", phase: "Running", reason: "", container_id: "9b2e7c4d1a0f", image: SCENARIO_IMAGE, labels_delta: { "sdp.hubertjablon.ski/quarantine": "true" }, deleted: false, at: at(talonMs) } });
        this.publishAt(talonMs + 40, { type: "run", data: { run_id: t.runId, scenario: "terminal", state: "responded", at: at(talonMs + 40), detail: "quarantine", pod: t.pod } });
        emit(talonMs + 260, { type: "victim", data: { run_id: t.runId, pod: t.pod, at: at(talonMs + 260), status: "unreachable", title: "", banner: "", probe_ms: 300, checksum: "" } });
        setTimeout(() => { if (this.terminal === t) t.running = false; }, (ms + 120) * this.speed);
      } else {
        // A terminate command either exits before the delete lands (non-TTY: cat, busybox echo —
        // `exited` with its code, achieved if it has an objective) or is cut off by the delete (a TTY
        // shell: `killed`, no exit code). Then the pod goes away and the run ends as `killed`.
        if (cmd.tty) {
          cmdEv(talonMs + 40, { state: "killed" });
        } else {
          lines(out.stdout, "stdout");
          lines(out.stderr, "stderr");
          cmdEv(ms + 60, { state: "exited", exit_code: out.exit, achieved: cmd.objective ? out.exit === 0 : false });
        }
        emit(talonMs, { type: "pod", data: { run_id: t.runId, pod: t.pod, uid: "", phase: "Terminating", reason: "", container_id: "9b2e7c4d1a0f", image: SCENARIO_IMAGE, labels_delta: {}, deleted: false, at: at(talonMs) } });
        this.publishAt(talonMs + 30, { type: "run", data: { run_id: t.runId, scenario: "terminal", state: "responded", at: at(talonMs + 30), detail: "terminate", pod: t.pod } });
        emit(talonMs + 80, { type: "pod", data: { run_id: t.runId, pod: t.pod, uid: "", phase: "Deleted", reason: "", container_id: "9b2e7c4d1a0f", image: SCENARIO_IMAGE, labels_delta: {}, deleted: true, at: at(talonMs + 80) } });
        emit(talonMs + 120, { type: "victim", data: { run_id: t.runId, pod: t.pod, at: at(talonMs + 120), status: "gone", title: "", banner: "", probe_ms: 0, checksum: "" } });
        setTimeout(() => { if (this.terminal === t) t.running = false; }, (talonMs + 100) * this.speed);
        setTimeout(() => this.endTerminal("killed"), (talonMs + 160) * this.speed);
      }
      return;
    }

    // allowed or prevented: just output, then exit. The run stays open.
    lines(out.stdout, "stdout");
    lines(out.stderr, "stderr");
    if (id === "deface") emit(ms, { type: "victim", data: { run_id: t.runId, pod: t.pod, at: at(ms), status: "defaced", title: "H4CK3D - SDP Shop", banner: "Defaced from the terminal", probe_ms: 3, checksum: "d3fac3d0badc0de1" } });
    cmdEv(ms + 40, { state: "exited", exit_code: out.exit, achieved: cmd.objective ? out.exit === 0 : false });
    setTimeout(() => { if (this.terminal === t) t.running = false; }, (ms + 60) * this.speed);
  }

  private publishAt(ms: number, ev: StreamEvent): void {
    setTimeout(() => this.publish(ev), ms * this.speed);
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
    const suffix = runId.replace(/[^a-z0-9]/g, "").slice(-5).padStart(5, "x");
    const guarded = `scenario-${scenarioId}-${suffix}`;
    const unguarded = `scenario-${scenarioId}-u${suffix}`;
    const quarantine = scenario.response === "quarantine";
    const at = (ms: number) => new Date(t0 + ms * speed).toISOString();
    const [up, hit] = victimScript(scenarioId);
    const cid = "4f1c2a9e8b7d";
    const podEv = (ms: number, pod: string, arm: Arm, phase: string, extra: Partial<PodEvent> = {}): [number, StreamEvent] => [ms, { type: "pod", data: { run_id: runId, pod, uid: `7c1e-${arm}`, phase, reason: "", container_id: "", image: SCENARIO_IMAGE, labels_delta: {}, deleted: false, at: at(ms), arm, ...extra } }];
    const vic = (ms: number, pod: string, arm: Arm, v: { status: VictimStatus; title: string; banner: string; checksum: string }, probe = 3): [number, StreamEvent] => [ms, { type: "victim", data: { run_id: runId, pod, at: at(ms), probe_ms: probe, arm, ...v } }];
    const events: [number, StreamEvent][] = [
      [0, { type: "run", data: { run_id: runId, scenario: scenarioId, state: "queued", at: at(0) } }],
      [80, { type: "run", data: { run_id: runId, scenario: scenarioId, state: "started", at: at(80), detail: "pods created", pod: guarded, pods: { guarded, unguarded } } }],
      podEv(120, guarded, "guarded", "Pending", { labels_delta: { "sdp.hubertjablon.ski/quarantine": "false", "sdp.hubertjablon.ski/run-id": runId } }),
      podEv(140, unguarded, "unguarded", "Pending", { labels_delta: { "sdp.hubertjablon.ski/run-id": runId } }),
      podEv(1880, guarded, "guarded", "Running", { container_id: cid }),
      podEv(1900, unguarded, "unguarded", "Running", { container_id: cid }),
      [1920, { type: "run", data: { run_id: runId, scenario: scenarioId, state: "pod_ready", at: at(1920), detail: cid, pod: guarded } }],
      vic(2010, guarded, "guarded", { ...up }, 4),
      vic(2020, unguarded, "unguarded", { ...up }, 4),
      vic(2180, guarded, "guarded", { ...hit }),
      vic(2190, unguarded, "unguarded", { ...hit }),
      // Both pods trip Falco. Only the guarded namespace has a Talon rule.
      [2240, { type: "falco", data: { at: at(2131), rule: scenario.detection, priority: quarantine ? "Warning" : "Critical", namespace: "sandbox", pod: guarded, output: falcoOutput(scenario, guarded).slice(0, 1024), fields: falcoFields(scenario, guarded), api_received_at: at(2158), arm: "guarded" } }],
      [2260, { type: "falco", data: { at: at(2151), rule: scenario.detection, priority: quarantine ? "Warning" : "Critical", namespace: "sandbox-unguarded", pod: unguarded, output: falcoOutput(scenario, unguarded).slice(0, 1024), fields: falcoFields(scenario, unguarded), api_received_at: at(2178), arm: "unguarded" } }],
      [2250, { type: "run", data: { run_id: runId, scenario: scenarioId, state: "detected", at: at(2250), detail: scenario.detection, pod: guarded } }],
      [2790, { type: "talon", data: { at: at(2766), action: quarantine ? "Quarantine Pod" : "Terminate Pod", actionner: quarantine ? "kubernetes:label" : "kubernetes:terminate", namespace: "sandbox", pod: guarded, status: "success", output: quarantine ? `the pod '${guarded}' has been labeled` : `the pod '${guarded}' has been terminated`, api_received_at: at(2779), arm: "guarded" } }],
    ];
    if (quarantine) {
      events.push(
        podEv(2730, guarded, "guarded", "Running", { container_id: cid, labels_delta: { "sdp.hubertjablon.ski/quarantine": "true" } }),
        [2740, { type: "run", data: { run_id: runId, scenario: scenarioId, state: "responded", at: at(2740), detail: "quarantine", pod: guarded } }],
        vic(3180, guarded, "guarded", { status: "unreachable", title: "", banner: "", checksum: "" }, 300),
      );
    } else {
      events.push(
        podEv(2730, guarded, "guarded", "Terminating", { container_id: cid }),
        [2740, { type: "run", data: { run_id: runId, scenario: scenarioId, state: "responded", at: at(2740), detail: "terminate", pod: guarded } }],
        podEv(2800, guarded, "guarded", "Deleted", { container_id: cid, deleted: true }),
        vic(3180, guarded, "guarded", { status: "gone", title: "", banner: "", checksum: "" }, 0),
      );
    }
    // The unguarded pod keeps serving its compromised page: Falco saw it, nothing answered. The API
    // holds it compare_hold_seconds (12) past the guarded response, then deletes it (not a `gone` event).
    events.push(
      vic(6000, unguarded, "unguarded", { ...hit }),
      [9200, { type: "run", data: { run_id: runId, scenario: scenarioId, state: "finished", at: at(9200), pod: guarded } }],
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
