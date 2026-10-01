import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClient } from "../../src/lib/api";
import { isFalcoEvent, isLimits, isPosture, isRunEvent, isScenario, isTalonEvent, parseRunEvents, parseScenarioDetails, parseStreamEvent } from "../../src/lib/contract";
import { MockBackend, mockOptionsFromUrl } from "../../src/lib/mock";
import { attackUrl } from "../../src/ui/common";
import { renderPostureData } from "../../src/ui/posture";
import { blockedReason, describeAttackResult, formatCountdown } from "../../src/ui/scenarios";
import { posture, SCENARIOS } from "../../src/lib/fixtures";

describe("fixtures match the contract", () => {
  it("scenarios and posture pass the same guards live data does", () => {
    expect(SCENARIOS.every(isScenario)).toBe(true);
    expect(SCENARIOS.map((s) => s.id)).toEqual(expect.arrayContaining(["shell-in-container", "network-tool", "sensitive-file-read", "drop-and-execute"]));
    expect(isPosture(posture())).toBe(true);
  });
});

describe("MockBackend", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  const settle = async (ms: number) => {
    await vi.advanceTimersByTimeAsync(ms);
  };

  it("runs a scenario end to end over the real client and emits contract-valid events", async () => {
    const mock = new MockBackend({ speed: 1, history: false });
    const api = new ApiClient({ fetch: mock.fetch });
    const src = mock.eventSource("/api/events");
    const seen: { type: string; data: unknown }[] = [];
    for (const t of ["run", "falco", "talon"]) src.addEventListener(t, (m) => seen.push({ type: t, data: JSON.parse(m.data) }));
    await settle(100);

    const p = api.attack("shell-in-container");
    await settle(200);
    const res = await p;
    expect(res.kind).toBe("accepted");

    // A second attack while the first is running is refused with 409.
    const busy = api.attack("network-tool");
    await settle(200);
    expect((await busy).kind).toBe("busy");

    await settle(4000);
    const states = seen.filter((e) => e.type === "run").map((e) => (e.data as { state: string }).state);
    expect(states).toEqual(["queued", "started", "pod_ready", "detected", "responded", "finished"]);
    for (const e of seen) {
      const ok = e.type === "run" ? isRunEvent(e.data) : e.type === "falco" ? isFalcoEvent(e.data) : isTalonEvent(e.data);
      expect(ok, JSON.stringify(e)).toBe(true);
    }
    expect((seen.find((e) => e.type === "falco")?.data as { output: string }).output.length).toBeLessThanOrEqual(300);
  });

  it("rate limits with Retry-After after the configured number of attacks", async () => {
    const mock = new MockBackend({ speed: 0.01, limit: 1, history: false });
    const api = new ApiClient({ fetch: mock.fetch });
    const first = api.attack("shell-in-container");
    await settle(100);
    expect((await first).kind).toBe("accepted");
    await settle(100);
    const second = api.attack("shell-in-container");
    await settle(100);
    const r = await second;
    expect(r.kind).toBe("rate-limited");
    if (r.kind === "rate-limited") expect(r.retryAfterSeconds).toBeGreaterThan(500);
  });

  it("answers unknown scenarios with a JSON 404", async () => {
    const api = new ApiClient({ fetch: new MockBackend({ speed: 0 }).fetch });
    const p = api.attack("nope");
    await settle(10);
    expect((await p).kind).toBe("unknown-scenario");
  });

  it("replays history to a new subscriber", async () => {
    const mock = new MockBackend({ speed: 0 });
    const src = mock.eventSource("/api/events");
    const types: string[] = [];
    for (const t of ["run", "falco", "talon"]) src.addEventListener(t, () => types.push(t));
    await settle(10);
    expect(types).toContain("falco");
    expect(types.filter((t) => t === "run")).toHaveLength(6);
  });
});

describe("mockOptionsFromUrl", () => {
  it("is off unless asked for", () => {
    expect(mockOptionsFromUrl("")).toBeNull();
    expect(mockOptionsFromUrl("?mock=0")).toBeNull();
    expect(mockOptionsFromUrl("?mock=1")).toMatchObject({ speed: undefined, limit: undefined });
    expect(mockOptionsFromUrl("?mock=1&mock-speed=0.2&mock-limit=1")).toMatchObject({ speed: 0.2, limit: 1 });
    expect(mockOptionsFromUrl("?mock=1&mock-speed=-1")).toMatchObject({ speed: undefined, limit: undefined });
  });

  it("reads the event-stream fault switches", () => {
    expect(mockOptionsFromUrl("?mock=1")).toMatchObject({ streamRefusals: undefined, streamStall: false });
    expect(mockOptionsFromUrl("?mock=1&mock-stream-refuse=3&mock-stream-retry-after=2&mock-stream-stall=1")).toMatchObject({
      streamRefusals: 3,
      streamRetryAfter: 2,
      streamStall: true,
    });
  });
});

describe("launcher helpers", () => {
  it("formats countdowns", () => {
    expect(formatCountdown(42)).toBe("42 s");
    expect(formatCountdown(272)).toBe("4:32");
    expect(formatCountdown(-3)).toBe("0 s");
  });

  it("knows why launching is blocked", () => {
    const now = 1_000_000;
    expect(blockedReason({}, now)).toBeNull();
    expect(blockedReason({ pending: "x" }, now)).toMatch(/Starting/);
    expect(blockedReason({ activeRun: { runId: "r", scenario: "x", since: now - 1000 } }, now)).toMatch(/in progress/);
    expect(blockedReason({ activeRun: { runId: "r", scenario: "x", since: now - 10 * 60_000 } }, now)).toBeNull();
    expect(blockedReason({ cooldownUntil: now + 5000 }, now)).toMatch(/Rate limited/);
    expect(blockedReason({ cooldownUntil: now - 1 }, now)).toBeNull();
  });

  it("explains each attack result", () => {
    expect(describeAttackResult({ kind: "rate-limited", retryAfterSeconds: 90 }, "X").text).toMatch(/1:30/);
    expect(describeAttackResult({ kind: "busy" }, "X").tone).toBe("warn");
    expect(describeAttackResult({ kind: "offline", message: "" }, "X").tone).toBe("error");
    expect(describeAttackResult({ kind: "accepted", run: { run_id: "r9", scenario: "s", state: "queued" } }, "Shell").text).toMatch(/Shell.*r9/);
  });

  it("links ATT&CK techniques and sub-techniques, and nothing else", () => {
    expect(attackUrl("T1059.004")).toBe("https://attack.mitre.org/techniques/T1059/004/");
    expect(attackUrl("T1046")).toBe("https://attack.mitre.org/techniques/T1046/");
    expect(attackUrl("javascript:alert(1)")).toBeNull();
  });
});

describe("rendering untrusted text", () => {
  it("renders Falco output and policy names as text, never markup", () => {
    const p = posture();
    p.kyverno.policies.push({ name: '<img src=x onerror="alert(1)">', pass: 1, fail: 1, warn: 0 });
    const el = renderPostureData(p);
    expect(el.querySelector("img")).toBeNull();
    expect(el.textContent).toContain('<img src=x onerror="alert(1)">');
  });

  it("parses stream payloads strictly", () => {
    expect(parseStreamEvent("falco", JSON.stringify({ at: "x", rule: 1 }))).toBeNull();
  });
});

describe("extension payloads", () => {
  it("accepts today's API events unchanged and drops malformed optional fields", () => {
    const old = parseStreamEvent("falco", JSON.stringify({ at: "t", rule: "r", priority: "Notice", namespace: "sandbox", pod: "p", output: "o" }));
    expect(old?.data).toEqual({ at: "t", rule: "r", priority: "Notice", namespace: "sandbox", pod: "p", output: "o" });
    const ev = parseStreamEvent("falco", JSON.stringify({ at: "t", rule: "r", priority: "Notice", namespace: "sandbox", pod: "p", output: "o".repeat(5000), fields: { "proc.name": "sh", "user.uid": 10001, "k8s.pod.ip": "10.0.0.1", "proc.cmdline": { x: 1 } }, api_received_at: 5 }));
    expect(ev?.type).toBe("falco");
    if (ev?.type !== "falco") throw new Error("unreachable");
    expect(ev.data.output.length).toBe(1024);
    expect(ev.data.fields).toEqual({ "proc.name": "sh", "user.uid": "10001" });
    expect(ev.data.api_received_at).toBeUndefined();
  });

  it("parses pod, victim and flow events and rejects unknown victim states", () => {
    expect(parseStreamEvent("pod", JSON.stringify({ run_id: "r", pod: "p", uid: "u", phase: "Running", reason: "", container_id: "0123456789abcdef", image: "i", labels_delta: { a: null, b: "1", c: 3 }, deleted: false, at: "t" }))?.data).toMatchObject({ container_id: "0123456789ab", labels_delta: { a: null, b: "1" } });
    expect(parseStreamEvent("victim", JSON.stringify({ run_id: "r", pod: "p", at: "t", status: "pwned" }))).toBeNull();
    const v = parseStreamEvent("victim", JSON.stringify({ run_id: "r", pod: "p", at: "t", status: "defaced", title: "t".repeat(200), banner: "<b>x</b>", probe_ms: 12, checksum: "ZZ" }));
    expect(v?.data).toMatchObject({ status: "defaced", banner: "<b>x</b>", checksum: "" });
    expect((v?.data as { title: string }).title.length).toBe(80);
    expect(parseStreamEvent("flow", JSON.stringify({ run_id: "r", pod: "p", at: "t", verdict: "DROPPED" }))?.type).toBe("flow");
    expect(parseStreamEvent("run", JSON.stringify({ run_id: "r", scenario: "s", state: "pod_ready", at: "t", pod: "p" }))?.data).toMatchObject({ pod: "p" });
  });

  it("parses scenario details leniently and refuses link-forging paths", () => {
    const d = parseScenarioDetails({
      exec_command: ["sh", "-c", "id", 5],
      pod_security: { runAsUser: 10001, runAsNonRoot: true, capabilities_drop: ["ALL"] },
      resources: { limits: { cpu: "100m" }, memory: "32Mi" },
      image: { ref: "ghcr.io/x@sha256:" + "a".repeat(64), digest: "sha256:" + "a".repeat(64) },
      falco_rule: { name: "r", file: "cluster/infra/falco/kustomization.yaml", line: 12 },
      talon_rule: { name: "t", file: "https://evil.example/x", line: 1 },
      policies: [{ kind: "ClusterPolicy", name: "p", file: "../../etc/passwd" }],
      commit: "abc1234",
      victim: true,
    });
    expect(d.exec_command).toEqual(["sh", "-c", "id"]);
    expect(d.resources).toEqual({ "limits.cpu": "100m", memory: "32Mi" });
    expect(d.falco_rule?.line).toBe(12);
    // A forged path loses its link, not the rule: shown by name only, like a stock Falco rule.
    expect(d.talon_rule).toEqual({ name: "t", file: "", line: 0 });
    expect(d.policies[0].file).toBe("");
    expect(parseScenarioDetails({ commit: "javascript:x" }).commit).toBe("");
  });

  it("checks limits and run event lists", () => {
    expect(isLimits({ per_visitor: { limit: 3, window_s: 600, remaining: 2, reset_in_s: 30 }, global: { limit: 30, window_s: 3600, remaining: 29 }, active_run: false, stream_slots_remaining: 40 })).toBe(true);
    expect(isLimits({ per_visitor: {} })).toBe(false);
    expect(parseRunEvents({ events: [{ type: "run", data: { run_id: "r", scenario: "s", state: "queued", at: "t" } }, { type: "nope", data: {} }] })).toHaveLength(1);
  });
});

describe("MockBackend extension endpoints and events", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("emits contract-valid pod, victim and flow events for a quarantine run", async () => {
    const mock = new MockBackend({ speed: 1, history: false });
    const api = new ApiClient({ fetch: mock.fetch });
    const src = mock.eventSource("/api/events");
    const seen: { type: string; raw: string }[] = [];
    for (const t of ["run", "falco", "talon", "pod", "victim", "flow"]) src.addEventListener(t, (m) => seen.push({ type: t, raw: m.data }));
    await vi.advanceTimersByTimeAsync(100);
    const p = api.attack("network-tool");
    await vi.advanceTimersByTimeAsync(200);
    expect((await p).kind).toBe("accepted");
    await vi.advanceTimersByTimeAsync(7000);
    for (const e of seen) expect(parseStreamEvent(e.type, e.raw), e.raw).not.toBeNull();
    const types = new Set(seen.map((e) => e.type));
    expect([...types].sort()).toEqual(["falco", "flow", "pod", "run", "talon", "victim"]);
    const victims = seen.filter((e) => e.type === "victim").map((e) => JSON.parse(e.raw).status);
    expect(victims).toEqual(["up", "compromised", "unreachable"]);
  });

  it("serves details (or a 404 when told to), limits and a run's events", async () => {
    const mock = new MockBackend({ speed: 0 });
    const api = new ApiClient({ fetch: mock.fetch });
    const d = api.scenarioDetails("shell-in-container");
    const l = api.limits();
    await vi.advanceTimersByTimeAsync(10);
    const details = await d;
    expect(details.ok && details.value.exec_command[0]).toBe("sh");
    const limits = await l;
    expect(limits.ok && limits.value.per_visitor.limit).toBe(3);
    const off = new ApiClient({ fetch: new MockBackend({ speed: 0, noDetails: true }).fetch }).scenarioDetails("shell-in-container");
    await vi.advanceTimersByTimeAsync(10);
    expect((await off).ok).toBe(false);
    const runs = mock.fetch("/api/runs/mock-history-1");
    await vi.advanceTimersByTimeAsync(10);
    const body = await (await runs).json();
    expect(parseRunEvents(body).length).toBeGreaterThan(10);
  });
});
