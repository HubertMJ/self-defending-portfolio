import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClient } from "../../src/lib/api";
import { isFalcoEvent, isPosture, isRunEvent, isScenario, isTalonEvent, parseStreamEvent } from "../../src/lib/contract";
import { MockBackend, mockOptionsFromUrl } from "../../src/lib/mock";
import { attackUrl } from "../../src/ui/common";
import { renderPostureData } from "../../src/ui/posture";
import { blockedReason, describeAttackResult, formatCountdown } from "../../src/ui/scenarios";
import { posture, SCENARIOS } from "../../src/lib/fixtures";

describe("fixtures match the contract", () => {
  it("scenarios and posture pass the same guards live data does", () => {
    expect(SCENARIOS.every(isScenario)).toBe(true);
    expect(SCENARIOS.map((s) => s.id)).toEqual(expect.arrayContaining(["shell-in-container", "network-tool", "sensitive-file-read"]));
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

    await settle(3000);
    const states = seen.filter((e) => e.type === "run").map((e) => (e.data as { state: string }).state);
    expect(states).toEqual(["queued", "started", "detected", "responded", "finished"]);
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
    expect(types.filter((t) => t === "run")).toHaveLength(5);
  });
});

describe("mockOptionsFromUrl", () => {
  it("is off unless asked for", () => {
    expect(mockOptionsFromUrl("")).toBeNull();
    expect(mockOptionsFromUrl("?mock=0")).toBeNull();
    expect(mockOptionsFromUrl("?mock=1")).toEqual({ speed: undefined, limit: undefined });
    expect(mockOptionsFromUrl("?mock=1&mock-speed=0.2&mock-limit=1")).toEqual({ speed: 0.2, limit: 1 });
    expect(mockOptionsFromUrl("?mock=1&mock-speed=-1")).toEqual({ speed: undefined, limit: undefined });
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
