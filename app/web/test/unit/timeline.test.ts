import { describe, expect, it } from "vitest";
import type { FalcoEvent, RunState, StreamEvent, TalonEvent } from "../../src/lib/contract";
import { buildTimeline, formatDuration } from "../../src/lib/timeline";

const T0 = Date.parse("2026-10-01T12:00:00.000Z");
const at = (ms: number) => new Date(T0 + ms).toISOString();

const run = (run_id: string, state: RunState, ms: number, detail?: string): StreamEvent => ({
  type: "run",
  data: { run_id, scenario: "shell-in-container", state, at: at(ms), ...(detail ? { detail } : {}) },
});
const falco = (pod: string, ms: number): StreamEvent => ({
  type: "falco",
  data: { at: at(ms), rule: "Terminal shell in container", priority: "Notice", namespace: "sandbox", pod, output: "..." } satisfies FalcoEvent,
});
const talon = (pod: string, ms: number): StreamEvent => ({
  type: "talon",
  data: { at: at(ms), action: "kubernetes:terminate", namespace: "sandbox", pod, status: "success" } satisfies TalonEvent,
});

const full = (id: string, offset: number, pod: string): StreamEvent[] => [
  run(id, "queued", offset),
  run(id, "started", offset + 500),
  falco(pod, offset + 1300),
  run(id, "detected", offset + 1400),
  talon(pod, offset + 1700),
  run(id, "responded", offset + 1750),
  run(id, "finished", offset + 3000),
];

describe("buildTimeline", () => {
  it("assembles a run with its Falco and Talon events and latencies", () => {
    const v = buildTimeline(full("r1", 0, "p1"), T0 + 4000);
    expect(v.runs).toHaveLength(1);
    const r = v.runs[0];
    expect(r.current).toBe("finished");
    expect(r.active).toBe(false);
    expect(r.pod).toBe("p1");
    expect(r.falco).toHaveLength(1);
    expect(r.talon).toHaveLength(1);
    // detection = earliest of Falco alert (1300) and run "detected" (1400), from started (500)
    expect(r.timings).toEqual({ detectMs: 800, respondMs: 400, totalMs: 2500 });
    expect(v.activeRun).toBeUndefined();
    expect(v.unmatched).toHaveLength(0);
  });

  it("is independent of arrival order", () => {
    const events = full("r1", 0, "p1");
    const shuffled = [events[4], events[2], events[6], events[0], events[3], events[1], events[5]];
    expect(buildTimeline(shuffled, T0 + 4000)).toEqual(buildTimeline(events, T0 + 4000));
  });

  it("orders runs newest first and attributes events to the right run", () => {
    const events = [...full("r1", 0, "p1"), ...full("r2", 60_000, "p2")];
    const v = buildTimeline(events, T0 + 70_000);
    expect(v.runs.map((r) => r.runId)).toEqual(["r2", "r1"]);
    expect(v.runs[0].pod).toBe("p2");
    expect(v.runs[1].pod).toBe("p1");
  });

  it("reports the in-progress run as active", () => {
    const v = buildTimeline([run("r1", "queued", 0), run("r1", "started", 500), falco("p1", 900)], T0 + 1000);
    expect(v.activeRun?.runId).toBe("r1");
    expect(v.activeRun?.timings.detectMs).toBe(400);
    expect(v.activeRun?.timings.respondMs).toBeUndefined();
  });

  it("does not let a lost terminal event keep a run active forever", () => {
    // No details for the scenario: the contract's 300 s ceiling plus the 60 s margin.
    const v = buildTimeline([run("r1", "queued", 0), run("r1", "started", 500)], T0 + 361_000);
    expect(v.runs[0].active).toBe(false);
    expect(v.activeRun).toBeUndefined();
    expect(buildTimeline([run("r1", "queued", 0)], T0 + 359_000).activeRun?.runId).toBe("r1");
  });

  describe("how long a run without an end event counts as running (ADR 0033, 2026-10-03 limits)", () => {
    const term = (state: RunState, ms: number): StreamEvent => ({ type: "run", data: { run_id: "t1", scenario: "terminal", state, at: at(ms), pod: "terminal-t1" } });
    const open = [term("queued", 0), term("pod_ready", 2000)];

    it("a terminal session four minutes in is still the live run (its timeout is 300 s)", () => {
      const v = buildTimeline(open, T0 + 240_000, new Map([["terminal", 300]]));
      expect(v.activeRun?.runId).toBe("t1");
      expect(v.runs[0].staleAfterMs).toBe(360_000);
      expect(buildTimeline(open, T0 + 359_000, new Map([["terminal", 300]])).activeRun?.runId).toBe("t1");
      expect(buildTimeline(open, T0 + 361_000, new Map([["terminal", 300]])).activeRun).toBeUndefined();
    });

    it("a terminal run never gets less than 300 s + 60 s, whatever its details say or without them", () => {
      expect(buildTimeline(open, T0 + 300_000, new Map([["terminal", 120]])).activeRun?.runId).toBe("t1");
      expect(buildTimeline(open, T0 + 300_000).activeRun?.runId).toBe("t1");
    });

    it("a one-click run follows its own scenario's timeout plus the margin", () => {
      const events = [run("r1", "queued", 0), run("r1", "started", 500)];
      const timeouts = new Map([["shell-in-container", 90]]);
      expect(buildTimeline(events, T0 + 149_000, timeouts).activeRun?.runId).toBe("r1");
      expect(buildTimeline(events, T0 + 151_000, timeouts).activeRun).toBeUndefined();
    });
  });

  it("keeps the furthest state and its detail, even if an earlier one arrives late", () => {
    const v = buildTimeline([run("r1", "failed", 5000, "pod never became ready"), run("r1", "queued", 0)], T0 + 6000);
    expect(v.runs[0].current).toBe("failed");
    expect(v.runs[0].detail).toBe("pod never became ready");
  });

  it("keeps sandbox events outside any run as unmatched", () => {
    const v = buildTimeline([falco("someone-elses-pod", -60_000), ...full("r1", 0, "p1")], T0 + 4000);
    expect(v.unmatched).toHaveLength(1);
    expect(v.runs[0].falco).toHaveLength(1);
  });

  it("accepts a late Talon event within the grace window after the run finished", () => {
    const v = buildTimeline([...full("r1", 0, "p1").filter((e) => e.type !== "talon"), talon("p1", 5000)], T0 + 6000);
    expect(v.runs[0].talon).toHaveLength(1);
  });

  it("caps the number of runs", () => {
    const events = Array.from({ length: 30 }, (_, i) => full(`r${i}`, i * 60_000, `p${i}`)).flat();
    const v = buildTimeline(events, T0 + 31 * 60_000);
    expect(v.runs).toHaveLength(20);
    expect(v.runs[0].runId).toBe("r29");
  });
});

describe("formatDuration", () => {
  it.each([
    [undefined, "–"],
    [0, "0 ms"],
    [840, "840 ms"],
    [2400, "2.4 s"],
    [12_400, "12 s"],
    [72_000, "1 min 12 s"],
  ])("%s -> %s", (ms, out) => {
    expect(formatDuration(ms)).toBe(out);
  });
});

describe("buildTimeline with the extension events", () => {
  it("takes the pod name from the run event and attributes pod, victim and flow events by run id", () => {
    const events: StreamEvent[] = [
      { type: "run", data: { run_id: "r1", scenario: "s", state: "started", at: at(0), pod: "pod-a" } },
      { type: "pod", data: { run_id: "r1", pod: "pod-a", uid: "uid-1", phase: "Running", reason: "", container_id: "abc123abc123", image: "img@sha256:1", labels_delta: {}, deleted: false, at: at(100) } },
      { type: "victim", data: { run_id: "r1", pod: "pod-a", at: at(200), status: "up", title: "Shop", banner: "", probe_ms: 3, checksum: "aa" } },
      { type: "victim", data: { run_id: "r1", pod: "pod-a", at: at(700), status: "up", title: "Shop", banner: "", probe_ms: 4, checksum: "aa" } },
      { type: "victim", data: { run_id: "r1", pod: "pod-a", at: at(1200), status: "defaced", title: "x", banner: "y", probe_ms: 5, checksum: "bb" } },
      { type: "flow", data: { run_id: "r1", pod: "pod-a", at: at(1300), direction: "ingress", l4: "TCP/8080", verdict: "DROPPED", drop_reason: "Policy denied" } },
    ];
    const r = buildTimeline(events, T0 + 2000).runs[0];
    expect(r.pod).toBe("pod-a");
    expect(r.podUid).toBe("uid-1");
    expect(r.containerId).toBe("abc123abc123");
    expect(r.victim.map((v) => [v.status, v.count])).toEqual([["up", 2], ["defaced", 1]]);
    expect(r.victim[0].until).toBe(T0 + 700);
    expect(r.flows).toHaveLength(1);
    expect(r.events).toHaveLength(6);
  });

  it("orders pod_ready between started and detected", () => {
    const v = buildTimeline([run("r1", "pod_ready", 600), run("r1", "started", 500)], T0 + 1000);
    expect(v.runs[0].current).toBe("pod_ready");
  });
});

describe("detection latency with pod_ready", () => {
  it("is measured from the attack command, not from the pod's creation", () => {
    const v = buildTimeline([run("r1", "started", 0), run("r1", "pod_ready", 1800), falco("p1", 1900)], T0 + 2000);
    expect(v.runs[0].timings.detectMs).toBe(100);
  });
});
