import { describe, expect, it } from "vitest";
import type { StreamEvent } from "../../src/lib/contract";
import { MIN_DWELL_MS, TIMER_END, TIMER_START, humanAction, runHops, scheduleHops, timerReading } from "../../src/lib/pipeline";
import { buildTimeline } from "../../src/lib/timeline";

const T0 = Date.parse("2026-10-01T12:00:00.000Z");
const at = (ms: number) => new Date(T0 + ms).toISOString();
const POD = "scenario-shell-in-container-x7k2p";

/** A terminate run as the extended API reports it. */
function terminateRun(): StreamEvent[] {
  return [
    { type: "run", data: { run_id: "r1", scenario: "shell-in-container", state: "queued", at: at(0) } },
    { type: "run", data: { run_id: "r1", scenario: "shell-in-container", state: "started", at: at(40), pod: POD } },
    { type: "pod", data: { run_id: "r1", pod: POD, uid: "u-1", phase: "Pending", reason: "", container_id: "", image: "ghcr.io/x/scenario@sha256:ab", labels_delta: {}, deleted: false, at: at(60) } },
    { type: "pod", data: { run_id: "r1", pod: POD, uid: "u-1", phase: "Running", reason: "", container_id: "4f1c2a9e8b7d", image: "ghcr.io/x/scenario@sha256:ab", labels_delta: {}, deleted: false, at: at(2100) } },
    { type: "run", data: { run_id: "r1", scenario: "shell-in-container", state: "pod_ready", at: at(2150), pod: POD, detail: "4f1c2a9e8b7d" } },
    { type: "falco", data: { at: at(2210), rule: "Terminal shell in container", priority: "Notice", namespace: "sandbox", pod: POD, output: "x", api_received_at: at(2232) } },
    { type: "talon", data: { at: at(2251), action: "Terminate Pod", actionner: "kubernetes:terminate", namespace: "sandbox", pod: POD, status: "success" } },
    { type: "pod", data: { run_id: "r1", pod: POD, uid: "u-1", phase: "Terminating", reason: "", container_id: "4f1c2a9e8b7d", image: "", labels_delta: {}, deleted: false, at: at(2262) } },
    { type: "pod", data: { run_id: "r1", pod: POD, uid: "u-1", phase: "Deleted", reason: "", container_id: "4f1c2a9e8b7d", image: "", labels_delta: {}, deleted: true, at: at(2290) } },
    { type: "run", data: { run_id: "r1", scenario: "shell-in-container", state: "finished", at: at(2400), pod: POD } },
  ];
}

describe("runHops", () => {
  it("on a compare run, hop 8 is the guarded pod's: the twin's unreachable or gone never lights it", () => {
    const pods = { guarded: "g", unguarded: "g-u" };
    const ev = (type: string, data: Record<string, unknown>) => ({ type, data }) as unknown as StreamEvent;
    const v = (ms: number, pod: string, arm: string, status: string) => ev("victim", { run_id: "c", pod, at: at(ms), status, title: "", banner: "", probe_ms: 3, checksum: "", arm });
    const base = [
      ev("run", { run_id: "c", scenario: "network-tool", state: "started", at: at(0), pod: "g", pods, detail: "" }),
      ev("talon", { at: at(900), action: "Quarantine Pod", actionner: "kubernetes:label", namespace: "sandbox", pod: "g", status: "success", arm: "guarded" }),
      ev("pod", { run_id: "c", pod: "g", uid: "u", phase: "Running", reason: "", container_id: "c", image: "", labels_delta: { "sdp.hubertjablon.ski/quarantine": "true" }, deleted: false, at: at(950), arm: "guarded" }),
      // The twin's probe fails first (its own pod being cleaned up, say)…
      v(1000, "g-u", "unguarded", "unreachable"),
    ];
    let hops = runHops(buildTimeline(base, T0 + 5000).runs[0]);
    expect(hops[7].at).toBeUndefined();
    // …and only the guarded pod's own cut lights the hop.
    hops = runHops(buildTimeline([...base, v(1400, "g", "guarded", "unreachable")], T0 + 5000).runs[0]);
    expect(hops[7].at).toBe(T0 + 1400);
    const term = [ev("run", { run_id: "d", scenario: "drop-and-execute", state: "started", at: at(0), pod: "g", pods, detail: "" }), v(500, "g-u", "unguarded", "gone")];
    expect(runHops(buildTimeline(term, T0 + 5000).runs[0])[7].at).toBeUndefined();
  });

  it("maps every hop of a terminate run to its real timestamp", () => {
    const run = buildTimeline(terminateRun(), T0 + 5000).runs[0];
    const hops = runHops(run);
    expect(hops.map((h) => h.key)).toEqual(["create", "running", "exec", "falco", "sidekick", "talon", "act", "effect"]);
    expect(hops.map((h) => (h.at === undefined ? undefined : h.at - T0))).toEqual([60, 2100, 2150, 2210, 2232, 2251, 2262, 2290]);
    expect(hops[5].what).toBe("Talon deleted the pod");
    expect(hops[7].who).toBe("kubelet");
  });

  it("uses the Cilium hop and the label for a quarantine run", () => {
    const events: StreamEvent[] = [
      { type: "run", data: { run_id: "q", scenario: "network-tool", state: "started", at: at(0), pod: "p" } },
      { type: "talon", data: { at: at(900), action: "Quarantine Pod", actionner: "kubernetes:label", namespace: "sandbox", pod: "p", status: "success" } },
      { type: "pod", data: { run_id: "q", pod: "p", uid: "u", phase: "Running", reason: "", container_id: "c", image: "", labels_delta: { "sdp.hubertjablon.ski/quarantine": "true" }, deleted: false, at: at(950) } },
      { type: "victim", data: { run_id: "q", pod: "p", at: at(1400), status: "unreachable", title: "", banner: "", probe_ms: 300, checksum: "" } },
    ];
    const run = buildTimeline(events, T0 + 2000).runs[0];
    expect(run.quarantinedAt).toBe(T0 + 950);
    const hops = runHops(run);
    expect(hops[6].what).toBe("quarantine label set");
    expect(hops[7].who).toBe("Cilium");
    expect(hops[7].at).toBe(T0 + 1400);
  });

  it("falls back to run states on an API without the extension", () => {
    const events: StreamEvent[] = [
      { type: "run", data: { run_id: "o", scenario: "s", state: "started", at: at(0) } },
      { type: "run", data: { run_id: "o", scenario: "s", state: "responded", at: at(800) } },
    ];
    const hops = runHops(buildTimeline(events, T0 + 1000).runs[0]);
    expect(hops[0].at).toBe(T0);
    expect(hops[2].at).toBe(T0);
    expect(hops[6].at).toBe(T0 + 800);
    expect(hops[4].at).toBeUndefined();
  });
});

describe("scheduleHops", () => {
  it("holds each hop for at least the minimum dwell and reports the slowdown", () => {
    // Everything known at once (a burst), real gaps of 20 ms.
    const hops = [0, 20, 40, 60].map((r) => ({ real: r, known: 1000 }));
    const s = scheduleHops(hops, { chainFrom: 0 });
    expect(s.lightAt).toEqual([1000, 1000 + MIN_DWELL_MS, 1000 + 2 * MIN_DWELL_MS, 1000 + 3 * MIN_DWELL_MS]);
    expect(s.realSpanMs).toBe(60);
    expect(s.shownSpanMs).toBe(3 * MIN_DWELL_MS);
    expect(s.slowdown).toBe(30);
  });

  it("never lights a hop before the page knew of it", () => {
    const s = scheduleHops([{ real: 0, known: 0 }, { real: 3000, known: 3100 }], { chainFrom: 0 });
    expect(s.lightAt).toEqual([0, 3100]);
    expect(s.slowdown).toBe(1);
  });

  it("clamps long real gaps in a replay", () => {
    const s = scheduleHops([{ real: 0, known: 0 }, { real: 20_000, known: 0 }], { chainFrom: 0, maxGapMs: 2500 });
    expect(s.lightAt).toEqual([0, 2500]);
  });

  it("skips hops without data without holding the next ones back", () => {
    const s = scheduleHops([{ real: 0, known: 0 }, {}, { real: 10, known: 0 }], { chainFrom: 0 });
    expect(s.lightAt).toEqual([0, undefined, MIN_DWELL_MS]);
  });

  it("lights everything as it arrives when instant (reduced motion, history)", () => {
    const s = scheduleHops([0, 20, 40].map((r) => ({ real: r, known: 5 })), { instant: true, chainFrom: 0 });
    expect(s.lightAt).toEqual([5, 5, 5]);
    expect(s.slowdown).toBe(1);
  });
});

describe("timerReading", () => {
  const hops = [{ real: 0, known: 0 }, { real: 0, known: 0 }, { real: 100, known: 0 }, { real: 150, known: 0 }, {}, {}, { real: 400, known: 0 }];
  const s = scheduleHops(hops, { chainFrom: 0 });

  it("is undefined before the start lights, then runs monotonically to the real total", () => {
    const start = TIMER_START;
    const end = TIMER_END;
    expect(timerReading(hops, s, start, end, (s.lightAt[start] as number) - 1)).toBeUndefined();
    let last = -1;
    for (let t = s.lightAt[start] as number; t <= (s.lightAt[end] as number) + 100; t += 25) {
      const v = timerReading(hops, s, start, end, t) as number;
      expect(v).toBeGreaterThanOrEqual(last);
      last = v;
    }
    // From the detected syscall (150) to the response in the API server (400).
    expect(last).toBe(250);
  });
});

describe("humanAction", () => {
  it("says what Talon did in words", () => {
    expect(humanAction("Terminate Pod", "kubernetes:terminate")).toBe("Talon deleted the pod");
    expect(humanAction("kubernetes:label")).toBe("Talon quarantined the pod");
    expect(humanAction("Something new")).toBe("Talon ran “Something new”");
  });
});

describe("Talon's hop is never after the action it caused", () => {
  it("shows the API server's record as an upper bound and keeps the timer equal to the badge span", () => {
    const ev = terminateRun().map((e) =>
      e.type === "talon" ? { ...e, data: { ...e.data, at: at(2300) } } : e,
    ) as StreamEvent[];
    const run = buildTimeline(ev, T0 + 5000).runs[0];
    const hops = runHops(run);
    const rel = hops.map((h) => (h.at === undefined ? undefined : h.at - T0));
    expect(rel[5]).toBe(2262);
    expect(hops[5].bound).toBe(true);
    for (let i = 3; i < 8; i++) expect(rel[i] as number).toBeGreaterThanOrEqual(rel[i - 1] as number);
    const t = hops.map((h) => ({ real: h.at, known: 0 }));
    const s = scheduleHops(t);
    expect(s.realSpanMs).toBe(2262 - 2210);
    expect(timerReading(t, s, TIMER_START, TIMER_END, 1e9)).toBe(s.realSpanMs);
  });

  it("takes the container start from pod_ready when the watch event comes later", () => {
    const ev = terminateRun().map((e) => (e.type === "pod" && e.data.phase === "Running" ? { ...e, data: { ...e.data, at: at(2160) } } : e)) as StreamEvent[];
    const hops = runHops(buildTimeline(ev, T0 + 5000).runs[0]);
    expect((hops[1].at as number) - T0).toBe(2150);
  });
});
