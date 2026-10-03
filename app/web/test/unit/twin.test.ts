// The unguarded twin's "held for" counter against the real API's compare sequence (compare.go): the
// unguarded pod's probe reports `compromised` once and then nothing, because the probe publishes only
// changes, until the API deletes that pod compare_hold (12 s) after the guarded arm's response.

import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiClient } from "../../src/lib/api";
import { type StreamEvent, toStreamEvent } from "../../src/lib/contract";
import { buildTimeline } from "../../src/lib/timeline";
import { mountConsole } from "../../src/ui/console";
import { renderTwin } from "../../src/ui/twin";

const T0 = Date.parse("2026-10-02T12:00:00Z");
const RUN = "0a1b2c3d4e5f6a7b";
const G = "network-tool-0a1b2c3d4e";
const U = `${G}-u`;

function compareRun(opts: { held?: boolean } = {}): StreamEvent[] {
  let id = 0;
  const at = (ms: number) => new Date(T0 + ms).toISOString();
  const pods = { guarded: G, unguarded: U };
  const ev = (type: string, data: Record<string, unknown>) => toStreamEvent(type, data, ++id) as StreamEvent;
  const run = (state: string, ms: number, detail = "") => ev("run", { run_id: RUN, scenario: "network-tool", state, at: at(ms), detail, pods, ...(state === "queued" ? {} : { pod: G }) });
  const victim = (ms: number, pod: string, arm: string, status: string) => ev("victim", { run_id: RUN, pod, at: at(ms), status, title: "SDP Shop", banner: status === "up" ? "" : "Beaconing", probe_ms: 3, checksum: "5e0c1a77d3b2f190", arm });
  const out = [
    run("queued", 0),
    run("started", 80, "pod created"),
    run("pod_ready", 1900, "4f1c2a9e8b7d"),
    victim(2000, G, "guarded", "up"),
    victim(2010, U, "unguarded", "up"),
    victim(2200, G, "guarded", "compromised"),
    victim(2210, U, "unguarded", "compromised"),
    ev("falco", { at: at(2130), rule: "SDP network tool in sandbox", priority: "Warning", namespace: "sandbox-unguarded", pod: U, output: "x", arm: "unguarded" }),
    run("detected", 2250, "SDP network tool in sandbox"),
    run("responded", 2740, "quarantine"),
  ];
  if (!opts.held) {
    out.push(
      ev("pod", { run_id: RUN, pod: U, uid: "u", phase: "Deleted", reason: "", container_id: "4f1c2a9e8b7d", image: "i", labels_delta: {}, deleted: true, at: at(14_800), arm: "unguarded" }),
      run("finished", 16_500), // the guarded pod's own cleanup can take longer
    );
  }
  return out;
}

const held = (el: ParentNode) => el.querySelector(".twin__held")?.textContent;

afterEach(() => {
  vi.useRealTimers();
  document.body.replaceChildren();
});

describe("renderTwin's held counter (review 2, item 4)", () => {
  it("runs with the clock while the run is live, from the unguarded pod's compromise", () => {
    const run = buildTimeline(compareRun({ held: true }), T0 + 5000).runs[0];
    expect(held(renderTwin(run, T0 + 5210))).toBe("attacker has held this pod 3.0 s");
    expect(held(renderTwin(run, T0 + 9210))).toBe("attacker has held this pod 7.0 s");
  });

  it("stops when the API deletes the unguarded pod, however late the page looks", () => {
    const run = buildTimeline(compareRun(), T0 + 60_000).runs[0];
    expect(held(renderTwin(run, T0 + 60_000))).toBe("attacker has held this pod 13 s"); // 14 800 − 2 210
  });

  it("ticks in the console with no new event", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "setTimeout", "clearTimeout", "Date"] });
    vi.setSystemTime(T0 + 5210);
    const root = document.createElement("section");
    document.body.append(root);
    const api = new ApiClient({ fetch: async () => new Response("{}", { status: 404, headers: { "Content-Type": "application/json" } }) });
    const c = mountConsole(root, api);
    c.update(buildTimeline(compareRun({ held: true }), Date.now()));
    expect(held(root)).toBe("attacker has held this pod 3.0 s");
    await vi.advanceTimersByTimeAsync(4000);
    expect(held(root)).toBe("attacker has held this pod 7.0 s");
  });
});

describe("the twin's clock is stopped on every path (final review, item 7)", () => {
  it("when the run ends, and when the console has nothing to show", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
    vi.setSystemTime(T0 + 5210);
    // The console's one-second clocks (the page's other timers — animation frames — run faster).
    const clocks = new Set<unknown>();
    const set = globalThis.setInterval;
    const clear = globalThis.clearInterval;
    vi.spyOn(globalThis, "setInterval").mockImplementation(((fn: () => void, ms?: number) => {
      const id = set(fn, ms);
      if (ms === 1000) clocks.add(id);
      return id;
    }) as typeof setInterval);
    vi.spyOn(globalThis, "clearInterval").mockImplementation(((id?: ReturnType<typeof setInterval>) => {
      clocks.delete(id);
      clear(id);
    }) as typeof clearInterval);
    try {
      const root = document.createElement("section");
      document.body.append(root);
      const api = new ApiClient({ fetch: async () => new Response("{}", { status: 404, headers: { "Content-Type": "application/json" } }) });
      const c = mountConsole(root, api);
      const live = compareRun({ held: true });
      c.update(buildTimeline(live, Date.now()));
      expect(clocks.size).toBe(1);
      c.update(buildTimeline(compareRun(), Date.now()));
      expect(clocks.size).toBe(0);
      c.update(buildTimeline(live, Date.now()));
      expect(clocks.size).toBe(1);
      c.update({ runs: [], unmatched: [] }); // nothing to show
      expect(clocks.size).toBe(0);
    } finally {
      vi.restoreAllMocks();
    }
  });
});
