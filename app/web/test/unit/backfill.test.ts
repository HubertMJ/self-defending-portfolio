import { describe, expect, it } from "vitest";
import type { Result } from "../../src/lib/api";
import { Backfill } from "../../src/lib/backfill";
import { type StreamEvent, toStreamEvent } from "../../src/lib/contract";
import { buildTimeline } from "../../src/lib/timeline";

const T0 = Date.parse("2026-10-02T12:00:00Z");
const at = (ms: number) => new Date(T0 + ms).toISOString();
const ev = (type: string, data: Record<string, unknown>, id: number) => toStreamEvent(type, data, id) as StreamEvent;

/** What a page that joins mid-session gets from the replay: the run's later events, not its start. */
const joined = [
  ev("run", { run_id: "4f1c2a9e8b7d6c5a", scenario: "terminal", state: "responded", at: at(5000), detail: "quarantine", pod: "terminal-4f1c2a9e8b", command_seq: 2 }, 230),
  ev("command", { run_id: "4f1c2a9e8b7d6c5a", seq: 3, id: "whoami", state: "started", at: at(6000) }, 231),
];

describe("a run joined mid-session (review 2, item 6)", () => {
  it("is the live run, though the replay held none of its start", () => {
    const v = buildTimeline(joined, T0 + 7000);
    expect(v.runs[0].active).toBe(true);
    expect(v.activeRun?.runId).toBe("4f1c2a9e8b7d6c5a");
    expect(v.unmatched).toEqual([]); // its events are its own, so nothing is unmatched…
  });

  it("…and is backfilled anyway, because it lacks its start", async () => {
    const asked: string[] = [];
    const b = new Backfill(async (id) => (asked.push(id), { ok: true, value: { events: [], truncated: false } }), () => {});
    b.view(buildTimeline(joined, T0 + 7000));
    b.view(buildTimeline(joined, T0 + 7000));
    await Promise.resolve();
    expect(asked).toEqual(["4f1c2a9e8b7d6c5a"]);
  });

  it("after a failed backfill, waits before trying again instead of refetching on every render", async () => {
    let now = T0;
    const asked: number[] = [];
    const fail: Result<{ events: StreamEvent[]; truncated: boolean }> = { ok: false, error: "offline", message: "HTTP 503", status: 503, json: true };
    const b = new Backfill(async () => (asked.push(now), fail), () => {}, () => now);
    const view = buildTimeline(joined, T0 + 7000);
    for (let i = 0; i < 50; i++) {
      b.view(view);
      await Promise.resolve();
      now += 100; // fifty renders over five seconds
    }
    expect(asked).toHaveLength(1);
    now = T0 + 30_000;
    b.view(view);
    await Promise.resolve();
    expect(asked).toHaveLength(2);
    now = T0 + 80_000; // the next wait is 60 s, so not yet
    b.view(view);
    await Promise.resolve();
    expect(asked).toHaveLength(2);
  });

  it("backfills the active run when the stream opens again after a hidden-tab stop", async () => {
    const asked: string[] = [];
    const b = new Backfill(async (id) => (asked.push(id), { ok: true, value: { events: [], truncated: false } }), () => {});
    b.stream("open", "r1");
    expect(asked).toEqual([]); // a first open is not a gap
    b.stopped(); // hidden for 60 s: the page closed the stream itself
    b.stream("connecting", "r1"); // and starts it again, as a fresh connect
    b.stream("open", "r1");
    await Promise.resolve();
    expect(asked).toEqual(["r1"]);
    b.stream("reconnecting", "r1");
    b.stream("open", "r1");
    await Promise.resolve();
    expect(asked).toEqual(["r1", "r1"]);
  });
});

describe("backfill of events that name a run the feed never showed (final review, item 5)", () => {
  it("fetches that run", async () => {
    const asked: string[] = [];
    const b = new Backfill(async (id) => (asked.push(id), { ok: true, value: { events: [], truncated: false } }), () => {});
    const orphan = ev("victim", { run_id: "0123456789abcdef", pod: "p", at: at(0), status: "up", title: "", banner: "", probe_ms: 3, checksum: "" }, 9);
    b.view({ runs: [], unmatched: [orphan] });
    await Promise.resolve();
    expect(asked).toEqual(["0123456789abcdef"]);
  });
});

describe("a backfill the run store answers with a 404 (final review, item 7)", () => {
  it("is not asked again, however long the page stays", async () => {
    let now = T0;
    const asked: number[] = [];
    const gone: Result<{ events: StreamEvent[]; truncated: boolean }> = { ok: false, error: "offline", message: "HTTP 404", status: 404, json: true };
    const b = new Backfill(async () => (asked.push(now), gone), () => {}, () => now);
    const view = buildTimeline(joined, T0 + 7000);
    for (let i = 0; i < 20; i++) {
      b.view(view);
      await Promise.resolve();
      now += 60_000;
    }
    expect(asked).toHaveLength(1);
  });
});

describe("a backfill the store had to cut short (final review, item 7)", () => {
  it("reports it, so the terminal can say its history has gaps", async () => {
    const cut: string[] = [];
    const b = new Backfill(async () => ({ ok: true, value: { events: [], truncated: true } }), () => {}, Date.now, (id) => cut.push(id));
    b.view(buildTimeline(joined, T0 + 7000));
    await Promise.resolve();
    await Promise.resolve();
    expect(cut).toEqual(["4f1c2a9e8b7d6c5a"]);
  });
});
