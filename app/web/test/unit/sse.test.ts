import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { StreamEvent } from "../../src/lib/contract";
import { type ConnectionState, type EventSourceLike, EventStream, backoffDelay } from "../../src/lib/sse";

/** A controllable EventSource: tests decide when it opens, errors, closes and what it delivers. */
class FakeSource implements EventSourceLike {
  static all: FakeSource[] = [];
  readyState = 0;
  onopen: ((ev: Event) => unknown) | null = null;
  onerror: ((ev: Event) => unknown) | null = null;
  closed = false;
  listeners = new Map<string, ((ev: MessageEvent) => void)[]>();

  constructor(public url: string) {
    FakeSource.all.push(this);
  }
  addEventListener(type: string, l: (ev: MessageEvent) => void) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), l]);
  }
  close() {
    this.closed = true;
    this.readyState = 2;
  }
  open() {
    this.readyState = 1;
    this.onopen?.(new Event("open"));
  }
  /** Transient drop: the browser keeps retrying by itself. */
  drop() {
    this.readyState = 0;
    this.onerror?.(new Event("error"));
  }
  /** Fatal: non-200 or wrong content type; the browser gives up. */
  fail() {
    this.readyState = 2;
    this.onerror?.(new Event("error"));
  }
  send(type: string, data: unknown) {
    const raw = typeof data === "string" ? data : JSON.stringify(data);
    for (const l of this.listeners.get(type) ?? []) l(new MessageEvent(type, { data: raw }));
  }
}

const last = () => FakeSource.all[FakeSource.all.length - 1];

const runEv = (state: string, at = "2026-10-01T12:00:00.000Z") => ({ run_id: "r1", scenario: "shell-in-container", state, at });

function makeStream(extra: Partial<ConstructorParameters<typeof EventStream>[0]> = {}) {
  const events: StreamEvent[] = [];
  const states: { state: ConnectionState; retryInMs?: number }[] = [];
  const stream = new EventStream({
    url: "/api/events",
    factory: (url) => new FakeSource(url),
    random: () => 0.5,
    onEvent: (e) => events.push(e),
    onState: (state, d) => states.push({ state, retryInMs: d.retryInMs }),
    ...extra,
  });
  return { stream, events, states };
}

beforeEach(() => {
  FakeSource.all = [];
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

describe("backoffDelay", () => {
  it("grows exponentially, is jittered and capped", () => {
    expect(backoffDelay(0, 1000, 30_000, () => 0)).toBe(500);
    expect(backoffDelay(0, 1000, 30_000, () => 1)).toBe(1000);
    expect(backoffDelay(3, 1000, 30_000, () => 1)).toBe(8000);
    expect(backoffDelay(10, 1000, 30_000, () => 1)).toBe(30_000);
    expect(backoffDelay(10, 1000, 30_000, () => 0)).toBe(500);
  });
});

describe("EventStream", () => {
  it("connects to the url and reports connecting -> open", () => {
    const { stream, states } = makeStream();
    stream.start();
    expect(last().url).toBe("/api/events");
    last().open();
    expect(states.map((s) => s.state)).toEqual(["connecting", "open"]);
  });

  it("delivers typed, validated events and ignores malformed ones", () => {
    const { stream, events } = makeStream();
    stream.start();
    last().open();
    last().send("run", runEv("queued"));
    last().send("run", "{not json");
    last().send("run", { run_id: "r1", state: "exploded" });
    last().send("falco", { at: "x", rule: "r", priority: "Notice", namespace: "sandbox", pod: "p", output: "o" });
    last().send("talon", { at: "x", action: "kubernetes:terminate", namespace: "sandbox", pod: "p", status: "success" });
    last().send("unknown", { a: 1 });
    expect(events.map((e) => e.type)).toEqual(["run", "falco", "talon"]);
  });

  it("drops events replayed after a reconnect", () => {
    const { stream, events } = makeStream();
    stream.start();
    last().open();
    last().send("run", runEv("queued"));
    last().send("run", runEv("started", "2026-10-01T12:00:01.000Z"));
    last().fail();
    vi.runOnlyPendingTimers();
    // The server replays its buffer on connect, then continues live.
    last().open();
    last().send("run", runEv("queued"));
    last().send("run", runEv("started", "2026-10-01T12:00:01.000Z"));
    last().send("run", runEv("detected", "2026-10-01T12:00:02.000Z"));
    expect(events.map((e) => (e.type === "run" ? e.data.state : e.type))).toEqual(["queued", "started", "detected"]);
  });

  it("replaces a CLOSED source with backoff, and reports offline after repeated failures", () => {
    const { stream, states } = makeStream({ baseDelayMs: 1000, offlineAfter: 3 });
    stream.start();
    last().fail();
    expect(FakeSource.all[0].closed).toBe(true);
    expect(states.at(-1)).toEqual({ state: "reconnecting", retryInMs: 750 });

    vi.advanceTimersByTime(749);
    expect(FakeSource.all).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(FakeSource.all).toHaveLength(2);

    last().fail(); // attempt 2: delay base*2 range
    expect(states.at(-1)).toEqual({ state: "reconnecting", retryInMs: 1250 });
    vi.advanceTimersByTime(1250);
    last().fail(); // attempt 3
    expect(states.at(-1)).toEqual({ state: "offline", retryInMs: 2250 });
    vi.advanceTimersByTime(2250);
    expect(FakeSource.all).toHaveLength(4);
    expect(states.at(-1)?.state).toBe("offline");
  });

  it("resets backoff only after a connection has stayed healthy", () => {
    const { stream, states } = makeStream({ baseDelayMs: 1000, healthyAfterMs: 5000 });
    stream.start();
    last().fail();
    vi.runOnlyPendingTimers();
    last().fail();
    vi.runOnlyPendingTimers();
    // Opens, then dies before proving healthy: the backoff keeps growing.
    last().open();
    vi.advanceTimersByTime(1000);
    last().fail();
    expect(states.at(-1)?.retryInMs).toBe(backoffDelay(2, 1000, 30_000, () => 0.5));
    vi.runOnlyPendingTimers();
    // Opens and stays up: the next failure starts from the base delay again.
    last().open();
    vi.advanceTimersByTime(5000);
    last().fail();
    expect(states.at(-1)?.retryInMs).toBe(750);
  });

  it("lets the browser handle a transient drop without opening a second connection", () => {
    const { stream, states } = makeStream();
    stream.start();
    last().open();
    last().drop();
    expect(states.at(-1)?.state).toBe("reconnecting");
    vi.advanceTimersByTime(60_000);
    expect(FakeSource.all).toHaveLength(1);
    last().open();
    expect(states.at(-1)?.state).toBe("open");
  });

  it("retryNow skips the pending backoff", () => {
    const { stream } = makeStream({ baseDelayMs: 10_000 });
    stream.start();
    last().fail();
    expect(FakeSource.all).toHaveLength(1);
    stream.retryNow();
    expect(FakeSource.all).toHaveLength(2);
    vi.advanceTimersByTime(60_000);
    expect(FakeSource.all).toHaveLength(2);
  });

  it("stop closes the source, cancels retries and ignores late events", () => {
    const { stream, events } = makeStream();
    stream.start();
    const s = last();
    s.open();
    stream.stop();
    expect(s.closed).toBe(true);
    s.send("run", runEv("queued"));
    expect(events).toHaveLength(0);
    vi.advanceTimersByTime(120_000);
    expect(FakeSource.all).toHaveLength(1);
    expect(stream.start()).toBe(true);
    expect(stream.start()).toBe(false);
    expect(FakeSource.all).toHaveLength(2);
  });

  it("retries when the factory itself throws", () => {
    let n = 0;
    const { stream } = makeStream({
      factory: (url) => {
        n += 1;
        if (n === 1) throw new Error("SecurityError");
        return new FakeSource(url);
      },
    });
    stream.start();
    expect(FakeSource.all).toHaveLength(0);
    vi.runOnlyPendingTimers();
    expect(FakeSource.all).toHaveLength(1);
  });

  it("bounds the dedup window", () => {
    const { stream, events } = makeStream({ dedupWindow: 2 });
    stream.start();
    last().open();
    const a = runEv("queued", "2026-10-01T12:00:00.000Z");
    last().send("run", a);
    last().send("run", runEv("started", "2026-10-01T12:00:01.000Z"));
    last().send("run", runEv("detected", "2026-10-01T12:00:02.000Z"));
    last().send("run", a); // evicted from the window, so delivered again
    expect(events).toHaveLength(4);
  });
});
