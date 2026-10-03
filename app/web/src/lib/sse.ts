// A reconnecting wrapper around EventSource for GET /api/events.
//
// EventSource retries on its own after a dropped connection, but gives up for good (readyState
// CLOSED) when a (re)connect gets a non-200 or a non-event-stream response -- exactly what happens
// while the API is being redeployed, or before phase 5 exists at all. This wrapper owns the retry
// loop instead: exponential backoff with full jitter, reset after a connection has proven healthy,
// paused while the tab is hidden so a forgotten tab does not keep a connection open for nothing.
//
// One scheduler owns every retry: a new retry always cancels the pending one, its delay is drawn once
// per attempt, and the state callback carries that delay exactly once, so a countdown shown from it
// counts down instead of jumping between freshly jittered values. EventSource cannot read why a
// connection was refused, so after a refusal an optional probe asks the server (a 429 from the
// stream cap carries Retry-After) and the retry waits at least that long. After maxAttempts refused
// connections in a row the stream stops retrying on its own and says so; retryNow() starts over.
//
// The server replays the last 50 events on every connect, so a reconnect re-delivers events the page
// has already shown. They are dropped here by identity (the event's id, with its type and payload, or
// type and payload alone from a server that sends no ids), which keeps the consumers free of dedup
// logic. Two identical lines of output are two events with two ids, and both are kept.

import { STREAM_EVENT_TYPES, type StreamEvent, type Tick, parseStreamEvent, parseTick } from "./contract";

export type ConnectionState = "connecting" | "open" | "reconnecting" | "offline";

export interface EventSourceLike {
  readonly readyState: number;
  onopen: ((ev: Event) => unknown) | null;
  onerror: ((ev: Event) => unknown) | null;
  addEventListener(type: string, listener: (ev: MessageEvent) => void): void;
  close(): void;
}

export type EventSourceFactory = (url: string) => EventSourceLike;

export interface Clock {
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
  now(): number;
}

export interface StateDetail {
  attempt: number;
  /** Set once per scheduled retry: the delay until the next connection attempt. */
  retryInMs?: number;
  /** Automatic retries stopped after maxAttempts refusals; only retryNow() reconnects. */
  gaveUp?: boolean;
}

/** Asks the server why the stream was refused: the Retry-After of a 429/503 in ms, else undefined. */
export type RetryProbe = (url: string) => Promise<number | undefined>;

export interface StreamOptions {
  url: string;
  onEvent: (ev: StreamEvent) => void;
  onState?: (state: ConnectionState, detail: StateDetail) => void;
  factory?: EventSourceFactory;
  clock?: Clock;
  random?: () => number;
  /** First retry delay; doubles per failed attempt up to maxDelayMs. */
  baseDelayMs?: number;
  maxDelayMs?: number;
  /** After this many consecutive failures the state reads "offline" (retries continue). */
  offlineAfter?: number;
  /** How long a connection must stay open before the backoff resets. */
  healthyAfterMs?: number;
  /** Size of the dedup window; comfortably above the server's 50-event replay. */
  dedupWindow?: number;
  /** Refused connections in a row after which automatic retries stop. */
  maxAttempts?: number;
  /** Optional; see RetryProbe. Without it the retry waits the backoff alone. */
  probe?: RetryProbe;
  /**
   * The opt-in `event: tick` frames of `?tick=1` (ADR 0035): the server's clock, after the replay and
   * then every 15 s. A clock reading, not an event: it bypasses the dedup and never reaches onEvent.
   */
  onTick?: (tick: Tick) => void;
}

// Every named event the contract defines; an older API simply never sends the newer ones.
const EVENT_TYPES = STREAM_EVENT_TYPES;
const CLOSED = 2;
/** Upper bound for a server-requested wait, so a broken Retry-After cannot park the feed for an hour. */
const MAX_RETRY_AFTER_MS = 5 * 60_000;

const defaultClock: Clock = {
  setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms),
  clearTimeout: (h) => globalThis.clearTimeout(h as ReturnType<typeof setTimeout>),
  // Monotonic where available: a countdown must not jump when the wall clock is adjusted.
  now: () => (typeof performance !== "undefined" ? performance.now() : Date.now()),
};

function definedOnly<T extends object>(o: T): T {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as T;
}

/** Full-jitter exponential backoff: uniform in [base/2, min(max, base * 2^attempt)]. */
export function backoffDelay(attempt: number, base: number, max: number, random: () => number): number {
  const ceiling = Math.min(max, base * 2 ** Math.max(0, attempt));
  const floor = Math.min(ceiling, base / 2);
  return Math.round(floor + random() * (ceiling - floor));
}

export class EventStream {
  private readonly opts: Required<Omit<StreamOptions, "onState" | "probe" | "onTick">> & Pick<StreamOptions, "onState" | "probe" | "onTick">;
  private source: EventSourceLike | null = null;
  private retryTimer: unknown = null;
  private healthyTimer: unknown = null;
  private failures = 0;
  /** Refused connections in a row (a CLOSED source); reset only by a healthy connection. */
  private refusals = 0;
  /** Bumped whenever a pending retry is cancelled, so a probe that answers late is ignored. */
  private epoch = 0;
  private stopped = true;
  private readonly seen: string[] = [];
  private readonly seenSet = new Set<string>();
  state: ConnectionState = "connecting";

  constructor(opts: StreamOptions) {
    this.opts = {
      factory: (url) => new EventSource(url),
      clock: defaultClock,
      random: Math.random,
      baseDelayMs: 1000,
      maxDelayMs: 30_000,
      offlineAfter: 3,
      healthyAfterMs: 5000,
      dedupWindow: 200,
      maxAttempts: 8,
      // Only the options that are actually set: a caller passing `factory: undefined` (main.ts
      // outside mock mode) must get the default, not a spread that overwrites it with undefined -
      // which made every connect throw before an EventSource was ever created.
      ...definedOnly(opts),
    };
  }

  /** Starts the stream; returns false if it was already running. */
  start(): boolean {
    if (!this.stopped) return false;
    this.stopped = false;
    this.connect();
    return true;
  }

  stop(): void {
    this.stopped = true;
    this.teardown();
    this.clearRetry();
  }

  /** Reconnect now, skipping any pending backoff (e.g. a "retry" button or the tab becoming visible). */
  retryNow(): void {
    if (this.stopped) return;
    this.clearRetry();
    this.refusals = 0;
    this.teardown();
    this.connect();
  }

  private setState(state: ConnectionState, retryInMs?: number, gaveUp?: boolean): void {
    this.state = state;
    this.opts.onState?.(state, { attempt: this.failures, retryInMs, gaveUp });
  }

  private connect(): void {
    this.setState(this.failures === 0 ? "connecting" : this.failures >= this.opts.offlineAfter ? "offline" : "reconnecting");
    let source: EventSourceLike;
    try {
      source = this.opts.factory(this.opts.url);
    } catch {
      this.scheduleRetry();
      return;
    }
    this.source = source;

    source.onopen = () => {
      if (this.source !== source) return;
      this.setState("open");
      const { clock } = this.opts;
      if (this.healthyTimer !== null) clock.clearTimeout(this.healthyTimer);
      this.healthyTimer = clock.setTimeout(() => {
        this.healthyTimer = null;
        this.failures = 0;
        this.refusals = 0;
      }, this.opts.healthyAfterMs);
    };

    source.onerror = () => {
      if (this.source !== source) return;
      // A transient drop leaves the browser retrying by itself (CONNECTING); let it, but say so.
      // A CLOSED source will never come back, so it is replaced on our own schedule.
      if (source.readyState === CLOSED) {
        this.teardown();
        this.scheduleRetry();
      } else {
        this.clearHealthy();
        this.failures += 1;
        this.setState(this.failures >= this.opts.offlineAfter ? "offline" : "reconnecting");
      }
    };

    const { onTick } = this.opts;
    if (onTick) {
      source.addEventListener("tick", (msg: MessageEvent) => {
        if (this.source !== source) return;
        const tick = parseTick(typeof msg.data === "string" ? msg.data : "");
        if (tick) onTick(tick);
      });
    }

    for (const type of EVENT_TYPES) {
      source.addEventListener(type, (msg: MessageEvent) => {
        if (this.source !== source) return;
        const raw = typeof msg.data === "string" ? msg.data : "";
        const key = `${msg.lastEventId}\u0000${type}\u0000${raw}`;
        if (this.seenSet.has(key)) return;
        const ev = parseStreamEvent(type, raw, msg.lastEventId);
        if (!ev) return;
        this.remember(key);
        this.opts.onEvent(ev);
      });
    }
  }

  private remember(key: string): void {
    this.seen.push(key);
    this.seenSet.add(key);
    while (this.seen.length > this.opts.dedupWindow) {
      this.seenSet.delete(this.seen.shift() as string);
    }
  }

  private scheduleRetry(): void {
    if (this.stopped) return;
    this.clearRetry();
    const epoch = this.epoch;
    this.refusals += 1;
    if (this.refusals > this.opts.maxAttempts) {
      this.setState("offline", undefined, true);
      return;
    }
    // Drawn once for this attempt; nothing below recomputes it.
    const backoff = backoffDelay(this.failures, this.opts.baseDelayMs, this.opts.maxDelayMs, this.opts.random);
    this.failures += 1;
    const state: ConnectionState = this.failures >= this.opts.offlineAfter ? "offline" : "reconnecting";
    const arm = (retryAfterMs?: number) => {
      if (this.stopped || epoch !== this.epoch) return;
      const delay = Math.max(backoff, Math.min(MAX_RETRY_AFTER_MS, retryAfterMs ?? 0));
      this.setState(state, delay);
      this.retryTimer = this.opts.clock.setTimeout(() => {
        this.retryTimer = null;
        this.connect();
      }, delay);
    };
    const { probe } = this.opts;
    if (!probe) {
      arm();
      return;
    }
    this.setState(state);
    probe(this.opts.url).then(arm, () => arm());
  }

  private clearRetry(): void {
    this.epoch += 1;
    if (this.retryTimer !== null) {
      this.opts.clock.clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
  }

  private clearHealthy(): void {
    if (this.healthyTimer !== null) {
      this.opts.clock.clearTimeout(this.healthyTimer);
      this.healthyTimer = null;
    }
  }

  private teardown(): void {
    this.clearHealthy();
    if (this.source) {
      const s = this.source;
      this.source = null;
      s.onopen = null;
      s.onerror = null;
      s.close();
    }
  }
}
