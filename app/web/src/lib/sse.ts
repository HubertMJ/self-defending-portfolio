// A reconnecting wrapper around EventSource for GET /api/events.
//
// EventSource retries on its own after a dropped connection, but gives up for good (readyState
// CLOSED) when a (re)connect gets a non-200 or a non-event-stream response -- exactly what happens
// while the API is being redeployed, or before phase 5 exists at all. This wrapper owns the retry
// loop instead: exponential backoff with full jitter, reset after a connection has proven healthy,
// paused while the tab is hidden so a forgotten tab does not keep a connection open for nothing.
//
// The server replays the last 50 events on every connect, so a reconnect re-delivers events the page
// has already shown. They are dropped here by identity (type + payload), which keeps the consumers
// free of dedup logic.

import { type StreamEvent, parseStreamEvent } from "./contract";

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

export interface StreamOptions {
  url: string;
  onEvent: (ev: StreamEvent) => void;
  onState?: (state: ConnectionState, detail: { attempt: number; retryInMs?: number }) => void;
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
}

const EVENT_TYPES = ["run", "falco", "talon"] as const;
const CLOSED = 2;

const defaultClock: Clock = {
  setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms),
  clearTimeout: (h) => globalThis.clearTimeout(h as ReturnType<typeof setTimeout>),
  now: () => Date.now(),
};

/** Full-jitter exponential backoff: uniform in [base/2, min(max, base * 2^attempt)]. */
export function backoffDelay(attempt: number, base: number, max: number, random: () => number): number {
  const ceiling = Math.min(max, base * 2 ** Math.max(0, attempt));
  const floor = Math.min(ceiling, base / 2);
  return Math.round(floor + random() * (ceiling - floor));
}

export class EventStream {
  private readonly opts: Required<Omit<StreamOptions, "onState">> & Pick<StreamOptions, "onState">;
  private source: EventSourceLike | null = null;
  private retryTimer: unknown = null;
  private healthyTimer: unknown = null;
  private failures = 0;
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
      ...opts,
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
    this.teardown();
    this.connect();
  }

  private setState(state: ConnectionState, retryInMs?: number): void {
    this.state = state;
    this.opts.onState?.(state, { attempt: this.failures, retryInMs });
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

    for (const type of EVENT_TYPES) {
      source.addEventListener(type, (msg: MessageEvent) => {
        if (this.source !== source) return;
        const raw = typeof msg.data === "string" ? msg.data : "";
        const key = `${type}\u0000${raw}`;
        if (this.seenSet.has(key)) return;
        const ev = parseStreamEvent(type, raw);
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
    const delay = backoffDelay(this.failures, this.opts.baseDelayMs, this.opts.maxDelayMs, this.opts.random);
    this.failures += 1;
    this.setState(this.failures >= this.opts.offlineAfter ? "offline" : "reconnecting", delay);
    this.retryTimer = this.opts.clock.setTimeout(() => {
      this.retryTimer = null;
      this.connect();
    }, delay);
  }

  private clearRetry(): void {
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
