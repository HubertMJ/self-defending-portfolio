// HTTP half of the API client. The SSE half lives in sse.ts.
//
// Every call has a timeout and returns a discriminated result instead of throwing, because the UI
// has to render each failure differently (offline panel, "a run is already active", a countdown) and
// a thrown error would flatten all of them into one catch block.

import {
  type AttackAccepted,
  type Limits,
  type Posture,
  type Scenario,
  type ScenarioDetails,
  isAttackAccepted,
  isLimits,
  isPosture,
  parseScenarioDetails,
  parseScenarios,
} from "./contract";

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export type Result<T> =
  | { ok: true; value: T }
  | { ok: false; error: "offline" | "bad-response"; message: string };

export type AttackResult =
  | { kind: "accepted"; run: AttackAccepted }
  | { kind: "busy" }
  | { kind: "rate-limited"; retryAfterSeconds: number }
  | { kind: "unknown-scenario" }
  | { kind: "offline"; message: string }
  | { kind: "error"; status: number; message: string };

/** Fallback when a 429 arrives without a usable Retry-After: the contract's per-IP window is 10 min. */
export const DEFAULT_RETRY_AFTER_SECONDS = 60;
const MAX_RETRY_AFTER_SECONDS = 60 * 60;

/**
 * Retry-After is either delta-seconds or an HTTP-date (RFC 9110 §10.2.3). Returns whole seconds,
 * clamped to [1, 1h] so a broken or hostile header cannot lock the buttons for a day.
 */
export function parseRetryAfter(header: string | null, now: number = Date.now()): number {
  if (header === null) return DEFAULT_RETRY_AFTER_SECONDS;
  const value = header.trim();
  let seconds: number;
  if (/^\d+$/.test(value)) {
    seconds = Number(value);
  } else if (/^[A-Za-z]{3},/.test(value)) {
    // IMF-fixdate ("Sun, 06 Nov 1994 08:49:37 GMT"); anything else is malformed, not a date to guess at.
    const date = Date.parse(value);
    if (Number.isNaN(date)) return DEFAULT_RETRY_AFTER_SECONDS;
    seconds = Math.ceil((date - now) / 1000);
  } else {
    return DEFAULT_RETRY_AFTER_SECONDS;
  }
  return Math.min(MAX_RETRY_AFTER_SECONDS, Math.max(1, seconds));
}

export interface ApiClientOptions {
  base?: string;
  fetch?: FetchLike;
  timeoutMs?: number;
}

export class ApiClient {
  private readonly base: string;
  private readonly fetchImpl: FetchLike;
  private readonly timeoutMs: number;

  constructor(opts: ApiClientOptions = {}) {
    this.base = opts.base ?? "/api";
    this.fetchImpl = opts.fetch ?? ((input, init) => globalThis.fetch(input, init));
    this.timeoutMs = opts.timeoutMs ?? 8000;
  }

  url(path: string): string {
    return `${this.base}${path}`;
  }

  /**
   * Why was the event stream refused? EventSource cannot see the status of a failed connect, so this
   * repeats the request with fetch, reads the status and Retry-After, and aborts before any body is
   * read (a 200 means the stream would be accepted now). Returns the wait in ms for a 429/503, else
   * undefined. Used by EventStream after a refused connection.
   */
  async streamRetryAfterMs(path = "/events"): Promise<number | undefined> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(this.url(path), {
        credentials: "omit",
        cache: "no-store",
        signal: controller.signal,
        headers: { Accept: "text/event-stream" },
      });
      if (res.status !== 429 && res.status !== 503) return undefined;
      return parseRetryAfter(res.headers.get("Retry-After")) * 1000;
    } catch {
      return undefined;
    } finally {
      clearTimeout(timer);
      controller.abort();
    }
  }

  private async request(path: string, init: RequestInit = {}): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return await this.fetchImpl(this.url(path), {
        ...init,
        // Same-origin API; no cookies exist, but never send any that might appear later.
        credentials: "omit",
        cache: "no-store",
        signal: controller.signal,
        headers: { Accept: "application/json", ...(init.headers ?? {}) },
      });
    } finally {
      clearTimeout(timer);
    }
  }

  private async getJson<T>(path: string, guard: (v: unknown) => T): Promise<Result<T>> {
    let res: Response;
    try {
      res = await this.request(path);
    } catch (e) {
      return { ok: false, error: "offline", message: describe(e) };
    }
    // A 404/502/503 here almost always means "phase 5 is not deployed" or "the API pod is down",
    // and the static site's own fallback would answer with HTML. Both are offline for the visitor.
    if (!res.ok || !isJson(res)) {
      return { ok: false, error: "offline", message: `HTTP ${res.status}` };
    }
    try {
      return { ok: true, value: guard(await res.json()) };
    } catch (e) {
      return { ok: false, error: "bad-response", message: describe(e) };
    }
  }

  scenarios(): Promise<Result<Scenario[]>> {
    return this.getJson("/scenarios", parseScenarios);
  }

  posture(): Promise<Result<Posture>> {
    return this.getJson("/posture", (v) => {
      if (!isPosture(v)) throw new TypeError("posture: response does not match the contract");
      return v;
    });
  }

  /** Extension endpoint; an API without it answers 404, which the caller treats as "no details". */
  scenarioDetails(id: string): Promise<Result<ScenarioDetails>> {
    return this.getJson(`/scenarios/${encodeURIComponent(id)}/details`, parseScenarioDetails);
  }

  /** Extension endpoint: the rate limits as the server counts them for this visitor. */
  limits(): Promise<Result<Limits>> {
    return this.getJson("/limits", (v) => {
      if (!isLimits(v)) throw new TypeError("limits: response does not match the contract");
      return v;
    });
  }

  async attack(id: string): Promise<AttackResult> {
    let res: Response;
    try {
      res = await this.request(`/attack/${encodeURIComponent(id)}`, { method: "POST" });
    } catch (e) {
      return { kind: "offline", message: describe(e) };
    }
    switch (res.status) {
      case 202: {
        const body: unknown = await res.json().catch(() => null);
        return isAttackAccepted(body)
          ? { kind: "accepted", run: body }
          : { kind: "error", status: 202, message: "unexpected response body" };
      }
      case 404:
        // The SPA host answers 404 too when /api is not routed at all; only trust a JSON 404.
        return isJson(res) ? { kind: "unknown-scenario" } : { kind: "offline", message: "HTTP 404" };
      case 409:
        return { kind: "busy" };
      case 429:
        return { kind: "rate-limited", retryAfterSeconds: parseRetryAfter(res.headers.get("Retry-After")) };
      case 502:
      case 503:
      case 504:
        return { kind: "offline", message: `HTTP ${res.status}` };
      default:
        // Not the API talking (e.g. the static host's 405 for a POST when /api is not routed).
        if (!isJson(res)) return { kind: "offline", message: `HTTP ${res.status}` };
        return { kind: "error", status: res.status, message: `HTTP ${res.status}` };
    }
  }
}

function isJson(res: Response): boolean {
  return (res.headers.get("Content-Type") ?? "").toLowerCase().includes("application/json");
}

function describe(e: unknown): string {
  if (e instanceof DOMException && e.name === "AbortError") return "timed out";
  return e instanceof Error ? e.message : String(e);
}
