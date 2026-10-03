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
  type Stats,
  type StreamEvent,
  type TerminalAccepted,
  isAttackAccepted,
  isCommandAccepted,
  isLimits,
  isTerminalAccepted,
  parsePosture,
  parseRunEvents,
  parseScenarioDetails,
  parseScenarios,
  parseStats,
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

/** Starting the terminal returns the same shapes, plus the per-run token on success. */
export type TerminalResult =
  | { kind: "accepted"; run: TerminalAccepted }
  | { kind: "busy" }
  | { kind: "rate-limited"; retryAfterSeconds: number }
  | { kind: "unavailable" }
  | { kind: "offline"; message: string }
  | { kind: "error"; status: number; message: string };

/**
 * Sending one command id to a running terminal (POST /api/runs/{id}/commands). A 429 is either the
 * run's command budget or the per-visitor request limiter; only the body tells them apart, so its
 * `error` text is kept as `reason`.
 */
export type CommandResult =
  | { kind: "accepted"; seq: number }
  | { kind: "unauthorized" }
  | { kind: "not-found" }
  | { kind: "conflict" }
  | { kind: "too-large" }
  | { kind: "rate-limited"; retryAfterSeconds: number; reason: string }
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
    return this.getJson("/posture", parsePosture);
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

  /** Extension endpoint: the counters across every visitor's runs. */
  stats(): Promise<Result<Stats>> {
    return this.getJson("/stats", parseStats);
  }

  /** GET /api/runs/{id}: the stored events of a run, for backfilling a session joined mid-way. */
  runEvents(id: string): Promise<Result<StreamEvent[]>> {
    return this.getJson(`/runs/${encodeURIComponent(id)}`, parseRunEvents);
  }

  /** `compare: true` runs the same catalogue attack in two pods at once (?compare=1). */
  async attack(id: string, opts: { compare?: boolean } = {}): Promise<AttackResult> {
    let res: Response;
    try {
      res = await this.request(`/attack/${encodeURIComponent(id)}${opts.compare ? "?compare=1" : ""}`, { method: "POST" });
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

  /** Starts the terminal scenario; the token in the 202 is the only copy, so the caller must keep it. */
  async attackTerminal(): Promise<TerminalResult> {
    let res: Response;
    try {
      res = await this.request(`/attack/terminal`, { method: "POST" });
    } catch (e) {
      return { kind: "offline", message: describe(e) };
    }
    switch (res.status) {
      case 202: {
        const body: unknown = await res.json().catch(() => null);
        return isTerminalAccepted(body) ? { kind: "accepted", run: body } : { kind: "error", status: 202, message: "unexpected response body" };
      }
      case 404:
        // An API without the terminal scenario answers a JSON 404; the SPA host answers a non-JSON one.
        return isJson(res) ? { kind: "unavailable" } : { kind: "offline", message: "HTTP 404" };
      case 409:
        return { kind: "busy" };
      case 429:
        return { kind: "rate-limited", retryAfterSeconds: parseRetryAfter(res.headers.get("Retry-After")) };
      case 502:
      case 503:
      case 504:
        return { kind: "offline", message: `HTTP ${res.status}` };
      default:
        if (!isJson(res)) return { kind: "offline", message: `HTTP ${res.status}` };
        return { kind: "error", status: res.status, message: `HTTP ${res.status}` };
    }
  }

  /** Sends one command id to a running terminal. The token authorises it (Bearer), never a visitor string. */
  async runCommand(runId: string, token: string, id: string): Promise<CommandResult> {
    let res: Response;
    try {
      res = await this.request(`/runs/${encodeURIComponent(runId)}/commands`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ id }),
      });
    } catch (e) {
      return { kind: "offline", message: describe(e) };
    }
    switch (res.status) {
      case 202: {
        const body: unknown = await res.json().catch(() => null);
        return isCommandAccepted(body) ? { kind: "accepted", seq: body.seq } : { kind: "error", status: 202, message: "unexpected response body" };
      }
      case 401:
        return { kind: "unauthorized" };
      case 404:
        return { kind: "not-found" };
      case 409:
        return { kind: "conflict" };
      case 413:
        return { kind: "too-large" };
      case 429:
        return { kind: "rate-limited", retryAfterSeconds: parseRetryAfter(res.headers.get("Retry-After")), reason: await errorText(res) };
      case 502:
      case 503:
      case 504:
        return { kind: "offline", message: `HTTP ${res.status}` };
      default:
        if (!isJson(res)) return { kind: "offline", message: `HTTP ${res.status}` };
        return { kind: "error", status: res.status, message: `HTTP ${res.status}` };
    }
  }

  /** The visitor leaves: ends their terminal run. Best effort — the run also ends on idle/deadline. */
  async leaveRun(runId: string, token: string): Promise<boolean> {
    try {
      const res = await this.request(`/runs/${encodeURIComponent(runId)}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
        // Let the request outlive the page when sent from a pagehide handler.
        keepalive: true,
      });
      return res.ok || res.status === 404;
    } catch {
      return false;
    }
  }
}

/** The `error` field of a JSON error body, or "". */
async function errorText(res: Response): Promise<string> {
  const body: unknown = isJson(res) ? await res.json().catch(() => null) : null;
  return typeof body === "object" && body !== null && typeof (body as { error?: unknown }).error === "string" ? (body as { error: string }).error.slice(0, 200) : "";
}

function isJson(res: Response): boolean {
  return (res.headers.get("Content-Type") ?? "").toLowerCase().includes("application/json");
}

function describe(e: unknown): string {
  if (e instanceof DOMException && e.name === "AbortError") return "timed out";
  return e instanceof Error ? e.message : String(e);
}
