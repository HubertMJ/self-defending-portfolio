import { describe, expect, it, vi } from "vitest";
import { ApiClient, DEFAULT_RETRY_AFTER_SECONDS, type FetchLike, parseRetryAfter } from "../../src/lib/api";
import { SCENARIOS, posture } from "../../src/lib/fixtures";

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });

const client = (impl: FetchLike) => new ApiClient({ fetch: impl, timeoutMs: 50 });

describe("parseRetryAfter", () => {
  const now = Date.parse("2026-10-01T12:00:00Z");

  it("reads delta-seconds", () => {
    expect(parseRetryAfter("120", now)).toBe(120);
    expect(parseRetryAfter(" 7 ", now)).toBe(7);
  });

  it("reads an HTTP-date relative to now, rounding up", () => {
    expect(parseRetryAfter("Thu, 01 Oct 2026 12:01:30 GMT", now)).toBe(90);
  });

  it("clamps to at least one second and at most an hour", () => {
    expect(parseRetryAfter("0", now)).toBe(1);
    expect(parseRetryAfter("Thu, 01 Oct 2026 11:00:00 GMT", now)).toBe(1);
    expect(parseRetryAfter("999999", now)).toBe(3600);
  });

  it("falls back when missing or garbage", () => {
    expect(parseRetryAfter(null, now)).toBe(DEFAULT_RETRY_AFTER_SECONDS);
    expect(parseRetryAfter("soon", now)).toBe(DEFAULT_RETRY_AFTER_SECONDS);
    expect(parseRetryAfter("-5", now)).toBe(DEFAULT_RETRY_AFTER_SECONDS);
  });
});

describe("ApiClient GETs", () => {
  it("returns scenarios and drops entries that do not match the contract", async () => {
    const api = client(async () => json(200, [...SCENARIOS, { id: "broken" }]));
    const res = await api.scenarios();
    expect(res).toEqual({ ok: true, value: SCENARIOS });
  });

  it("calls same-origin /api paths without credentials", async () => {
    const f = vi.fn<FetchLike>(async () => json(200, []));
    await client(f).scenarios();
    expect(f).toHaveBeenCalledWith("/api/scenarios", expect.objectContaining({ credentials: "omit", cache: "no-store" }));
  });

  it("accepts a contract-shaped posture", async () => {
    const p = posture(0);
    const res = await client(async () => json(200, p)).posture();
    expect(res).toEqual({ ok: true, value: p });
  });

  it("accepts a posture from an API without the image breakdown, unchanged", async () => {
    const p = posture(0);
    const old = { ...p, trivy: { images: 27, critical: 0, high: 3, medium: 41, low: 88 } };
    const res = await client(async () => json(200, old)).posture();
    expect(res).toEqual({ ok: true, value: old });
  });

  it("drops a malformed breakdown or row but never touches the totals", async () => {
    const p = posture(0);
    const bad = {
      ...p,
      trivy: {
        ...p.trivy,
        own: { images: 3, critical: 0, high: "0", fixable: 0 },
        by_image: [{ image: "x".repeat(500), own: false, critical: 1, high: 2, fixable: 3 }, { image: 5, own: false, critical: 0, high: 0, fixable: 0 }, null],
      },
    };
    const res = await client(async () => json(200, bad)).posture();
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    const tr = res.value.trivy;
    expect([tr.images, tr.critical, tr.high, tr.medium, tr.low]).toEqual([27, 0, 3, 41, 88]);
    expect(tr.own).toBeUndefined();
    expect(tr.third_party).toBeUndefined();
    expect(tr.by_image).toHaveLength(1);
    expect(tr.by_image?.[0].image.length).toBe(200);
  });

  it("rejects a posture with a missing section as bad-response", async () => {
    const p: Record<string, unknown> = { ...posture(0) };
    delete p.trivy;
    const res = await client(async () => json(200, p)).posture();
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toBe("bad-response");
  });

  it("treats a network error as offline", async () => {
    const res = await client(async () => {
      throw new TypeError("Failed to fetch");
    }).posture();
    expect(res).toEqual({ ok: false, error: "offline", message: "Failed to fetch" });
  });

  it("treats the static host's HTML/plain 404 (no API deployed) as offline", async () => {
    const res = await client(async () => new Response("not found\n", { status: 404, headers: { "Content-Type": "text/plain" } })).scenarios();
    expect(res).toMatchObject({ ok: false, error: "offline", message: "HTTP 404" });
  });

  it("treats a 200 that is not JSON as offline (e.g. a captive portal or error page)", async () => {
    const res = await client(async () => new Response("<html>", { status: 200, headers: { "Content-Type": "text/html" } })).posture();
    expect(res).toMatchObject({ ok: false, error: "offline" });
  });

  it("times out a hanging request", async () => {
    const hang: FetchLike = (_u, init) =>
      new Promise((_r, reject) => init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError"))));
    const res = await client(hang).posture();
    expect(res).toEqual({ ok: false, error: "offline", message: "timed out" });
  });
});

describe("ApiClient.attack", () => {
  it("POSTs to /api/attack/{id} with the id encoded", async () => {
    const f = vi.fn<FetchLike>(async () => json(202, { run_id: "r1", scenario: "a b", state: "queued" }));
    const res = await client(f).attack("a b");
    expect(f.mock.calls[0][0]).toBe("/api/attack/a%20b");
    expect(f.mock.calls[0][1]?.method).toBe("POST");
    expect(res).toEqual({ kind: "accepted", run: { run_id: "r1", scenario: "a b", state: "queued" } });
  });

  it("maps 409 to busy", async () => {
    expect(await client(async () => json(409, {})).attack("x")).toEqual({ kind: "busy" });
  });

  it("maps 429 to rate-limited with Retry-After", async () => {
    const res = await client(async () => json(429, {}, { "Retry-After": "42" })).attack("x");
    expect(res).toEqual({ kind: "rate-limited", retryAfterSeconds: 42 });
  });

  it("maps 429 without Retry-After to the default wait", async () => {
    const res = await client(async () => json(429, {})).attack("x");
    expect(res).toEqual({ kind: "rate-limited", retryAfterSeconds: DEFAULT_RETRY_AFTER_SECONDS });
  });

  it("maps a JSON 404 to unknown-scenario but a plain 404 to offline", async () => {
    expect(await client(async () => json(404, { error: "unknown" })).attack("x")).toEqual({ kind: "unknown-scenario" });
    const plain = await client(async () => new Response("not found", { status: 404, headers: { "Content-Type": "text/plain" } })).attack("x");
    expect(plain.kind).toBe("offline");
  });

  it("maps gateway errors and network errors to offline", async () => {
    expect((await client(async () => new Response("", { status: 503 })).attack("x")).kind).toBe("offline");
    expect(
      (
        await client(async () => {
          throw new TypeError("network");
        }).attack("x")
      ).kind,
    ).toBe("offline");
  });

  it("flags a 202 whose body is not a queued run", async () => {
    const res = await client(async () => json(202, { run_id: 1 })).attack("x");
    expect(res).toMatchObject({ kind: "error", status: 202 });
  });

  it("reports other JSON statuses as errors, non-JSON ones as offline", async () => {
    expect(await client(async () => json(500, {})).attack("x")).toMatchObject({ kind: "error", status: 500 });
    const html405 = await client(async () => new Response("<html>", { status: 405, headers: { "Content-Type": "text/html" } })).attack("x");
    expect(html405.kind).toBe("offline");
  });
});

describe("ApiClient.leaveRun (final review, item 5)", () => {
  it("sends the DELETE with keepalive, so it outlives a page that is closing", async () => {
    const inits: RequestInit[] = [];
    const ok = await client(async (_u, init) => (inits.push(init ?? {}), json(202, { state: "finishing" }))).leaveRun("4f1c2a9e8b7d6c5a", "0123456789abcdef0123456789abcdef");
    expect(ok).toBe(true);
    expect(inits[0].method).toBe("DELETE");
    expect(inits[0].keepalive).toBe(true);
  });
});
