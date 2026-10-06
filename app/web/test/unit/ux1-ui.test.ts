// UX stage 1 on the page (ADR 0035 amendment 2026-10-06): the status strip and its toast, the SIEM
// scenario block, the three-tier incident board, the folded SIEM health and the folded run history.

import { afterEach, describe, expect, it, vi } from "vitest";
import type { Result } from "../../src/lib/api";
import { type Correlation, type StreamEvent, parseCorrelation, toStreamEvent } from "../../src/lib/contract";
import { TERMINAL_COMMANDS } from "../../src/lib/fixtures";
import { buildTimeline } from "../../src/lib/timeline";
import { EAGER_POLL_MS, POLL_MS, mountCorrelation, renderBoard, renderHealth, tierOf } from "../../src/ui/correlation";
import { type RunReading, mountRunStatus } from "../../src/ui/runstatus";
import { HISTORY_SHOWN, mountTimeline } from "../../src/ui/timeline";

const RUN = "4f1c2a9e8b7d6c5a";
const POD = "terminal-4f1c2a9e8b";
const NOW = Date.parse("2026-10-06T08:00:00Z");
const at = (sAgo: number) => new Date(NOW - sAgo * 1000).toISOString();

function incident(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { id: "c0a1b2c3d4e5f607", kind: "contained-intrusion", severity: "high", title: "", run_id: "7e57000000000001", arm: "", first_at: at(600), last_at: at(598), attack: [], falco_events: 1, flag_match: null, ttd_ms: 840, tti_ms: 212, steps: [], evidence: [], ...over };
}
const answer = (incidents: Record<string, unknown>[], over: Record<string, unknown> = {}) => ({
  available: true,
  checked_at: at(20),
  rules: { commit: "a7cc041e5d2b9f30c1a4e6b8d0f2a3c5e7f9b1d3", applied_at: at(5400), status: "applied" },
  health: { ingest: "ok", evidence_rewritten: false, disk: "ok" },
  metrics: { since: at(86_400), incidents: incidents.length, median_ttd_ms: 840, median_tti_ms: 212, median_twin_dwell_ms: null, host_findings: 0 },
  incidents,
  ...over,
});

function feed(): StreamEvent[] {
  const out: StreamEvent[] = [];
  let id = 1;
  const push = (type: string, data: Record<string, unknown>) => out.push(toStreamEvent(type, data, ++id) as StreamEvent);
  const t = (ms: number) => new Date(NOW + ms).toISOString();
  push("run", { run_id: RUN, scenario: "terminal", state: "queued", at: t(0), detail: "" });
  push("run", { run_id: RUN, scenario: "terminal", state: "pod_ready", at: t(1900), detail: "", pod: POD });
  push("command", { run_id: RUN, seq: 1, id: "dns-exfil", state: "started", at: t(3000) });
  push("command", { run_id: RUN, seq: 1, id: "dns-exfil", state: "exited", at: t(3200), exit_code: 0, achieved: true });
  return out;
}

afterEach(() => {
  document.body.replaceChildren();
  vi.useRealTimers();
});

describe("the status strip and its toast", () => {
  const setup = () => {
    const calls = { timeline: 0, again: 0, open: [] as string[], readings: [] as RunReading[] };
    const status = mountRunStatus({ toastParent: document.body, onTimeline: () => calls.timeline++, onAgain: () => calls.again++, onOpen: (id) => calls.open.push(id), onReading: (r) => calls.readings.push(r) });
    document.body.append(status.strip);
    return { status, calls };
  };
  const run = () => buildTimeline(feed(), NOW + 10_000).runs[0];

  it("one polite live region speaks the message; the toast carries the same words and is not live", () => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW + 10_000);
    const { status } = setup();
    status.setSession({ runId: RUN, run: run(), commands: TERMINAL_COMMANDS, idleSeconds: 90 });
    const live = document.querySelectorAll("[aria-live]");
    expect(live).toHaveLength(1);
    expect(live[0].getAttribute("aria-live")).toBe("polite");
    expect(live[0].textContent).toBe("Waiting for the SIEM (usually 1–3 min)…");
    const toast = document.querySelector(".run-toast") as HTMLElement;
    expect(toast.querySelector(".run-toast__msg")?.textContent).toBe("Waiting for the SIEM (usually 1–3 min)…");
    expect(toast.hasAttribute("aria-live")).toBe(false);
    expect(status.strip.hidden).toBe(false);
  });

  it("the incident for the run: 'Open it' links to its card and asks for the pulse; dismissed, it stays away until the next message", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW + 10_000);
    const { status, calls } = setup();
    status.setSession({ runId: RUN, run: run(), commands: TERMINAL_COMMANDS });
    status.setCorrelation(true, parseCorrelation(answer([incident({ id: "d000000000000001", kind: "dns-exfil", severity: "critical", run_id: RUN })])).incidents);
    expect(status.strip.querySelector(".run-strip__msg")?.textContent).toBe("The SIEM caught your DNS exfil — CRITICAL. Falco never saw it.");
    const open = status.strip.querySelector<HTMLAnchorElement>("a.run-strip__btn");
    expect(open?.getAttribute("href")).toBe("#incident-d000000000000001");
    open?.addEventListener("click", (e) => e.preventDefault());
    open?.click();
    await vi.advanceTimersByTimeAsync(0);
    expect(calls.open).toEqual(["d000000000000001"]);
    (status.strip.querySelector(".run-strip__close") as HTMLButtonElement).click();
    expect(status.strip.hidden).toBe(true);
    status.setSession({ runId: RUN, run: run(), commands: TERMINAL_COMMANDS });
    expect(status.strip.hidden).toBe(true);
    // The reading every part shows: the scenario found, the SIEM row filed, no eager poll left.
    const r = calls.readings.at(-1);
    expect(r?.scenario).toEqual({ phase: "found", incidentId: "d000000000000001", severity: "critical" });
    expect(r?.siem.text).toBe("CRITICAL — DNS exfiltration");
    expect(r?.eager).toBe(false);
    expect(r?.ownRuns).toEqual([RUN]);
  });

  it("asks for the eager poll while waiting, and not while the SIEM is down", () => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW + 10_000);
    const { status, calls } = setup();
    status.setSession({ runId: RUN, run: run(), commands: TERMINAL_COMMANDS });
    expect(calls.readings.at(-1)?.eager).toBe(true);
    status.setCorrelation(false, []);
    expect(calls.readings.at(-1)?.eager).toBe(false);
    expect(calls.readings.at(-1)?.scenario.phase).toBe("down");
  });
});

describe("the incident board's tiers", () => {
  const ctx = (own: string[] = []) => ({ now: NOW, rules: new Map(), commit: "", own: new Set(own) });

  it("pinned: caught by correlation (its kind, or no Falco event) and the visitor's own; contained folded; tests folded", () => {
    const own = new Set([RUN]);
    const tier = (over: Record<string, unknown>) => tierOf(parseCorrelation(answer([incident(over)])).incidents[0], own);
    expect(tier({ kind: "dns-exfil" })).toBe("pinned");
    expect(tier({ kind: "policy-probing" })).toBe("pinned");
    expect(tier({ kind: "prevented-not-detected" })).toBe("pinned");
    expect(tier({ kind: "detection-missing", falco_events: 0 })).toBe("pinned");
    expect(tier({})).toBe("contained");
    expect(tier({ run_id: RUN })).toBe("pinned");
    expect(tier({ kind: "staged-attack" })).toBe("other");
    expect(tier({ kind: "exec-outside-api", operator_test: true })).toBe("test");
  });

  it("the visitor's own incident first and in full, the severity before the rest; contained intrusions one line each under a summary with medians", () => {
    const c = parseCorrelation(
      answer([
        incident({ id: "0000000000000001", kind: "prevented-not-detected", severity: "low" }),
        incident({ id: "0000000000000002", ttd_ms: 400, tti_ms: 10 }),
        incident({ id: "0000000000000003", ttd_ms: 600, tti_ms: 30 }),
        incident({ id: "0000000000000004", kind: "dns-exfil", severity: "critical" }),
        incident({ id: "0000000000000005", run_id: RUN }),
      ]),
    );
    const board = renderBoard(c, ctx([RUN]));
    const cards = [...board.querySelectorAll(".corr-tier--pinned .incident")];
    expect(cards.map((e) => e.getAttribute("data-incident"))).toEqual(["0000000000000005", "0000000000000004", "0000000000000001"]);
    expect(cards[0].classList.contains("incident--own")).toBe(true);
    expect(cards[0].textContent).toContain("From your run on this page.");
    expect(cards[1].classList.contains("incident--pinned")).toBe(true);
    expect(cards[1].querySelector(".incident__head")?.firstElementChild?.classList.contains("chip")).toBe(true);
    const fold = board.querySelector<HTMLDetailsElement>("details.corr-contained");
    expect(fold?.open).toBe(false);
    expect(fold?.querySelector("summary")?.textContent).toBe("Contained automatically by Falco + Talon (2)");
    expect(fold?.querySelector(".corr-contained__line")?.textContent).toMatch(/^2 intrusions caught and ended · median 400 ms to detect · 10 ms to isolate\./);
    expect(fold?.querySelectorAll("li[data-incident]")).toHaveLength(2);
  });
});

describe("the SIEM health, folded", () => {
  it("closed by default; its summary says every check is ok, or names the ones that are not", () => {
    const ok = renderHealth(parseCorrelation(answer([])), NOW) as HTMLDetailsElement;
    expect(ok.tagName).toBe("DETAILS");
    expect(ok.open).toBe(false);
    expect(ok.querySelector("summary")?.textContent).toBe("SIEM health ✓every check ok");
    const bad = renderHealth(parseCorrelation(answer([], { health: { ingest: "silent", evidence_rewritten: false, disk: "high" } })), NOW);
    expect([...bad.querySelectorAll("summary .chip")].map((c) => c.textContent)).toEqual(["!ingest silent", "!disk high"]);
  });
});

describe("the SIEM scenario block and the eager poll", () => {
  const setup = (seq: Result<Correlation>[]) => {
    const section = document.createElement("section");
    const mounts = { scenario: document.createElement("div"), health: document.createElement("div"), metrics: document.createElement("div"), board: document.createElement("div"), rules: document.createElement("div") };
    section.append(...Object.values(mounts));
    document.body.append(section);
    const calls = { correlation: 0, scenario: 0, data: [] as (Correlation | null)[] };
    const api = {
      correlation: async () => (calls.correlation++, seq.length > 1 ? (seq.shift() as Result<Correlation>) : seq[0]),
      correlationRules: async () => ({ ok: false, error: "offline", message: "x" }) as never,
    };
    const handle = mountCorrelation(section, mounts, api, undefined, { onData: (c) => calls.data.push(c), onScenario: () => calls.scenario++ });
    return { section, mounts, calls, handle };
  };
  const ok = (incidents: Record<string, unknown>[] = []): Result<Correlation> => ({ ok: true, value: parseCorrelation(answer(incidents)) });

  it("the copy, the button, the state chip from not run to found, a link to the card", async () => {
    vi.useFakeTimers();
    const { mounts, calls, handle } = setup([ok()]);
    await vi.advanceTimersByTimeAsync(0);
    expect(mounts.scenario.querySelector(".corr-scenario__title")?.textContent).toBe("Make the SIEM catch what Falco cannot.");
    expect(mounts.scenario.textContent).toContain("one to three minutes later the SIEM ties it to your run and raises a CRITICAL incident below");
    const chip = mounts.scenario.querySelector(".corr-scenario__state") as HTMLElement;
    expect(chip.textContent).toBe("not run yet");
    (mounts.scenario.querySelector(".corr-scenario__btn") as HTMLButtonElement).click();
    expect(calls.scenario).toBe(1);
    handle.setVisitor({ ownRuns: [RUN], scenario: { phase: "waiting" }, eager: false });
    expect(chip.textContent).toBe("waiting for the SIEM (≈2 min)…");
    handle.setVisitor({ ownRuns: [RUN], scenario: { phase: "found", incidentId: "d000000000000001", severity: "critical" }, eager: false });
    expect(chip.textContent).toBe("found it: the CRITICAL incident is below ↓");
    expect(chip.querySelector("a")?.getAttribute("href")).toBe("#incident-d000000000000001");
    handle.setTerminal(false);
    (mounts.scenario.querySelector(".corr-scenario__btn") as HTMLButtonElement).click();
    expect(calls.scenario).toBe(1);
    expect(calls.data).toHaveLength(1);
  });

  it("asks every EAGER_POLL_MS while a filing is awaited, back to the minute after; the own run's incident is pinned and pulses once", async () => {
    vi.useFakeTimers();
    const { mounts, calls, handle } = setup([ok(), ok(), ok([incident({ id: "d000000000000001", kind: "contained-intrusion", run_id: RUN })])]);
    await vi.advanceTimersByTimeAsync(0);
    expect(calls.correlation).toBe(1);
    handle.setVisitor({ ownRuns: [RUN], scenario: { phase: "waiting" }, eager: true });
    await vi.advanceTimersByTimeAsync(EAGER_POLL_MS);
    expect(calls.correlation).toBe(2);
    await vi.advanceTimersByTimeAsync(EAGER_POLL_MS);
    expect(calls.correlation).toBe(3);
    const card = mounts.board.querySelector('.corr-tier--pinned .incident[data-incident="d000000000000001"]');
    expect(card?.classList.contains("is-pulsing")).toBe(true);
    handle.setVisitor({ ownRuns: [RUN], scenario: { phase: "idle" }, eager: false });
    await vi.advanceTimersByTimeAsync(EAGER_POLL_MS);
    expect(calls.correlation).toBe(4); // the one scheduled while eager
    await vi.advanceTimersByTimeAsync(EAGER_POLL_MS);
    expect(calls.correlation).toBe(4);
    await vi.advanceTimersByTimeAsync(POLL_MS);
    expect(calls.correlation).toBe(5);
  });
});

describe("run history, four cards then a fold", () => {
  it("folds every run after the fourth under 'N earlier runs', and keeps the fold open across re-renders", async () => {
    const root = document.createElement("div");
    const handle = mountTimeline(root, document.createElement("div"), document.createElement("div"), () => {}, () => {});
    for (let n = 0; n < HISTORY_SHOWN + 2; n++) {
      const id = `10000000000000${n.toString(16).padStart(2, "0")}`;
      handle.push(toStreamEvent("run", { run_id: id, scenario: "network-tool", state: "queued", at: at(1000 - n * 60), detail: "" }, n * 10 + 1) as StreamEvent);
      handle.push(toStreamEvent("run", { run_id: id, scenario: "network-tool", state: "finished", at: at(990 - n * 60), detail: "" }, n * 10 + 2) as StreamEvent);
    }
    await new Promise((r) => setTimeout(r, 30));
    expect(root.querySelectorAll(":scope > ol.runs > .run")).toHaveLength(HISTORY_SHOWN);
    const more = root.querySelector<HTMLDetailsElement>("details.runs-more");
    expect(more?.querySelector("summary")?.textContent).toBe("2 earlier runs");
    expect(more?.querySelectorAll(".run")).toHaveLength(2);
    if (more) {
      more.open = true;
      more.dispatchEvent(new Event("toggle"));
    }
    handle.setTitles(new Map([["network-tool", "Download tool"]]));
    await new Promise((r) => setTimeout(r, 30));
    expect(root.querySelector<HTMLDetailsElement>("details.runs-more")?.open).toBe(true);
  });
});
