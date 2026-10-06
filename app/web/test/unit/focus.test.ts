// This session first (ADR 0035, amendment 2026-10-06 "this session first"): the page shows the
// visitor's own runs and any run in progress now; everything else is behind "All activity, last 24 h";
// the empty state is a prompt and exactly one labelled example; the SIEM's evidence is one line of counts.

import { afterEach, describe, expect, it } from "vitest";
import { type StreamEvent, parseCorrelation, toStreamEvent } from "../../src/lib/contract";
import { ALL, type Focus, OWN_RUNS_KEY, OWN_RUNS_MAX, SCOPE_KEY, exampleIncident, focusRun, loadOwnRuns, loadScope, saveOwnRuns, saveScope, scopedIncidents, scopedRuns } from "../../src/lib/scope";
import { buildTimeline } from "../../src/lib/timeline";
import { evidenceSummary, mountCorrelation, renderIncident, renderSessionBoard } from "../../src/ui/correlation";
import { renderEvidenceCard, renderTicker, tickerItems } from "../../src/ui/evidence";
import { mountScope } from "../../src/ui/scope";
import { mountTimeline } from "../../src/ui/timeline";

const NOW = Date.now();
const iso = (msAgo: number) => new Date(NOW - msAgo).toISOString();
const MINE = "aaaa000000000001";
const OTHER = "bbbb000000000002";
const LIVE = "cccc000000000003";

/** A finished run of each of MINE and OTHER, minutes ago, and LIVE still running (queued seconds ago). */
function feed(): StreamEvent[] {
  let id = 0;
  const ev = (data: Record<string, unknown>) => toStreamEvent("run", data, ++id) as StreamEvent;
  return [
    ev({ run_id: OTHER, scenario: "network-tool", state: "queued", at: iso(600_000), detail: "" }),
    ev({ run_id: OTHER, scenario: "network-tool", state: "finished", at: iso(590_000), detail: "" }),
    ev({ run_id: MINE, scenario: "shell-in-container", state: "queued", at: iso(300_000), detail: "" }),
    ev({ run_id: MINE, scenario: "shell-in-container", state: "finished", at: iso(290_000), detail: "" }),
    ev({ run_id: LIVE, scenario: "network-tool", state: "queued", at: iso(2000), detail: "" }),
  ];
}

const session = (own: string[] = []): Focus => ({ all: false, own: new Set(own) });

function memStore(init: Record<string, string> = {}) {
  const m = new Map(Object.entries(init));
  return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v), removeItem: (k: string) => void m.delete(k), m };
}

function incident(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { id: "c0a1b2c3d4e5f607", kind: "contained-intrusion", severity: "high", title: "", run_id: OTHER, arm: "", first_at: iso(600_000), last_at: iso(598_000), attack: [], falco_events: 1, flag_match: null, ttd_ms: 840, tti_ms: 212, steps: [], evidence: [], ...over };
}
const answer = (incidents: Record<string, unknown>[]) =>
  parseCorrelation({
    available: true,
    checked_at: iso(20_000),
    rules: { commit: "a7cc041e5d2b9f30c1a4e6b8d0f2a3c5e7f9b1d3", applied_at: iso(5_400_000), status: "applied" },
    health: { ingest: "ok", evidence_rewritten: false, disk: "ok" },
    metrics: { since: iso(86_400_000), incidents: incidents.length, median_ttd_ms: 840, median_tti_ms: 212, median_twin_dwell_ms: null, host_findings: 0 },
    incidents,
  });
const ctx = { now: NOW, rules: new Map(), commit: "a7cc041e5d2b9f30c1a4e6b8d0f2a3c5e7f9b1d3" };

afterEach(() => {
  document.body.replaceChildren();
  localStorage.clear();
});

describe("the scope and the tab's own runs, stored", () => {
  it("defaults to this session; 'all' is kept, and a broken storage reads as the default", () => {
    const s = memStore();
    expect(loadScope(s)).toBe("session");
    saveScope("all", s);
    expect(s.m.get(SCOPE_KEY)).toBe("all");
    expect(loadScope(s)).toBe("all");
    saveScope("session", s);
    expect(s.m.has(SCOPE_KEY)).toBe(false);
    expect(loadScope({ getItem: () => { throw new Error("denied"); }, setItem: () => {}, removeItem: () => {} })).toBe("session");
    expect(loadScope(undefined)).toBe("session");
  });

  it("own run ids: only valid ids, no repeats, the newest OWN_RUNS_MAX; garbage reads as none", () => {
    const s = memStore({ [OWN_RUNS_KEY]: JSON.stringify([MINE, "<script>", 7, MINE, "a/b", OTHER]) });
    expect(loadOwnRuns(s)).toEqual([MINE, OTHER]);
    expect(loadOwnRuns(memStore({ [OWN_RUNS_KEY]: "{not json" }))).toEqual([]);
    expect(loadOwnRuns(memStore({ [OWN_RUNS_KEY]: '{"a":1}' }))).toEqual([]);
    const many = Array.from({ length: OWN_RUNS_MAX + 5 }, (_, n) => `r${String(n).padStart(4, "0")}`);
    saveOwnRuns(many, s);
    expect(loadOwnRuns(s)).toEqual(many.slice(-OWN_RUNS_MAX));
  });
});

describe("what this session shows", () => {
  const view = () => buildTimeline(feed(), NOW);

  it("the lists: the visitor's own runs and the one in progress; everything with 'all'", () => {
    const runs = view().runs;
    expect(scopedRuns(runs, session([MINE])).map((r) => r.runId)).toEqual([LIVE, MINE]);
    expect(scopedRuns(runs, session()).map((r) => r.runId)).toEqual([LIVE]);
    expect(scopedRuns(runs, ALL).map((r) => r.runId)).toEqual([LIVE, MINE, OTHER]);
  });

  it("the hero's run: own live, else someone's live, else own newest, else the newest as the example", () => {
    const runs = view().runs;
    expect(focusRun(runs, session([MINE]))).toMatchObject({ run: { runId: LIVE }, whose: "live" });
    expect(focusRun(runs, session([MINE, LIVE]))).toMatchObject({ run: { runId: LIVE }, whose: "own" });
    const ended = runs.filter((r) => r.runId !== LIVE);
    expect(focusRun(ended, session([MINE]))).toMatchObject({ run: { runId: MINE }, whose: "own" });
    expect(focusRun(ended, session())).toMatchObject({ run: { runId: MINE }, whose: "example" });
    expect(focusRun(ended, ALL)).toMatchObject({ run: { runId: MINE }, whose: "other" });
    expect(focusRun([], session())).toBeUndefined();
    // The example is the newest run the cluster answered, before a newer one it did not.
    let id = 100;
    const answered = buildTimeline(
      [
        ...feed(),
        toStreamEvent("run", { run_id: OTHER, scenario: "network-tool", state: "responded", at: iso(595_000), detail: "terminate" }, ++id) as StreamEvent,
      ],
      NOW,
    ).runs.filter((r) => r.runId !== LIVE);
    expect(focusRun(answered, session())).toMatchObject({ run: { runId: OTHER }, whose: "example" });
  });

  it("the incidents: own and live only; the example is the newest critical DNS exfil, never a test exec", () => {
    const c = answer([
      incident({ id: "a100000000000001", run_id: MINE }),
      incident({ id: "a200000000000002", run_id: LIVE }),
      incident({ id: "a300000000000003", run_id: OTHER }),
      incident({ id: "e100000000000001", kind: "dns-exfil", severity: "critical", last_at: iso(900_000) }),
      incident({ id: "e200000000000002", kind: "dns-exfil", severity: "critical", last_at: iso(100_000) }),
      incident({ id: "c100000000000001", kind: "staged-attack", severity: "critical", last_at: iso(10_000) }),
      incident({ id: "0b5e7a10c0ff0001", kind: "exec-outside-api", severity: "critical", operator_test: true, run_id: "", last_at: iso(1000) }),
    ]).incidents;
    expect(scopedIncidents(c, new Set([MINE]), LIVE).map((i) => i.id)).toEqual(["a100000000000001", "a200000000000002"]);
    expect(exampleIncident(c)?.id).toBe("e200000000000002");
    expect(exampleIncident(c.filter((i) => i.kind !== "dns-exfil"))?.id).toBe("c100000000000001");
    expect(exampleIncident(c.filter((i) => i.operator_test))).toBeUndefined();
    // An incident tied to no run is no visitor's: never the example, however severe or new.
    const orphan = answer([incident({ id: "e400000000000004", kind: "dns-exfil", severity: "critical", run_id: "", last_at: iso(1000) }), incident({ id: "e200000000000002", kind: "dns-exfil", severity: "critical", last_at: iso(100_000) })]).incidents;
    expect(exampleIncident(orphan)?.id).toBe("e200000000000002");
    expect(exampleIncident(orphan.filter((i) => !i.run_id))).toBeUndefined();
  });
});

describe("the run history, scoped", () => {
  const mount = () => {
    const root = document.createElement("div");
    const t = mountTimeline(root, document.createElement("div"), document.createElement("div"), () => {}, () => {});
    return { root, t };
  };
  const flush = () => new Promise((r) => setTimeout(r, 30));
  const cards = (root: HTMLElement) => [...root.querySelectorAll<HTMLElement>(".run")].map((r) => [r.dataset.run, r.dataset.who ?? "", r.querySelector(".run__who")?.textContent ?? ""]);

  it("this session: the own run and the live one, labelled; the rest counted behind the filter", async () => {
    const { root, t } = mount();
    t.setFocus(session([MINE]));
    for (const e of feed()) t.push(e);
    await flush();
    expect(cards(root)).toEqual([
      [LIVE, "live", "Someone else is attacking right now"],
      [MINE, "own", "Your run"],
    ]);
    expect(root.querySelector(".scope-hidden")?.textContent).toBe("1 run by other visitors under “All activity, last 24 h”.");
    // Everything: every run, the own and live ones still labelled, nothing said to be hidden.
    t.setFocus({ all: true, own: new Set([MINE]) });
    await flush();
    expect(cards(root).map((c) => c[0])).toEqual([LIVE, MINE, OTHER]);
    expect(cards(root)[2]).toEqual([OTHER, "", ""]);
    expect(root.querySelector(".scope-hidden")).toBeNull();
  });

  it("nothing of the visitor's and nothing live: the prompt and exactly one labelled example", async () => {
    const { root, t } = mount();
    t.setFocus(session());
    for (const e of feed().filter((e) => "run_id" in e.data && e.data.run_id !== LIVE)) t.push(e);
    await flush();
    expect(root.querySelector(".scope-empty")?.textContent).toBe("Nothing from you yet — launch an attack.");
    expect(root.querySelector(".scope-empty a")?.getAttribute("href")).toBe("#attack");
    expect(cards(root)).toEqual([[MINE, "example", "Example: an earlier visitor’s run"]]);
    expect(root.querySelector(".scope-hidden")?.textContent).toBe("1 more run by other visitors under “All activity, last 24 h”.");
  });
});

describe("the hero's card and the ticker, scoped", () => {
  it("the card says whose run it is; the example comes after the prompt", () => {
    const run = buildTimeline(feed(), NOW).runs.find((r) => r.runId === OTHER);
    if (!run) throw new Error("no run");
    const eyebrow = (whose?: "own" | "live" | "example") => renderEvidenceCard(run, { title: "Download tool", now: NOW, whose }).querySelector(".evcard__eyebrow")?.textContent;
    expect(eyebrow()).toBe("Latest attack, as recorded");
    expect(eyebrow("own")).toBe("Your latest attack, as recorded");
    expect(eyebrow("live")).toBe("Someone else is attacking right now");
    expect(eyebrow("example")).toBe("Example: an earlier visitor’s attack");
    const ex = renderEvidenceCard(run, { title: "Download tool", now: NOW, whose: "example" });
    expect(ex.querySelector(".evcard__prompt")?.textContent).toBe("Nothing from you yet — launch an attack.");
    expect(renderEvidenceCard(run, { title: "Download tool", now: NOW, whose: "own" }).querySelector(".evcard__prompt")).toBeNull();
  });

  it("the ticker: only the visitor's and the live run's events, and how many it leaves out", () => {
    const view = buildTimeline(feed(), NOW);
    const scoped = { runs: scopedRuns(view.runs, session([MINE])), unmatched: [] };
    expect(new Set(tickerItems(scoped).map((i) => i.run))).toEqual(new Set([MINE, LIVE]));
    const el = renderTicker(tickerItems(scoped), { now: NOW, connected: true, hidden: 2 });
    expect(el.querySelectorAll(".ticker__item")).toHaveLength(3);
    expect(el.querySelector(".scope-hidden")?.textContent).toBe("2 more events by other visitors under “All activity, last 24 h”.");
    const empty = renderTicker([], { now: NOW, connected: true, hidden: 5 });
    expect(empty.querySelector(".scope-empty")?.textContent).toBe("Nothing from you yet — launch an attack.");
    expect(empty.querySelector(".ticker__empty")?.textContent).toBe("No event from your runs yet; the stream is connected.");
    // Everything: the list as before, no prompt, no note.
    expect(renderTicker([], { now: NOW, connected: true }).querySelector(".scope-empty")).toBeNull();
  });
});

describe("the SIEM's board, scoped", () => {
  const titles = (el: HTMLElement) => [...el.querySelectorAll(".corr-tier__title")].map((t) => t.textContent);

  it("own and live incidents under their headings; no example then", () => {
    const c = answer([incident({ id: "a100000000000001", run_id: MINE }), incident({ id: "a200000000000002", run_id: LIVE }), incident({ id: "a300000000000003" }), incident({ id: "e300000000000003", kind: "dns-exfil", severity: "critical" })]);
    const el = renderSessionBoard(c, { ...ctx, own: new Set([MINE]), live: LIVE });
    expect(titles(el)).toEqual(["From your run on this page", "Someone else is attacking right now"]);
    expect([...el.querySelectorAll(".incident")].map((i) => i.getAttribute("data-incident"))).toEqual(["a100000000000001", "a200000000000002"]);
    expect(el.querySelector(".incident--live")?.getAttribute("data-incident")).toBe("a200000000000002");
    expect(el.querySelector(".scope-hidden")?.textContent).toBe("2 more incidents by other visitors under “All activity, last 24 h”.");
  });

  it("nothing of the visitor's: the prompt and exactly one example, labelled", () => {
    const c = answer([
      incident({ id: "a300000000000003" }),
      incident({ id: "e300000000000003", kind: "dns-exfil", severity: "critical" }),
      incident({ id: "f100000000000001", kind: "policy-probing", severity: "medium" }),
      // Neither an operator's test nor an incident tied to no run counts as another visitor's.
      incident({ id: "0b5e7a10c0ff0001", kind: "exec-outside-api", severity: "low", operator_test: true, run_id: "" }),
      incident({ id: "9001abcdef012345", kind: "policy-probing", severity: "medium", run_id: "" }),
    ]);
    const el = renderSessionBoard(c, { ...ctx, own: new Set() });
    expect(el.querySelector(".scope-empty")?.textContent).toBe("Nothing from you yet — launch an attack, or run the DNS exfiltration above.");
    expect(titles(el)).toEqual(["Example: from an earlier visitor’s run"]);
    expect([...el.querySelectorAll(".incident")].map((i) => i.getAttribute("data-incident"))).toEqual(["e300000000000003"]);
    expect(el.querySelector(".incident--example")).not.toBeNull();
    expect(el.querySelector(".scope-hidden")?.textContent).toBe("2 more incidents by other visitors under “All activity, last 24 h”.");
    // The visitor ran something the SIEM has not filed yet: the prompt says so instead.
    const waiting = renderSessionBoard(c, { ...ctx, own: new Set([MINE]) });
    expect(waiting.querySelector(".scope-empty")?.textContent).toMatch(/^Nothing filed for your runs yet/);
  });

  it("the mounted section follows setFocus: the session board, then the whole board", async () => {
    const section = document.createElement("section");
    const m = { health: document.createElement("div"), metrics: document.createElement("div"), board: document.createElement("div"), rules: document.createElement("div") };
    const c = answer([incident({ id: "a100000000000001", run_id: MINE, evidence: [{ type: "finding", id: "f-1" }] }), incident({ id: "a300000000000003" })]);
    const handle = mountCorrelation(section, m, { correlation: async () => ({ ok: true, value: c }), correlationRules: async () => ({ ok: false as const, error: "offline" as const, message: "offline" }) });
    handle.setFocus(session([MINE]));
    await new Promise((r) => setTimeout(r, 10));
    expect(m.board.querySelector(".corr-board--session")).not.toBeNull();
    expect(m.board.querySelectorAll(".incident")).toHaveLength(1);
    // The visitor opens an incident's evidence ids: they stay open when the board is redrawn.
    const fold = m.board.querySelector<HTMLDetailsElement>("details.incident__evidence");
    if (!fold) throw new Error("no evidence fold");
    fold.open = true;
    fold.dispatchEvent(new Event("toggle"));
    handle.setFocus({ all: true, own: new Set([MINE]) });
    expect(m.board.querySelector(".corr-board--session")).toBeNull();
    expect(m.board.querySelector<HTMLDetailsElement>('[data-incident="a100000000000001"] details.incident__evidence')?.open).toBe(true);
    expect(m.board.querySelector(".corr-tier--own .incident")?.getAttribute("data-incident")).toBe("a100000000000001");
    // The SOC figures say they are everyone's.
    expect(m.metrics.querySelector(".corr-metrics__title")?.textContent).toBe("SOC figures · last 24 h, all visitors");
  });
});

describe("the SIEM evidence line", () => {
  it("one line of counts by type, the ids folded as chips", () => {
    const list: { type: "correlation" | "finding"; id: string }[] = [
      { type: "correlation", id: "cyNpQ1w2E3r4T5y6U7i8" },
      { type: "finding", id: "d8006aea-0d6b-4f7e-9a51-2b7f3c4d5e6f" },
      { type: "finding", id: "e9117bfb-1e7c-4a8f-8b62-3c8a4d5e6f70" },
      { type: "finding", id: "fa228c0c-2f8d-4b90-9c73-4d9b5e6f7081" },
      { type: "finding", id: "0b339d1d-3a9e-4ca1-8d84-5eac6f708192" },
    ];
    expect(evidenceSummary(list)).toBe("1 SA correlation · 4 findings");
    expect(evidenceSummary([{ type: "document", id: "e300000000000003" }, { type: "alert", id: "f100000000000001" }, { type: "alert", id: "z" }])).toBe("1 document · 2 alerts");
    const card = renderIncident(answer([incident({ evidence: list })]).incidents[0], ctx);
    const fold = card.querySelector<HTMLDetailsElement>("details.incident__evidence");
    expect(fold?.open).toBe(false);
    expect(fold?.querySelector("summary")?.textContent).toBe("Evidence: 1 SA correlation · 4 findings show IDs");
    expect([...(fold?.querySelectorAll(".idchip code") ?? [])].map((c) => c.textContent)).toEqual(list.map((e) => e.id));
    expect(fold?.querySelector('a[href="/api/correlation"]')).not.toBeNull();
    expect(card.textContent).not.toContain("SIEM evidence:");
  });
});

describe("the control", () => {
  it("every copy moves together, the choice is kept in localStorage, and onChange hears each change", () => {
    const seen: string[] = [];
    const s = mountScope((x) => seen.push(x));
    expect(s.scope).toBe("session");
    const a = s.control("runs");
    const b = s.control("incidents");
    // Each copy is named for what it scopes.
    expect([a, b].map((c) => c.getAttribute("aria-label"))).toEqual(["Which runs to show", "Which incidents to show"]);
    const live = document.querySelector(".scope-live");
    expect(live?.getAttribute("aria-live")).toBe("polite");
    expect(live?.textContent).toBe("");
    document.body.append(a, b);
    const pressed = (el: HTMLElement) => [...el.querySelectorAll<HTMLElement>(".scope__opt")].map((o) => `${o.textContent}:${o.getAttribute("aria-pressed")}`);
    expect(pressed(a)).toEqual(["This session:true", "All activity, last 24 h:false"]);
    a.querySelector<HTMLButtonElement>('[data-scope="all"]')?.click();
    expect(pressed(b)).toEqual(["This session:false", "All activity, last 24 h:true"]);
    expect(localStorage.getItem(SCOPE_KEY)).toBe("all");
    // One polite line says what the page now shows, once per change.
    expect(live?.textContent).toBe("Showing all activity of the last 24 hours, every visitor's.");
    expect(mountScope(() => {}).scope).toBe("all");
    b.querySelector<HTMLButtonElement>('[data-scope="session"]')?.click();
    expect(localStorage.getItem(SCOPE_KEY)).toBeNull();
    expect(seen).toEqual(["all", "session"]);
    expect(live?.textContent).toBe("Showing this session: your runs and any run in progress now.");
  });
});
