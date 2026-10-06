// The visitor's own run told back (lib/runstatus.ts): the status strip's state machine, the SIEM
// scenario's state chip and the "This run" panel's SIEM row, driven by run events in the API's shapes
// (fed through the same parser and timeline the page uses) and incidents in GET /api/correlation's.

import { describe, expect, it } from "vitest";
import { type CorrelationIncident, type StreamEvent, toStreamEvent } from "../../src/lib/contract";
import { TERMINAL_COMMANDS } from "../../src/lib/fixtures";
import { SIEM_WAIT_MS, StripTracker, lastAlert, lastResponse, paletteTone, runEndsWithin, scenarioState, siemPending, siemRow } from "../../src/lib/runstatus";
import { type RunView, buildTimeline } from "../../src/lib/timeline";

const RUN = "4f1c2a9e8b7d6c5a";
const OTHER = "0a0b0c0d0e0f1011";
const POD = "terminal-4f1c2a9e8b";
const T0 = Date.parse("2026-10-06T08:00:00Z");

class Feed {
  events: StreamEvent[] = [];
  private id = 1;
  constructor(readonly runId = RUN) {}
  private push(type: string, data: Record<string, unknown>) {
    const ev = toStreamEvent(type, data, ++this.id);
    if (!ev) throw new Error(`bad ${type}`);
    this.events.push(ev);
    return this;
  }
  at = (ms: number) => new Date(T0 + ms).toISOString();
  run(state: string, ms: number, detail = "", extra: Record<string, unknown> = {}) {
    return this.push("run", { run_id: this.runId, scenario: "terminal", state, at: this.at(ms), detail, ...(state === "queued" ? {} : { pod: POD }), ...extra });
  }
  cmd(seq: number, id: string, state: string, ms: number, extra: Record<string, unknown> = {}) {
    return this.push("command", { run_id: this.runId, seq, id, state, at: this.at(ms), ...extra });
  }
  ran(seq: number, id: string, ms: number, code: number) {
    return this.cmd(seq, id, "started", ms).cmd(seq, id, "exited", ms + 40, { exit_code: code });
  }
  falco(ms: number, rule: string, seq: number) {
    return this.push("falco", { at: this.at(ms), rule, priority: "Warning", namespace: "sandbox", pod: POD, output: rule, command_seq: seq });
  }
  talon(ms: number, action: "terminate" | "label", seq: number) {
    return this.push("talon", { at: this.at(ms), action: action === "terminate" ? "Terminate Pod" : "Quarantine Pod", actionner: `kubernetes:${action}`, namespace: "sandbox", pod: POD, status: "success", command_seq: seq });
  }
  open() {
    return this.run("queued", 0).run("started", 40, "pod created").run("pod_ready", 1900, "9b2e7c4d1a0f");
  }
  view(): RunView | undefined {
    return buildTimeline(this.events, T0 + 60_000).runs.find((r) => r.runId === this.runId);
  }
}

function incident(over: Partial<CorrelationIncident> & { id: string; kind: string }): CorrelationIncident {
  return {
    severity: "high",
    title: "",
    run_id: RUN,
    arm: "",
    first_at: new Date(T0).toISOString(),
    last_at: new Date(T0 + 1000).toISOString(),
    attack: [],
    falco_events: 0,
    flag_match: null,
    operator_test: false,
    ttd_ms: null,
    tti_ms: null,
    steps: [],
    evidence: [],
    ...over,
  };
}

const facts = (f: Feed | undefined, extra: Partial<Parameters<StripTracker["update"]>[0]> = {}) => ({
  runId: RUN,
  run: f?.view(),
  commands: TERMINAL_COMMANDS,
  idleSeconds: 90,
  incidents: [] as CorrelationIncident[],
  siem: "available" as const,
  now: T0 + 30_000,
  ...extra,
});
const line = (s: ReturnType<StripTracker["update"]>) => (s ? `${s.lead}${s.text}` : null);

describe("the status strip (REPORT point 3)", () => {
  it("says nothing without a session of the visitor's own", () => {
    expect(new StripTracker().update({ ...facts(undefined), runId: undefined })).toBeNull();
  });

  it("starting, then a visible ready moment", () => {
    const t = new StripTracker();
    expect(line(t.update(facts(undefined)))).toBe("Pod starting… The input unlocks when it is ready, in a few seconds.");
    const f = new Feed().open();
    const s = t.update(facts(f));
    expect(line(s)).toBe("Pod ready. uid 10001, no network, read-only root. Type a command.");
    expect(s?.toast).toBe(false);
  });

  it("a command Falco allows changes nothing; an alert says which rule, timed from the Enter", () => {
    const t = new StripTracker();
    const f = new Feed().open();
    t.update(facts(f));
    f.ran(1, "whoami", 3000, 0);
    expect(t.update(facts(f))?.kind).toBe("ready");
    f.cmd(2, "read-shadow", "started", 5000).falco(5443, "Read sensitive file untrusted", 2).run("detected", 5450, "Read sensitive file untrusted", { command_seq: 2 });
    const s = t.update(facts(f));
    expect(line(s)).toBe("Falco saw that — Read sensitive file untrusted at +443 ms");
    expect(s?.toast).toBe(true);
  });

  it("Talon's delete ends it: how long after the alert, the session over, the timeline and run-again buttons", () => {
    const t = new StripTracker();
    const f = new Feed().open();
    t.update(facts(f));
    f.cmd(1, "read-shadow", "started", 5000).falco(5443, "Read sensitive file untrusted", 1);
    t.update(facts(f));
    f.cmd(1, "read-shadow", "exited", 5450, { exit_code: 0, achieved: true }).run("responded", 5455, "terminate", { command_seq: 1 }).run("finished", 5600, "killed");
    const s = t.update(facts(f));
    expect(line(s)).toBe("Talon deleted the pod 12 ms later. Session over.");
    expect(s?.actions).toEqual(["timeline", "again"]);
  });

  it("a quarantine keeps the shell and says the network is cut", () => {
    const t = new StripTracker();
    const f = new Feed().open();
    t.update(facts(f));
    f.cmd(1, "beacon", "started", 4000).falco(4100, "SDP network tool in sandbox", 1).run("responded", 4130, "quarantine", { command_seq: 1 });
    expect(line(t.update(facts(f)))).toBe("Talon quarantined the pod 30 ms later. You keep the shell, but its network is cut both ways.");
  });

  it("DNS exfil: waiting for the SIEM; a kill meanwhile shows with the wait as a note; the incident replaces both", () => {
    const t = new StripTracker();
    const f = new Feed().open();
    t.update(facts(f));
    f.ran(1, "dns-exfil", 3000, 0);
    const wait = t.update(facts(f));
    expect(line(wait)).toBe("Waiting for the SIEM (usually 1–3 min)…");
    expect(wait?.tone).toBe("pending");
    f.cmd(2, "read-shadow", "started", 6000).falco(6400, "Read sensitive file untrusted", 2).run("responded", 6420, "terminate", { command_seq: 2 }).run("finished", 6500, "killed");
    const killed = t.update(facts(f));
    expect(killed?.kind).toBe("killed");
    expect(killed?.note).toBe("Still waiting for the SIEM on your DNS exfil (usually 1–3 min)…");
    const exfil = incident({ id: "7e57000000000001", kind: "dns-exfil", severity: "critical" });
    const found = t.update(facts(f, { incidents: [exfil] }));
    expect(line(found)).toBe("The SIEM caught your DNS exfil — CRITICAL. Falco never saw it.");
    expect(found?.incidentId).toBe("7e57000000000001");
    expect(found?.actions).toEqual(["open", "again"]);
    expect(found?.note).toBeUndefined();
  });

  it("a milder filing landing later does not replace a more severe one; the strip says there is more", () => {
    const t = new StripTracker();
    const f = new Feed().open().ran(1, "dns-exfil", 3000, 0);
    f.cmd(2, "read-shadow", "started", 6000).falco(6400, "Read sensitive file untrusted", 2).run("responded", 6420, "terminate", { command_seq: 2 }).run("finished", 6500, "killed");
    const exfil = incident({ id: "7e57000000000001", kind: "dns-exfil", severity: "critical" });
    t.update(facts(f, { incidents: [exfil] }));
    const both = t.update(facts(f, { incidents: [incident({ id: "7e57000000000002", kind: "contained-intrusion" }), exfil] }));
    expect(both?.incidentId).toBe("7e57000000000001");
    expect(both?.note).toBe("The SIEM filed 1 more incident for this run on the board below.");
  });

  it("an incident of another run is not the visitor's", () => {
    const t = new StripTracker();
    const f = new Feed().open().ran(1, "dns-exfil", 3000, 0);
    const s = t.update(facts(f, { incidents: [incident({ id: "7e57000000000009", kind: "dns-exfil", severity: "critical", run_id: OTHER })] }));
    expect(s?.kind).toBe("siem-waiting");
  });

  it("a contained intrusion is filed with its severity and kind", () => {
    const t = new StripTracker();
    const f = new Feed().open().cmd(1, "read-shadow", "started", 5000).falco(5400, "Read sensitive file untrusted", 1).run("responded", 5420, "terminate", { command_seq: 1 }).run("finished", 5500, "killed");
    t.update(facts(f));
    expect(line(t.update(facts(f, { incidents: [incident({ id: "7e57000000000002", kind: "contained-intrusion" })] })))).toBe("The SIEM filed this as HIGH — Contained intrusion");
  });

  it("a replay seen all at once shows the biggest news, not the first state", () => {
    const f = new Feed().open().cmd(1, "read-shadow", "started", 5000).falco(5400, "Read sensitive file untrusted", 1).run("responded", 5420, "terminate", { command_seq: 1 }).run("finished", 5500, "killed");
    expect(new StripTracker().update(facts(f))?.kind).toBe("killed");
  });

  it("late after the usual wait, and honest when the SIEM is down", () => {
    const f = new Feed().open().ran(1, "dns-exfil", 3000, 0);
    expect(new StripTracker().update(facts(f, { now: T0 + 3040 + SIEM_WAIT_MS + 1 }))?.kind).toBe("siem-late");
    expect(line(new StripTracker().update(facts(f, { siem: "unavailable" })))).toBe("The SIEM is not reachable right now, so nothing on this page can tie your DNS query to this run.");
  });

  it("the end of a session for another reason says which, with run-again", () => {
    const f = new Feed().open().run("finished", 92_000, "idle");
    const s = new StripTracker().update(facts(f));
    expect(line(s)).toBe("Session over — it ended after 90 s without a command.");
    expect(s?.actions).toEqual(["again"]);
  });

  it("a new session starts from nothing: the last session's incident is not carried over", () => {
    const t = new StripTracker();
    const f = new Feed().open().ran(1, "dns-exfil", 3000, 0);
    t.update(facts(f, { incidents: [incident({ id: "7e57000000000001", kind: "dns-exfil", severity: "critical" })] }));
    const next = new Feed(OTHER).open();
    expect(t.update({ ...facts(next), runId: OTHER, incidents: [incident({ id: "7e57000000000001", kind: "dns-exfil", severity: "critical" })] })?.kind).toBe("ready");
  });
});

describe("the SIEM scenario's state chip (REPORT point 1)", () => {
  const state = (f: Feed | undefined, extra: Partial<Parameters<typeof scenarioState>[0]> = {}) =>
    scenarioState({ run: f?.view(), incidents: [], ownRuns: f ? [f.runId] : [], siem: "available", now: T0 + 30_000, ...extra });

  it("not run → running → waiting → found it, the incident matched by the run's id", () => {
    expect(state(undefined).phase).toBe("idle");
    const f = new Feed().open();
    expect(state(f).phase).toBe("idle");
    f.cmd(1, "dns-exfil", "started", 3000);
    expect(state(f).phase).toBe("running");
    f.cmd(1, "dns-exfil", "exited", 3200, { exit_code: 0, achieved: true });
    expect(state(f).phase).toBe("waiting");
    expect(state(f, { incidents: [incident({ id: "7e57000000000009", kind: "dns-exfil", run_id: OTHER })] }).phase).toBe("waiting");
    expect(state(f, { incidents: [incident({ id: "7e57000000000001", kind: "dns-exfil", severity: "critical" })] })).toEqual({ phase: "found", incidentId: "7e57000000000001", severity: "critical" });
  });

  it("a query that did not go out, a SIEM that is late or down", () => {
    expect(state(new Feed().open().ran(1, "dns-exfil", 3000, 1)).phase).toBe("failed");
    const ok = new Feed().open().ran(1, "dns-exfil", 3000, 0);
    expect(state(ok, { now: T0 + 3040 + SIEM_WAIT_MS + 1 }).phase).toBe("late");
    expect(state(ok, { siem: "unavailable" }).phase).toBe("down");
  });

  it("with no exfil in this session, an earlier session's incident of this page view still counts", () => {
    const now = new Feed(OTHER).open();
    expect(state(now, { ownRuns: [RUN, OTHER], incidents: [incident({ id: "7e57000000000001", kind: "dns-exfil" })] }).phase).toBe("found");
    expect(state(now, { ownRuns: [OTHER], incidents: [incident({ id: "7e57000000000001", kind: "dns-exfil" })] }).phase).toBe("idle");
  });
});

describe("the This-run panel's SIEM row and the eager poll", () => {
  it("nothing to correlate, waiting, filed", () => {
    const quiet = new Feed().open().ran(1, "whoami", 3000, 0);
    const base = { commands: TERMINAL_COMMANDS, incidents: [] as CorrelationIncident[], siem: "available" as const, now: T0 + 30_000 };
    expect(siemRow({ ...base, run: quiet.view() }).text).toBe("nothing to correlate yet");
    expect(siemPending({ ...base, run: quiet.view() })).toBe(false);
    const exfil = new Feed().open().ran(1, "dns-exfil", 3000, 0);
    expect(siemRow({ ...base, run: exfil.view() })).toEqual({ text: "waiting… (usually 1–3 min)", tone: "pending" });
    expect(siemPending({ ...base, run: exfil.view() })).toBe(true);
    const filed = [incident({ id: "7e57000000000001", kind: "dns-exfil", severity: "critical" })];
    expect(siemRow({ ...base, run: exfil.view(), incidents: filed })).toEqual({ text: "CRITICAL — DNS exfiltration", tone: "siem", incidentId: "7e57000000000001" });
    expect(siemPending({ ...base, run: exfil.view(), incidents: filed })).toBe(false);
  });

  it("a prevented command expects a filing too", () => {
    const f = new Feed().open().ran(1, "touch-bin", 3000, 1);
    expect(siemRow({ run: f.view(), commands: TERMINAL_COMMANDS, incidents: [], siem: "available", now: T0 + 30_000 }).tone).toBe("pending");
  });
});

describe("helpers", () => {
  it("palette tones: grey allowed, red detected, amber prevented, green when only the SIEM sees it", () => {
    const tone = (id: string) => paletteTone(TERMINAL_COMMANDS.find((c) => c.id === id)!);
    expect([tone("whoami"), tone("read-shadow"), tone("touch-bin"), tone("dns-exfil")]).toEqual(["allowed", "detected", "prevented", "siem"]);
  });

  it("the alert and the response, each timed from what caused it", () => {
    const f = new Feed().open().cmd(1, "read-shadow", "started", 5000).falco(5443, "Read sensitive file untrusted", 1).talon(5460, "terminate", 1);
    const run = f.view()!;
    expect(lastAlert(run)).toEqual({ rule: "Read sensitive file untrusted", at: T0 + 5443, afterEnterMs: 443 });
    expect(lastResponse(run)).toEqual({ action: "terminate", at: T0 + 5460, afterAlertMs: 17 });
  });

  it("the busy slot ends at the sooner of the deadline and the idle limit", () => {
    const run = new Feed().open().ran(1, "whoami", 10_000, 0).view()!;
    expect(runEndsWithin(run, T0 + 20_000, 300, 90)).toBe(80_000);
    expect(runEndsWithin(run, T0 + 20_000, 300)).toBe(280_000);
    expect(runEndsWithin(run, T0 + 400_000, 300, 90)).toBe(0);
    expect(runEndsWithin(run, T0, undefined, undefined)).toBeUndefined();
  });
});
