// The guided tour (site redesign 2026-10-12): six steps, progress derived from the visitor's own runs
// and the SIEM's incidents for them, and the folding defaults the page ships.

import { afterEach, describe, expect, it, vi } from "vitest";
import { buildTimeline } from "../../src/lib/timeline";
import { deriveNotices, deriveProgress, mountTour, STEPS, WIDE_QUERY } from "../../src/ui/tour";
import { FOLDED_BY_DEFAULT, startsFolded } from "../../src/lib/folds";
import type { CorrelationIncident, StreamEvent } from "../../src/lib/contract";

const RUN = "aa11bb22cc33dd44";

function runOf(...cmds: { id: string; achieved?: boolean; killed?: boolean }[]) {
  const evs: StreamEvent[] = [
    { type: "run", data: { run_id: RUN, scenario: "terminal", state: "started", at: "2026-10-03T18:00:00Z", pod: "terminal-aa11bb22cc" } },
    { type: "run", data: { run_id: RUN, scenario: "terminal", state: "pod_ready", at: "2026-10-03T18:00:01Z" } },
  ];
  let seq = 1;
  let t = 2;
  for (const c of cmds) {
    const s = seq++;
    evs.push({ type: "command", data: { run_id: RUN, seq: s, id: c.id, state: "started", at: `2026-10-03T18:00:0${t++}Z` } });
    if (c.killed) {
      evs.push({ type: "command", data: { run_id: RUN, seq: s, id: c.id, state: "killed", at: `2026-10-03T18:00:0${t++}Z` } });
    } else {
      evs.push({ type: "command", data: { run_id: RUN, seq: s, id: c.id, state: "exited", at: `2026-10-03T18:00:0${t++}Z`, exit_code: 0, achieved: c.achieved === true } });
    }
  }
  return buildTimeline(evs, Date.parse("2026-10-03T18:00:30Z")).runs[0];
}

describe("tour progress is derived from real events", () => {
  it("has six steps, each with a done line", () => {
    expect(STEPS).toHaveLength(6);
    for (const s of STEPS) expect(s.done.length).toBeGreaterThan(5);
  });

  it("ticks 'look around' from a recon command; 'break something' needs both the deface and the flag", () => {
    const flagOnly = runOf({ id: "whoami", achieved: false }, { id: "read-flag", achieved: true });
    let p = deriveProgress([flagOnly], [], new Set([RUN]));
    expect(p.done.has("look")).toBe(true);
    expect(p.done.has("tamper")).toBe(false);
    expect(p.current?.id).toBe("tamper");
    const both = runOf({ id: "whoami" }, { id: "deface", achieved: true }, { id: "read-flag", achieved: true });
    p = deriveProgress([both], [], new Set([RUN]));
    expect(p.done.has("tamper")).toBe(true);
    expect(p.current?.id).toBe("hide");
  });

  it("ticks 'get caught' only for a terminal session where the shell ran and the pod was terminated", () => {
    const killed = (scenario: string, withShell: boolean): StreamEvent[] => [
      { type: "run", data: { run_id: RUN, scenario, state: "started", at: "2026-10-03T18:00:00Z", pod: "p" } },
      ...(withShell ? [{ type: "command", data: { run_id: RUN, seq: 1, id: "shell", state: "started", at: "2026-10-03T18:00:04Z" } } as StreamEvent] : []),
      { type: "falco", data: { at: "2026-10-03T18:00:05Z", rule: "Terminal shell in container", priority: "Critical", namespace: "sandbox", pod: "p", output: "x" } },
      { type: "talon", data: { at: "2026-10-03T18:00:05.5Z", action: "Terminate Pod", actionner: "kubernetes:terminate", namespace: "sandbox", pod: "p", status: "success" } },
      { type: "run", data: { run_id: RUN, scenario, state: "finished", at: "2026-10-03T18:00:06Z", detail: "killed" } },
    ];
    const at = Date.parse("2026-10-03T18:00:30Z");
    expect(deriveProgress([buildTimeline(killed("terminal", true), at).runs[0]], [], new Set([RUN])).done.has("caught")).toBe(true);
    // A one-click run the cluster killed is not the visitor getting caught in the terminal.
    expect(deriveProgress([buildTimeline(killed("shell-in-container", false), at).runs[0]], [], new Set([RUN])).done.has("caught")).toBe(false);
    // A terminal session killed without the shell having run is not step 4 either.
    expect(deriveProgress([buildTimeline(killed("terminal", false), at).runs[0]], [], new Set([RUN])).done.has("caught")).toBe(false);
  });

  it("ticks 'see it in the SIEM' only for an incident of the visitor's own run", () => {
    const run = runOf({ id: "dns-exfil", achieved: true });
    const inc = (runId: string): CorrelationIncident => ({ id: "0123456789abcdef", kind: "dns-exfil", severity: "medium", title: "", run_id: runId, arm: "", first_at: "2026-10-03T18:02:00Z", last_at: "2026-10-03T18:02:00Z", attack: [], falco_events: null, flag_match: null, operator_test: false, ttd_ms: null, tti_ms: null, steps: [], evidence: [] });
    expect(deriveProgress([run], [inc(RUN)], new Set([RUN])).done.has("siem")).toBe(true);
    expect(deriveProgress([run], [inc("ffffffffffffffff")], new Set([RUN])).done.has("siem")).toBe(false);
    // The DNS step itself ticks from the command exiting 0, before the SIEM files anything.
    expect(deriveProgress([run], [], new Set([RUN])).done.has("hide")).toBe(true);
  });
});

describe("fold defaults", () => {
  it("everything below the attack folds on a first visit; the attack stays open", () => {
    expect(FOLDED_BY_DEFAULT).not.toContain("attack");
    for (const id of ["correlation", "how", "evidence", "posture", "verify", "about", "skills", "projects"]) expect(FOLDED_BY_DEFAULT).toContain(id);
  });

  it("a stored choice wins over the default either way", () => {
    expect(startsFolded("posture", null)).toBe(true);
    expect(startsFolded("posture", "0")).toBe(false);
    expect(startsFolded("attack", null)).toBe(false);
    expect(startsFolded("attack", "1")).toBe(true);
  });
});

const INCIDENT: CorrelationIncident = { id: "0123456789abcdef", kind: "dns-exfil", severity: "critical", title: "DNS exfiltration", run_id: RUN, arm: "", first_at: "2026-10-03T18:02:00Z", last_at: "2026-10-03T18:02:00Z", attack: [], falco_events: null, flag_match: null, operator_test: false, ttd_ms: null, tti_ms: null, steps: [], evidence: [] };

function caughtRun(): ReturnType<typeof runOf> {
  const evs: StreamEvent[] = [
    { type: "run", data: { run_id: RUN, scenario: "terminal", state: "started", at: "2026-10-03T18:00:00Z", pod: "p" } },
    { type: "command", data: { run_id: RUN, seq: 1, id: "shell", state: "started", at: "2026-10-03T18:00:04Z" } },
    { type: "falco", data: { at: "2026-10-03T18:00:05Z", rule: "Terminal shell in container", priority: "Critical", namespace: "sandbox", pod: "p", output: "x" } },
    { type: "talon", data: { at: "2026-10-03T18:00:05.5Z", action: "Terminate Pod", actionner: "kubernetes:terminate", namespace: "sandbox", pod: "p", status: "success" } },
    { type: "run", data: { run_id: RUN, scenario: "terminal", state: "finished", at: "2026-10-03T18:00:06Z", detail: "killed" } },
  ];
  return buildTimeline(evs, Date.parse("2026-10-03T18:00:30Z")).runs[0];
}

describe("the notices are derived from the same evidence (amendment 2026-10-13)", () => {
  const now = Date.parse("2026-10-03T18:05:00Z");

  it("names Falco's detection, Talon's response and the SIEM's incident for the visitor's own run, newest first, with the time", () => {
    const n = deriveNotices([caughtRun()], [INCIDENT], new Set([RUN]), now);
    expect(n.map((x) => x.kind)).toEqual(["siem", "talon", "falco"]);
    expect(n[2].text).toBe("Falco detected: Terminal shell in container at 20:00:05 CEST.");
    expect(n[1].text).toBe("Talon deleted the pod at 20:00:05 CEST.");
    expect(n[0].text).toBe("The SIEM caught your DNS exfiltration — incident filed at 20:02:00 CEST.");
    expect(n[0].link).toEqual({ href: "#incident-0123456789abcdef", label: "Show in SIEM" });
    expect(n[1].link).toBeUndefined();
  });

  it("says nothing about another visitor's run or incident", () => {
    expect(deriveNotices([caughtRun()], [INCIDENT], new Set(["ffffffffffffffff"]), now)).toEqual([]);
  });

  it("is stable: the same events give the same ids, so a redraw lists nothing twice", () => {
    const a = deriveNotices([caughtRun()], [INCIDENT], new Set([RUN]), now).map((x) => x.id);
    const b = deriveNotices([caughtRun()], [INCIDENT], new Set([RUN]), now).map((x) => x.id);
    expect(a).toEqual(b);
    expect(new Set(a).size).toBe(a.length);
  });
});

describe("the tour panel never moves the page (amendment 2026-10-13)", () => {
  const scrolls: string[] = [];
  const mm = (wide: boolean) => ((q: string) => ({ matches: q === WIDE_QUERY && wide, addEventListener() {} }) as unknown as MediaQueryList);
  const hooks = (wide: boolean) => ({ onCommand: vi.fn(), onScenario: vi.fn(), onTimeline: vi.fn(), toastParent: document.body, matchMedia: mm(wide) });

  afterEach(() => {
    document.body.replaceChildren();
    scrolls.length = 0;
    vi.useRealTimers();
  });

  function mountSpies() {
    Element.prototype.scrollIntoView = function () {
      scrolls.push("scrollIntoView");
    };
    window.scrollTo = (() => scrolls.push("scrollTo")) as unknown as typeof window.scrollTo;
  }

  it("wide: a side panel with the current step expanded, done steps ticked, a notice list that is polite and in place; no scroll, no focus", () => {
    mountSpies();
    const root = document.createElement("div");
    document.body.append(root);
    const t = mountTour(root, hooks(true));
    const tour = root.querySelector(".tour") as HTMLElement;
    expect(tour.dataset.layout).toBe("side");
    expect(root.querySelector(".tour__toggle")).toBeNull();
    expect(root.querySelectorAll(".tour__step")).toHaveLength(6);
    expect(root.querySelector('.tour__step[data-current="true"] .tour__hint')).not.toBeNull();
    expect(root.querySelector('.tour__step[data-id="tamper"] .tour__hint')).toBeNull();
    const list = root.querySelector(".tour__notices") as HTMLElement;
    expect(list.getAttribute("aria-live")).toBe("polite");
    const input = document.createElement("input");
    document.body.append(input);
    input.focus();
    t.update([caughtRun()], [INCIDENT], new Set([RUN]));
    expect(root.querySelector('.tour__step[data-id="caught"]')?.getAttribute("data-done")).toBe("true");
    expect(root.querySelector('.tour__step[data-id="siem"]')?.getAttribute("data-done")).toBe("true");
    // The same list element, with the notices added, newest first; the SIEM's offers its link.
    expect(root.querySelector(".tour__notices")).toBe(list);
    expect([...list.querySelectorAll(".tour__notice")].map((el) => (el as HTMLElement).dataset.kind)).toEqual(["siem", "talon", "falco"]);
    expect(list.querySelector('.tour__notice--siem a[href="#incident-0123456789abcdef"]')?.textContent).toBe("Show in SIEM");
    // A done step offers its way there; nothing was scrolled or focused.
    expect(root.querySelector('.tour__step[data-id="siem"] a[href="#incident-0123456789abcdef"]')).not.toBeNull();
    expect(root.querySelector('.tour__step[data-id="caught"] button')?.textContent).toBe("Watch the kill timeline");
    expect(scrolls).toEqual([]);
    expect(document.activeElement).toBe(input);
    // No toast on a wide screen.
    expect(document.querySelector(".tour-toast")).toBeNull();
    // A second derivation of the same evidence adds nothing.
    t.update([caughtRun()], [INCIDENT], new Set([RUN]));
    expect(list.querySelectorAll(".tour__notice")).toHaveLength(3);
  });

  it("narrow: a folded bar with the current step's button; the steps open on the toggle; a fresh notice is a toast that auto-hides and can be dismissed", () => {
    vi.useFakeTimers();
    mountSpies();
    const root = document.createElement("div");
    document.body.append(root);
    const t = mountTour(root, hooks(false));
    const tour = root.querySelector(".tour") as HTMLElement;
    expect(tour.dataset.layout).toBe("bar");
    expect((root.querySelector("#tour-steps") as HTMLElement).hidden).toBe(true);
    expect(root.querySelector(".tour__barstep .tour__bartitle")?.textContent).toBe("Look around");
    expect(root.querySelector(".tour__barstep .tour__btn")?.textContent).toBe("Do this step");
    const toggle = root.querySelector(".tour__toggle") as HTMLButtonElement;
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    toggle.click();
    expect((root.querySelector("#tour-steps") as HTMLElement).hidden).toBe(false);
    expect((root.querySelector(".tour__toggle") as HTMLElement).getAttribute("aria-expanded")).toBe("true");
    // A notice from the past (a reload) lists, but raises no toast.
    t.update([caughtRun()], [INCIDENT], new Set([RUN]));
    expect(root.querySelectorAll(".tour__notice")).toHaveLength(3);
    expect(document.querySelector(".tour-toast")).toBeNull();
    // A fresh one does.
    const fresh = { ...INCIDENT, id: "fedcba9876543210", first_at: new Date(Date.now() - 2000).toISOString() };
    t.update([caughtRun()], [INCIDENT, fresh], new Set([RUN]));
    const toast = document.querySelector(".tour-toast") as HTMLElement;
    expect(toast.hidden).toBe(false);
    expect(toast.getAttribute("role")).toBe("status");
    expect(toast.querySelector(".tour-toast__msg")?.textContent).toMatch(/^The SIEM caught your DNS exfiltration — incident filed at /);
    expect(toast.querySelector('a[href="#incident-fedcba9876543210"]')).not.toBeNull();
    expect(scrolls).toEqual([]);
    vi.advanceTimersByTime(9_100);
    expect(toast.hidden).toBe(true);
    // Dismissed by hand.
    const fresher = { ...fresh, id: "0000000000000001", first_at: new Date(Date.now() - 1000).toISOString() };
    t.update([caughtRun()], [INCIDENT, fresh, fresher], new Set([RUN]));
    expect(toast.hidden).toBe(false);
    (toast.querySelector(".tour-toast__close") as HTMLButtonElement).click();
    expect(toast.hidden).toBe(true);
  });
});
