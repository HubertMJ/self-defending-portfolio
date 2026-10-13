// The guided tour (site redesign 2026-10-12): six steps, progress derived from the visitor's own runs
// and the SIEM's incidents for them, and the folding defaults the page ships.

import { afterEach, describe, expect, it, vi } from "vitest";
import { buildTimeline } from "../../src/lib/timeline";
import { deriveNotices, deriveProgress, mountTour, noticeText, SETTLE_MS, STEPS, twinLines, WIDE_QUERY } from "../../src/ui/tour";
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

describe("a done step's button goes to its run (2026-10-13)", () => {
  it("names the caught session and the side-by-side run; 'Show the live run' puts that run in the console", () => {
    const compare: StreamEvent[] = [
      { type: "run", data: { run_id: "bb22cc33dd44ee55", scenario: "shell-in-container", state: "started", at: "2026-10-03T18:10:00Z", pod: "g", pods: { guarded: "g", unguarded: "u" } } },
      { type: "run", data: { run_id: "bb22cc33dd44ee55", scenario: "shell-in-container", state: "finished", at: "2026-10-03T18:10:09Z", detail: "killed" } },
    ];
    const runs = [caughtRun(), buildTimeline(compare, Date.parse("2026-10-03T18:11:00Z")).runs[0]];
    const p = deriveProgress(runs, [], new Set([RUN, "bb22cc33dd44ee55"]));
    expect(p.runs.caught).toBe(RUN);
    expect(p.runs.compare).toBe("bb22cc33dd44ee55");
    expect(p.done.has("compare")).toBe(true);
    const root = document.createElement("div");
    document.body.append(root);
    const onShowRun = vi.fn();
    const t = mountTour(root, { onCommand: vi.fn(), onScenario: vi.fn(), onTimeline: vi.fn(), onShowRun, matchMedia: ((q: string) => ({ matches: q === WIDE_QUERY, addEventListener() {} }) as unknown as MediaQueryList) });
    t.update(runs, [], new Set([RUN, "bb22cc33dd44ee55"]));
    const btn = root.querySelector<HTMLButtonElement>('.tour__step[data-id="compare"] button');
    expect(btn?.getAttribute("aria-label")).toBe("Show the live run");
    btn?.click();
    expect(onShowRun).toHaveBeenCalledWith("bb22cc33dd44ee55");
    document.body.replaceChildren();
  });
});

describe("the notices are derived from the same evidence (amendment 2026-10-13)", () => {
  const now = Date.parse("2026-10-03T18:05:00Z");

  it("names Falco's detection, Talon's response and the SIEM's incident for the visitor's own run, newest first, with the time", () => {
    const n = deriveNotices([caughtRun()], [INCIDENT], new Set([RUN]));
    expect(n.map((x) => x.kind)).toEqual(["siem", "talon", "falco"]);
    expect(noticeText(n[2], now)).toBe("Falco detected: Terminal shell in container at 20:00:05 CEST.");
    expect(noticeText(n[1], now)).toBe("Talon deleted the pod at 20:00:05 CEST.");
    // The API publishes the incident's first event, not its filing: the notice dates the attack.
    expect(noticeText(n[0], now)).toBe("The SIEM caught your DNS exfiltration (first seen 20:02:00 CEST).");
    expect(n[0].link).toEqual({ href: "#incident-0123456789abcdef", label: "Show in SIEM" });
    expect(n[1].link).toBeUndefined();
    // Read on a later day, the clock carries its date.
    expect(noticeText(n[0], now + 86_400_000)).toBe("The SIEM caught your DNS exfiltration (first seen 2026-10-03 20:02:00 CEST).");
  });

  it("says nothing about another visitor's run or incident", () => {
    expect(deriveNotices([caughtRun()], [INCIDENT], new Set(["ffffffffffffffff"]))).toEqual([]);
  });

  it("is stable: the same events give the same ids, so a redraw lists nothing twice", () => {
    const a = deriveNotices([caughtRun()], [INCIDENT], new Set([RUN])).map((x) => x.id);
    const b = deriveNotices([caughtRun()], [INCIDENT], new Set([RUN])).map((x) => x.id);
    expect(a).toEqual(b);
    expect(new Set(a).size).toBe(a.length);
  });
});

describe("the tour panel never moves the page (amendment 2026-10-13)", () => {
  const scrolls: string[] = [];
  let clock = Date.parse("2026-10-03T18:05:00Z");
  const mm = (wide: boolean) => ((q: string) => ({ matches: q === WIDE_QUERY && wide, addEventListener() {} }) as unknown as MediaQueryList);
  const shows = new Set<string>();
  const hooks = (wide: boolean, below?: HTMLElement) => ({ onCommand: vi.fn(), onScenario: vi.fn(), onTimeline: vi.fn(), onShowRun: vi.fn(), showsRun: (id: string) => shows.has(id), toastParent: document.body, matchMedia: mm(wide), below, now: () => clock });

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
    // A done step offers its way there - where there is somewhere to go: the kill timeline only while
    // the terminal shows that session; nothing was scrolled or focused.
    expect(root.querySelector('.tour__step[data-id="siem"] a[href="#incident-0123456789abcdef"]')).not.toBeNull();
    expect(root.querySelector('.tour__step[data-id="caught"] button')).toBeNull();
    shows.add(RUN);
    t.update([caughtRun()], [INCIDENT], new Set([RUN]));
    const watch = root.querySelector('.tour__step[data-id="caught"] button');
    expect(watch?.getAttribute("aria-label")).toBe("Watch the kill timeline");
    expect(watch?.textContent).toBe("Timeline");
    // A done step is one line: the link sits in its title's line, no button row of its own.
    expect(watch?.closest(".tour__title")).not.toBeNull();
    shows.clear();
    expect(scrolls).toEqual([]);
    expect(document.activeElement).toBe(input);
    // No toast on a wide screen.
    expect(document.querySelector(".tour-toast")).toBeNull();
    // A second derivation of the same evidence adds nothing; a day later the clocks carry their date.
    clock += 86_400_000;
    t.update([caughtRun()], [INCIDENT], new Set([RUN]));
    expect(list.querySelectorAll(".tour__notice")).toHaveLength(3);
    expect(list.querySelector(".tour__notice--falco .tour__ntext")?.textContent).toBe("Falco detected: Terminal shell in container at 2026-10-03 20:00:05 CEST.");
    clock -= 86_400_000;
    // Skipped, the panel keeps the notices.
    (root.querySelector('[data-focus="skip"]') as HTMLButtonElement).click();
    expect(root.querySelector(".tour--skipped")).not.toBeNull();
    expect(root.querySelectorAll(".tour__step")).toHaveLength(0);
    expect(root.querySelectorAll(".tour__notice")).toHaveLength(3);
    (root.querySelector('[data-focus="skip"]') as HTMLButtonElement).click();
    expect(root.querySelectorAll(".tour__step")).toHaveLength(6);
  });

  it("the side panel shows the newest two notices; 'Earlier notices (n)' opens the rest in place; skip is a small link on the head's line", () => {
    const root = document.createElement("div");
    document.body.append(root);
    const t = mountTour(root, hooks(true));
    expect(root.querySelector(".tour__head .tour__skip")?.textContent).toBe("Skip the tour");
    t.update([caughtRun()], [INCIDENT], new Set([RUN]));
    const sec = root.querySelector(".tour__nsec") as HTMLElement;
    const more = root.querySelector(".tour__more") as HTMLButtonElement;
    expect(sec.querySelectorAll(".tour__notice")).toHaveLength(3);
    expect(sec.dataset.all).toBe("false");
    expect(more.hidden).toBe(false);
    expect(more.textContent).toBe("Earlier notices (1)");
    expect(more.getAttribute("aria-expanded")).toBe("false");
    more.click();
    expect(sec.dataset.all).toBe("true");
    expect(more.getAttribute("aria-expanded")).toBe("true");
    expect(more.textContent).toBe("Fewer notices");
    // Kept open across a redraw; no chip, no inner scroller.
    t.update([caughtRun()], [INCIDENT], new Set([RUN]));
    expect((root.querySelector(".tour__nsec") as HTMLElement).dataset.all).toBe("true");
    expect(root.querySelector(".tour__newchip")).toBeNull();
  });

  it("step 5 in the rail: blocked, its button is off and the line under it says why; free, the press launches and the launcher's words show there", () => {
    const root = document.createElement("div");
    document.body.append(root);
    const h = hooks(true);
    const t = mountTour(root, h);
    // Steps 1-4 done (a shell caught after the deface, the flag and the DNS trick): step 5 is current.
    const caught = buildTimeline(
      [
        { type: "run", data: { run_id: RUN, scenario: "terminal", state: "started", at: "2026-10-03T18:00:00Z", pod: "p" } },
        ...(["whoami", "deface", "read-flag", "dns-exfil"] as const).flatMap((id, i): StreamEvent[] => [
          { type: "command", data: { run_id: RUN, seq: i + 1, id, state: "started", at: `2026-10-03T18:00:0${i + 1}Z` } },
          { type: "command", data: { run_id: RUN, seq: i + 1, id, state: "exited", at: `2026-10-03T18:00:0${i + 1}.5Z`, exit_code: 0, achieved: true } },
        ]),
        { type: "command", data: { run_id: RUN, seq: 5, id: "shell", state: "started", at: "2026-10-03T18:00:06Z" } },
        { type: "talon", data: { at: "2026-10-03T18:00:06.5Z", action: "Terminate Pod", actionner: "kubernetes:terminate", namespace: "sandbox", pod: "p", status: "success" } },
        { type: "run", data: { run_id: RUN, scenario: "terminal", state: "finished", at: "2026-10-03T18:00:07Z", detail: "killed" } },
      ],
      Date.parse("2026-10-03T18:00:30Z"),
    ).runs[0];
    t.update([caught], [], new Set([RUN]));
    const five = () => root.querySelector('.tour__step[data-id="compare"]') as HTMLElement;
    expect(five().dataset.current).toBe("true");
    t.setLaunch({ blocked: "A run is in progress", tone: "info", text: "Another visitor’s run is in progress." });
    const btn = five().querySelector("button") as HTMLButtonElement;
    expect(btn.getAttribute("aria-disabled")).toBe("true");
    expect(five().querySelector(".tour__launch")?.textContent).toBe("A run is in progress. Another visitor’s run is in progress.");
    expect(five().querySelector(".tour__launch")?.getAttribute("aria-live")).toBe("polite");
    btn.click();
    expect(h.onScenario).not.toHaveBeenCalled();
    // Free again: the press launches; the accepted line points at the rail, not at a hidden console.
    t.setLaunch({ blocked: null, tone: "ok", text: "“Shell” queued as run 0123. Watch it play out in the live run below." });
    expect(btn.getAttribute("aria-disabled")).toBe("false");
    expect(five().querySelector(".tour__launch")?.textContent).toBe("“Shell” queued as run 0123. Both pods show here as it plays out.");
    btn.click();
    expect(h.onScenario).toHaveBeenCalledWith("shell-in-container", 5);
    // A cooldown: the reason alone (no "Rate limited." before it), the countdown beside it as a timer:
    // read with the line, never announced every second.
    t.setLaunch({ blocked: "Rate limited", tone: "warn", text: "Too many attacks.", countdown: "Unlocks in 0:42" });
    expect(five().querySelector(".tour__launch > span")?.textContent).toBe("Too many attacks.");
    expect(five().querySelector(".tour__launchcount")?.textContent).toBe(" Unlocks in 0:42");
    expect(five().querySelector(".tour__launchcount")?.getAttribute("role")).toBe("timer");
  });

  it("twinLines: the guarded pod answered in N ms, the unguarded one held for N s", () => {
    const evs: StreamEvent[] = [
      { type: "run", data: { run_id: RUN, scenario: "shell-in-container", state: "started", at: "2026-10-03T18:00:00Z", pod: "g", pods: { guarded: "g", unguarded: "u" } } },
      { type: "run", data: { run_id: RUN, scenario: "shell-in-container", state: "detected", at: "2026-10-03T18:00:02Z" } },
      { type: "falco", data: { at: "2026-10-03T18:00:02Z", rule: "Terminal shell in container", priority: "Critical", namespace: "sandbox", pod: "g", output: "x", arm: "guarded" } },
      { type: "falco", data: { at: "2026-10-03T18:00:02Z", rule: "Terminal shell in container", priority: "Critical", namespace: "sandbox-unguarded", pod: "u", output: "x", arm: "unguarded" } },
      { type: "talon", data: { at: "2026-10-03T18:00:02.2Z", action: "Terminate Pod", actionner: "kubernetes:terminate", namespace: "sandbox", pod: "g", status: "success" } },
      { type: "run", data: { run_id: RUN, scenario: "shell-in-container", state: "responded", at: "2026-10-03T18:00:02.2Z" } },
    ];
    const run = buildTimeline(evs, Date.parse("2026-10-03T18:00:10Z")).runs[0];
    const l = twinLines(run, Date.parse("2026-10-03T18:00:10Z"));
    expect(l.guarded).toBe("Falco detected it, Talon answered in 200 ms.");
    expect(l.unguarded).toMatch(/^Falco detected it, nothing answered/);
  });

  it("a redraw under the keyboard puts the focus back on the same control", () => {
    const root = document.createElement("div");
    document.body.append(root);
    const t = mountTour(root, hooks(true));
    const step = root.querySelector('.tour__step[data-current="true"] .tour__btn') as HTMLButtonElement;
    step.focus();
    expect(document.activeElement).toBe(step);
    // The feed's view arrives: the panel is redrawn, the focus is on the current step's button again.
    t.update([runOf({ id: "whoami" })], [], new Set([RUN]));
    expect(document.activeElement).not.toBe(step);
    expect((document.activeElement as HTMLElement).dataset.focus).toBe("step:tamper");
    expect(document.activeElement?.closest(".tour__step")?.getAttribute("data-current")).toBe("true");
    // The skip button too.
    (root.querySelector('[data-focus="skip"]') as HTMLButtonElement).focus();
    t.update([runOf({ id: "whoami" })], [], new Set([RUN]));
    expect((document.activeElement as HTMLElement).dataset.focus).toBe("skip");
  });

  it("narrow: a fixed bar with the current step's button; the steps open below the terminal; a fresh notice is a toast that auto-hides and can be dismissed", () => {
    vi.useFakeTimers();
    mountSpies();
    const root = document.createElement("div");
    const below = document.createElement("div");
    document.body.append(root, below);
    const t = mountTour(root, hooks(false, below));
    const tour = root.querySelector(".tour") as HTMLElement;
    expect(tour.dataset.layout).toBe("bar");
    const panel = below.querySelector("#tour-steps") as HTMLElement;
    expect(panel).not.toBeNull();
    expect(panel.hidden).toBe(true);
    expect(root.querySelector("#tour-steps")).toBeNull();
    expect(root.querySelector(".tour__barstep .tour__bartitle")?.textContent).toBe("Look around");
    expect(root.querySelector(".tour__barstep .tour__btn")?.textContent).toBe("Do this step");
    const toggle = root.querySelector(".tour__toggle") as HTMLButtonElement;
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    expect(toggle.getAttribute("aria-controls")).toBe("tour-steps");
    toggle.focus();
    toggle.click();
    expect(panel.hidden).toBe(false);
    expect(panel.querySelectorAll(".tour__step")).toHaveLength(6);
    expect((root.querySelector(".tour__toggle") as HTMLElement).getAttribute("aria-expanded")).toBe("true");
    expect((document.activeElement as HTMLElement).dataset.focus).toBe("toggle");
    // What the page lists in its first seconds is what it knew (a reload): no toast, whatever the age.
    const justNow = { ...INCIDENT, id: "fedcba9876543210", first_at: new Date(clock - 2000).toISOString() };
    t.update([caughtRun()], [justNow], new Set([RUN]));
    expect(panel.querySelectorAll(".tour__notice")).toHaveLength(3);
    expect(document.querySelector(".tour-toast")).toBeNull();
    // Later, a new notice is news - even one the SIEM dates minutes back, as it files late.
    clock += SETTLE_MS + 1000;
    const late = { ...INCIDENT, id: "0000000000000001", first_at: new Date(clock - 180_000).toISOString() };
    t.update([caughtRun()], [justNow, late], new Set([RUN]));
    const toast = document.querySelector(".tour-toast") as HTMLElement;
    expect(toast.hidden).toBe(false);
    expect(toast.getAttribute("role")).toBe("status");
    expect(toast.querySelector(".tour-toast__msg")?.textContent).toMatch(/^The SIEM caught your DNS exfiltration \(first seen /);
    expect(toast.querySelector('a[href="#incident-0000000000000001"]')).not.toBeNull();
    expect(scrolls).toEqual([]);
    vi.advanceTimersByTime(9_100);
    expect(toast.hidden).toBe(true);
    // Dismissed by hand.
    const later = { ...late, id: "0000000000000002" };
    t.update([caughtRun()], [justNow, late, later], new Set([RUN]));
    expect(toast.hidden).toBe(false);
    (toast.querySelector(".tour-toast__close") as HTMLButtonElement).click();
    expect(toast.hidden).toBe(true);
    // Every step done: the bar keeps its line.
    expect(root.querySelector(".tour__barstep")).not.toBeNull();
  });

  it("narrow: the first correlation answer, however late after a reload, lists its incidents without a toast; the next incident is news", () => {
    vi.useFakeTimers();
    const root = document.createElement("div");
    const below = document.createElement("div");
    document.body.append(root, below);
    const t = mountTour(root, hooks(false, below));
    // The feed's replay came at once; the SIEM's answer only well past the settling window.
    t.update([caughtRun()], [], new Set([RUN]));
    clock += SETTLE_MS + 30_000;
    t.update([caughtRun()], [INCIDENT], new Set([RUN]));
    expect(below.querySelectorAll(".tour__notice--siem")).toHaveLength(1);
    expect(document.querySelector(".tour-toast")).toBeNull();
    // A Talon notice arriving now would be news (the feed was heard at once); so is the next incident.
    const next = { ...INCIDENT, id: "0000000000000003" };
    t.update([caughtRun()], [INCIDENT, next], new Set([RUN]));
    const toast = document.querySelector(".tour-toast") as HTMLElement;
    expect(toast.hidden).toBe(false);
    expect(toast.querySelector('a[href="#incident-0000000000000003"]')).not.toBeNull();
  });
});
