// The guided tour (site redesign 2026-10-12): six steps, progress derived from the visitor's own runs
// and the SIEM's incidents for them, and the folding defaults the page ships.

import { describe, expect, it } from "vitest";
import { buildTimeline } from "../../src/lib/timeline";
import { deriveProgress, STEPS } from "../../src/ui/tour";
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

  it("ticks 'look around' from a recon command, 'break something' from the flag", () => {
    const run = runOf({ id: "whoami", achieved: false }, { id: "read-flag", achieved: true });
    const p = deriveProgress([run], [], new Set([RUN]));
    expect(p.done.has("look")).toBe(true);
    expect(p.done.has("tamper")).toBe(true);
    expect(p.done.has("hide")).toBe(false);
    expect(p.current?.id).toBe("hide");
  });

  it("ticks 'get caught' when a run of the visitor's was terminated", () => {
    const evs: StreamEvent[] = [
      { type: "run", data: { run_id: RUN, scenario: "terminal", state: "started", at: "2026-10-03T18:00:00Z", pod: "p" } },
      { type: "falco", data: { at: "2026-10-03T18:00:05Z", rule: "Terminal shell in container", priority: "Critical", namespace: "sandbox", pod: "p", output: "x" } },
      { type: "talon", data: { at: "2026-10-03T18:00:05.5Z", action: "Terminate Pod", actionner: "kubernetes:terminate", namespace: "sandbox", pod: "p", status: "success" } },
      { type: "run", data: { run_id: RUN, scenario: "terminal", state: "finished", at: "2026-10-03T18:00:06Z", detail: "killed" } },
    ];
    const run = buildTimeline(evs, Date.parse("2026-10-03T18:00:30Z")).runs[0];
    expect(deriveProgress([run], [], new Set([RUN])).done.has("caught")).toBe(true);
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
