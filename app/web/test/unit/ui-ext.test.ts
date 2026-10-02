import { describe, expect, it } from "vitest";
import { humanSpeed } from "../../src/ui/console";
import { LAYERS, litFromCommands, renderDefenceMap } from "../../src/ui/defencemap";
import { renderStats } from "../../src/ui/stats";
import { stats, TERMINAL_COMMANDS, TERMINAL_OBJECTIVES } from "../../src/lib/fixtures";
import { isCommandEvent, parseStats, parseStreamEvent } from "../../src/lib/contract";
import { buildTimeline } from "../../src/lib/timeline";

describe("command events (ADR 0029 wire format)", () => {
  it("accepts a well-formed command event and rejects a malformed one", () => {
    expect(isCommandEvent({ run_id: "r", seq: 1, id: "whoami", state: "started", at: "t" })).toBe(true);
    expect(isCommandEvent({ run_id: "r", seq: "x", id: "whoami", state: "started", at: "t" })).toBe(false);
    expect(parseStreamEvent("command", JSON.stringify({ run_id: "r", seq: 2, id: "x", state: "nope", at: "t" }))).toBeNull();
  });

  it("scrubs control characters, carriage returns and bidi/zero-width format characters from output", () => {
    const raw = "ok\r\n\u001b[31mred\u001b[0m‮evil‬​zero\tflag=SDP{0123456789abcdef}";
    const ev = parseStreamEvent("command", JSON.stringify({ run_id: "r", seq: 1, id: "x", state: "output", at: "t", stream: "stdout", chunk: raw }));
    if (ev?.type !== "command") throw new Error("expected a command event");
    const chunk = ev.data.chunk ?? "";
    expect(chunk).not.toMatch(/[\u001b\r‮‬​]/);
    expect(chunk).toContain("SDP{0123456789abcdef}");
    expect(chunk).toContain("\t"); // tab is kept
  });

  it("caps a command chunk at 1024 characters and keeps the truncated flag", () => {
    const ev = parseStreamEvent("command", JSON.stringify({ run_id: "r", seq: 1, id: "x", state: "output", at: "t", stream: "stdout", chunk: "a".repeat(5000), truncated: true }));
    if (ev?.type !== "command") throw new Error("expected a command event");
    expect((ev.data.chunk ?? "").length).toBe(1024);
    expect(ev.data.truncated).toBe(true);
  });
});

describe("timeline assembles a terminal run's commands", () => {
  it("groups command events by seq into ordered CommandRuns with accumulated output", () => {
    const at = (ms: number) => new Date(1_000_000 + ms).toISOString();
    const evs = [
      { type: "run", data: { run_id: "r", scenario: "terminal", state: "started", at: at(0), pod: "p" } },
      { type: "command", data: { run_id: "r", seq: 1, id: "whoami", state: "started", at: at(10) } },
      { type: "command", data: { run_id: "r", seq: 1, id: "whoami", state: "output", stream: "stdout", chunk: "uid=10001\n", at: at(20) } },
      { type: "command", data: { run_id: "r", seq: 1, id: "whoami", state: "exited", exit_code: 0, achieved: true, at: at(30) } },
    ].map((e) => parseStreamEvent(e.type, JSON.stringify(e.data))!);
    const view = buildTimeline(evs);
    const run = view.runs[0];
    expect(run.commands).toHaveLength(1);
    expect(run.commands[0]).toMatchObject({ seq: 1, id: "whoami", stdout: "uid=10001\n", exitCode: 0, achieved: true, killed: false });
  });
});

describe("parseStats", () => {
  it("ignores inherited properties and fills missing sections", () => {
    const s = parseStats({ objectives: { recon: { attempts: 3, achieved: 2 } } });
    expect(s.objectives.recon).toEqual({ attempts: 3, achieved: 2 });
    // A prototype key must not leak in as "undefined of undefined".
    expect(Object.prototype.hasOwnProperty.call(s.objectives, "constructor")).toBe(false);
    expect(s.runs).toBe(0);
    expect(s.response_ms).toEqual({ last: 0, p50: 0, min: 0, max: 0 });
  });
});

describe("humanSpeed (FIX 3)", () => {
  it("anchors fast times on a blink and degrades sensibly", () => {
    expect(humanSpeed(30)).toMatch(/blink/);
    expect(humanSpeed(100)).toMatch(/blink/);
    expect(humanSpeed(300)).toMatch(/shutter/);
    expect(humanSpeed(700)).toMatch(/under a second/);
    expect(humanSpeed(2000)).toMatch(/couple of seconds/);
    expect(humanSpeed(9000)).toMatch(/slower than it should/);
  });
});

describe("defence map (ADR 0033, D)", () => {
  it("has the seven layers in depth order", () => {
    expect(LAYERS.map((l) => l.id)).toEqual(["edge", "host", "network", "supply-chain", "admission", "pod-security", "runtime"]);
  });

  it("litFromCommands lists each command under its layer with its own verdict; strongest colours the card", () => {
    const lit = litFromCommands([
      { layer: "runtime", outcome: "allowed", control: "watched", input: "id" },
      { layer: "runtime", outcome: "detected", control: "Falco → Talon", input: "cat /etc/shadow", ended: true },
      { layer: "pod-security", outcome: "prevented", control: "read-only", input: "touch /bin/x" },
    ]);
    expect(lit.get("runtime")?.outcome).toBe("detected");
    expect(lit.get("runtime")?.entries.map((e) => [e.input, e.outcome, e.ended])).toEqual([
      ["id", "allowed", false],
      ["cat /etc/shadow", "detected", true],
    ]);
    expect(lit.get("pod-security")?.outcome).toBe("prevented");
  });

  it("renders all seven layers; in result mode the out-of-reach ones say so", () => {
    const lit = litFromCommands([{ layer: "runtime", outcome: "detected", control: "Falco → Talon", input: "sh -i" }]);
    const el = renderDefenceMap({ lit });
    expect(el.querySelectorAll(".deflayer")).toHaveLength(7);
    expect(el.querySelector('.deflayer[data-layer="runtime"]')?.getAttribute("data-state")).toBe("detected");
    expect(el.querySelector('.deflayer[data-layer="edge"]')?.getAttribute("data-state")).toBe("out-of-reach");
    expect(el.querySelector('.deflayer[data-layer="edge"]')?.textContent).toContain("never reached");
  });

  it("renders text only — a layer control that looked like markup stays text", () => {
    const el = renderDefenceMap({});
    expect(el.querySelector("script")).toBeNull();
    expect(el.querySelectorAll(".deflayer")).toHaveLength(7);
  });
});

describe("hero stats (ADR 0033, E+F)", () => {
  it("shows counters and objectives, naming the never-reached ones, with no escapes counter", () => {
    const el = renderStats(stats(), TERMINAL_OBJECTIVES);
    expect(el.textContent).toContain("attacks");
    expect(el.textContent).toContain("detections answered");
    const never = [...el.querySelectorAll('.herostats__obj[data-never="true"]')];
    expect(never.length).toBeGreaterThan(0);
    expect(never.some((n) => /not reached yet/.test(n.textContent ?? ""))).toBe(true);
    // The contract rules out an escapes/"got out" counter (review item 18).
    expect(el.textContent).not.toMatch(/got out|call-home|escap/i);
  });

  it("shows the last real run when one is given", () => {
    const el = renderStats(stats(), TERMINAL_OBJECTIVES, { title: "Download tool in a container", at: Date.now() - 5000, respondMs: 142 });
    expect(el.textContent).toContain("last run");
    expect(el.textContent).toContain("Download tool in a container");
    expect(el.textContent).toContain("142 ms");
  });
});

describe("terminal catalogue (fixture follows the contract)", () => {
  it("has 12–16 commands with stable ids and the required outcome classes", () => {
    expect(TERMINAL_COMMANDS.length).toBeGreaterThanOrEqual(12);
    expect(TERMINAL_COMMANDS.length).toBeLessThanOrEqual(16);
    for (const c of TERMINAL_COMMANDS) expect(c.id).toMatch(/^[a-z0-9-]{1,32}$/);
    const outcomes = new Set(TERMINAL_COMMANDS.map((c) => c.outcome));
    expect(outcomes).toEqual(new Set(["allowed", "prevented", "detected"]));
    // Every detected command names its detection rule and a response; quarantine and terminate both appear.
    const detected = TERMINAL_COMMANDS.filter((c) => c.outcome === "detected");
    expect(detected.every((c) => c.detection && c.response)).toBe(true);
    expect(new Set(detected.map((c) => c.response))).toEqual(new Set(["quarantine", "terminate"]));
  });

  it("every command input is unique and <= 80 printable ASCII", () => {
    const inputs = TERMINAL_COMMANDS.map((c) => c.input);
    expect(new Set(inputs).size).toBe(inputs.length);
    for (const i of inputs) {
      expect(i.length).toBeLessThanOrEqual(80);
      expect(i).toMatch(/^[\x20-\x7e]+$/);
    }
  });
});
