import { describe, expect, it } from "vitest";
import { humanSpeed } from "../../src/ui/console";
import { LAYERS, litFromCommands, renderDefenceMap } from "../../src/ui/defencemap";
import { renderStats } from "../../src/ui/stats";
import { stats, TERMINAL_COMMANDS, TERMINAL_OBJECTIVES } from "../../src/lib/fixtures";

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

  it("litFromCommands keeps the strongest verdict per layer and collects the inputs", () => {
    const lit = litFromCommands([
      { layer: "runtime", outcome: "allowed", control: "watched", input: "id" },
      { layer: "runtime", outcome: "detected", control: "Falco → Talon", input: "cat /etc/shadow" },
      { layer: "pod-security", outcome: "prevented", control: "read-only", input: "touch /bin/x" },
    ]);
    expect(lit.get("runtime")?.outcome).toBe("detected");
    expect(lit.get("runtime")?.control).toBe("Falco → Talon");
    expect(lit.get("runtime")?.inputs).toEqual(["id", "cat /etc/shadow"]);
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
  it("shows counters, the call-home line and objectives, naming the never-reached ones", () => {
    const el = renderStats(stats(), TERMINAL_OBJECTIVES);
    expect(el.textContent).toContain("attacks launched");
    // The owner's example: call-homes that got out of 412 network-tool runs.
    expect(el.textContent).toMatch(/of 412/);
    const never = [...el.querySelectorAll('.herostats__obj[data-never="true"]')];
    expect(never.length).toBeGreaterThan(0);
    expect(never[0].textContent).toContain("not reached by anyone yet");
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
