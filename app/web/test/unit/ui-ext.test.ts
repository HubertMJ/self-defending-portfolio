import { describe, expect, it, vi } from "vitest";
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

describe("timeline backfill dedup (review item 8)", () => {
  it("drops an event it already has, so a backfill never double-counts output", async () => {
    const { mountTimeline } = await import("../../src/ui/timeline");
    const root = document.createElement("div");
    const conn = document.createElement("div");
    const live = document.createElement("div");
    let latest: import("../../src/lib/timeline").TimelineView | undefined;
    const handle = mountTimeline(root, conn, live, (v) => (latest = v), () => {});
    const evs = [
      { type: "run", data: { run_id: "r", scenario: "terminal", state: "started", at: "2026-10-02T00:00:00.000Z", pod: "p" } },
      { type: "command", data: { run_id: "r", seq: 1, id: "whoami", state: "output", stream: "stdout", chunk: "uid=10001\n", at: "2026-10-02T00:00:01.000Z" } },
    ].map((e) => parseStreamEvent(e.type, JSON.stringify(e.data))!);
    for (const e of evs) handle.push(e);
    // Push the identical command event again (as a backfill from /api/runs/{id} would).
    handle.push(evs[1]);
    await new Promise((r) => setTimeout(r, 30));
    const run = latest?.runs.find((x) => x.runId === "r");
    expect(run?.commands[0].stdout).toBe("uid=10001\n"); // once, not twice
  });

  it("keeps two identical lines of output that are two events (two ids), and drops a replayed id", async () => {
    const { mountTimeline } = await import("../../src/ui/timeline");
    const root = document.createElement("div");
    let latest: import("../../src/lib/timeline").TimelineView | undefined;
    const handle = mountTimeline(root, document.createElement("div"), document.createElement("div"), (v) => (latest = v), () => {});
    const at = "2026-10-02T00:00:01.000Z";
    const line = { run_id: "r", seq: 1, id: "ps", state: "output", stream: "stdout", chunk: "same\n", at };
    handle.push(parseStreamEvent("run", JSON.stringify({ run_id: "r", scenario: "terminal", state: "started", at: "2026-10-02T00:00:00.000Z", pod: "p" }), "1")!);
    handle.push(parseStreamEvent("command", JSON.stringify(line), "2")!);
    handle.push(parseStreamEvent("command", JSON.stringify(line), "3")!);
    handle.push(parseStreamEvent("command", JSON.stringify(line), "3")!); // the same event, replayed
    await new Promise((r) => setTimeout(r, 30));
    expect(latest?.runs[0].commands[0].stdout).toBe("same\nsame\n");
  });
});

describe("the timeline's staleness bound follows the scenario's details (ADR 0033, 2026-10-03 limits)", () => {
  it("a run 160 s old with no end event: running while its timeout is unknown, over once it is 90 s", async () => {
    const { mountTimeline } = await import("../../src/ui/timeline");
    let latest: import("../../src/lib/timeline").TimelineView | undefined;
    const handle = mountTimeline(document.createElement("div"), document.createElement("div"), document.createElement("div"), (v) => (latest = v), () => {});
    const at = new Date(Date.now() - 160_000).toISOString();
    handle.push(parseStreamEvent("run", JSON.stringify({ run_id: "r", scenario: "network-tool", state: "started", at, detail: "" }), "1")!);
    await new Promise((r) => setTimeout(r, 30));
    expect(latest?.activeRun?.runId).toBe("r");
    handle.setScenarioTimeout("network-tool", 90);
    await new Promise((r) => setTimeout(r, 30));
    expect(latest?.activeRun).toBeUndefined();
  });
});

describe("parseScenarioDetails commands (review item 13)", () => {
  it("keeps the whole real catalogue and rejects duplicate or unusable spellings", async () => {
    const { parseScenarioDetails } = await import("../../src/lib/contract");
    const { terminalDetails } = await import("../../src/lib/fixtures");
    const parsed = parseScenarioDetails(terminalDetails());
    expect(parsed.commands?.length).toBe(TERMINAL_COMMANDS.length);
    const bad = parseScenarioDetails({
      interactive: true,
      commands: [
        { id: "a", input: "id", command: ["id"], outcome: "allowed", layer: "runtime" },
        { id: "b", input: "ID", command: ["id"], outcome: "allowed", layer: "runtime" }, // same spelling (case-insensitive)
        { id: "c", input: "has a \u0001 control char", command: ["x"], outcome: "allowed", layer: "runtime" },
        { id: "d", input: "", command: ["x"], outcome: "allowed", layer: "runtime" },
        { id: "e", input: "ls", aliases: ["id"], command: ["ls"], outcome: "allowed", layer: "runtime" }, // alias collides with a
      ],
    });
    expect(bad.commands?.map((c) => c.id)).toEqual(["a"]);
  });
});

describe("parseStats", () => {
  it("fills missing sections", () => {
    const s = parseStats({ objectives: { recon: { attempts: 3, achieved: 2 } } });
    expect(s.objectives.recon).toEqual({ attempts: 3, achieved: 2 });
    expect(s.runs).toBe(0);
    expect(s.response_ms).toEqual({ last: 0, p50: 0, min: 0, max: 0 });
  });

  it("keeps a `__proto__` key as data: the parsed object's prototype is untouched (review 2, item 14)", () => {
    const s = parseStats(JSON.parse('{"objectives":{"__proto__":{"attempts":7,"achieved":7},"recon":{"attempts":1,"achieved":1}},"commands":{"__proto__":{"attempts":1}}}'));
    expect(Object.getPrototypeOf(s.objectives)).toBe(Object.prototype);
    expect(Object.getPrototypeOf(s.commands)).toBe(Object.prototype);
    expect(Object.keys(s.objectives)).toEqual(["__proto__", "recon"]);
    expect((s.objectives as Record<string, unknown>).attempts).toBeUndefined();
  });

  it("an objective the catalogue has and the stats lack reads 0, even one named like a prototype key", () => {
    const el = renderStats(parseStats({ objectives: {} }), [{ id: "constructor", title: "Odd id" }]);
    expect(el.querySelector(".herostats__objcount")?.textContent).toBe("not reached yet — tried in 0 runs");
  });
});

describe("GET /api/runs/{id} (review 2, item 14)", () => {
  it("never builds a URL from a run id that is not one", async () => {
    const { ApiClient } = await import("../../src/lib/api");
    const urls: string[] = [];
    const api = new ApiClient({ fetch: async (u) => (urls.push(u), new Response("[]", { status: 200, headers: { "Content-Type": "application/json" } })) });
    for (const bad of ["../limits", "a/b", "x?y", "", "%2e%2e"]) expect((await api.runEvents(bad)).ok).toBe(false);
    expect(urls).toEqual([]);
    expect((await api.runEvents("4f1c2a9e8b7d6c5a")).ok).toBe(true);
    expect(urls).toEqual(["/api/runs/4f1c2a9e8b7d6c5a"]);
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
    expect(el.textContent).toContain("detected runs answered");
    const never = [...el.querySelectorAll('.herostats__obj[data-never="true"]')];
    expect(never.length).toBeGreaterThan(0);
    expect(never.some((n) => /not reached yet/.test(n.textContent ?? ""))).toBe(true);
    // The contract rules out an escapes/"got out" counter (review item 18).
    expect(el.textContent).not.toMatch(/got out|call-home|escap/i);
  });

  it("shows the last real run when one is given", () => {
    const el = renderStats(stats(), TERMINAL_OBJECTIVES, { title: "Download tool in a container", at: Date.now() - 5000 });
    expect(el.textContent).toContain("last run");
    expect(el.textContent).toContain("Download tool in a container");
    // One definition of response time on the band: the API's, on its own tile; none on the last run.
    expect(el.querySelector(".herostats__tile")?.textContent).not.toMatch(/\bms\b|answered in/);
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

describe("the shop window without a title or banner (the terminal's real deface)", () => {
  it("still says what happened", async () => {
    const { renderVictim } = await import("../../src/ui/victim");
    const at = (ms: number) => new Date(1_000_000 + ms).toISOString();
    const evs = [
      { type: "run", data: { run_id: "r", scenario: "terminal", state: "started", at: at(0), pod: "terminal-0123456789" } },
      { type: "victim", data: { run_id: "r", pod: "terminal-0123456789", at: at(10), status: "up", title: "SDP Shop", banner: "", probe_ms: 3, checksum: "5e0c1a77d3b2f190" } },
      { type: "victim", data: { run_id: "r", pod: "terminal-0123456789", at: at(20), status: "defaced", title: "", banner: "", probe_ms: 3, checksum: "" } },
    ].map((e) => parseStreamEvent(e.type, JSON.stringify(e.data))!);
    const el = renderVictim(buildTimeline(evs, 1_000_100).runs[0], false);
    expect(el.getAttribute("data-status")).toBe("defaced");
    expect(el.querySelector(".defaced__title")?.textContent).toBe("Page replaced");
    expect(el.querySelector(".defaced__banner")?.textContent).not.toBe("");
    expect(el.querySelector(".defaced__sum")).toBeNull(); // no checksum, no "→ undefined"
  });
});

describe("hero stats band (review 2, item 5)", () => {
  it("is not redrawn when the feed reports the same last run again", async () => {
    const { mountStats } = await import("../../src/ui/stats");
    const { ApiClient } = await import("../../src/lib/api");
    const body = JSON.stringify(stats());
    const api = new ApiClient({ fetch: async () => new Response(body, { status: 200, headers: { "Content-Type": "application/json" } }) });
    const root = document.createElement("div");
    const handle = mountStats(root, api);
    await new Promise((r) => setTimeout(r, 10));
    const last = { title: "Read /etc/shadow", at: Date.now() - 1000 };
    handle.setLastRun(last);
    const drawn = root.firstElementChild;
    expect(drawn).not.toBeNull();
    handle.setLastRun({ ...last });
    expect(root.firstElementChild).toBe(drawn);
    handle.setLastRun({ ...last, at: last.at + 1 });
    expect(root.firstElementChild).not.toBe(drawn);
  });
});

describe("degrading against today's API (review 2, items 8 and 13)", () => {
  const jsonFetch = (status: number, body: unknown, count: { n: number }) => async () => {
    count.n += 1;
    return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  };

  it("does not poll /api/stats after a 404, and gives up after a few other failures", async () => {
    vi.useFakeTimers();
    try {
      const { mountStats } = await import("../../src/ui/stats");
      const { ApiClient } = await import("../../src/lib/api");
      const missing = { n: 0 };
      mountStats(document.createElement("div"), new ApiClient({ fetch: jsonFetch(404, { error: "not found" }, missing) }));
      const broken = { n: 0 };
      mountStats(document.createElement("div"), new ApiClient({ fetch: jsonFetch(500, { error: "x" }, broken) }));
      await vi.advanceTimersByTimeAsync(6 * 3600_000);
      expect(missing.n).toBe(1);
      expect(broken.n).toBe(4);
    } finally {
      vi.useRealTimers();
    }
  });

  it("offers the twin only when the API's scenarios say it knows ?compare=1 (an `interactive` field)", async () => {
    const { mountScenarios } = await import("../../src/ui/scenarios");
    const { ApiClient } = await import("../../src/lib/api");
    const old = [{ id: "network-tool", title: "t", summary: "s", technique: "T1071.001", detection: "d", response: "quarantine", victim: true }];
    for (const [list, twins] of [[old, 0], [old.map((s) => ({ ...s, interactive: false })), 1]] as const) {
      const root = document.createElement("div");
      mountScenarios(root, document.createElement("p"), new ApiClient({ fetch: jsonFetch(200, list, { n: 0 }) }));
      await new Promise((r) => setTimeout(r, 10));
      expect(root.querySelectorAll(".scenario .btn--attack")).toHaveLength(1);
      expect(root.querySelectorAll(".scenario__twin")).toHaveLength(twins);
    }
  });
});

describe("hero stats wording and tiles (review 2, item 13 and the cross-side point)", () => {
  it("without a last run, no tile repeats another; the grid knows how many tiles it has", () => {
    const el = renderStats(stats(), TERMINAL_OBJECTIVES);
    const tiles = [...el.querySelectorAll(".herostats__tile")];
    expect(tiles).toHaveLength(3);
    const values = tiles.map((t) => t.querySelector(".herostats__value")?.textContent);
    expect(new Set(values).size).toBe(values.length);
    expect(el.querySelector(".herostats__tiles")?.getAttribute("data-count")).toBe("3");
    const withLast = renderStats(stats(), TERMINAL_OBJECTIVES, { title: "x", at: Date.now() });
    expect(withLast.querySelector(".herostats__tiles")?.getAttribute("data-count")).toBe("4");
  });

  it("counts objectives in runs, and says what 'reached' means next to how long the pod was kept", () => {
    const el = renderStats(stats(), TERMINAL_OBJECTIVES);
    const counts = [...el.querySelectorAll(".herostats__objcount")].map((c) => c.textContent ?? "");
    expect(counts.every((c) => /runs?\b/.test(c) && !/tries/.test(c))).toBe(true);
    expect(counts[2]).toBe("reached in 30 of 30 runs that tried"); // credentials: `cat /etc/shadow` exits 0
    const reached = el.querySelector(".herostats__reached")?.textContent ?? "";
    expect(reached).toContain("exited 0");
    expect(reached).toContain("Detection is not prevention");
    expect(reached).toContain("median 48 s");
  });
});

describe("hero tiles say what their numbers count (final review, item 4)", () => {
  it("runs answered of runs detected, next to runs that ran out of time unanswered", () => {
    const el = renderStats(stats(), TERMINAL_OBJECTIVES);
    const tile = [...el.querySelectorAll(".herostats__tile")].find((t) => t.textContent?.includes("1266 of 1279"));
    expect(tile?.querySelector(".herostats__name")?.textContent).toBe("detected runs answered");
    expect(tile?.querySelector(".herostats__foot")?.textContent).toBe("11 ran out of time with a detection unanswered");
    expect(el.textContent).not.toContain("went unanswered");
    expect(el.textContent).toContain("last detection to response");
  });
});

describe("the defence map in result mode (final review, item 7)", () => {
  it("gives every layer a status pill: a verdict, 'never reached', or 'not tried'", () => {
    const el = renderDefenceMap({ lit: litFromCommands([{ layer: "runtime", outcome: "allowed", control: "watched", input: "id" }]) });
    const pill = (id: string) => el.querySelector(`.deflayer[data-layer="${id}"] .deflayer__head .deflayer__verdict`)?.textContent;
    expect(pill("runtime")).toBe("allowed");
    expect(pill("edge")).toBe("never reached");
    expect(pill("network")).toBe("not tried");
    expect(pill("pod-security")).toBe("not tried");
    // The static map (How it works) has no pills.
    expect(renderDefenceMap({}).querySelector(".deflayer__verdict")).toBeNull();
  });
});
