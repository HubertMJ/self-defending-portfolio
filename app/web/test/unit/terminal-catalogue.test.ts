import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
// @ts-expect-error -- a plain .mjs build script, no type declarations
import { FIXTURE, render, terminalCatalogue } from "../../scripts/terminal-catalogue.mjs";
import { parseScenarioDetails } from "../../src/lib/contract";
import { TERMINAL_COMMANDS, TERMINAL_OUTPUT, terminalDetails } from "../../src/lib/fixtures";

// An excerpt in the real file's shapes: another scenario before it, comments, flow maps and
// sequences, a folded scalar, a block sequence, an escaped double-quoted string and an alias.
const EXCERPT = `# header comment
- id: network-tool
  title: Download tool
  exec: {command: ["wget"], tty: false}
- id: terminal
  title: Attacker's terminal
  interactive: true
  timeout_seconds: 300
  idle_seconds: 90
  objectives:
    - {id: recon, title: "Look around"}
    - {id: tamper, title: "Deface the shop"}
  pod:
    containers:
      - name: target
        image: *scenario-image
  commands:
    # ---- recon ----
    - id: whoami
      input: "id"
      aliases: ["whoami"]
      objective: recon
      technique: T1033
      command: ["id"]
      tty: false
      outcome: allowed
      layer: runtime
      control: "Falco is watching; plain recon matches no rule"
      explain: >-
        You are an unprivileged user (uid 10001) in a hardened pod. Falco sees this and lets it pass -
        looking around is not, by itself, an attack.
    - id: deface
      input: "echo pwned>/srv/shop/index.html;echo '{\\"status\\":\\"defaced\\"}'>/srv/shop/state.json"
      aliases: ["deface"]
      objective: tamper
      technique: T1491.001
      command:
        - sh
        - -c
        - "echo pwned>/srv/shop/index.html;echo '{\\"status\\":\\"defaced\\"}'>/srv/shop/state.json"
      tty: false
      outcome: allowed
      layer: runtime
      control: "Falco is watching; an app rewriting its own files is not drift"
      explain: >-
        The shop window next to you just changed.
`;

describe("terminal catalogue generator (scripts/terminal-catalogue.mjs)", () => {
  it("reads the terminal scenario out of the real file's YAML shapes", () => {
    const c = terminalCatalogue(EXCERPT);
    expect(c.timeout_seconds).toBe(300);
    expect(c.idle_seconds).toBe(90);
    expect(c.objectives).toEqual([
      { id: "recon", title: "Look around" },
      { id: "tamper", title: "Deface the shop" },
    ]);
    expect(c.commands.map((x: { id: string }) => x.id)).toEqual(["whoami", "deface"]);
    expect(c.commands[0].explain).toBe(
      "You are an unprivileged user (uid 10001) in a hardened pod. Falco sees this and lets it pass - looking around is not, by itself, an attack.",
    );
    const deface = c.commands[1];
    expect(deface.input).toBe(`echo pwned>/srv/shop/index.html;echo '{"status":"defaced"}'>/srv/shop/state.json`);
    expect(deface.command).toEqual(["sh", "-c", deface.input]);
    // Optional fields absent in the YAML stay absent (not null).
    expect("detection" in deface).toBe(false);
  });

  it("keeps a '#' inside a block scalar as text, and drops comments outside it (final review, item 7)", () => {
    const c = terminalCatalogue(EXCERPT.replace("        The shop window next to you just changed.", "        The shop window changed (see issue #42).\n        # still part of the text").replace("      tty: false\n      outcome: allowed\n      layer: runtime\n      control: \"Falco is watching; an app", "      tty: false # a TTY is not needed\n      outcome: allowed\n      layer: runtime\n      control: \"Falco is watching; an app"));
    expect(c.commands[1].explain).toBe("The shop window changed (see issue #42). # still part of the text");
    expect(c.commands[1].tty).toBe(false);
  });

  it("fails loudly on a command missing a field the page needs", () => {
    expect(() => terminalCatalogue(EXCERPT.replace('      layer: runtime\n      control: "Falco is watching; plain', '      control: "Falco is watching; plain'))).toThrow(/whoami has no layer/);
    expect(() => terminalCatalogue("- id: other\n  title: x\n")).toThrow(/no `- id: terminal`/);
  });
});

describe("the committed ?mock=1 catalogue", () => {
  it("is the real one: five objectives, fourteen commands, deface's real 80-character line", () => {
    const parsed = parseScenarioDetails(terminalDetails());
    // The session limits the API now sends: 300 s, and 90 s without a command.
    expect(parsed.timeout_seconds).toBe(300);
    expect(parsed.idle_seconds).toBe(90);
    expect(parsed.objectives).toHaveLength(5);
    expect(parsed.commands).toHaveLength(14); // none dropped by the page's own catalogue checks
    const deface = parsed.commands?.find((c) => c.id === "deface");
    expect(deface?.input).toHaveLength(80);
    expect(deface?.aliases).toEqual(["deface"]);
  });

  it("gives every catalogue command a mock output, and nothing else one", () => {
    expect(Object.keys(TERMINAL_OUTPUT).sort()).toEqual(TERMINAL_COMMANDS.map((c) => c.id).sort());
  });

  // The cluster file is not part of this worktree's build; point SDP_SCENARIOS_YAML at it (e.g. a
  // checkout of the cluster branch) and this fails when the committed fixture has drifted from it.
  const source = process.env.SDP_SCENARIOS_YAML;
  if (source) {
    it(`matches ${source}`, () => {
      expect(readFileSync(FIXTURE, "utf8")).toBe(render(terminalCatalogue(readFileSync(source, "utf8"))));
    });
  }
});
