import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Result } from "../../src/lib/api";
import { type Correlation, MAX_INCIDENTS, MAX_STEPS, type RuleIndex, parseCorrelation, parseRuleIndex, publishable } from "../../src/lib/contract";
import { RULE_INDEX, correlation as fixtureCorrelation, shiftTimes } from "../../src/lib/fixtures";
import { BOARD_INCIDENTS, POLL_404_MS, POLL_MS, coverage, kindLabel, mountCorrelation, percentile, renderBoard, renderHealth, renderIncident, renderMetrics, renderRuleLibrary } from "../../src/ui/correlation";
import { CORRELATION_PATHS, renderVerifyPanel } from "../../src/ui/verify";

// ADR 0036 on the page: the lenient parsers, the publication guard (ADR 0021), the section's parts
// rendered as text only, and the mount that shows the section only while the SIEM says available.

const NOW = Date.parse("2026-10-04T12:00:00Z");
const at = (sAgo: number) => new Date(NOW - sAgo * 1000).toISOString();
const COMMIT = "0448cff5a1b2c3d4e5f60718293a4b5c6d7e8f90";
const UUID = "6c2d3e4f-5061-4b72-9c83-a4b5c6d7e8f9";

function incident(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "c0a1b2c3d4e5f607",
    kind: "contained-intrusion",
    severity: "high",
    title: "Shadow file read, pod quarantined",
    run_id: "7e57000000000001",
    arm: "",
    first_at: at(600),
    last_at: at(598),
    attack: ["T1003.008"],
    falco_events: 1,
    flag_match: null,
    ttd_ms: 840,
    tti_ms: 212,
    steps: [
      { at: at(600), source: "api", rule: "Terminal command", rule_id: "", command_seq: 3, detail: "sandbox/terminal-7e57000001 · read-shadow" },
      { at: at(599), source: "falco", rule: "Credential file read", rule_id: UUID, command_seq: 3, detail: "sandbox/terminal-7e57000001 · cat /etc/shadow" },
    ],
    evidence: [{ type: "finding", id: "f-77ab01c2d3" }],
    ...over,
  };
}

function answer(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    available: true,
    checked_at: at(20),
    rules: { commit: "a7cc041e5d2b9f30c1a4e6b8d0f2a3c5e7f9b1d3", applied_at: at(5400), status: "applied" },
    health: { ingest: "ok", evidence_rewritten: false, disk: "ok" },
    metrics: { since: at(86_400), incidents: 1, median_ttd_ms: 840, median_tti_ms: 212, median_twin_dwell_ms: null, host_findings: 0 },
    incidents: [incident()],
    ...over,
  };
}

const index = (): RuleIndex =>
  parseRuleIndex({
    rules: [{ id: UUID, title: "Credential file read", level: "high", status: "stable", source: "falco", attack: ["T1003.008"], file: "siem/rules/falco/credential-file-read.yml", line: 3, canary: "falco-shadow-read" }],
    monitors: [{ name: "sdp-git: ingest silent", file: "siem/monitors/ingest-silent.json", canary: "" }],
    correlations: [],
  });

describe("publishable (ADR 0021 on the page)", () => {
  it("withholds what the API's leak test forbids", () => {
    for (const bad of ["to 10.43.0.10:53", "dns.kube-system.svc", "x.cluster.local", "on k3s01", "SIEM01 disk", "system:serviceaccount:falco-response:falco-talon", "the serviceaccount token", "user hm1:0123456789abcdef", "sdp-0123456789abcdef.exfil", "SDP{flag}"]) {
      expect(publishable(bad), bad).toBe(false);
    }
  });

  it("allows pod refs only in the sandbox namespaces, and paths are not refs", () => {
    expect(publishable("sandbox/terminal-7e57000001 · exec")).toBe(true);
    expect(publishable("sandbox-unguarded/scenario-network-tool-7e57aaaaaa-u · delete")).toBe(true);
    expect(publishable("kube-system/coredns-5d78c9869d-x7k2p · exec")).toBe(false);
    expect(publishable("falco-response/falco-talon-7d9 · patch")).toBe(false);
    expect(publishable("cat /etc/shadow")).toBe(true);
    expect(publishable("wget -O /tmp/x http://127.0.0.1/a")).toBe(true);
    expect(publishable("loopback 127.0.0.1 only")).toBe(true);
    expect(publishable("T1048.003 seen 3 times")).toBe(true);
    // What the API's details carry (app/api/internal/incidents): resource/subresource, protocol/port.
    expect(publishable("get pods/exec on sandbox/terminal-7e57000005 not by the API, response 101")).toBe(true);
    expect(publishable("Hubble: DROPPED egress UDP/53 (POLICY_DENIED) on sandbox/terminal-7e57000005")).toBe(true);
    expect(publishable("udp/53 and tcp/443")).toBe(true);
    // Another namespace of this cluster, whatever the pod is called; elsewhere, a controller's pod name.
    expect(publishable("default/nginx")).toBe(false);
    expect(publishable("on monitoring/prometheus-k8s-0")).toBe(false);
  });
});

describe("publishable: review M2 probes", () => {
  it("an address at the end of a sentence is withheld; a version-like number run is not an address", () => {
    expect(publishable("to 10.43.0.10.")).toBe(false);
    expect(publishable("to 10.43.0.10")).toBe(false);
    expect(publishable("(10.43.0.10)")).toBe(false);
    expect(publishable("version 1.2.3.4.5")).toBe(true);
  });

  it("checks the whole text before the cap: a leak past character 200 still withholds the detail and the title", () => {
    const long = `${"x".repeat(195)} to 10.43.0.10:53`;
    const c = parseCorrelation(answer({ incidents: [incident({ title: `${"t".repeat(195)} on k3s01`, steps: [{ at: at(1), source: "hubble", rule: `${"r".repeat(190)} kube-system/coredns-1`, rule_id: "", command_seq: null, detail: long }] })] }));
    const i = c.incidents[0];
    expect(i.title).toBe("");
    expect(i.steps[0]).toMatchObject({ rule: "", detail: "", withheld: true });
  });

  it("the SIEM's own <ns>_<pod> form outside the sandbox is withheld; words with an underscore are not refs", () => {
    expect(publishable("kube-system_coredns-5d78c9869d-x7k2p")).toBe(false);
    expect(publishable("on falco-response_falco-talon-7d9f")).toBe(false);
    expect(publishable("sandbox_terminal-7e57000001")).toBe(true);
    expect(publishable("sandbox-unguarded_scenario-network-tool-7e57aaaaaa-u")).toBe(true);
    for (const word of ["read_shadow", "event_overwrite", "default_value", "ingest_lag_ms", "falco_events", "sdp_falco", "k8s_pod_ref"]) expect(publishable(`field ${word} set`), word).toBe(true);
  });
});

describe("publishable: review L3, aligned with the API's redactions", () => {
  it("withholds ServiceAccounts in any spelling, the flag in any case, tokens, IPv6 and API paths into other namespaces", () => {
    for (const bad of [
      "the service account of the pod",
      "service_account token",
      "Service-Account",
      "sdp{abc}",
      "Authorization: Bearer abcdefghijklmnop1234",
      "jwt eyJhbGciOiJSUzI1NiIs.eyJzdWIiOiJ4In0",
      "to fd00:10:42::5",
      "from 2001:db8:0:0:0:0:0:1",
      "GET /api/v1/namespaces/kube-system/pods/coredns-1/exec",
      "/api/v1/namespaces/default/pods/x",
    ]) {
      expect(publishable(bad), bad).toBe(false);
    }
  });

  it("normalises compatibility characters before testing", () => {
    expect(publishable("on ｋ３ｓ０１")).toBe(false);
    expect(publishable("ＳＤＰ｛x｝")).toBe(false);
  });

  it("keeps what only looks close: clock times, loopback, a MAC, short bearer words, sandbox API paths", () => {
    for (const ok of ["at 12:00:00 UTC", "::1 only", "mac aa:bb:cc:dd:ee:ff", "bearer token missing", "/api/v1/namespaces/sandbox/pods/terminal-7e57000001/exec", "/api/v1/namespaces/sandbox-unguarded/pods/x-u", "Talon: Terminate Pod (kubernetes:terminate) success"]) {
      expect(publishable(ok), ok).toBe(true);
    }
  });
});

describe("parseCorrelation", () => {
  it("parses a full answer, newest first", () => {
    const c = parseCorrelation(answer({ incidents: [incident(), incident({ id: "d15e0f17a1b2c3d4", kind: "dns-exfil", last_at: at(10), first_at: at(12), flag_match: true, falco_events: 0 })] }));
    expect(c.available).toBe(true);
    expect(c.incidents.map((i) => i.id)).toEqual(["d15e0f17a1b2c3d4", "c0a1b2c3d4e5f607"]);
    expect(c.incidents[0].flag_match).toBe(true);
    expect(c.incidents[1].steps[1]).toEqual({ at: at(599), source: "falco", rule: "Credential file read", rule_id: UUID, command_seq: 3, detail: "sandbox/terminal-7e57000001 · cat /etc/shadow" });
    expect(c.rules.status).toBe("applied");
    expect(c.metrics.median_twin_dwell_ms).toBeNull();
  });

  it("orders by first_at as the API does, not by last_at", () => {
    // A long incident that began earlier but ended last stays below one that began later.
    const c = parseCorrelation(answer({ incidents: [incident({ id: "000000000000000a", first_at: at(100), last_at: at(5) }), incident({ id: "000000000000000b", first_at: at(50), last_at: at(40) })] }));
    expect(c.incidents.map((i) => i.id)).toEqual(["000000000000000b", "000000000000000a"]);
  });

  it("is available only for a literal true, and an unavailable answer carries nothing else", () => {
    for (const v of [false, "true", 1, null, undefined]) {
      const c = parseCorrelation(answer({ available: v }));
      expect(c.available, String(v)).toBe(false);
      expect(c.incidents).toEqual([]);
      expect(c.rules).toEqual({ commit: "", applied_at: null, status: "unknown" });
      expect(c.metrics.incidents).toBe(0);
    }
    expect(() => parseCorrelation([1, 2])).toThrow();
    expect(() => parseCorrelation("x")).toThrow();
  });

  it("drops malformed and duplicate incidents and steps, unknown words become unknown", () => {
    const c = parseCorrelation(
      answer({
        incidents: [
          incident(),
          incident(),
          incident({ id: "not-hex" }),
          incident({ id: "0000000000000001", kind: "Has Caps" }),
          incident({ id: "0000000000000002", first_at: "yesterday" }),
          "junk",
          incident({ id: "0000000000000003", first_at: at(2), last_at: at(1), severity: "apocalyptic", arm: "both", run_id: "../x", attack: ["T1048.003", "t1", "T99999"], falco_events: -1, ttd_ms: "840", flag_match: "yes", steps: [{ at: at(1), source: "syslog", rule: "x" }, { at: "never", source: "api" }, { at: at(2), source: "api", rule: "ok", rule_id: "not-a-uuid", command_seq: 0, detail: 5 }] }),
        ],
        health: { ingest: "loud", evidence_rewritten: "no", disk: 90 },
        rules: { commit: "a7cc041", applied_at: "x", status: "done" },
      }),
    );
    expect(c.incidents.map((i) => i.id)).toEqual(["0000000000000003", "c0a1b2c3d4e5f607"]);
    const odd = c.incidents[0];
    expect(odd).toMatchObject({ severity: "unknown", arm: "", run_id: "", attack: ["T1048.003"], falco_events: null, ttd_ms: null, flag_match: null });
    expect(odd.steps).toEqual([{ at: at(2), source: "api", rule: "ok", rule_id: "", command_seq: null, detail: "" }]);
    expect(c.health).toEqual({ ingest: "unknown", evidence_rewritten: null, disk: "unknown" });
    // Only a full commit becomes a link.
    expect(c.rules).toEqual({ commit: "", applied_at: null, status: "unknown" });
  });

  it("drops an evidence id that is not publishable or not an id (review L4)", () => {
    const c = parseCorrelation(answer({ incidents: [incident({ evidence: [{ type: "document", id: "kube-system_coredns-5d78c9869d-x7k2p" }, { type: "finding", id: "a b" }, { type: "alert", id: "x".repeat(65) }, { type: "finding", id: "f-77ab01c2d3" }] })] }));
    expect(c.incidents[0].evidence).toEqual([{ type: "finding", id: "f-77ab01c2d3" }]);
  });

  it("withholds unpublishable titles and details, and says so per step", () => {
    const c = parseCorrelation(
      answer({
        incidents: [incident({ title: "exec by system:serviceaccount:kube-system:x", steps: [{ at: at(5), source: "k8s-audit", rule: "Exec", rule_id: "", command_seq: null, detail: "kube-system/coredns-1 · exec" }, { at: at(4), source: "hubble", rule: "to 10.43.0.10", rule_id: "", command_seq: null, detail: "" }] })],
      }),
    );
    const i = c.incidents[0];
    expect(i.title).toBe("");
    expect(i.steps[0]).toMatchObject({ detail: "", withheld: true });
    expect(i.steps[1]).toMatchObject({ rule: "", detail: "" });
    expect(i.steps[1].withheld).toBeUndefined();
    expect(JSON.stringify(c)).not.toMatch(/kube-system|10\.43|serviceaccount/);
  });

  it("caps incidents and steps at the API's own limits, and strips control characters", () => {
    const many = Array.from({ length: MAX_INCIDENTS + 20 }, (_, n) => incident({ id: n.toString(16).padStart(16, "0") }));
    expect(parseCorrelation(answer({ incidents: many })).incidents).toHaveLength(MAX_INCIDENTS);
    const steps = Array.from({ length: MAX_STEPS + 5 }, (_, n) => ({ at: at(100 - n), source: "api", rule: `r${n}`, rule_id: "", command_seq: null, detail: "a‮b\u0007c" }));
    const i = parseCorrelation(answer({ incidents: [incident({ steps })] })).incidents[0];
    expect(i.steps).toHaveLength(MAX_STEPS);
    expect(i.steps[0].detail).toBe("abc");
    expect(parseCorrelation(answer({ incidents: [incident({ title: "x".repeat(500) })] })).incidents[0].title).toHaveLength(200);
  });
});

describe("parseRuleIndex", () => {
  it("keeps valid rules only, links only repository paths", () => {
    const idx = parseRuleIndex({
      rules: [
        { id: UUID, title: "Ok", level: "high", status: "stable", source: "falco", attack: ["T1105", "bad"], file: "siem/rules/falco/x.yml", line: 4, canary: "c1" },
        { id: UUID, title: "Duplicate id" },
        { id: "nope", title: "Bad id" },
        { id: "7d3e4f50-6172-4c83-ad94-b5c6d7e8f901", title: "Bad file", level: "extreme", source: "Falco!", file: "https://evil.example/x", line: 9, canary: true },
      ],
      monitors: [{ name: "m", file: "../../etc/passwd" }, { name: "" }, "x"],
    });
    expect(idx.rules).toHaveLength(2);
    expect(idx.rules[0]).toEqual({ id: UUID, title: "Ok", level: "high", status: "stable", source: "falco", attack: ["T1105"], file: "siem/rules/falco/x.yml", line: 4, canary: "c1" });
    expect(idx.rules[1]).toMatchObject({ level: "", source: "", file: "", line: 0, canary: "yes" });
    expect(idx.monitors).toEqual([{ name: "m", file: "", canary: "" }]);
    expect(idx.correlations).toEqual([]);
    expect(() => parseRuleIndex({})).toThrow();
  });
});

describe("review L5: what the parsers drop and sort", () => {
  it("a rule whose title is not publishable is dropped, and so is a monitor or correlation rule whose name is not", () => {
    const idx = parseRuleIndex({
      rules: [
        { id: UUID, title: "Exec on kube-system/coredns-5d78c9869d-x7k2p", source: "k8s-audit" },
        { id: "7d3e4f50-6172-4c83-ad94-b5c6d7e8f901", title: "DNS query carries an exfil label", source: "hubble" },
      ],
      monitors: [{ name: "ingest silent on k3s01" }, { name: "sdp-git: policy-probing" }],
      correlations: [{ name: "to 10.43.0.10" }, { name: "contained-intrusion" }],
    });
    expect(idx.rules.map((r) => r.title)).toEqual(["DNS query carries an exfil label"]);
    expect(idx.monitors.map((m) => m.name)).toEqual(["sdp-git: policy-probing"]);
    expect(idx.correlations.map((m) => m.name)).toEqual(["contained-intrusion"]);
  });

  it("steps that arrive out of order are drawn in time order", () => {
    const steps = [
      { at: at(1), source: "talon", rule: "third", rule_id: "", command_seq: null, detail: "" },
      { at: at(3), source: "api", rule: "first", rule_id: "", command_seq: null, detail: "" },
      { at: at(2), source: "falco", rule: "second", rule_id: "", command_seq: null, detail: "" },
    ];
    expect(parseCorrelation(answer({ incidents: [incident({ steps })] })).incidents[0].steps.map((x) => x.rule)).toEqual(["first", "second", "third"]);
  });
});

describe("the section's parts", () => {
  const ctx = (c: Correlation) => ({ now: NOW, rules: new Map(index().rules.map((r) => [r.id, r])), commit: COMMIT, c });

  it("an incident: severity, kind, UTC times, TTD/TTI, the timeline with rule links at the commit, the evidence ids", () => {
    const c = parseCorrelation(answer());
    const el = renderIncident(c.incidents[0], ctx(c));
    expect(el.querySelector(".incident__title")?.textContent).toBe("Shadow file read, pod quarantined");
    expect(el.querySelector(".chip")?.textContent).toContain("high");
    expect(el.querySelector(".incident__kind")?.textContent).toContain(kindLabel("contained-intrusion"));
    expect(el.querySelector(".incident__when")?.textContent).toBe("from 11:50:00.000 UTC to 11:50:02.000 UTC");
    expect(el.querySelector(".incident__facts")?.textContent).toContain("Time to detect840 ms");
    expect(el.querySelector(".incident__facts")?.textContent).toContain("Time to isolate212 ms");
    const steps = el.querySelectorAll(".corr-step");
    expect(steps).toHaveLength(2);
    expect(steps[1].textContent).toBe("11:50:01.000 UTC +1.0 s falco Credential file read (opens in a new tab) · command 3 · sandbox/terminal-7e57000001 · cat /etc/shadow");
    expect(steps[1].querySelector("a")?.getAttribute("href")).toBe(`https://github.com/HubertMJ/self-defending-portfolio/blob/${COMMIT}/siem/rules/falco/credential-file-read.yml#L3`);
    // A step without a rule id has no link.
    expect(steps[0].querySelector("a")).toBeNull();
    expect(el.querySelector(".incident__evidence")?.textContent).toBe("SIEM evidence: finding f-77ab01c2d3");
    expect(el.querySelector('a[href="/api/runs/7e57000000000001"]')).not.toBeNull();
  });

  it("a stream document without a finding has no rule: its detail stands alone", () => {
    const c = parseCorrelation(answer({ incidents: [incident({ steps: [{ at: at(5), source: "k8s-audit", rule: "", rule_id: "", command_seq: null, detail: "patch pods on sandbox/terminal-7e57000001 by Talon, response 200" }] })] }));
    const step = renderIncident(c.incidents[0], ctx(c)).querySelector(".corr-step");
    expect(step?.textContent).toBe("11:59:55.000 UTC audit patch pods on sandbox/terminal-7e57000001 by Talon, response 200");
    expect(step?.querySelector("strong")).toBeNull();
  });

  it("no rule link when the commit is not a commit", () => {
    const c = parseCorrelation(answer());
    const el = renderIncident(c.incidents[0], { ...ctx(c), commit: "../main" });
    expect(el.querySelectorAll(".corr-step a")).toHaveLength(0);
  });

  it("dns-exfil says Falco saw nothing and what the flag match is; the other kinds do not", () => {
    const dns = (flag: unknown) => parseCorrelation(answer({ incidents: [incident({ kind: "dns-exfil", falco_events: 0, flag_match: flag })] })).incidents[0];
    const facts = (flag: unknown) => renderIncident(dns(flag), ctx(parseCorrelation(answer()))).querySelector(".incident__facts")?.textContent ?? "";
    expect(facts(true)).toContain("Falcono event");
    expect(facts(true)).toContain("matched the run's flag");
    expect(facts(false)).toContain("no match for this run");
    expect(facts(null)).toContain("flag match unavailable");
    const c = parseCorrelation(answer());
    expect(renderIncident(c.incidents[0], ctx(c)).querySelector(".incident__facts")?.textContent).not.toContain("Flag");
  });

  it("renders hostile text as text: no element, no attribute comes from the API", () => {
    const evil = '<img src=x onerror="alert(1)">';
    const c = parseCorrelation(answer({ incidents: [incident({ title: evil, steps: [{ at: at(1), source: "api", rule: evil, rule_id: "", command_seq: null, detail: evil }] })] }));
    const el = renderIncident(c.incidents[0], ctx(c));
    expect(el.querySelector("img")).toBeNull();
    expect(el.querySelector(".incident__title")?.textContent).toBe(evil);
    expect(el.querySelector(".corr-step__detail")?.textContent).toBe(` · ${evil}`);
  });

  it("a withheld detail says so, a withheld title falls back to the kind", () => {
    const c = parseCorrelation(answer({ incidents: [incident({ title: "on k3s01", steps: [{ at: at(1), source: "k8s-audit", rule: "Exec", rule_id: "", command_seq: null, detail: "kube-system/x-1 · exec" }] })] }));
    const el = renderIncident(c.incidents[0], ctx(c));
    expect(el.querySelector(".incident__title")?.textContent).toBe(kindLabel("contained-intrusion"));
    expect(el.querySelector(".corr-step__detail--withheld")?.textContent).toContain("withheld");
    expect(el.textContent).not.toMatch(/k3s01|kube-system/);
  });

  it("an unknown kind reads as a plain Incident (review L4)", () => {
    const c = parseCorrelation(answer({ incidents: [incident({ kind: "constructor", title: "" }), incident({ id: "0000000000000004", kind: "new-kind-from-a-newer-api", title: "" })] }));
    for (const i of c.incidents) {
      const el = renderIncident(i, ctx(c));
      expect(el.querySelector(".incident__title")?.textContent).toBe("Incident");
      expect(el.querySelector(".incident__kind")?.textContent).toMatch(/^Incident/);
    }
    expect(kindLabel("dns-exfil")).toBe("DNS exfiltration");
  });

  it("the board: the newest in full, the rest one line each; an empty board says since when it looks", () => {
    const many = Array.from({ length: BOARD_INCIDENTS + 3 }, (_, n) => incident({ id: n.toString(16).padStart(16, "0"), last_at: at(100 + n) }));
    const c = parseCorrelation(answer({ incidents: many }));
    const el = renderBoard(c, ctx(c));
    expect(el.querySelectorAll(".incident")).toHaveLength(BOARD_INCIDENTS);
    expect(el.querySelectorAll(".corr-older__item")).toHaveLength(3);
    expect(el.querySelector(".corr-older summary")?.textContent).toBe("3 older incidents");
    const empty = parseCorrelation(answer({ incidents: [] }));
    expect(renderBoard(empty, ctx(empty)).textContent).toContain("No incident in the last 24 hours");
  });

  it("the health line: the applied commit linked, each state in words", () => {
    const ok = renderHealth(parseCorrelation(answer()), NOW);
    expect(ok.querySelector(".corr-health__rules a")?.getAttribute("href")).toBe("https://github.com/HubertMJ/self-defending-portfolio/commit/a7cc041e5d2b9f30c1a4e6b8d0f2a3c5e7f9b1d3");
    expect(ok.textContent).toContain("ingest ok");
    expect(ok.textContent).toContain("evidence not rewritten");
    expect(ok.querySelector(".corr-health__checked")?.textContent).toContain("11:59:40 UTC (20 seconds ago)");
    const bad = renderHealth(parseCorrelation(answer({ rules: { commit: "", status: "refused" }, health: { ingest: "silent", evidence_rewritten: true, disk: "high" } })), NOW);
    expect(bad.textContent).toContain("rules refused (commit unknown)");
    expect(bad.textContent).toContain("ingest silent");
    expect(bad.textContent).toContain("evidence rewrite detected");
    expect(bad.textContent).toContain("disk high");
    expect(bad.querySelectorAll(".chip--critical")).toHaveLength(3);
    expect(bad.querySelectorAll(".chip--warning")).toHaveLength(1);
  });

  it("the rules chip: failed is critical, stale a warning, a word the page does not know reads as unknown and never good", () => {
    const rulesChip = (status: unknown) => {
      const el = renderHealth(parseCorrelation(answer({ rules: { commit: COMMIT, applied_at: at(5400), status } })), NOW);
      return { data: el.getAttribute("data-rules"), chip: el.querySelector(".corr-health__rules .chip") };
    };
    const failed = rulesChip("failed");
    expect(failed.data).toBe("failed");
    expect(failed.chip?.className).toBe("chip chip--critical");
    expect(failed.chip?.textContent).toContain("rules failed");
    // The rules sync has not checked in for over 30 minutes.
    const stale = rulesChip("stale");
    expect(stale.data).toBe("stale");
    expect(stale.chip?.className).toBe("chip chip--warning");
    expect(stale.chip?.textContent).toContain("rules stale");
    for (const word of ["unknown", "pending", "APPLIED", 1, null, undefined]) {
      const unknown = rulesChip(word);
      expect(unknown.data, String(word)).toBe("unknown");
      expect(unknown.chip?.className, String(word)).toBe("chip chip--neutral");
      expect(unknown.chip?.textContent, String(word)).toContain("rules unknown");
    }
    expect(rulesChip("applied").chip?.className).toBe("chip chip--good");
  });

  it("the metrics: the API's medians, a p95 only over two or more, host findings as a count", () => {
    const two = parseCorrelation(answer({ incidents: [incident(), incident({ id: "0000000000000009", tti_ms: 1830, ttd_ms: 1210 })] }));
    const el = renderMetrics(two, NOW);
    const tiles = [...el.querySelectorAll(".tile")].map((t) => t.textContent);
    expect(tiles[1]).toContain("840 ms");
    expect(tiles[2]).toContain("212 ms");
    expect(tiles[2]).toContain("p95 1.8 s over the 2 contained intrusions listed");
    expect(tiles[3]).toContain("–");
    expect(tiles[3]).toContain("no compare run yet");
    const one = renderMetrics(parseCorrelation(answer()), NOW);
    expect(one.textContent).not.toContain("p95");
    // A twin-dwell incident carries its guarded arm's TTI: it is not a second sample.
    const twin = renderMetrics(parseCorrelation(answer({ incidents: [incident(), incident({ id: "0000000000000009", kind: "twin-dwell", tti_ms: 1830 })] })), NOW);
    expect(twin.textContent).not.toContain("p95");
    expect(percentile([96, 212, 1830], 95)).toBe(1830);
    expect(percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 50)).toBe(5);
    expect(percentile([], 95)).toBeUndefined();
  });

  it("ingest lag per source: parsed leniently, one small line in source order, omitted when absent", () => {
    const c = parseCorrelation(answer({ metrics: { since: at(86_400), incidents: 1, median_ttd_ms: 840, median_tti_ms: 212, median_twin_dwell_ms: null, host_findings: 0, ingest_lag_ms: { hubble: 3400, falco: 1240, host: null, "Bad Key": 5, api: -1, talon: "860", "k8s-audit": Number.NaN } } }));
    // A negative lag is clock skew between the hosts, published as it is (ADR 0036 §5).
    expect(c.metrics.ingest_lag_ms).toEqual([["hubble", 3400], ["falco", 1240], ["host", null], ["api", -1]]);
    const line = renderMetrics(c, NOW).querySelector(".corr-lag");
    expect(line?.textContent).toBe("Ingest lag, per source (how far behind its newest record was when the API last read it): falco 1.2 s · hubble 3.4 s · api -1 ms · host –");
    expect(renderMetrics(parseCorrelation(answer()), NOW).querySelector(".corr-lag")).toBeNull();
    expect(parseCorrelation(answer({ metrics: { ingest_lag_ms: {} } })).metrics.ingest_lag_ms).toBeUndefined();
    expect(parseCorrelation(answer({ metrics: { ingest_lag_ms: [1, 2] } })).metrics.ingest_lag_ms).toBeUndefined();
  });

  it("coverage: rules per technique and source, incidents per technique, a seen technique without a rule is a gap", () => {
    const c = parseCorrelation(answer({ incidents: [incident({ attack: ["T1003.008", "T1059.004"] })] }));
    const cov = coverage(index(), c.incidents);
    expect(cov.techniques).toEqual(["T1003.008", "T1059.004"]);
    expect(cov.sources).toEqual(["falco"]);
    expect(cov.rules.get("T1003.008")?.get("falco")).toBe(1);
    expect(cov.seen.get("T1059.004")).toBe(1);
    const lib = renderRuleLibrary(index(), COMMIT, c.incidents);
    expect(lib.querySelector('tr[data-technique="T1059.004"] .corr-cell--gap')?.textContent).toBe("1, no rule");
    expect(lib.querySelector('.corr-rule a[href^="https://github.com/"]')?.getAttribute("href")).toBe(`https://github.com/HubertMJ/self-defending-portfolio/blob/${COMMIT}/siem/rules/falco/credential-file-read.yml#L3`);
    expect(lib.querySelector(".corr-rule")?.textContent).toContain("canary falco-shadow-read");
    expect(lib.querySelector(".corr-named")?.textContent).toContain("sdp-git: ingest silent (opens in a new tab) · no canary");
    expect(renderRuleLibrary(null, COMMIT, []).textContent).toContain("unavailable");
    expect(renderRuleLibrary(undefined, COMMIT, []).textContent).toContain("Loading");
  });

  it("the verify panel lists the endpoints only while the section is shown", () => {
    expect(renderVerifyPanel({ correlation: true }).textContent).toContain(`hubertjablon.ski${CORRELATION_PATHS[1]}`);
    expect(renderVerifyPanel({ correlation: false }).textContent).not.toContain("/api/correlation");
  });
});

describe("mountCorrelation", () => {
  afterEach(() => vi.useRealTimers());

  const setup = (seq: Result<Correlation>[], rules: Result<RuleIndex>[] = [{ ok: true, value: index() }]) => {
    const section = document.createElement("section");
    const mounts = { health: document.createElement("div"), metrics: document.createElement("div"), board: document.createElement("div"), rules: document.createElement("div") };
    section.append(...Object.values(mounts));
    document.body.append(section);
    const calls = { correlation: 0, rules: 0, available: [] as boolean[] };
    const api = {
      correlation: async () => (calls.correlation++, seq.length > 1 ? (seq.shift() as Result<Correlation>) : seq[0]),
      correlationRules: async () => (calls.rules++, rules.length > 1 ? (rules.shift() as Result<RuleIndex>) : rules[0]),
    };
    const handle = mountCorrelation(section, mounts, api, (a) => calls.available.push(a));
    return { section, mounts, calls, handle };
  };
  const ok = (over: Record<string, unknown> = {}): Result<Correlation> => ({ ok: true, value: parseCorrelation(answer(over)) });
  const off: Result<Correlation> = { ok: true, value: parseCorrelation({ available: false }) };
  const missing: Result<Correlation> = { ok: false, error: "offline", message: "HTTP 404", status: 404, json: true };
  const malformed: Result<Correlation> = { ok: false, error: "bad-response", message: "correlation: expected an object" };

  it("hidden until available; hidden again on available:false, a 404 or a malformed answer; the verify panel is told each change", async () => {
    vi.useFakeTimers();
    const { section, calls } = setup([ok(), off, ok(), malformed, ok(), missing]);
    expect(section.hidden).toBe(true);
    await vi.advanceTimersByTimeAsync(0);
    expect(section.hidden).toBe(false);
    expect(section.querySelectorAll(".incident")).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(POLL_MS);
    expect(section.hidden).toBe(true);
    await vi.advanceTimersByTimeAsync(POLL_MS);
    expect(section.hidden).toBe(false);
    await vi.advanceTimersByTimeAsync(POLL_MS);
    expect(section.hidden).toBe(true);
    await vi.advanceTimersByTimeAsync(POLL_MS);
    await vi.advanceTimersByTimeAsync(POLL_MS);
    expect(section.hidden).toBe(true);
    expect(calls.available).toEqual([true, false, true, false, true, false]);
    // After a 404 the endpoint is asked again only after 10 minutes.
    const n = calls.correlation;
    await vi.advanceTimersByTimeAsync(POLL_404_MS - POLL_MS);
    expect(calls.correlation).toBe(n);
    await vi.advanceTimersByTimeAsync(POLL_MS);
    expect(calls.correlation).toBe(n + 1);
  });

  it("an unchanged answer redraws nothing (an open <details> survives); the checked time is rewritten in place", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    const { section, calls } = setup([ok(), ok({ checked_at: at(-40) })]);
    await vi.advanceTimersByTimeAsync(0);
    const incident = section.querySelector(".incident");
    const checked = section.querySelector(".corr-health__at");
    expect(incident).not.toBeNull();
    await vi.advanceTimersByTimeAsync(POLL_MS);
    expect(calls.correlation).toBe(2);
    expect(section.querySelector(".incident")).toBe(incident);
    expect(section.querySelector(".corr-health__at")).toBe(checked);
    expect(checked?.getAttribute("datetime")).toBe(at(-40));
    // Asked once: the applied commit did not move.
    expect(calls.rules).toBe(1);
  });

  it("metrics.since moving on every poll redraws nothing; its time is rewritten in place", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    const moved = (ago: number) => ok({ checked_at: at(ago), metrics: { since: at(86_400 + ago), incidents: 1, median_ttd_ms: 840, median_tti_ms: 212, median_twin_dwell_ms: null, host_findings: 0 } });
    const { section, calls } = setup([moved(20), moved(-40)]);
    await vi.advanceTimersByTimeAsync(0);
    const incident = section.querySelector(".incident");
    const since = section.querySelector(".corr-since");
    await vi.advanceTimersByTimeAsync(POLL_MS);
    expect(calls.correlation).toBe(2);
    expect(section.querySelector(".incident")).toBe(incident);
    expect(section.querySelector(".corr-since")).toBe(since);
    expect(since?.getAttribute("datetime")).toBe(at(86_400 - 40));
  });

  it("ingest lags moving between polls are rewritten in place, nothing is redrawn", async () => {
    vi.useFakeTimers();
    const lagged = (falco: number) => ok({ metrics: { since: at(86_400), incidents: 1, median_ttd_ms: 840, median_tti_ms: 212, median_twin_dwell_ms: null, host_findings: 0, ingest_lag_ms: { falco, api: null } } });
    const { section } = setup([lagged(1240), lagged(2500)]);
    await vi.advanceTimersByTimeAsync(0);
    const incident = section.querySelector(".incident");
    const falco = section.querySelector('.corr-lag__ms[data-source="falco"]');
    expect(falco?.textContent).toBe("1.2 s");
    await vi.advanceTimersByTimeAsync(POLL_MS);
    expect(section.querySelector(".incident")).toBe(incident);
    expect(section.querySelector('.corr-lag__ms[data-source="falco"]')).toBe(falco);
    expect(falco?.textContent).toBe("2.5 s");
  });

  it("an ingest lag crossing zero (clock skew) keeps its row and redraws nothing: an open <details> stays open", async () => {
    vi.useFakeTimers();
    const many = Array.from({ length: BOARD_INCIDENTS + 2 }, (_, n) => incident({ id: n.toString(16).padStart(16, "0"), last_at: at(100 + n) }));
    const lagged = (falco: number) => ok({ incidents: many, metrics: { since: at(86_400), incidents: many.length, median_ttd_ms: 840, median_tti_ms: 212, median_twin_dwell_ms: null, host_findings: 0, ingest_lag_ms: { falco, api: null } } });
    const { section } = setup([lagged(100), lagged(-100)]);
    await vi.advanceTimersByTimeAsync(0);
    const older = section.querySelector<HTMLDetailsElement>(".corr-older");
    expect(older).not.toBeNull();
    if (older) older.open = true;
    const falco = section.querySelector('.corr-lag__ms[data-source="falco"]');
    expect(falco?.textContent).toBe("100 ms");
    await vi.advanceTimersByTimeAsync(POLL_MS);
    expect(section.querySelector(".corr-older")).toBe(older);
    expect(older?.open).toBe(true);
    expect(section.querySelector('.corr-lag__ms[data-source="falco"]')).toBe(falco);
    expect(falco?.textContent).toBe("-100 ms");
  });

  it("the rule index is asked again when the applied commit moves; a new answer redraws", async () => {
    vi.useFakeTimers();
    const { section, calls } = setup([ok(), ok({ rules: { commit: "b".repeat(40), applied_at: at(10), status: "applied" } })]);
    await vi.advanceTimersByTimeAsync(0);
    const before = section.querySelector(".incident");
    await vi.advanceTimersByTimeAsync(POLL_MS);
    expect(calls.rules).toBe(2);
    expect(section.querySelector(".incident")).not.toBe(before);
  });

  it("rule links follow the API's commit once the provenance names it", async () => {
    vi.useFakeTimers();
    const { section, handle } = setup([ok()]);
    await vi.advanceTimersByTimeAsync(0);
    expect(section.querySelector(".corr-step a")?.getAttribute("href")).toContain("/blob/a7cc041e5d2b9f30c1a4e6b8d0f2a3c5e7f9b1d3/");
    handle.setCommit(COMMIT);
    expect(section.querySelector(".corr-step a")?.getAttribute("href")).toContain(`/blob/${COMMIT}/`);
  });

  it("does not poll while the tab is hidden, and catches up when it is shown", async () => {
    vi.useFakeTimers();
    const hidden = vi.spyOn(document, "hidden", "get").mockReturnValue(true);
    try {
      const { calls } = setup([ok()]);
      await vi.advanceTimersByTimeAsync(0);
      expect(calls.correlation).toBe(1);
      await vi.advanceTimersByTimeAsync(3 * POLL_MS);
      expect(calls.correlation).toBe(1);
      hidden.mockReturnValue(false);
      document.dispatchEvent(new Event("visibilitychange"));
      await vi.advanceTimersByTimeAsync(0);
      expect(calls.correlation).toBe(2);
    } finally {
      hidden.mockRestore();
    }
  });
});

describe("the fixtures (?mock=1 and serve.mjs --siem)", () => {
  it("parse without a drop, and every text in them is publishable", () => {
    const raw = JSON.parse(readFileSync(join(__dirname, "../../src/lib/correlation-fixture.json"), "utf8"));
    const c = parseCorrelation(fixtureCorrelation(NOW));
    expect(c.available).toBe(true);
    expect(c.incidents).toHaveLength(raw.correlation.incidents.length);
    expect(c.incidents.flatMap((i) => i.steps).some((s) => s.withheld)).toBe(false);
    expect(c.incidents.every((i) => i.title)).toBe(true);
    expect(parseRuleIndex(RULE_INDEX).rules).toHaveLength(raw.rules.rules.length);
    // The anchor becomes the moment of the answer.
    expect(c.checked_at).toBe(new Date(NOW - 20_000).toISOString());
    expect(shiftTimes({ at: "2026-10-04T12:00:00.000Z", n: "2026-10-04T12:00:00.000Z" }, 1000)).toEqual({ at: "2026-10-04T12:00:01.000Z", n: "2026-10-04T12:00:00.000Z" });
    expect(parseCorrelation(fixtureCorrelation(NOW, false)).available).toBe(false);
  });
});
