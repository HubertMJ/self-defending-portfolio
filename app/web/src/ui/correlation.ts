// "Correlation" (ADR 0034 section "Correlation", ADR 0036): what the SIEM made of the evidence. Every
// Falco alert, Talon action, audited API call, Hubble flow and terminal command is shipped to a SIEM
// on its own VM that the cluster can append to but not rewrite; Sigma rules from git run there, and the
// API correlates their findings into incidents. This section shows those incidents with their
// evidence timeline, the SOC figures over them, the SIEM's health line (decision D1: alarms are
// Alerting alerts, shown here and in Dashboards) and the rule library with its ATT&CK coverage.
//
// It exists only while GET /api/correlation says `available: true`: a SIEM that is down or not
// configured, an API without the endpoint and a malformed answer all hide it, and the demo above never
// depends on it. Nothing is computed into the record here: every time is the SIEM's, shown in Polish time, and the
// only figures the page derives (the p95s) say what they are taken over.

import type { ApiClient, Result } from "../lib/api";
import { type Correlation, type CorrelationIncident, type CorrelationStep, type RuleIndex, type SiemRule, secondPrecision } from "../lib/contract";
import { h, refreshRelative, replace, setText, timeEl, plClock, when, whenEl } from "../lib/dom";
import { commitUrl } from "../lib/provenance";
import { type ScenarioState, kindLabel } from "../lib/runstatus";
import { formatDuration } from "../lib/timeline";
import { attackUrl, extLink, pulse, sourceUrl } from "./common";
import { type Tone, statusChip } from "./posture";

/** Polled while the page is visible; an API without the endpoint (a 404) is asked again after 10 min. */
export const POLL_MS = 60_000;
/** While a filing for the visitor's own run is awaited (lib/runstatus.ts siemPending). */
export const EAGER_POLL_MS = 20_000;
export const POLL_404_MS = 10 * 60_000;
/** Incidents drawn in full; older ones are listed one line each below them. */
export const BOARD_INCIDENTS = 6;
/** Steps drawn per incident; the rest are in the raw JSON. */
export const INCIDENT_STEPS = 12;

export { kindLabel };

const SEVERITY_TONE: Record<CorrelationIncident["severity"], Tone> = { critical: "critical", high: "critical", medium: "warning", low: "neutral", unknown: "neutral" };

const SOURCE_WORD: Record<CorrelationStep["source"], string> = { falco: "falco", talon: "talon", hubble: "hubble", "k8s-audit": "audit", api: "api" };

const rawRunUrl = (runId: string) => `/api/runs/${encodeURIComponent(runId)}`;

/**
 * Nearest-rank percentile of the values given; undefined for none. Used only for the p95s, which the
 * API does not publish: each says how many incidents it is taken over.
 */
export function percentile(values: number[], p: number): number | undefined {
  if (!values.length) return undefined;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1))];
}

// ---------- health line ----------

const RULES_TONE: Record<Correlation["rules"]["status"], Tone> = { applied: "good", refused: "critical", failed: "critical", stale: "warning", unknown: "neutral" };

/**
 * "SIEM health", folded: rules applied at <commit> <when> · ingest ok · evidence not rewritten · disk
 * ok · checked <when>, and the ingest lag per source. A first-time visitor meets the scenario and the
 * incidents first; the plumbing is one click away, and its summary names any check that is not ok.
 */
export function renderHealth(c: Correlation, now: number, open = false): HTMLElement {
  const commit = c.rules.commit;
  const url = commit ? commitUrl(commit) : null;
  const ingest: [Tone, string] = c.health.ingest === "ok" ? ["good", "ingest ok"] : c.health.ingest === "silent" ? ["critical", "ingest silent"] : ["neutral", "ingest unknown"];
  const evidence: [Tone, string] =
    c.health.evidence_rewritten === false ? ["good", "evidence not rewritten"] : c.health.evidence_rewritten === true ? ["critical", "evidence rewrite detected"] : ["neutral", "evidence rewrite check unknown"];
  const disk: [Tone, string] = c.health.disk === "ok" ? ["good", "disk ok"] : c.health.disk === "high" ? ["warning", "disk high"] : ["neutral", "disk unknown"];
  const rules: [Tone, string] = [RULES_TONE[c.rules.status], `rules ${c.rules.status}`];
  const notOk = [rules, ingest, evidence, disk].filter(([tone]) => tone !== "good");
  return h(
    "details",
    { class: "corr-healthfold", open },
    h("summary", {}, h("h3", { class: "panel-title corr-healthfold__title" }, "SIEM health"), " ", notOk.length ? notOk.map(([tone, word]) => statusChip(tone, word)) : statusChip("good", "every check ok")),
    h(
      "div",
      { class: "corr-health", "data-ingest": c.health.ingest, "data-disk": c.health.disk, "data-rules": c.rules.status },
      h(
        "ul",
        { class: "corr-health__list", role: "list" },
        h(
          "li",
          { class: "corr-health__rules" },
          statusChip(...rules),
          url ? [" at commit ", extLink(url, h("code", {}, commit.slice(0, 7)))] : " (commit unknown)",
          c.rules.applied_at ? [", applied ", whenEl(c.rules.applied_at, now)] : null,
        ),
        h("li", {}, statusChip(...ingest)),
        h("li", {}, statusChip(...evidence)),
        h("li", {}, statusChip(...disk)),
      ),
      c.checked_at ? h("p", { class: "small corr-health__checked" }, "Checked by the API ", whenEl(c.checked_at, now, { class: "corr-health__at" }), ". Alarms are the SIEM's own alerts; this line is where they show.") : null,
      lagLine(c.metrics),
    ),
  );
}

// ---------- SOC metrics ----------

function metricTile(label: string, value: string, tone: Tone, status: string, foot: (Node | string | null)[]): HTMLElement {
  return h("article", { class: `tile tile--${tone}` }, h("h3", { class: "tile__label" }, label), h("p", { class: "tile__value" }, value), statusChip(tone, status), h("p", { class: "tile__foot" }, ...foot));
}

/** "p95 1.4 s over the 7 contained intrusions listed", or null under two values (a p95 of one is the value itself). */
function p95Foot(values: number[]): string | null {
  const p = percentile(values, 95);
  return p !== undefined && values.length >= 2 ? `p95 ${formatDuration(p)} over the ${values.length} contained intrusions listed` : null;
}

export function renderMetrics(c: Correlation, now: number): HTMLElement {
  const m = c.metrics;
  // The API's medians are over contained-intrusion incidents (ADR 0036 §5): the p95s are over the same
  // kind (a twin-dwell incident carries its guarded arm's TTD and TTI too, and would count them twice).
  const contained = c.incidents.filter((i) => i.kind === "contained-intrusion");
  const ttd = contained.map((i) => i.ttd_ms).filter((x): x is number => x !== null);
  const tti = contained.map((i) => i.tti_ms).filter((x): x is number => x !== null);
  const median = (v: number | null) => (v === null ? "–" : formatDuration(v));
  const tiles = h(
    "div",
    { class: "tiles corr-metrics" },
    metricTile("Incidents", String(m.incidents), m.incidents > 0 ? "warning" : "good", m.incidents > 0 ? "correlated" : "none", m.since ? ["last 24 h, since ", whenEl(m.since, now, { class: "corr-since" })] : ["last 24 h"]),
    metricTile("Time to detect", median(m.median_ttd_ms), m.median_ttd_ms === null ? "neutral" : "good", m.median_ttd_ms === null ? "no sample yet" : "median", [
      "Falco's alert after the command started",
      p95Foot(ttd) ? ` · ${p95Foot(ttd)}` : null,
    ]),
    metricTile("Time to isolate", median(m.median_tti_ms), m.median_tti_ms === null ? "neutral" : "good", m.median_tti_ms === null ? "no sample yet" : "median", [
      "Talon's audited quarantine or delete after the alert",
      p95Foot(tti) ? ` · ${p95Foot(tti)}` : null,
    ]),
    metricTile("Twin dwell time", median(m.median_twin_dwell_ms), m.median_twin_dwell_ms === null ? "neutral" : "warning", m.median_twin_dwell_ms === null ? "no compare run yet" : "median", [
      "how long the unguarded twin lived, from its audited create to its delete",
    ]),
    metricTile("Host findings", String(m.host_findings), m.host_findings > 0 ? "warning" : "good", m.host_findings > 0 ? "on the VM hosts" : "none", ["counted only: a host finding names users and addresses, which this page never shows"]),
  );
  return h("div", {}, tiles);
}

/** A lag over an hour reads "> 1 h" (an absurd value is not spelled out); a negative one (clock skew) as it is, in ms (formatDuration). */
const lagText = (ms: number | null) => (ms === null ? "–" : ms > 3_600_000 ? "> 1 h" : formatDuration(ms));

/** "Ingest lag, per source: falco 1.2 s · talon 900 ms · hubble –", in the sources' usual order; null when the API sends none. */
function lagLine(m: Correlation["metrics"]): HTMLElement | null {
  if (!m.ingest_lag_ms) return null;
  const rank = (s: string) => (SOURCE_ORDER.includes(s) ? SOURCE_ORDER.indexOf(s) : SOURCE_ORDER.length);
  const rows = [...m.ingest_lag_ms].sort((a, b) => rank(a[0]) - rank(b[0]) || a[0].localeCompare(b[0]));
  return h(
    "p",
    { class: "small corr-lag" },
    "Ingest lag, per source (how far behind its newest record was when the API last read it): ",
    rows.flatMap(([src, ms], n) => [n ? " · " : "", h("span", { class: "corr-lag__src" }, src), " ", h("span", { class: "corr-lag__ms", "data-source": src }, lagText(ms))]),
  );
}

// ---------- incident board ----------

export interface BoardContext {
  now: number;
  /** The rule index by Sigma id, for step links. */
  rules: ReadonlyMap<string, SiemRule>;
  /** The commit the rule files are linked at. */
  commit: string;
  /** The visitor's own runs in this page view: their incidents are shown in full, pinned first. */
  own?: ReadonlySet<string>;
}

/** "T1046, T1048.003", each linked to its MITRE page. */
function techniqueLinks(list: string[]): (Node | string)[] {
  return list.flatMap((t, n) => {
    const url = attackUrl(t);
    return [n ? ", " : "", url ? extLink(url, t) : t];
  });
}

const fact = (k: string, v: Node | string | (Node | string)[] | null) => (v === null ? null : h("div", {}, h("dt", {}, k), h("dd", {}, v)));

function flagFact(i: CorrelationIncident): HTMLElement | null {
  if (i.kind !== "dns-exfil") return null;
  if (i.flag_match === true) return fact("Flag", statusChip("critical", "matched the run's flag"));
  if (i.flag_match === false) return fact("Flag", statusChip("neutral", "no match for this run"));
  return fact("Flag", statusChip("neutral", "flag match unavailable"));
}

/** Falco's count; for dns-exfil a zero is the point (nothing in the pod's syscalls gives it away). */
function falcoFact(i: CorrelationIncident): HTMLElement | null {
  if (i.falco_events === null) return null;
  if (i.falco_events === 0) return fact("Falco", h("span", { class: "corr-nofalco" }, "no event"));
  return fact("Falco", `${i.falco_events} event${i.falco_events === 1 ? "" : "s"}`);
}

/** The step's rule, linked to its Sigma file at the commit when the index knows it; null for a plain document. */
function ruleRef(step: CorrelationStep, ctx: BoardContext): Node | string | null {
  const r = step.rule_id ? ctx.rules.get(step.rule_id) : undefined;
  const url = r && r.file ? sourceUrl(ctx.commit, r.file, r.line) : null;
  const name = step.rule || r?.title || "";
  if (!name) return null;
  return url ? extLink(url, name) : name;
}

const countTitle = (count: number) => `${count} records of the same evidence`;

/** "×12": the step stands for that many records of the same evidence; `n` (its place) lets a new count be written in place. */
function countEl(s: CorrelationStep, n: number): HTMLElement | null {
  if (s.count === undefined || s.count < 2) return null;
  return h("span", { class: "corr-step__count", "data-step": String(n), title: countTitle(s.count) }, `×${s.count}`);
}

function stepItem(s: CorrelationStep, n: number, t0: number, ctx: BoardContext): HTMLElement {
  const at = Date.parse(s.at);
  const delta = at - t0;
  const rule = ruleRef(s, ctx);
  const count = countEl(s, n);
  const lead = !!rule || !!count;
  const coarse = secondPrecision(s);
  return h(
    "li",
    { class: "corr-step", "data-source": s.source, "data-precision": coarse ? "s" : "ms" },
    timeEl(s.at, plClock(s.at, ctx.now, { ms: !coarse }), { class: "corr-step__at" }),
    coarse
      ? h("span", { class: "corr-step__prec", title: "Talon records whole seconds: this step is listed by the end of its second" }, " (to the second)")
      : delta > 0
        ? h("span", { class: "corr-step__delta" }, ` +${formatDuration(delta)}`)
        : null,
    " ",
    h("span", { class: `tag tag--src tag--${s.source}` }, SOURCE_WORD[s.source]),
    " ",
    // A stream document without a finding has no rule: its detail says what it is.
    rule ? h("strong", { class: "corr-step__rule" }, rule) : null,
    count ? [rule ? " " : null, count] : null,
    s.command_seq !== null ? h("span", { class: "corr-step__cmd" }, `${lead ? " · " : ""}command ${s.command_seq}`) : null,
    s.detail
      ? h("span", { class: "corr-step__detail" }, lead || s.command_seq !== null ? " · " : null, s.detail)
      : s.withheld
        ? h("span", { class: "corr-step__detail corr-step__detail--withheld" }, lead || s.command_seq !== null ? " · " : null, "detail withheld by the page (ADR 0021)")
        : null,
  );
}

export function renderIncident(i: CorrelationIncident, ctx: BoardContext, tier?: "pinned" | "own"): HTMLElement {
  // Deltas count from the first step timed to the millisecond; a whole-second Talon step is no origin.
  const origin = i.steps.find((s) => !secondPrecision(s)) ?? i.steps[0];
  const t0 = origin ? Date.parse(origin.at) : Date.parse(i.first_at);
  const shown = i.steps.slice(0, INCIDENT_STEPS);
  const more = i.steps.length - shown.length;
  return h(
    "article",
    // The card carries the id every "Open it" link names, so the card's top (badge, title) is what lands.
    { class: tier ? `incident incident--${tier}` : "incident", id: `incident-${i.id}`, "data-kind": i.kind, "data-severity": i.severity, "data-incident": i.id, "aria-labelledby": `incident-${i.id}-title` },
    h(
      "header",
      { class: "incident__head" },
      statusChip(SEVERITY_TONE[i.severity], i.severity),
      " ",
      h("h4", { class: "incident__title", id: `incident-${i.id}-title` }, i.title || kindLabel(i.kind)),
    ),
    h(
      "p",
      { class: "incident__kind" },
      kindLabel(i.kind),
      i.arm ? [" ", h("span", { class: "tag tag--arm", "data-arm": i.arm }, i.arm === "guarded" ? "guarded" : "twin, unguarded")] : null,
      i.run_id ? [" · run ", extLink(rawRunUrl(i.run_id), h("code", {}, i.run_id))] : null,
    ),
    h("p", { class: "incident__when small" }, "from ", timeEl(i.first_at, plClock(i.first_at, ctx.now, { ms: true })), " to ", timeEl(i.last_at, plClock(i.last_at, ctx.now, { ms: true }))),
    h(
      "dl",
      { class: "facts incident__facts" },
      fact("Time to detect", i.ttd_ms !== null ? formatDuration(i.ttd_ms) : null),
      fact("Time to isolate", i.tti_ms !== null ? formatDuration(i.tti_ms) : null),
      falcoFact(i),
      flagFact(i),
      fact("ATT&CK", i.attack.length ? techniqueLinks(i.attack) : null),
    ),
    shown.length ? h("ol", { class: "corr-steps", "aria-label": "Evidence timeline" }, shown.map((s, n) => stepItem(s, n, t0, ctx))) : h("p", { class: "small" }, "No step of this incident is publishable."),
    more > 0 ? h("p", { class: "small" }, `${more} more step${more === 1 ? "" : "s"} in the raw JSON.`) : null,
    i.evidence.length
      ? h(
          "p",
          { class: "incident__evidence small" },
          "SIEM evidence: ",
          i.evidence.flatMap((e, n) => [n ? ", " : "", `${e.type} `, h("code", {}, e.id)]),
        )
      : null,
  );
}

function olderItem(i: CorrelationIncident, now: number): HTMLElement {
  return h(
    "li",
    { class: "corr-older__item", "data-incident": i.id },
    statusChip(SEVERITY_TONE[i.severity], i.severity),
    " ",
    timeEl(i.first_at, plClock(i.first_at, now)),
    " ",
    h("span", {}, i.title || kindLabel(i.kind)),
  );
}

/** Sessions an operator-test incident stands for: its steps, each counted. */
const sessions = (i: CorrelationIncident) => Math.max(1, i.steps.reduce((n, s) => n + (s.count ?? 1), 0));

/** "N operator test-suite execs in the last 24 h", folded; opened, one line per incident. */
function operatorTests(tests: CorrelationIncident[], now: number): HTMLElement {
  const n = tests.reduce((sum, i) => sum + sessions(i), 0);
  return h(
    "details",
    { class: "corr-optests" },
    h("summary", {}, `${n} operator test-suite exec${n === 1 ? "" : "s"} in the last 24 h`),
    h("p", { class: "small" }, "Sessions by the cluster admin's credential into pods the live test suites create (ADR 0036): true incidents, labelled and folded here, not hidden. The label says only what the evidence shows."),
    h("ol", { class: "corr-older__list" }, tests.map((i) => olderItem(i, now))),
  );
}

/** The kinds that are the project's thesis: caught by correlating sources, where Falco alone says nothing. */
const PINNED_KINDS: ReadonlySet<string> = new Set(["dns-exfil", "policy-probing", "prevented-not-detected"]);
const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

/**
 * Which tier an incident is drawn in. "own": the visitor's own incidents of this page view, under their
 * own heading first; "pinned": caught by correlation, not by Falco (its kind, or a Falco count of zero);
 * "contained": the
 * contained intrusions Falco and Talon handled on their own, folded into one line; "other": everything
 * else, as before; "test": the operator's test-suite execs, folded.
 */
export function tierOf(i: CorrelationIncident, own: ReadonlySet<string> = new Set()): "own" | "pinned" | "contained" | "other" | "test" {
  if (i.operator_test) return "test";
  if (i.run_id && own.has(i.run_id)) return "own";
  if (PINNED_KINDS.has(i.kind) || i.falco_events === 0) return "pinned";
  if (i.kind === "contained-intrusion") return "contained";
  return "other";
}

/** "12 intrusions caught and ended · median 692 ms to detect · 14 ms to isolate", over the ones listed. */
function containedSummary(list: CorrelationIncident[]): string {
  const med = (xs: (number | null)[]) => percentile(xs.filter((x): x is number => x !== null), 50);
  const ttd = med(list.map((i) => i.ttd_ms));
  const tti = med(list.map((i) => i.tti_ms));
  return [
    `${list.length} intrusion${list.length === 1 ? "" : "s"} caught and ended`,
    ttd !== undefined ? `median ${formatDuration(ttd)} to detect` : null,
    tti !== undefined ? `${ttd !== undefined ? "" : "median "}${formatDuration(tti)} to isolate` : null,
  ]
    .filter(Boolean)
    .join(" · ");
}

export function renderBoard(c: Correlation, ctx: BoardContext): HTMLElement {
  if (!c.incidents.length) {
    return h("div", { class: "corr-board" }, h("h3", { class: "panel-title" }, "Incidents"), h("p", { class: "empty" }, "No incident in the last 24 hours. The rules run on every event the cluster ships; when one fires, it appears here with its evidence."));
  }
  const own = ctx.own ?? new Set<string>();
  const by = (tier: ReturnType<typeof tierOf>) => c.incidents.filter((i) => tierOf(i, own) === tier);
  // The live test suites' own execs (operator_test) are folded into one line, never dropped.
  const tests = by("test");
  // The most severe first, then the newest (the API's order).
  const bySeverity = (list: CorrelationIncident[]) =>
    list
      .map((i, n) => ({ i, n }))
      .sort((a, b) => (SEVERITY_RANK[b.i.severity] ?? 0) - (SEVERITY_RANK[a.i.severity] ?? 0) || a.n - b.n)
      .map((x) => x.i);
  // The visitor's own incidents, all in full, under their own heading: one of them may be a contained
  // intrusion Falco did see, which is no "caught by correlation" card.
  const mine = bySeverity(by("own"));
  const pinned = bySeverity(by("pinned"));
  const pinnedFull = pinned.slice(0, BOARD_INCIDENTS);
  const contained = by("contained");
  const other = by("other");
  const otherFull = other.slice(0, Math.max(0, BOARD_INCIDENTS - pinnedFull.length));
  const older = [...pinned.filter((i) => !pinnedFull.includes(i)), ...other.slice(otherFull.length)].sort((a, b) => Date.parse(b.first_at) - Date.parse(a.first_at));
  return h(
    "div",
    { class: "corr-board" },
    h("h3", { class: "panel-title" }, `Incidents, newest first (${c.incidents.length} in the last 24 h)`),
    mine.length
      ? h(
          "section",
          { class: "corr-tier corr-tier--own", "aria-labelledby": "corr-own-title" },
          h("h4", { class: "corr-tier__title", id: "corr-own-title" }, "From your run on this page"),
          h("div", { class: "corr-incidents" }, mine.map((i) => renderIncident(i, ctx, "own"))),
        )
      : null,
    h(
      "section",
      { class: "corr-tier corr-tier--pinned", "aria-labelledby": "corr-pinned-title" },
      h("h4", { class: "corr-tier__title", id: "corr-pinned-title" }, "Caught by correlation, not by Falco"),
      pinnedFull.length
        ? h("div", { class: "corr-incidents" }, pinnedFull.map((i) => renderIncident(i, ctx, "pinned")))
        : h("p", { class: "empty" }, mine.length ? "None in the last 24 hours besides yours above." : contained.length || other.length ? "None in the last 24 hours. Run the DNS exfiltration above and yours appears here." : "No incident in the last 24 hours besides the operator's own test runs."),
    ),
    contained.length
      ? h(
          "details",
          { class: "corr-contained" },
          h("summary", {}, `Contained automatically by Falco + Talon (${contained.length})`),
          h("p", { class: "small corr-contained__line" }, containedSummary(contained), ". Falco caught each one and Talon ended it on its own; the SIEM filed them afterwards."),
          h("ol", { class: "corr-older__list" }, contained.map((i) => olderItem(i, ctx.now))),
        )
      : null,
    otherFull.length ? h("div", { class: "corr-incidents corr-incidents--other" }, otherFull.map((i) => renderIncident(i, ctx))) : null,
    tests.length ? operatorTests(tests, ctx.now) : null,
    older.length
      ? h("details", { class: "corr-older" }, h("summary", {}, `${older.length} older incident${older.length === 1 ? "" : "s"}`), h("ol", { class: "corr-older__list" }, older.map((i) => olderItem(i, ctx.now))))
      : null,
    h("p", { class: "small" }, "The whole board as the API publishes it: ", extLink("/api/correlation", "/api/correlation"), " (JSON)."),
  );
}

// ---------- the SIEM scenario (REPORT point 1) ----------

const PHASE_WORD: Record<ScenarioState["phase"], string> = {
  idle: "not run yet",
  running: "running…",
  waiting: "waiting for the SIEM (≈2 min)…",
  late: "still waiting: the SIEM is behind, and this board keeps asking",
  down: "the SIEM is not reachable right now",
  failed: "the query did not go out; try it early in a fresh session",
  found: "found it",
};

/** The chip's words for a state: "found it" links to the incident, wherever on the board it is. */
export function scenarioChip(state: ScenarioState): (Node | string)[] {
  if (state.phase === "found" && state.incidentId) return [`${PHASE_WORD.found}: `, h("a", { href: `#incident-${state.incidentId}` }, `the ${(state.severity ?? "").toUpperCase()} incident is below ↓`)];
  return [PHASE_WORD[state.phase]];
}

function renderScenario(onRun: () => void): { el: HTMLElement; chip: HTMLElement; btn: HTMLButtonElement; note: HTMLElement } {
  const btn = h("button", { type: "button", class: "btn btn--attack corr-scenario__btn" }, "Run it in the terminal ↑");
  btn.addEventListener("click", () => {
    if (btn.getAttribute("aria-disabled") !== "true") onRun();
  });
  const chip = h("span", { class: "corr-scenario__state", "data-phase": "idle" }, PHASE_WORD.idle);
  const note = h("p", { class: "small corr-scenario__note" }, "Opens a terminal session (it costs one run) and picks the command for you.");
  const el = h(
    "div",
    { class: "corr-scenario" },
    h("h3", { class: "corr-scenario__title" }, "Make the SIEM catch what Falco cannot."),
    h(
      "p",
      { class: "corr-scenario__lead" },
      "Falco watches syscalls and never reads DNS. Run ",
      h("strong", {}, "DNS exfiltration"),
      " in the terminal and the secret leaves as a name lookup: Falco stays silent, Hubble logs the query, and one to three minutes later the SIEM ties it to your run and raises a CRITICAL incident below.",
    ),
    h("div", { class: "corr-scenario__actions" }, btn, h("span", { class: "corr-scenario__statewrap" }, h("span", { class: "corr-scenario__label" }, "Your run: "), chip)),
    note,
  );
  return { el, chip, btn, note };
}

// ---------- rule library and ATT&CK coverage ----------

export interface Coverage {
  /** Technique ids, sorted. */
  techniques: string[];
  /** Log sources that have at least one rule, in the contract's order, then any other. */
  sources: string[];
  /** rules[technique][source]: how many rules cover the technique from that source. */
  rules: Map<string, Map<string, number>>;
  /** How many of the listed incidents name the technique. */
  seen: Map<string, number>;
}

const SOURCE_ORDER = ["falco", "talon", "k8s-audit", "hubble", "api"];

export function coverage(idx: RuleIndex, incidents: CorrelationIncident[]): Coverage {
  const rules = new Map<string, Map<string, number>>();
  const sources = new Set<string>();
  for (const r of idx.rules) {
    const src = r.source || "other";
    sources.add(src);
    for (const t of r.attack) {
      const row = rules.get(t) ?? new Map<string, number>();
      row.set(src, (row.get(src) ?? 0) + 1);
      rules.set(t, row);
    }
  }
  const seen = new Map<string, number>();
  for (const i of incidents) for (const t of i.attack) seen.set(t, (seen.get(t) ?? 0) + 1);
  const rank = (s: string) => (SOURCE_ORDER.includes(s) ? SOURCE_ORDER.indexOf(s) : SOURCE_ORDER.length);
  return {
    techniques: [...new Set([...rules.keys(), ...seen.keys()])].sort(),
    sources: [...sources].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b)),
    rules,
    seen,
  };
}

function coverageTable(cov: Coverage): HTMLElement {
  return h(
    "div",
    { class: "table-scroll" },
    h(
      "table",
      { class: "data-table corr-matrix" },
      h("caption", {}, "ATT&CK coverage: rules per technique and log source, and incidents in the last 24 h"),
      h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Technique"), cov.sources.map((s) => h("th", { scope: "col" }, s)), h("th", { scope: "col" }, "Incidents"))),
      h(
        "tbody",
        {},
        cov.techniques.map((t) => {
          const url = attackUrl(t);
          const row = cov.rules.get(t);
          const seen = cov.seen.get(t) ?? 0;
          return h(
            "tr",
            { "data-technique": t, "data-covered": String(!!row) },
            h("th", { scope: "row" }, url ? extLink(url, t) : t),
            cov.sources.map((s) => {
              const n = row?.get(s) ?? 0;
              return h("td", { "data-n": String(n) }, n ? h("span", { class: "corr-cell" }, h("span", { "aria-hidden": "true" }, "■ "), String(n)) : h("span", { class: "corr-cell corr-cell--none" }, "–"));
            }),
            // A technique seen in an incident without a rule of its own is a gap, and says so.
            h("td", { "data-seen": String(seen) }, row ? String(seen) : h("span", { class: "corr-cell--gap" }, `${seen}, no rule`)),
          );
        }),
      ),
    ),
  );
}

function ruleRow(r: SiemRule, commit: string): HTMLElement {
  const url = r.file ? sourceUrl(commit, r.file, r.line) : null;
  return h(
    "li",
    { class: "corr-rule", "data-rule": r.id, "data-source": r.source },
    h("strong", {}, r.title),
    r.level ? [" ", h("span", { class: "tag tag--level", "data-level": r.level }, r.level)] : null,
    h(
      "span",
      { class: "corr-rule__meta small" },
      r.source ? ` · ${r.source}` : null,
      r.status ? ` · ${r.status}` : null,
      r.attack.length ? [" · ", ...techniqueLinks(r.attack)] : null,
      r.canary ? [" · canary ", h("code", {}, r.canary)] : " · no canary",
      url ? [" · ", extLink(url, "Sigma YAML")] : null,
    ),
  );
}

export function renderRuleLibrary(idx: RuleIndex | null | undefined, commit: string, incidents: CorrelationIncident[]): HTMLElement {
  const head = h("h3", { class: "panel-title" }, "Rule library");
  if (idx === undefined) return h("div", { class: "corr-rules" }, head, h("p", { class: "loading" }, "Loading the rule library…"));
  if (idx === null || !idx.rules.length) return h("div", { class: "corr-rules" }, head, h("p", { class: "small" }, "The rule library is unavailable right now; the incidents above name their rules."));
  const named = (title: string, list: RuleIndex["monitors"]) =>
    list.length
      ? h(
          "div",
          { class: "corr-named" },
          h("h4", {}, title),
          h("ul", { class: "corr-named__list", role: "list" }, list.map((m) => h("li", {}, m.file && sourceUrl(commit, m.file) ? extLink(sourceUrl(commit, m.file) as string, m.name) : m.name, m.canary ? [" · canary ", h("code", {}, m.canary)] : " · no canary"))),
        )
      : null;
  const canaried = idx.rules.filter((r) => r.canary).length;
  return h(
    "div",
    { class: "corr-rules" },
    head,
    h(
      "p",
      { class: "small" },
      `${idx.rules.length} Sigma rule${idx.rules.length === 1 ? "" : "s"}, ${idx.monitors.length} monitor${idx.monitors.length === 1 ? "" : "s"} and ${idx.correlations.length} correlation rule${idx.correlations.length === 1 ? "" : "s"}, synced to the SIEM from `,
      h("code", {}, "siem/"),
      ` in git; ${canaried} of the rules have a canary that proves they fire.`,
    ),
    coverageTable(coverage(idx, incidents)),
    h("details", { class: "corr-rulelist" }, h("summary", {}, `The ${idx.rules.length} Sigma rules, each linked to its YAML`), h("ul", { class: "corr-rulelist__list", role: "list" }, idx.rules.map((r) => ruleRow(r, commit)))),
    named("Monitors", idx.monitors),
    named("Correlation rules", idx.correlations),
  );
}

// ---------- mount ----------

export interface CorrelationHandle {
  /** The API's commit (GET /api/provenance): the rule index is generated from it, so its files and lines are linked there. */
  setCommit(commit: string): void;
  /**
   * Whether the section's content can be seen (it is not folded away; folded is not hidden, which
   * says the SIEM is unavailable). While it cannot, the polls go on (they decide shown or hidden) but
   * nothing is drawn; the latest answer is drawn on the way back.
   */
  setActive(active: boolean): void;
  /**
   * The visitor's own runs and their scenario state (ui/runstatus.ts): their incidents are pinned in
   * full, the scenario chip follows, and while a filing is awaited the SIEM is asked every EAGER_POLL_MS.
   */
  setVisitor(v: { ownRuns: readonly string[]; scenario: ScenarioState; eager: boolean }): void;
  /** Whether the terminal is on this API: without it the scenario cannot be run from here. */
  setTerminal(available: boolean): void;
  /** Pulses an incident's card (the visitor was sent there). */
  pulse(incidentId: string): void;
}

/**
 * `section`: #correlation (hidden in the HTML). `onAvailable`: every change between shown and hidden,
 * so the verify panel lists the two endpoints only while they answer.
 */
export function mountCorrelation(
  section: HTMLElement,
  mounts: { scenario?: HTMLElement; health: HTMLElement; metrics: HTMLElement; board: HTMLElement; rules: HTMLElement },
  api: Pick<ApiClient, "correlation" | "correlationRules">,
  onAvailable?: (available: boolean) => void,
  opts: {
    /** The incidents while the SIEM is available; null once it says unavailable or has no endpoint. Not called on a failed poll. */
    onData?: (c: Correlation | null) => void;
    /** The scenario's button: take the visitor to the terminal with the DNS exfil picked. */
    onScenario?: () => void;
    eagerMs?: number;
  } = {},
): CorrelationHandle {
  let data: Correlation | undefined;
  let index: RuleIndex | null | undefined;
  let indexCommit: string | undefined;
  let apiCommit = "";
  let key = "";
  let shown = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let due = false;
  let active = true;
  let own: ReadonlySet<string> = new Set();
  let eager = false;
  let terminal = true;
  let scenario: ScenarioState = { phase: "idle" };
  const pulsed = new Set<string>();
  let healthOpen = false;
  const eagerMs = opts.eagerMs ?? EAGER_POLL_MS;
  const sc = mounts.scenario ? renderScenario(() => opts.onScenario?.()) : null;
  if (sc && mounts.scenario) replace(mounts.scenario, sc.el);

  /** The scenario's chip and button, patched in place (the board is not redrawn for them). */
  const drawScenario = () => {
    if (!sc) return;
    if (sc.chip.dataset.phase !== scenario.phase || sc.chip.dataset.incident !== (scenario.incidentId ?? "")) {
      sc.chip.dataset.phase = scenario.phase;
      sc.chip.dataset.incident = scenario.incidentId ?? "";
      replace(sc.chip, ...scenarioChip(scenario));
    }
    sc.btn.setAttribute("aria-disabled", String(!terminal));
    replace(sc.note, terminal ? "Opens a terminal session (it costs one run) and picks the command for you." : "The terminal is not on this build of the site right now, so the scenario cannot be run from here.");
  };
  drawScenario();

  const linkCommit = () => apiCommit || data?.rules.commit || "";

  const draw = (force = false) => {
    if (!data || !active) return;
    // Redrawn only when what it shows changes. The API moves checked_at and metrics.since on every
    // poll: those two are rewritten in place, so an open <details> or a focused link survives a poll.
    // The ingest lags move on every poll too: only which sources are listed is part of the key. So
    // does a step's count while its records keep arriving: only whether it shows one is.
    const lag = data.metrics.ingest_lag_ms;
    const counted = (s: CorrelationStep) => (s.count ?? 1) > 1;
    const incidents = data.incidents.map((i) => ({ ...i, steps: i.steps.map((s) => ({ ...s, count: counted(s) })) }));
    const k = JSON.stringify({ d: { ...data, checked_at: !!data.checked_at, metrics: { ...data.metrics, since: !!data.metrics.since, ingest_lag_ms: lag?.map(([src]) => src) }, incidents }, i: index === undefined ? "u" : index, c: linkCommit(), o: [...own] });
    const now = Date.now();
    if (!force && k === key) {
      const moveTo = (el: HTMLTimeElement | null, t: string) => {
        if (!el || !t) return;
        el.dataset.when = String(Date.parse(t));
        el.dateTime = new Date(t).toISOString();
        setText(el, when(t, now));
      };
      moveTo(mounts.health.querySelector<HTMLTimeElement>(".corr-health__at"), data.checked_at);
      moveTo(mounts.metrics.querySelector<HTMLTimeElement>(".corr-since"), data.metrics.since);
      for (const [src, ms] of lag ?? []) {
        const el = [...mounts.health.querySelectorAll<HTMLElement>(".corr-lag__ms")].find((e) => e.dataset.source === src);
        if (el) setText(el, lagText(ms));
      }
      for (const i of data.incidents) {
        i.steps.forEach((s, n) => {
          const el = counted(s) ? mounts.board.querySelector<HTMLElement>(`[data-incident="${i.id}"] .corr-step__count[data-step="${n}"]`) : null;
          if (el && s.count) {
            setText(el, `×${s.count}`);
            el.title = countTitle(s.count);
          }
        });
      }
      refreshRelative(section, now);
      return;
    }
    key = k;
    const rules = new Map((index ?? { rules: [] }).rules.map((r) => [r.id, r]));
    // The fold stays as the visitor left it across a redraw.
    const health = renderHealth(data, now, healthOpen);
    health.addEventListener("toggle", () => (healthOpen = (health as HTMLDetailsElement).open));
    replace(mounts.health, health);
    replace(mounts.metrics, renderMetrics(data, now));
    replace(mounts.board, renderBoard(data, { now, rules, commit: linkCommit(), own }));
    replace(mounts.rules, renderRuleLibrary(index, linkCommit(), data.incidents));
    // An incident of the visitor's own run pulses once when it first lands.
    for (const i of data.incidents) {
      if (!i.run_id || !own.has(i.run_id) || pulsed.has(i.id)) continue;
      pulsed.add(i.id);
      pulseCard(i.id);
    }
  };

  const pulseCard = (id: string) => {
    const card = mounts.board.querySelector<HTMLElement>(`.incident[data-incident="${id}"]`);
    if (card) pulse(card);
  };

  const show = (on: boolean) => {
    section.hidden = !on;
    if (on !== shown) {
      shown = on;
      onAvailable?.(on);
    }
  };

  // The index changes only with the rules: asked once, and again when the applied commit moves.
  const loadIndex = async (commit: string) => {
    if (indexCommit === commit && index) return;
    indexCommit = commit;
    const r = await api.correlationRules();
    index = r.ok ? r.value : null;
    draw();
  };

  const schedule = (ms: number) => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      // Not while the tab is hidden: the poll resumes when the visitor comes back.
      if (typeof document !== "undefined" && document.hidden) due = true;
      else void poll();
    }, ms);
  };

  const poll = async () => {
    due = false;
    const r: Result<Correlation> = await api.correlation();
    if (r.ok && r.value.available) {
      data = r.value;
      show(true);
      draw();
      void loadIndex(r.value.rules.commit);
    } else {
      show(false);
    }
    // Unavailable only when the API says so (available:false) or has no such endpoint (a 404): a
    // network blip, a 5xx, a 429 or a malformed answer leaves the visitor's last reading as it was.
    if (r.ok) opts.onData?.(r.value.available ? r.value : null);
    else if (r.status === 404) opts.onData?.(null);
    schedule(!r.ok && r.status === 404 ? POLL_404_MS : eager ? eagerMs : POLL_MS);
  };

  if (typeof document !== "undefined") {
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden && due) void poll();
    });
  }
  section.hidden = true;
  void poll();

  return {
    setCommit(c) {
      if (c === apiCommit) return;
      apiCommit = c;
      draw();
    },
    setActive(on) {
      active = on;
      draw();
    },
    setVisitor(v) {
      scenario = v.scenario;
      drawScenario();
      const next = new Set(v.ownRuns);
      if ([...next].some((r) => !own.has(r))) {
        own = next;
        draw();
      }
      // Asked sooner while a filing is awaited; back to the minute once it has landed.
      if (v.eager && !eager) schedule(eagerMs);
      eager = v.eager;
    },
    setTerminal(on) {
      terminal = on;
      drawScenario();
    },
    pulse: (id) => pulseCard(id),
  };
}
