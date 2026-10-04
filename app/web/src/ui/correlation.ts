// "Correlation" (ADR 0034 section "Correlation", ADR 0036): what the SIEM made of the evidence. Every
// Falco alert, Talon action, audited API call, Hubble flow and terminal command is shipped to a SIEM
// on its own VM that the cluster can append to but not rewrite; Sigma rules from git run there, and the
// API correlates their findings into incidents. This section shows those incidents with their
// evidence timeline, the SOC figures over them, the SIEM's health line (decision D1: alarms are
// Alerting alerts, shown here and in Dashboards) and the rule library with its ATT&CK coverage.
//
// It exists only while GET /api/correlation says `available: true`: a SIEM that is down or not
// configured, an API without the endpoint and a malformed answer all hide it, and the demo above never
// depends on it. Nothing is computed into the record here: every time is the SIEM's, in UTC, and the
// only figures the page derives (the p95s) say what they are taken over.

import type { ApiClient, Result } from "../lib/api";
import type { Correlation, CorrelationIncident, CorrelationStep, RuleIndex, SiemRule } from "../lib/contract";
import { h, refreshRelative, replace, setText, timeEl, utcClock, when, whenEl } from "../lib/dom";
import { commitUrl } from "../lib/provenance";
import { formatDuration } from "../lib/timeline";
import { attackUrl, extLink, sourceUrl } from "./common";
import { type Tone, statusChip } from "./posture";

/** Polled while the page is visible; an API without the endpoint (a 404) is asked again after 10 min. */
export const POLL_MS = 60_000;
export const POLL_404_MS = 10 * 60_000;
/** Incidents drawn in full; older ones are listed one line each below them. */
export const BOARD_INCIDENTS = 6;
/** Steps drawn per incident; the rest are in the raw JSON. */
export const INCIDENT_STEPS = 12;

/** What each incident kind means, in the page's words. A Map: a kind such as "constructor" finds nothing. */
const KINDS: ReadonlyMap<string, string> = new Map([
  ["staged-attack", "Staged attack"],
  ["contained-intrusion", "Contained intrusion"],
  ["dns-exfil", "DNS exfiltration"],
  ["policy-probing", "Policy probing"],
  ["prevented-not-detected", "Prevented, not detected"],
  ["detection-missing", "Detection missing"],
  ["exec-outside-api", "Exec outside the API"],
  ["twin-dwell", "Unguarded twin: dwell time"],
]);
export const kindLabel = (kind: string): string => KINDS.get(kind) ?? kind;

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

const RULES_TONE: Record<Correlation["rules"]["status"], Tone> = { applied: "good", refused: "critical", failed: "critical", unknown: "neutral" };

/** "SIEM health · rules applied at <commit> <when> · ingest ok · evidence not rewritten · disk ok · checked <when>". */
export function renderHealth(c: Correlation, now: number): HTMLElement {
  const commit = c.rules.commit;
  const url = commit ? commitUrl(commit) : null;
  const ingest: [Tone, string] = c.health.ingest === "ok" ? ["good", "ingest ok"] : c.health.ingest === "silent" ? ["critical", "ingest silent"] : ["neutral", "ingest unknown"];
  const evidence: [Tone, string] =
    c.health.evidence_rewritten === false ? ["good", "evidence not rewritten"] : c.health.evidence_rewritten === true ? ["critical", "evidence rewrite detected"] : ["neutral", "evidence rewrite check unknown"];
  const disk: [Tone, string] = c.health.disk === "ok" ? ["good", "disk ok"] : c.health.disk === "high" ? ["warning", "disk high"] : ["neutral", "disk unknown"];
  return h(
    "div",
    { class: "corr-health", "data-ingest": c.health.ingest, "data-disk": c.health.disk, "data-rules": c.rules.status },
    h("h3", { class: "panel-title" }, "SIEM health"),
    h(
      "ul",
      { class: "corr-health__list", role: "list" },
      h(
        "li",
        { class: "corr-health__rules" },
        statusChip(RULES_TONE[c.rules.status], `rules ${c.rules.status}`),
        url ? [" at commit ", extLink(url, h("code", {}, commit.slice(0, 7)))] : " (commit unknown)",
        c.rules.applied_at ? [", applied ", whenEl(c.rules.applied_at, now)] : null,
      ),
      h("li", {}, statusChip(...ingest)),
      h("li", {}, statusChip(...evidence)),
      h("li", {}, statusChip(...disk)),
    ),
    c.checked_at ? h("p", { class: "small corr-health__checked" }, "Checked by the API ", whenEl(c.checked_at, now, { class: "corr-health__at" }), ". Alarms are the SIEM's own alerts; this line is where they show.") : null,
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
  return h(
    "div",
    { class: "tiles corr-metrics" },
    metricTile("Incidents", String(m.incidents), m.incidents > 0 ? "warning" : "good", m.incidents > 0 ? "correlated" : "none", m.since ? ["last 24 h, since ", whenEl(m.since, now)] : ["last 24 h"]),
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
}

// ---------- incident board ----------

export interface BoardContext {
  now: number;
  /** The rule index by Sigma id, for step links. */
  rules: ReadonlyMap<string, SiemRule>;
  /** The commit the rule files are linked at. */
  commit: string;
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

function stepItem(s: CorrelationStep, t0: number, ctx: BoardContext): HTMLElement {
  const at = Date.parse(s.at);
  const delta = at - t0;
  const rule = ruleRef(s, ctx);
  return h(
    "li",
    { class: "corr-step", "data-source": s.source },
    timeEl(s.at, utcClock(s.at, ctx.now, { ms: true }), { class: "corr-step__at" }),
    delta > 0 ? h("span", { class: "corr-step__delta" }, ` +${formatDuration(delta)}`) : null,
    " ",
    h("span", { class: `tag tag--src tag--${s.source}` }, SOURCE_WORD[s.source]),
    " ",
    // A stream document without a finding has no rule: its detail says what it is.
    rule ? h("strong", { class: "corr-step__rule" }, rule) : null,
    s.command_seq !== null ? h("span", { class: "corr-step__cmd" }, `${rule ? " · " : ""}command ${s.command_seq}`) : null,
    s.detail
      ? h("span", { class: "corr-step__detail" }, rule || s.command_seq !== null ? " · " : null, s.detail)
      : s.withheld
        ? h("span", { class: "corr-step__detail corr-step__detail--withheld" }, rule || s.command_seq !== null ? " · " : null, "detail withheld by the page (ADR 0021)")
        : null,
  );
}

export function renderIncident(i: CorrelationIncident, ctx: BoardContext): HTMLElement {
  const t0 = i.steps.length ? Date.parse(i.steps[0].at) : Date.parse(i.first_at);
  const shown = i.steps.slice(0, INCIDENT_STEPS);
  const more = i.steps.length - shown.length;
  return h(
    "article",
    { class: "incident", "data-kind": i.kind, "data-severity": i.severity, "data-incident": i.id, "aria-labelledby": `incident-${i.id}` },
    h(
      "header",
      { class: "incident__head" },
      statusChip(SEVERITY_TONE[i.severity], i.severity),
      " ",
      h("h4", { class: "incident__title", id: `incident-${i.id}` }, i.title || kindLabel(i.kind)),
    ),
    h(
      "p",
      { class: "incident__kind" },
      kindLabel(i.kind),
      i.arm ? [" ", h("span", { class: "tag tag--arm", "data-arm": i.arm }, i.arm === "guarded" ? "guarded" : "twin, unguarded")] : null,
      i.run_id ? [" · run ", extLink(rawRunUrl(i.run_id), h("code", {}, i.run_id))] : null,
    ),
    h("p", { class: "incident__when small" }, "from ", timeEl(i.first_at, utcClock(i.first_at, ctx.now, { ms: true })), " to ", timeEl(i.last_at, utcClock(i.last_at, ctx.now, { ms: true }))),
    h(
      "dl",
      { class: "facts incident__facts" },
      fact("Time to detect", i.ttd_ms !== null ? formatDuration(i.ttd_ms) : null),
      fact("Time to isolate", i.tti_ms !== null ? formatDuration(i.tti_ms) : null),
      falcoFact(i),
      flagFact(i),
      fact("ATT&CK", i.attack.length ? techniqueLinks(i.attack) : null),
    ),
    shown.length ? h("ol", { class: "corr-steps", "aria-label": "Evidence timeline" }, shown.map((s) => stepItem(s, t0, ctx))) : h("p", { class: "small" }, "No step of this incident is publishable."),
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
    timeEl(i.first_at, utcClock(i.first_at, now)),
    " ",
    h("span", {}, i.title || kindLabel(i.kind)),
  );
}

export function renderBoard(c: Correlation, ctx: BoardContext): HTMLElement {
  if (!c.incidents.length) {
    return h("div", { class: "corr-board" }, h("h3", { class: "panel-title" }, "Incidents"), h("p", { class: "empty" }, "No incident in the last 24 hours. The rules run on every event the cluster ships; when one fires, it appears here with its evidence."));
  }
  const full = c.incidents.slice(0, BOARD_INCIDENTS);
  const older = c.incidents.slice(BOARD_INCIDENTS);
  return h(
    "div",
    { class: "corr-board" },
    h("h3", { class: "panel-title" }, `Incidents, newest first (${c.incidents.length} in the last 24 h)`),
    h("div", { class: "corr-incidents" }, full.map((i) => renderIncident(i, ctx))),
    older.length
      ? h("details", { class: "corr-older" }, h("summary", {}, `${older.length} older incident${older.length === 1 ? "" : "s"}`), h("ol", { class: "corr-older__list" }, older.map((i) => olderItem(i, ctx.now))))
      : null,
    h("p", { class: "small" }, "The whole board as the API publishes it: ", extLink("/api/correlation", "/api/correlation"), " (JSON)."),
  );
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
}

/**
 * `section`: #correlation (hidden in the HTML). `onAvailable`: every change between shown and hidden,
 * so the verify panel lists the two endpoints only while they answer.
 */
export function mountCorrelation(
  section: HTMLElement,
  mounts: { health: HTMLElement; metrics: HTMLElement; board: HTMLElement; rules: HTMLElement },
  api: Pick<ApiClient, "correlation" | "correlationRules">,
  onAvailable?: (available: boolean) => void,
): CorrelationHandle {
  let data: Correlation | undefined;
  let index: RuleIndex | null | undefined;
  let indexCommit: string | undefined;
  let apiCommit = "";
  let key = "";
  let shown = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let due = false;

  const linkCommit = () => apiCommit || data?.rules.commit || "";

  const draw = (force = false) => {
    if (!data) return;
    // Redrawn only when what it shows changes; the API's checked_at alone is rewritten in place, so
    // an open <details> or a focused link survives a poll.
    const k = JSON.stringify({ d: { ...data, checked_at: "" }, i: index === undefined ? "u" : index, c: linkCommit() });
    const now = Date.now();
    if (!force && k === key) {
      const at = mounts.health.querySelector<HTMLTimeElement>(".corr-health__at");
      if (at && data.checked_at) {
        at.dataset.when = String(Date.parse(data.checked_at));
        at.dateTime = new Date(data.checked_at).toISOString();
        setText(at, when(data.checked_at, now));
      }
      refreshRelative(section, now);
      return;
    }
    key = k;
    const rules = new Map((index ?? { rules: [] }).rules.map((r) => [r.id, r]));
    replace(mounts.health, renderHealth(data, now));
    replace(mounts.metrics, renderMetrics(data, now));
    replace(mounts.board, renderBoard(data, { now, rules, commit: linkCommit() }));
    replace(mounts.rules, renderRuleLibrary(index, linkCommit(), data.incidents));
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
    schedule(!r.ok && r.status === 404 ? POLL_404_MS : POLL_MS);
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
  };
}
