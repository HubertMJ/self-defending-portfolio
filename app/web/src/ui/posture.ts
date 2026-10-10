// "Live security posture": what admission, image scanning, the CIS benchmark and runtime detection
// say about the cluster right now, from GET /api/posture (cached server-side for 60 s).

import type { ApiClient, Result } from "../lib/api";
import type { BenchCheck, BenchNA, ImageVulns, KyvernoPolicy, KyvernoViolation, Posture, PostureTrivy } from "../lib/contract";
import { h, replace, timeEl, when } from "../lib/dom";
import { extLink, offlinePanel, sourceUrl } from "./common";

const REFRESH_MS = 60_000;
// How long an unfolded panel's live region stays off: past the accessibility tree's update of the draw.
const LIVE_RESTORE_MS = 250;
/** Rows of the per-image breakdown shown; the rest are summarised in the caption. */
const TOP_OFFENDERS = 5;

export type Tone = "good" | "warning" | "critical" | "neutral";

export function statusChip(tone: Tone, label: string): HTMLElement {
  const glyph = tone === "good" ? "✓" : tone === "neutral" ? "•" : "!";
  return h("span", { class: `chip chip--${tone}` }, h("span", { "aria-hidden": "true" }, glyph), label);
}

function tile(opts: {
  label: string;
  value: string;
  unit?: string;
  tone: Tone;
  status: string;
  foot: (Node | string)[];
  /** Below the foot: what the number is made of (ADR 0035), when the API says. */
  more?: HTMLElement | null;
}): HTMLElement {
  return h(
    "article",
    { class: `tile tile--${opts.tone}` },
    h("h3", { class: "tile__label" }, opts.label),
    h("p", { class: "tile__value" }, opts.value, opts.unit ? h("span", { class: "tile__unit" }, ` ${opts.unit}`) : null),
    statusChip(opts.tone, opts.status),
    h("p", { class: "tile__foot" }, ...opts.foot),
    opts.more ?? null,
  );
}

/**
 * The admission tile's tone (ADR 0035, decision O1). Amber "stale config, nothing running violates"
 * only when every failure is accounted for by a group whose resource has no running pod: the list is
 * complete (not truncated, nothing dropped as malformed, its counts add up to the policies' failures)
 * and every group says `running === false`. Any `true`, any unknown, any gap: red. The count shown is
 * never reduced either way.
 */
export function admissionTone(p: Posture): Tone {
  const fail = p.kyverno.policies.reduce((a, x) => a + x.fail, 0);
  const warn = p.kyverno.policies.reduce((a, x) => a + x.warn, 0);
  if (fail === 0) return warn > 0 ? "warning" : "good";
  const v = p.kyverno.violations;
  const complete = v !== undefined && v.length > 0 && !p.kyverno.violations_truncated && !p.kyverno.violations_incomplete && v.reduce((a, x) => a + x.count, 0) === fail;
  return complete && v.every((x) => x.running === false) ? "warning" : "critical";
}

const STALE_STATUS = "stale config, nothing running violates";

/** "7 × restrict-image-registries / autogen-validate-registries on ReplicaSet in falco-response - 0 running: …" */
function violationText(v: KyvernoViolation): string {
  const running =
    v.running === true
      ? "running now"
      : v.running === false
        ? v.kind === "ReplicaSet"
          ? "0 running: old revisions kept at 0 replicas"
          : "0 running"
        : "whether it runs is unknown";
  return `${v.count} × ${v.policy} / ${v.rule} on ${v.kind}${v.namespace ? ` in ${v.namespace}` : ""} - ${running}`;
}

/** The policy's file at the API's commit, or the bare name when either is unknown. */
function policyRef(v: KyvernoViolation, commit: string): Node | string {
  const url = v.file ? sourceUrl(commit, v.file) : null;
  return url ? extLink(url, v.policy) : v.policy;
}

/** The tiles list this many groups or checks; the rest are named in the table below or after the list. */
export const TILE_ROWS = 5;

function violationList(vs: KyvernoViolation[], truncated: boolean, commit: string): HTMLElement {
  return h(
    "ul",
    { class: "tile__list" },
    vs.slice(0, TILE_ROWS).map((v) => h("li", { "data-running": String(v.running) }, violationText(v), v.file && sourceUrl(commit, v.file) ? [" (", policyRef(v, commit), ")"] : null)),
    vs.length > TILE_ROWS ? h("li", { class: "tile__more" }, `${vs.length - TILE_ROWS} more in the table below`) : null,
    truncated ? h("li", {}, "…and more groups than the API lists (it sends the 50 largest).") : null,
  );
}

/** `rows`: how many are listed in full; the rest are named by id. */
function benchList(checks: BenchCheck[], rows = TILE_ROWS): HTMLElement {
  return h(
    "ul",
    { class: "tile__list tile__list--bench" },
    checks.slice(0, rows).map((c) =>
      h(
        "li",
        {},
        h("code", {}, c.id),
        " ",
        c.title,
        c.remediation ? h("details", { class: "tile__remedy", open: true }, h("summary", {}, "Remediation"), h("p", {}, c.remediation)) : null,
      ),
    ),
    checks.length > rows ? h("li", { class: "tile__more" }, `${checks.length - rows} more: `, checks.slice(rows).flatMap((c, i) => [i ? ", " : "", h("code", {}, c.id)])) : null,
  );
}

/** The checks the benchmark configuration marks as not applicable, each with its reason. */
function naList(checks: BenchNA[]): HTMLElement {
  return h(
    "ul",
    { class: "tile__list tile__list--na" },
    checks.map((c) => h("li", {}, h("code", {}, c.id), " ", c.title, c.reason ? h("p", { class: "tile__reason" }, c.reason) : null)),
  );
}

/**
 * Under the CIS tile: the failing checks, open; then, folded, the manual / warn checks with their
 * remediation and the not-applicable ones with their reason (ADR 0025, amendment 2026-10-10) - every
 * check the benchmark did not pass is named, none is hidden or counted as a pass.
 */
function benchMore(kb: Posture["kube_bench"]): HTMLElement | null {
  const parts = [
    kb.failing?.length ? benchList(kb.failing) : null,
    kb.warning?.length ? h("details", { class: "tile__group" }, h("summary", {}, `Manual / warn (${kb.warn})`), benchList(kb.warning, kb.warning.length)) : null,
    kb.not_applicable && kb.not_applicable_checks?.length
      ? h("details", { class: "tile__group" }, h("summary", {}, `Not applicable (${kb.not_applicable})`), naList(kb.not_applicable_checks))
      : null,
  ].filter((x): x is HTMLElement => x !== null);
  return parts.length ? h("div", { class: "tile__bench" }, parts) : null;
}

interface Segment {
  key: string;
  label: string;
  value: number;
}

/** A labelled stacked bar. Identity is carried by the legend text and order, never by colour alone. */
function stackedBar(caption: string, segments: Segment[]): HTMLElement {
  const total = segments.reduce((a, s) => a + s.value, 0);
  const bar = h("div", { class: "stack", role: "img", "aria-label": `${caption}: ${segments.map((s) => `${s.value} ${s.label}`).join(", ")}` });
  for (const s of segments) {
    if (s.value === 0) continue;
    const seg = h("span", { class: `stack__seg stack__seg--${s.key}`, title: `${s.label}: ${s.value}` });
    seg.style.setProperty("--share", String(total ? s.value / total : 0));
    bar.appendChild(seg);
  }
  if (total === 0) bar.appendChild(h("span", { class: "stack__empty" }));
  const legend = h(
    "ul",
    { class: "legend" },
    segments.map((s) =>
      h("li", {}, h("span", { class: `legend__swatch stack__seg--${s.key}`, "aria-hidden": "true" }), h("span", { class: "legend__label" }, s.label), h("strong", {}, String(s.value))),
    ),
  );
  return h("figure", { class: "stack-figure" }, h("figcaption", {}, caption), bar, legend);
}

function kyvernoTable(policies: KyvernoPolicy[]): HTMLElement {
  return h(
    "table",
    { class: "data-table" },
    h("caption", {}, "Kyverno policy reports, per policy"),
    h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Policy"), h("th", { scope: "col" }, "Pass"), h("th", { scope: "col" }, "Fail"), h("th", { scope: "col" }, "Warn"))),
    h(
      "tbody",
      {},
      policies.map((p) =>
        h(
          "tr",
          { class: p.fail > 0 ? "is-failing" : null },
          h("th", { scope: "row" }, h("code", {}, p.name)),
          h("td", {}, String(p.pass)),
          h("td", {}, p.fail > 0 ? statusChip("critical", String(p.fail)) : "0"),
          h("td", {}, String(p.warn)),
        ),
      ),
    ),
  );
}

function violationTable(vs: KyvernoViolation[], commit: string): HTMLElement {
  // Policy and rule names are long and unbreakable; the table scrolls inside its box on a phone
  // rather than widening the page.
  return h(
    "div",
    { class: "table-scroll" },
    h(
    "table",
    { class: "data-table data-table--wrap" },
    h("caption", {}, "Kyverno failures, grouped by policy, rule and what they are about (no resource names)"),
    h(
      "thead",
      {},
      h("tr", {}, h("th", { scope: "col" }, "Policy / rule"), h("th", { scope: "col" }, "Kind"), h("th", { scope: "col" }, "Namespace"), h("th", { scope: "col" }, "Count"), h("th", { scope: "col" }, "Running")),
    ),
    h(
      "tbody",
      {},
      vs.map((v) =>
        h(
          "tr",
          { "data-running": String(v.running) },
          h("th", { scope: "row" }, policyRef(v, commit), " / ", h("code", {}, v.rule)),
          h("td", {}, v.kind),
          h("td", {}, v.namespace || "–"),
          h("td", {}, String(v.count)),
          h("td", {}, v.running === true ? "yes" : v.running === false ? "no" : "unknown"),
        ),
      ),
    ),
    ),
  );
}

/**
 * Whose findings the image total is: this project's images against third-party ones, and the worst
 * images by name (ADR 0023). Text and the existing table style only. The total in the tile is never
 * reduced by this - the split is the same findings counted again by owner, and it is only rendered
 * when the API sends it (an older API gets the page it always got).
 */
function imageBreakdown(tr: PostureTrivy): HTMLElement | null {
  const own = tr.own;
  const third = tr.third_party;
  const rows = (tr.by_image ?? []).filter((r) => r.critical + r.high > 0);
  if (!own || !third) return null;
  const ownTotal = own.critical + own.high;
  const thirdTotal = third.critical + third.high;
  const fixable = own.fixable + third.fixable;
  const top = rows.slice(0, TOP_OFFENDERS);
  const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

  const summary = h(
    "p",
    { class: "posture-split" },
    `Of ${tr.critical + tr.high} critical + high findings, `,
    h("strong", {}, String(ownTotal)),
    ` are in this project's own ${plural(own.images, "image", "images")} and `,
    h("strong", {}, String(thirdTotal)),
    ` in ${plural(third.images, "third-party image", "third-party images")} (cluster components). `,
    `${fixable} of them already have a fix released upstream; none is hidden or filtered from the total.`,
  );
  if (top.length === 0) return h("div", { class: "posture-offenders" }, summary);

  const label = (r: ImageVulns) => (r.own ? "own" : "third-party");
  const table = h(
    "table",
    { class: "data-table" },
    h("caption", {}, `Critical + high findings per image, worst first (top ${top.length} of ${rows.length} affected)`),
    h(
      "thead",
      {},
      h("tr", {}, h("th", { scope: "col" }, "Image"), h("th", { scope: "col" }, "Critical"), h("th", { scope: "col" }, "High"), h("th", { scope: "col" }, "Fixable")),
    ),
    h(
      "tbody",
      {},
      top.map((r) =>
        h(
          "tr",
          {},
          h("th", { scope: "row" }, h("code", {}, r.image), ` (${label(r)})`),
          h("td", {}, String(r.critical)),
          h("td", {}, String(r.high)),
          h("td", {}, String(r.fixable)),
        ),
      ),
    ),
  );
  return h("div", { class: "posture-offenders" }, summary, table);
}

/** `commit`: the API's build commit (GET /api/provenance), for the policy file links; "" when unknown. */
export function renderPostureData(p: Posture, now: number = Date.now(), commit = ""): HTMLElement {
  const ky = p.kyverno.policies.reduce((a, x) => ({ pass: a.pass + x.pass, fail: a.fail + x.fail, warn: a.warn + x.warn }), { pass: 0, fail: 0, warn: 0 });
  const kb = p.kube_bench;
  const kbScored = kb.pass + kb.fail + kb.warn;
  const kbPct = kbScored ? Math.round((kb.pass / kbScored) * 100) : 0;
  const tr = p.trivy;

  const tiles = h(
    "div",
    { class: "tiles" },
    tile({
      label: "Admission policy",
      value: String(ky.fail),
      unit: ky.fail === 1 ? "violation" : "violations",
      tone: admissionTone(p),
      status: ky.fail > 0 ? (admissionTone(p) === "warning" ? STALE_STATUS : "Failing checks") : ky.warn > 0 ? "Warnings only" : "All passing",
      foot: [`${p.kyverno.policies.length} Kyverno policies · ${ky.pass} pass · ${ky.warn} warn`],
      more: ky.fail > 0 && p.kyverno.violations?.length ? violationList(p.kyverno.violations, p.kyverno.violations_truncated === true, commit) : null,
    }),
    tile({
      label: "Image vulnerabilities",
      value: String(tr.critical + tr.high),
      unit: "critical + high",
      tone: tr.critical > 0 ? "critical" : tr.high > 0 ? "warning" : "good",
      status: tr.critical > 0 ? "Critical present" : tr.high > 0 ? "High present" : "None critical/high",
      foot: [
        tr.own && tr.third_party
          ? `Trivy, ${tr.images} running images · own ${tr.own.critical + tr.own.high} · third-party ${tr.third_party.critical + tr.third_party.high}`
          : `Trivy, ${tr.images} running images`,
        ...(tr.last_scan ? [" · last scan ", timeEl(tr.last_scan, when(tr.last_scan, now))] : []),
      ],
    }),
    tile({
      label: "CIS benchmark",
      value: kbScored ? `${kbPct}%` : "–",
      unit: "pass",
      tone: kb.fail > 0 ? "warning" : kbScored ? "good" : "neutral",
      status: kb.fail > 0 ? `${kb.fail} failing` : kbScored ? (kb.warn > 0 ? `No failures · ${kb.warn} manual / warn` : "No failures") : "Not run yet",
      foot: kb.last_run ? ["kube-bench, last run ", timeEl(kb.last_run, when(kb.last_run, now))] : ["kube-bench, last run never"],
      more: benchMore(kb),
    }),
    // The API's window covers the current hour and the 23 before it, and only since it started
    // counting: it is labelled by the time it counts from, never as a bare "24 h" (ADR 0035).
    tile({
      label: p.falco.counted_since ? "Runtime" : "Runtime, last 24 h",
      value: String(p.falco.alerts_24h),
      unit: p.falco.alerts_24h === 1 ? "alert" : "alerts",
      tone: "neutral",
      status: `${p.talon.actions_24h} automated responses`,
      foot: p.falco.counted_since
        ? ["Falco detections → Falco Talon actions, counted since ", timeEl(p.falco.counted_since, when(p.falco.counted_since, now))]
        : ["Falco detections → Falco Talon actions"],
    }),
  );

  const details = h(
    "div",
    { class: "posture-details" },
    stackedBar("Vulnerabilities in running images, by severity", [
      { key: "critical", label: "Critical", value: tr.critical },
      { key: "high", label: "High", value: tr.high },
      { key: "medium", label: "Medium", value: tr.medium },
      { key: "low", label: "Low", value: tr.low },
    ]),
    stackedBar("CIS Kubernetes benchmark checks", [
      { key: "pass", label: "Pass", value: kb.pass },
      { key: "fail", label: "Fail", value: kb.fail },
      { key: "warn", label: "Manual / warn", value: kb.warn },
      { key: "info", label: "Info", value: kb.info },
      // Older APIs count these in Info; then there is no such segment.
      ...(kb.not_applicable !== undefined ? [{ key: "na", label: "Not applicable", value: kb.not_applicable }] : []),
    ]),
    imageBreakdown(tr),
    kyvernoTable(p.kyverno.policies),
    ky.fail > 0 && p.kyverno.violations?.length ? violationTable(p.kyverno.violations, commit) : null,
  );

  const generated = timeEl(p.generated_at, when(p.generated_at, now));
  return h(
    "div",
    { class: "posture" },
    tiles,
    details,
    h("p", { class: "panel-foot" }, "Report generated ", generated, ". Refreshes every 60 seconds."),
  );
}

export interface PostureHandle {
  refresh: () => Promise<void>;
  /** The API's build commit, once known: the policy links point at it. */
  setCommit(commit: string): void;
  /**
   * Whether the panel can be seen (its section is not folded away). While it cannot, the posture is
   * still fetched and passed to `onData` (the liveness line reads it), but not drawn; it is drawn on
   * the way back.
   */
  setActive(active: boolean): void;
}

/** `onData`: every fresh posture, for the liveness line (its generated_at, kube-bench, Trivy times). */
export function mountPosture(root: HTMLElement, api: ApiClient, onData?: (p: Posture) => void): PostureHandle {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let last: Posture | undefined;
  let commit = "";
  let active = true;
  // The answer not drawn yet because the panel could not be seen.
  let pending: Result<Posture> | undefined;

  const draw = (res: Result<Posture>) => {
    if (!active) {
      pending = res;
      return;
    }
    pending = undefined;
    if (res.ok) {
      replace(root, renderPostureData(res.value, Date.now(), commit));
    } else {
      replace(
        root,
        offlinePanel({
          title: "Live posture is unavailable",
          body: "The API that summarises the cluster's policy, scan and benchmark reports is not answering right now. Everything else on this page still works; this panel retries every minute.",
          detail: res.message,
          onRetry: () => void refresh(),
        }),
      );
    }
  };

  const show = (res: Result<Posture>) => {
    root.setAttribute("aria-busy", "false");
    root.dataset.state = res.ok ? "live" : "offline";
    if (res.ok) last = res.value;
    draw(res);
    if (res.ok) onData?.(res.value);
  };

  const refresh = async () => {
    clearTimeout(timer);
    root.setAttribute("aria-busy", "true");
    show(await api.posture());
    timer = setTimeout(() => void refresh(), REFRESH_MS);
  };

  void refresh();
  return {
    refresh,
    setCommit(c) {
      if (c === commit) return;
      commit = c;
      if (last && root.dataset.state === "live") draw({ ok: true, value: last });
    },
    setActive(on) {
      active = on;
      if (!on || !pending) return;
      // The panel is a polite live region (a refresh is announced), but the visitor who unfolds it
      // asked to see it: drawn with the region off, which comes back once the new content is in.
      root.setAttribute("aria-live", "off");
      draw(pending);
      setTimeout(() => root.setAttribute("aria-live", "polite"), LIVE_RESTORE_MS);
    },
  };
}
