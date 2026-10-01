// "Live security posture": what admission, image scanning, the CIS benchmark and runtime detection
// say about the cluster right now, from GET /api/posture (cached server-side for 60 s).

import type { ApiClient, Result } from "../lib/api";
import type { KyvernoPolicy, Posture } from "../lib/contract";
import { h, relativeTime, replace } from "../lib/dom";
import { offlinePanel } from "./common";

const REFRESH_MS = 60_000;

type Tone = "good" | "warning" | "critical" | "neutral";

function statusChip(tone: Tone, label: string): HTMLElement {
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
}): HTMLElement {
  return h(
    "article",
    { class: `tile tile--${opts.tone}` },
    h("h3", { class: "tile__label" }, opts.label),
    h("p", { class: "tile__value" }, opts.value, opts.unit ? h("span", { class: "tile__unit" }, ` ${opts.unit}`) : null),
    statusChip(opts.tone, opts.status),
    h("p", { class: "tile__foot" }, ...opts.foot),
  );
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

export function renderPostureData(p: Posture, now: number = Date.now()): HTMLElement {
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
      tone: ky.fail > 0 ? "critical" : ky.warn > 0 ? "warning" : "good",
      status: ky.fail > 0 ? "Failing checks" : ky.warn > 0 ? "Warnings only" : "All passing",
      foot: [`${p.kyverno.policies.length} Kyverno policies · ${ky.pass} pass · ${ky.warn} warn`],
    }),
    tile({
      label: "Image vulnerabilities",
      value: String(tr.critical + tr.high),
      unit: "critical + high",
      tone: tr.critical > 0 ? "critical" : tr.high > 0 ? "warning" : "good",
      status: tr.critical > 0 ? "Critical present" : tr.high > 0 ? "High present" : "None critical/high",
      foot: [`Trivy, ${tr.images} running images`],
    }),
    tile({
      label: "CIS benchmark",
      value: kbScored ? `${kbPct}%` : "–",
      unit: "pass",
      tone: kb.fail > 0 ? "warning" : kbScored ? "good" : "neutral",
      status: kb.fail > 0 ? `${kb.fail} failing` : kbScored ? "No failures" : "Not run yet",
      foot: [`kube-bench, last run ${relativeTime(kb.last_run, now)}`],
    }),
    tile({
      label: "Runtime, last 24 h",
      value: String(p.falco.alerts_24h),
      unit: p.falco.alerts_24h === 1 ? "alert" : "alerts",
      tone: "neutral",
      status: `${p.talon.actions_24h} automated responses`,
      foot: ["Falco detections → Falco Talon actions"],
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
    ]),
    kyvernoTable(p.kyverno.policies),
  );

  const generated = h("time", { datetime: p.generated_at }, relativeTime(p.generated_at, now));
  return h(
    "div",
    { class: "posture" },
    tiles,
    details,
    h("p", { class: "panel-foot" }, "Report generated ", generated, ". Refreshes every 60 seconds."),
  );
}

export function mountPosture(root: HTMLElement, api: ApiClient): { refresh: () => Promise<void> } {
  let timer: ReturnType<typeof setTimeout> | undefined;

  const show = (res: Result<Posture>) => {
    root.setAttribute("aria-busy", "false");
    if (res.ok) {
      root.dataset.state = "live";
      replace(root, renderPostureData(res.value));
    } else {
      root.dataset.state = "offline";
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

  const refresh = async () => {
    clearTimeout(timer);
    root.setAttribute("aria-busy", "true");
    show(await api.posture());
    timer = setTimeout(() => void refresh(), REFRESH_MS);
  };

  void refresh();
  return { refresh };
}
