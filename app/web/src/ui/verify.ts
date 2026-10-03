// "Verify it yourself" for the site itself (ADR 0035, B3). A compact strip in the hero, above the
// fold: which commit each running image was built from, its digest, a copy of the cosign command
// and the digest's Rekor search. The #verify panel has the full digests, commands, CI runs and a
// copyable curl for every public endpoint. The api's commit, CI run and digests come from
// GET /api/provenance; the web's commit and CI run from /build.json; either may be missing (an API
// before ADR 0035, a local build), and then the panel shows what is known and says what is not.

import type { BuildInfo, Provenance } from "../lib/contract";
import { h, replace, timeEl, when } from "../lib/dom";
import { ciRunUrl, commitUrl, cosignVerifyCommand, digestOf, oneLine, rekorSearchUrl, shortDigest } from "../lib/provenance";
import { copyButton, extLink } from "./common";

/** The public origin the raw-data commands name: the commands are for the visitor's own terminal. */
export const SITE_URL = "https://hubertjablon.ski";

export const RAW_PATHS = [
  "/api/posture",
  "/api/stats",
  "/api/scenarios",
  "/api/scenarios/terminal/details",
  "/api/runs",
  "/api/limits",
  "/api/provenance",
  "/build.json",
] as const;

export interface VerifyData {
  /** undefined: not answered yet; null: unavailable (404, offline, malformed). */
  provenance?: Provenance | null;
  build?: BuildInfo | null;
  latestRunId?: string;
}

interface ImageRow {
  name: "api" | "web";
  commit: string;
  runId: string;
  images: string[];
}

function rows(d: VerifyData): ImageRow[] {
  const p = d.provenance ?? undefined;
  return [
    { name: "api", commit: p?.api.commit ?? "", runId: p?.api.ci_run_id ?? "", images: p?.api.images ?? [] },
    { name: "web", commit: d.build?.commit ?? "", runId: d.build?.ci_run_id ?? "", images: p?.web.images ?? [] },
  ];
}

const short = (sha: string) => sha.slice(0, 7);

function commitLink(sha: string): Node | string {
  const url = commitUrl(sha);
  return url ? extLink(url, h("code", {}, short(sha))) : "unknown commit";
}

/** The hero strip: one line per image, then the way to the full panel. */
export function renderStrip(d: VerifyData): HTMLElement {
  const unavailable = d.provenance === null;
  const lines = rows(d)
    .filter((r) => r.commit || r.images.length)
    .map((r) => {
      const image = r.images[0];
      const digest = image ? digestOf(image) : "";
      const rekor = digest ? rekorSearchUrl(digest) : null;
      return h(
        "li",
        { class: "vstrip__row", "data-image": r.name },
        h("span", { class: "vstrip__name" }, r.name),
        " ",
        r.commit ? commitLink(r.commit) : null,
        digest ? [" ", h("code", { class: "vstrip__digest", title: digest }, shortDigest(digest))] : null,
        image ? [" ", copyButton(() => oneLine(cosignVerifyCommand(image)), "Copy cosign")] : null,
        rekor ? [" ", extLink(rekor, "Rekor")] : null,
        r.images.length > 1 ? h("span", { class: "vstrip__more" }, ` +${r.images.length - 1} during a rollout`) : null,
      );
    });
  return h(
    "div",
    { class: "vstrip" },
    h("p", { class: "vstrip__label" }, "Running now, signed in CI"),
    lines.length ? h("ul", { class: "vstrip__rows", role: "list" }, lines) : null,
    h(
      "p",
      { class: "vstrip__foot" },
      unavailable ? h("span", { class: "vstrip__na" }, "API provenance unavailable · ") : null,
      h("a", { href: "#verify" }, "Verify & raw data"),
    ),
  );
}

function curlLine(path: string, stream = false): HTMLElement {
  const cmd = `curl -s${stream ? "N" : ""} ${SITE_URL}${path}`;
  return h("li", { class: "vraw__row" }, h("code", {}, cmd), " ", copyButton(() => cmd), " ", extLink(path, "open"));
}

/** The full panel. */
export function renderVerifyPanel(d: VerifyData, now: number = Date.now()): HTMLElement {
  const p = d.provenance ?? undefined;
  const images = rows(d).map((r) =>
    h(
      "section",
      { class: "card vimage", "data-image": r.name },
      h("h3", { class: "card__title" }, r.name === "api" ? "The API" : "This page (web)"),
      h(
        "p",
        {},
        "built from ",
        r.commit ? commitLink(r.commit) : "an unknown commit",
        r.runId && ciRunUrl(r.runId) ? [" by ", extLink(ciRunUrl(r.runId) as string, `CI run ${r.runId}`)] : r.name === "api" && !p ? " (API provenance unavailable)" : " (CI run unknown)",
      ),
      r.images.length
        ? r.images.map((image) => {
            const digest = digestOf(image);
            const rekor = rekorSearchUrl(digest);
            return h(
              "div",
              { class: "vimage__digest" },
              h("p", { class: "small" }, h("code", {}, image)),
              h("div", { class: "cmd" }, h("pre", { class: "term" }, h("code", {}, cosignVerifyCommand(image))), copyButton(() => oneLine(cosignVerifyCommand(image)))),
              rekor ? h("p", { class: "small" }, extLink(rekor, "Rekor transparency log entries for this digest")) : null,
            );
          })
        : h("p", { class: "small" }, p ? "No running pod of this image was seen in the last pod list." : "Running digests unknown: API provenance unavailable."),
    ),
  );
  return h(
    "div",
    { class: "verify-panel" },
    h("div", { class: "vimages" }, images),
    h("p", { class: "small" }, "Each image is rebuilt only when its directory changes, so the two commits can differ."),
    p?.images_observed_at ? h("p", { class: "small" }, "Digests as of the API's last pod list, ", timeEl(p.images_observed_at, when(p.images_observed_at, now)), ".") : null,
    h("h3", { class: "panel-title" }, "Raw data"),
    h("p", { class: "small" }, "Everything on this page comes from these endpoints. Each visitor has a budget of 120 API requests a minute; this page uses a few."),
    h(
      "ul",
      { class: "vraw", role: "list" },
      RAW_PATHS.map((path) => curlLine(path)),
      d.latestRunId ? curlLine(`/api/runs/${encodeURIComponent(d.latestRunId)}`) : null,
      curlLine("/api/events", true),
    ),
    d.latestRunId ? h("p", {}, extLink(`/api/runs/${encodeURIComponent(d.latestRunId)}`, "Latest run raw JSON")) : null,
  );
}

export interface VerifyHandle {
  set(patch: Partial<VerifyData>): void;
}

export function mountVerify(strip: HTMLElement, panel: HTMLElement): VerifyHandle {
  let data: VerifyData = {};
  let key = "";
  const draw = () => {
    // Redrawn only when what it shows changes, so a Copy button's "Copied" is not cut short.
    const k = JSON.stringify(data);
    if (k === key) return;
    key = k;
    if (data.provenance !== undefined || data.build !== undefined) {
      strip.hidden = false;
      replace(strip, renderStrip(data));
    }
    replace(panel, renderVerifyPanel(data));
  };
  return {
    set(patch) {
      data = { ...data, ...patch };
      draw();
    },
  };
}
