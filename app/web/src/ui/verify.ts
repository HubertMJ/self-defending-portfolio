// "Verify it yourself" for the site itself (ADR 0035, B3; amended 2026-10-04 and 2026-10-05). The #verify
// panel, below the evidence and the posture, above the skills: which commit each running image was built from, by which CI run, its
// digests, the cosign command to check each one, the digest's Rekor search, and a copyable curl for
// every public endpoint. The footer carries one link to it; the evidence card is the above-the-fold proof.
// The api's commit, CI run and digests come from GET /api/provenance; the web's commit and CI run
// from /build.json; either may be missing (an API before ADR 0035, a local build), and then the
// panel shows what is known and says what is not.

import type { Result } from "../lib/api";
import type { BuildInfo, Provenance } from "../lib/contract";
import { h, replace, timeEl, when } from "../lib/dom";
import { ciRunUrl, commitUrl, cosignVerifyCommand, digestOf, isPinnedImageRef, oneLine, rekorSearchUrl } from "../lib/provenance";
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
  /** GET /api/correlation answers `available: true` (ADR 0036): its two endpoints are listed too. */
  correlation?: boolean;
}

/** Listed only while the correlation section is shown: an API without a SIEM answers them with nothing to see. */
export const CORRELATION_PATHS = ["/api/correlation", "/api/correlation/rules"] as const;

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
              isPinnedImageRef(image) ? h("div", { class: "cmd" }, h("pre", { class: "term" }, h("code", {}, cosignVerifyCommand(image))), copyButton(() => oneLine(cosignVerifyCommand(image)))) : null,
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
      d.correlation ? CORRELATION_PATHS.map((path) => curlLine(path)) : null,
      d.latestRunId ? curlLine(`/api/runs/${encodeURIComponent(d.latestRunId)}`) : null,
      curlLine("/api/events", true),
    ),
    d.latestRunId ? h("p", {}, extLink(`/api/runs/${encodeURIComponent(d.latestRunId)}`, "Latest run raw JSON")) : null,
  );
}

/**
 * Polls GET /api/provenance with the posture's rhythm (the API derives the digests from the same pod
 * list): every 60 s. A failure keeps the last good answer on the page (`unavailable` only fires while
 * there has never been one); an API without the endpoint (a 404, e.g. an older API during a rollout)
 * is asked again every 10 minutes, anything else after 2.
 */
export function pollProvenance(load: () => Promise<Result<Provenance>>, on: { data: (p: Provenance) => void; unavailable: () => void }): void {
  let good = false;
  const run = async () => {
    const r = await load();
    if (r.ok) {
      good = true;
      on.data(r.value);
      setTimeout(() => void run(), 60_000);
      return;
    }
    if (!good) on.unavailable();
    setTimeout(() => void run(), r.status === 404 ? 10 * 60_000 : 120_000);
  };
  void run();
}

export interface VerifyHandle {
  set(patch: Partial<VerifyData>): void;
}

export function mountVerify(panel: HTMLElement): VerifyHandle {
  let data: VerifyData = {};
  let key = "";
  const draw = () => {
    // Redrawn only when what it shows changes, so a Copy button's "Copied" is not cut short.
    // The response's own generated_at changes on every refresh and is not shown.
    const k = JSON.stringify({ ...data, provenance: data.provenance ? { ...data.provenance, generated_at: undefined } : data.provenance });
    if (k === key) return;
    key = k;
    replace(panel, renderVerifyPanel(data));
  };
  return {
    set(patch) {
      data = { ...data, ...patch };
      draw();
    },
  };
}
