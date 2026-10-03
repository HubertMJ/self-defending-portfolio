// Evidence by default (ADR 0035, B4). The latest real attack, without a click or a scroll: a card in
// the hero's right column (after the hero copy on narrow screens), then in #evidence a ticker of the
// last feed items, a liveness line and the run's full record. Everything here is drawn from events
// the API published (the stream, or GET /api/runs/{id} for the newest run when the replay held none)
// and from server timestamps. Nothing is synthesised, looped or padded: when nothing happened, the
// page says since when, and the only thing that changes on its own is the server's clock (the opt-in
// SSE tick) and "x minutes ago" next to an absolute UTC time.

import { type CatalogueCommand, type CommandOutcome, FALCO_FIELDS, type FalcoEvent, type Posture, type ScenarioDetails, type StreamEvent, type TalonEvent, type Tick, isRunId } from "../lib/contract";
import { h, relativeTime, replace, timeEl, utc, utcClock, when } from "../lib/dom";
import { humanAction } from "../lib/pipeline";
import { cosignVerifyCommand, digestOf, oneLine, shortDigest } from "../lib/provenance";
import type { ConnectionState } from "../lib/sse";
import { type RunView, type TimelineView, formatDuration, ts } from "../lib/timeline";
import { copyButton, extLink, sourceUrl } from "./common";

/** The card shows this many Falco/Talon events and terminal commands; the rest are in #evidence and the raw JSON. */
export const CARD_EVENTS = 3;
export const CARD_COMMANDS = 5;
/** The ticker's length. */
export const TICKER_ITEMS = 8;

const STATE_WORD: Record<string, string> = {
  queued: "Queued",
  started: "Attack running",
  pod_ready: "Pod ready",
  detected: "Detected",
  responded: "Contained",
  finished: "Finished",
  failed: "Failed",
  timeout: "Timed out",
};

export interface EvidenceContext {
  title: string;
  now: number;
  details?: ScenarioDetails;
  /** Terminal catalogue, by command id: what the visitor typed and the command's outcome class. */
  commands?: ReadonlyMap<string, CatalogueCommand>;
}

const rawUrl = (runId: string) => `/api/runs/${encodeURIComponent(runId)}`;

/** Falco and Talon events of the run in time order: the card's first three, #evidence's all. */
type Answer = { type: "falco"; data: FalcoEvent } | { type: "talon"; data: TalonEvent };
function answers(run: RunView): Answer[] {
  return [...run.falco.map((data) => ({ type: "falco" as const, data })), ...run.talon.map((data) => ({ type: "talon" as const, data }))].sort((a, b) => ts(a.data.at) - ts(b.data.at));
}

/** The pod's name is published only for a sandbox scenario pod (ADR 0021): every event naming a namespace says sandbox. */
function sandboxPod(run: RunView): string | undefined {
  return run.pod && [...run.falco, ...run.talon].every((e) => !e.namespace || e.namespace === "sandbox") ? run.pod : undefined;
}

const fact = (k: string, v: Node | string | null | undefined) => (v ? h("div", {}, h("dt", {}, k), h("dd", {}, v)) : null);
const code = (s: string | undefined, title?: string) => (s ? h("code", title ? { title } : {}, s) : null);

function answerItem(a: Answer, now: number): HTMLElement {
  if (a.type === "falco") {
    const f = a.data;
    const delay = f.api_received_at ? ts(f.api_received_at) - ts(f.at) : undefined;
    return h(
      "li",
      { class: "evlist__item", "data-type": "falco" },
      h("span", { class: "tag tag--detect" }, "falco"),
      " ",
      h("strong", {}, f.rule),
      ` (${f.priority}) at `,
      timeEl(f.at, utcClock(f.at, now, { ms: true })),
      f.api_received_at ? [", received ", timeEl(f.api_received_at, utcClock(f.api_received_at, now, { ms: true }))] : null,
      delay !== undefined && delay >= 0 ? `, delivered in ${formatDuration(delay)}` : null,
    );
  }
  const t = a.data;
  return h(
    "li",
    { class: "evlist__item", "data-type": "talon" },
    h("span", { class: "tag tag--respond" }, "talon"),
    " ",
    h("strong", {}, humanAction(t.action, t.actionner)),
    " ",
    code(t.actionner ?? t.action),
    ` ${t.status} at `,
    timeEl(t.at, utcClock(t.at, now, { ms: true })),
  );
}

function commandItems(run: RunView, ctx: EvidenceContext, max: number): HTMLElement[] {
  return run.commands.slice(0, max).map((c) => {
    const cat = ctx.commands?.get(c.id);
    const exit = c.exitCode !== undefined ? `exit ${c.exitCode}` : c.killed ? "killed" : c.endedAt !== undefined ? "ended, no exit code" : "running";
    return h("li", { class: "evlist__item", "data-type": "command" }, h("code", {}, cat?.input ?? c.id), ` · ${exit}`, cat ? ` · ${cat.outcome}` : null);
  });
}

/** detect/respond latencies; a terminal run's gap to its first detection is dwell time, not latency. */
function latencies(run: RunView): string | null {
  const parts = [
    run.scenario !== "terminal" && run.timings.detectMs !== undefined ? `detected ${formatDuration(run.timings.detectMs)} after the attack command` : null,
    run.timings.respondMs !== undefined ? `answered ${formatDuration(run.timings.respondMs)} after the detection` : null,
  ].filter((x): x is string => x !== null);
  return parts.length ? parts.join(" · ") : null;
}

function ruleLink(ctx: EvidenceContext): HTMLElement | null {
  const d = ctx.details;
  const r = d?.falco_rule;
  const url = d && r ? sourceUrl(d.commit, r.file, r.line) : null;
  return d && r && url ? h("p", { class: "evcard__rule" }, "Falco rule ", extLink(url, r.name), ` at commit ${d.commit.slice(0, 7)}`) : null;
}

const runStart = (run: RunView) => run.states.started ?? run.states.queued ?? Math.min(...Object.values(run.states).filter((x): x is number => x !== undefined));

/** The hero card for one run: expanded, capped, every time absolute UTC. */
export function renderEvidenceCard(run: RunView, ctx: EvidenceContext): HTMLElement {
  const { now } = ctx;
  const all = answers(run);
  const shown = all.slice(0, CARD_EVENTS);
  const more = all.length - shown.length;
  const start = runStart(run);
  const digest = run.image ? digestOf(run.image) : "";
  const failed = run.current === "failed" || run.current === "timeout";
  return h(
    "article",
    { class: "evcard", "data-run": run.runId, "aria-labelledby": "evcard-title" },
    h("p", { class: "evcard__eyebrow" }, run.active ? "Attack in progress" : "Latest attack, as recorded"),
    h(
      "header",
      { class: "evcard__head" },
      h("h2", { class: "evcard__title", id: "evcard-title" }, ctx.title),
      h("span", { class: `chip chip--${failed ? "critical" : run.active ? "warning" : "good"}` }, STATE_WORD[run.current] ?? run.current),
    ),
    Number.isFinite(start) ? h("p", { class: "evcard__when" }, "last attack ", timeEl(start, when(start, now))) : null,
    h(
      "dl",
      { class: "facts facts--mono evcard__facts" },
      fact("Pod", code(sandboxPod(run))),
      fact("Pod UID", code(run.podUid)),
      fact("Image", digest ? code(shortDigest(digest), digest) : null),
      fact("Container", code(run.containerId)),
    ),
    shown.length ? h("ol", { class: "evlist" }, shown.map((a) => answerItem(a, now))) : h("p", { class: "small" }, run.active ? "No Falco or Talon event yet." : "No Falco or Talon event for this run."),
    run.scenario === "terminal" && run.commands.length ? h("ol", { class: "evlist evlist--commands", "aria-label": "Commands" }, commandItems(run, ctx, CARD_COMMANDS)) : null,
    latencies(run) ? h("p", { class: "evcard__lat" }, latencies(run)) : null,
    h(
      "p",
      { class: "evcard__more" },
      isRunId(run.runId) ? extLink(rawUrl(run.runId), more > 0 ? `${more} more - raw JSON` : "raw JSON") : more > 0 ? `${more} more in the full record below` : null,
      " · ",
      h("a", { href: "#evidence" }, "full record"),
    ),
    ruleLink(ctx),
  );
}

/** No run in memory: say when the API started and when the last run was recorded, and offer one. */
export function renderNoAttack(opts: { apiStartedAt?: string; lastRunAt?: string; now: number; loading?: boolean }): HTMLElement {
  if (opts.loading) return h("article", { class: "evcard evcard--empty" }, h("p", { class: "evcard__eyebrow" }, "Latest attack"), h("p", {}, "Loading the latest recorded attack…"));
  return h(
    "article",
    { class: "evcard evcard--empty" },
    h("p", { class: "evcard__eyebrow" }, "Latest attack"),
    h(
      "p",
      { class: "evcard__none" },
      "No attack since the API started",
      opts.apiStartedAt ? [" at ", timeEl(opts.apiStartedAt)] : null,
      opts.lastRunAt ? [" - last attack recorded ", timeEl(opts.lastRunAt, when(opts.lastRunAt, opts.now))] : null,
      ".",
    ),
    h("p", {}, h("a", { class: "btn btn--ghost btn--small", href: "#attack" }, "Launch one yourself")),
  );
}

/** #evidence's full record of the run: every Falco/Talon event, the allow-listed Falco fields, Talon's output, the image's signature. */
export function renderEvidenceDetail(run: RunView, ctx: EvidenceContext): HTMLElement {
  const { now } = ctx;
  const image = ctx.details?.image.ref || run.image || "";
  return h(
    "div",
    { class: "evdetail", "data-run": run.runId },
    h("h3", { class: "panel-title" }, `${ctx.title}: the full record`),
    h(
      "dl",
      { class: "facts facts--wide facts--mono" },
      fact("Run id", code(run.runId)),
      fact("Pod", code(sandboxPod(run))),
      fact("Pod UID", code(run.podUid)),
      fact("Image", code(run.image)),
      fact("Container", code(run.containerId)),
      fact("Raw run", isRunId(run.runId) ? h("span", {}, extLink(rawUrl(run.runId), rawUrl(run.runId)), " (JSON, kept for the last 50 runs)") : null),
    ),
    run.falco.map((f) =>
      h(
        "section",
        { class: "card evdetail__event" },
        h("h4", {}, "Falco: ", f.rule),
        h("ul", { class: "evlist" }, answerItem({ type: "falco", data: f }, now)),
        h("code", { class: "run__output" }, f.output),
        f.fields
          ? h(
              "table",
              { class: "data-table evdetail__fields" },
              h("caption", {}, "Falco output fields (allow-listed)"),
              h(
                "tbody",
                {},
                FALCO_FIELDS.filter((k) => f.fields && Object.prototype.hasOwnProperty.call(f.fields, k)).map((k) => h("tr", {}, h("th", { scope: "row" }, h("code", {}, k)), h("td", {}, h("code", {}, (f.fields as Record<string, string>)[k])))),
              ),
            )
          : null,
      ),
    ),
    run.talon.map((t) =>
      h(
        "section",
        { class: "card evdetail__event" },
        h("h4", {}, "Talon: ", humanAction(t.action, t.actionner)),
        h("ul", { class: "evlist" }, answerItem({ type: "talon", data: t }, now)),
        h("dl", { class: "facts facts--mono" }, fact("target", code(`${t.namespace}/${t.pod}`)), fact("output", code(t.output))),
      ),
    ),
    run.scenario === "terminal" && run.commands.length ? h("section", { class: "card" }, h("h4", {}, "Commands"), h("ol", { class: "evlist" }, commandItems(run, ctx, run.commands.length))) : null,
    latencies(run) ? h("p", { class: "small" }, latencies(run)) : null,
    image && digestOf(image)
      ? h(
          "div",
          {},
          h("p", { class: "small" }, "The scenario image is signed in CI. Check the signature:"),
          h("div", { class: "cmd" }, h("pre", { class: "term" }, h("code", {}, cosignVerifyCommand(image))), copyButton(() => oneLine(cosignVerifyCommand(image)))),
        )
      : null,
    ruleLink(ctx),
  );
}

export interface TickerItem {
  at: number;
  key: string;
  type: StreamEvent["type"];
  text: string;
}

/**
 * The last feed items, newest first: run states, Falco rules, Talon actions and the end of each
 * terminal command. Only events the timeline holds; nothing else is ever added to fill the list.
 */
export function tickerItems(view: TimelineView, max = TICKER_ITEMS): TickerItem[] {
  const out: TickerItem[] = [];
  const add = (ev: StreamEvent, text: string) => out.push({ at: ts(ev.data.at), key: `${ev.id ?? ""}|${ev.type}|${ev.data.at}|${text}`, type: ev.type, text });
  for (const ev of [...view.runs.flatMap((r) => r.events), ...view.unmatched]) {
    switch (ev.type) {
      case "run":
        add(ev, `${ev.data.scenario}: ${STATE_WORD[ev.data.state] ?? ev.data.state}`);
        break;
      case "falco":
        add(ev, `Falco: ${ev.data.rule}`);
        break;
      case "talon":
        add(ev, `Talon: ${humanAction(ev.data.action, ev.data.actionner)} (${ev.data.status})`);
        break;
      case "command":
        if (ev.data.state === "exited") add(ev, `command ${ev.data.id}: ${ev.data.exit_code !== undefined ? `exit ${ev.data.exit_code}` : "ended, no exit code"}`);
        else if (ev.data.state === "killed") add(ev, `command ${ev.data.id}: killed`);
        break;
    }
  }
  const unique = [...new Map(out.map((i) => [i.key, i])).values()];
  return unique.sort((a, b) => b.at - a.at || b.key.localeCompare(a.key)).slice(0, max);
}

export function renderTicker(items: TickerItem[], opts: { now: number; since?: string | number; connected: boolean; tickAt?: string; fresh?: ReadonlySet<string> }): HTMLElement {
  if (items.length === 0) {
    return h(
      "p",
      { class: "ticker__empty" },
      opts.since !== undefined ? ["No events since ", timeEl(opts.since), "; "] : "No events yet; ",
      opts.connected ? "the stream is connected" : "the stream is not connected",
      opts.connected && opts.tickAt ? [" (server time ", timeEl(opts.tickAt, utc(opts.tickAt)), ")"] : null,
      ".",
    );
  }
  return h(
    "ol",
    { class: "ticker", "aria-label": "Latest events, newest first" },
    items.map((i) =>
      h(
        "li",
        { class: "ticker__item", "data-type": i.type, "data-new": opts.fresh?.has(i.key) ? "true" : null },
        timeEl(i.at, utcClock(i.at, opts.now, { ms: true })),
        h("span", { class: "ticker__ago" }, ` (${relativeTime(new Date(i.at).toISOString(), opts.now)})`),
        " ",
        h("span", { class: "ticker__text" }, i.text),
      ),
    ),
  );
}

/** "3 h 12 min", "4 min", "2 d 5 h": how long the API has been up. */
export function uptime(ms: number): string {
  const m = Math.floor(Math.max(0, ms) / 60_000);
  if (m < 1) return "under a minute";
  if (m < 60) return `${m} min`;
  const hrs = Math.floor(m / 60);
  if (hrs < 48) return `${hrs} h ${m % 60} min`;
  return `${Math.floor(hrs / 24)} d ${hrs % 24} h`;
}

export interface Liveness {
  apiStartedAt?: string;
  tickAt?: string;
  postureAt?: string;
  kubeBench?: string | null;
  trivy?: string;
}

/** "API up … (since …) · server time … · posture refreshed … · kube-bench … · Trivy …"; absent pieces omitted. */
export function renderLiveness(l: Liveness, now: number): HTMLElement {
  const parts: (Node | string)[][] = [];
  if (l.apiStartedAt) parts.push([`API up ${uptime((l.tickAt ? Date.parse(l.tickAt) : now) - Date.parse(l.apiStartedAt))} (since `, timeEl(l.apiStartedAt), ")"]);
  if (l.tickAt) parts.push(["server time ", timeEl(l.tickAt, utc(l.tickAt), { class: "liveness__server" })]);
  if (l.postureAt) parts.push(["posture refreshed ", timeEl(l.postureAt, when(l.postureAt, now))]);
  if (l.kubeBench) parts.push(["kube-bench ", timeEl(l.kubeBench, when(l.kubeBench, now))]);
  if (l.trivy) parts.push(["Trivy ", timeEl(l.trivy, when(l.trivy, now))]);
  return h("p", { class: "liveness" }, parts.flatMap((p, i) => (i ? [" · ", ...p] : p)));
}

export interface EvidenceHandle {
  update(view: TimelineView): void;
  setTitles(titles: Map<string, string>): void;
  setDetails(scenario: string, details: ScenarioDetails): void;
  setCatalogue(commands: CatalogueCommand[]): void;
  /** The stream opened; with no tick within 3 s (an API before ADR 0035) the liveness line shows without a server time. */
  streamOpened(): void;
  setConnection(state: ConnectionState): void;
  tick(t: Tick): void;
  setPosture(p: Posture): void;
  setApiStart(iso: string): void;
  setLastRunAt(iso: string): void;
  /** The newest run of GET /api/runs is being loaded into the timeline (or there is none). */
  setLoading(loading: boolean): void;
}

const LIVENESS_FALLBACK_MS = 3000;
const RELATIVE_REFRESH_MS = 30_000;

/**
 * `card`: the hero's right-column mount (its static figure is the pre-mount content); `section`:
 * #evidence's mounts. `onDecided` fires once, on the first tick or 3 s after the first open: the
 * moment the replay is in, when a page with no run asks GET /api/runs for the newest.
 */
export function mountEvidence(
  card: HTMLElement,
  section: { ticker: HTMLElement; liveness: HTMLElement; detail: HTMLElement },
  onDecided: () => void,
): EvidenceHandle {
  let view: TimelineView = { runs: [], unmatched: [] };
  let titles = new Map<string, string>();
  const details = new Map<string, ScenarioDetails>();
  let commands = new Map<string, CatalogueCommand>();
  let live: Liveness = {};
  let lastRunAt: string | undefined;
  let connected = false;
  let decided = false;
  let loading = false;
  let livenessShown = false;
  let fallback: ReturnType<typeof setTimeout> | undefined;
  const openedAt = Date.now();
  let seen = new Set<string>();
  let tickerDrawn = false;
  let lastKey = "";

  const ctxFor = (run: RunView, now: number): EvidenceContext => ({ title: titles.get(run.scenario) ?? run.scenario, now, details: details.get(run.scenario), commands });

  const drawRun = (force = false) => {
    const run = view.runs[0];
    const key = run ? `${run.runId}|${run.events.length}|${run.current}|${run.active}|${titles.get(run.scenario) ?? ""}|${details.has(run.scenario)}|${commands.size}` : `none|${decided}|${loading}|${live.apiStartedAt ?? ""}|${lastRunAt ?? ""}`;
    if (!force && key === lastKey) return;
    lastKey = key;
    const now = Date.now();
    card.dataset.state = run ? "run" : "empty";
    if (run) {
      replace(card, renderEvidenceCard(run, ctxFor(run, now)));
      replace(section.detail, renderEvidenceDetail(run, ctxFor(run, now)));
    } else if (decided) {
      replace(card, renderNoAttack({ apiStartedAt: live.apiStartedAt, lastRunAt, now, loading }));
      replace(section.detail, h("p", { class: "small" }, "The full record of the next attack appears here as it happens."));
    }
  };

  const drawTicker = () => {
    const items = tickerItems(view);
    // Items that were not on screen before are marked new (a short fade where motion is allowed);
    // the first drawing marks none.
    const fresh = tickerDrawn ? new Set(items.map((i) => i.key).filter((k) => !seen.has(k))) : new Set<string>();
    seen = new Set(items.map((i) => i.key));
    tickerDrawn = true;
    replace(section.ticker, renderTicker(items, { now: Date.now(), since: live.apiStartedAt ?? openedAt, connected, tickAt: live.tickAt, fresh }));
  };

  const drawLiveness = () => {
    if (!livenessShown) return;
    replace(section.liveness, renderLiveness(live, Date.now()));
  };

  const decide = () => {
    clearTimeout(fallback);
    livenessShown = true;
    drawLiveness();
    drawTicker();
    if (decided) return;
    decided = true;
    drawRun();
    onDecided();
  };

  // Relative texts ("6 minutes ago") follow the clock; nothing else is redrawn on a timer.
  setInterval(() => {
    drawRun(true);
    drawTicker();
    drawLiveness();
  }, RELATIVE_REFRESH_MS);

  return {
    update(v) {
      view = v;
      drawRun();
      drawTicker();
    },
    setTitles(t) {
      titles = t;
      drawRun();
    },
    setDetails(scenario, d) {
      details.set(scenario, d);
      drawRun();
    },
    setCatalogue(list) {
      commands = new Map(list.map((c) => [c.id, c]));
      drawRun();
    },
    streamOpened() {
      if (livenessShown || fallback !== undefined) return;
      fallback = setTimeout(decide, LIVENESS_FALLBACK_MS);
    },
    setConnection(state) {
      connected = state === "open";
      drawTicker();
    },
    tick(t) {
      live = { ...live, tickAt: t.at, apiStartedAt: live.apiStartedAt ?? t.started_at };
      decide();
    },
    setPosture(p) {
      live = { ...live, postureAt: p.generated_at, kubeBench: p.kube_bench.last_run, trivy: p.trivy.last_scan };
      drawLiveness();
    },
    setApiStart(iso) {
      if (live.apiStartedAt === iso) return;
      live = { ...live, apiStartedAt: iso };
      drawLiveness();
      drawRun();
    },
    setLastRunAt(iso) {
      lastRunAt = iso;
      drawRun();
    },
    setLoading(l) {
      loading = l;
      drawRun();
    },
  };
}
