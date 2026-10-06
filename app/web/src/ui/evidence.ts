// Evidence by default (ADR 0035, B4). The latest real attack, without a click or a scroll: a card in
// the hero's right column (after the hero copy on narrow screens), then in #evidence a ticker of the
// last feed items, a liveness line and the run's full record. Everything here is drawn from events
// the API published (the stream, or GET /api/runs/{id} for the newest run when the replay held none)
// and from server timestamps. Nothing is synthesised, looped or padded: when nothing happened, the
// page says since when, and the only thing that changes on its own is the server's clock (the opt-in
// SSE tick) and "x minutes ago" next to an absolute time (Polish, CET/CEST).

import { type CatalogueCommand, type CommandOutcome, FALCO_FIELDS, type RunSummary, type FalcoEvent, type Posture, type ScenarioDetails, type StreamEvent, type TalonEvent, type Tick, isRunId } from "../lib/contract";
import { h, refreshRelative, relativeTime, replace, setText, timeEl, plTime, plClock, whenEl } from "../lib/dom";
import { humanAction } from "../lib/pipeline";
import { cosignVerifyCommand, digestOf, isPinnedImageRef, oneLine, shortDigest } from "../lib/provenance";
import type { ConnectionState } from "../lib/sse";
import { type RunView, type TimelineView, formatDuration, noDetection, publishedPod, ts } from "../lib/timeline";
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


/**
 * Which pod of a side-by-side run an event is about, from its namespace (ADR 0031): a Map, so a
 * namespace such as "constructor" finds nothing. Any other namespace gets no label.
 */
const ARM_OF_NAMESPACE: ReadonlyMap<string, string> = new Map([
  ["sandbox", "guarded"],
  ["sandbox-unguarded", "twin, unguarded"],
]);
const armTag = (namespace: string) => {
  const arm = ARM_OF_NAMESPACE.get(namespace);
  return arm ? [h("span", { class: "tag tag--arm", "data-arm": namespace === "sandbox" ? "guarded" : "unguarded" }, arm), " "] : null;
};

/** The card's header follows the run's state, as the chip does: contained and over are not "in progress". */
function eyebrow(run: RunView): string {
  if (run.current === "responded") return "Attack contained";
  return run.active ? "Attack in progress" : "Latest attack, as recorded";
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
      armTag(f.namespace),
      h("strong", {}, f.rule),
      ` (${f.priority}) at `,
      timeEl(f.at, plClock(f.at, now, { ms: true })),
      f.api_received_at ? [", received ", timeEl(f.api_received_at, plClock(f.api_received_at, now, { ms: true }))] : null,
      delay !== undefined && delay >= 0 ? `, delivered in ${formatDuration(delay)}` : null,
    );
  }
  const t = a.data;
  return h(
    "li",
    { class: "evlist__item", "data-type": "talon" },
    h("span", { class: "tag tag--respond" }, "talon"),
    " ",
    armTag(t.namespace),
    h("strong", {}, humanAction(t.action, t.actionner)),
    " ",
    code(t.actionner ?? t.action),
    // Talon's own status word only when it is not plain success.
    `${t.status === "success" ? "" : ` (${t.status})`} at `,
    timeEl(t.at, plClock(t.at, now, { ms: true })),
  );
}

function commandItems(run: RunView, ctx: EvidenceContext, max: number): HTMLElement[] {
  return run.commands.slice(0, max).map((c) => {
    const cat = ctx.commands?.get(c.id);
    const exit = c.exitCode !== undefined ? `exit ${c.exitCode}` : c.killed ? "killed" : c.endedAt !== undefined ? "ended, no exit code" : "running";
    return h("li", { class: "evlist__item", "data-type": "command" }, h("code", {}, cat?.input ?? c.id), ` · ${exit}`, // The catalogue's class is what the command is expected to meet, not a record of what happened.
      cat ? ` · expected: ${cat.outcome}` : null);
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

/** The hero card for one run: expanded, capped, every time absolute, in Polish time. */
export function renderEvidenceCard(run: RunView, ctx: EvidenceContext): HTMLElement {
  const { now } = ctx;
  const all = answers(run);
  const shown = all.slice(0, CARD_EVENTS);
  const more = all.length - shown.length;
  const start = runStart(run);
  const digest = run.image ? digestOf(run.image) : "";
  const failed = run.current === "failed" || run.current === "timeout";
  const outcomes = new Map<string, CommandOutcome>([...(ctx.commands ?? new Map<string, CatalogueCommand>()).values()].map((c) => [c.id, c.outcome]));
  // A detection the catalogue expected and that never came is said in the chip, in the critical colour.
  const missed = noDetection(run, outcomes) === "missed";
  return h(
    "article",
    { class: "evcard", "data-run": run.runId, "aria-labelledby": "evcard-title" },
    h("p", { class: "evcard__eyebrow" }, eyebrow(run)),
    h(
      "header",
      { class: "evcard__head" },
      h("h2", { class: "evcard__title", id: "evcard-title" }, ctx.title),
      missed
        ? h("span", { class: "chip chip--critical" }, "Detection expected, none arrived")
        : h("span", { class: `chip chip--${failed ? "critical" : run.active ? "warning" : "good"}` }, STATE_WORD[run.current] ?? run.current),
    ),
    Number.isFinite(start) ? h("p", { class: "evcard__when" }, "last attack ", whenEl(start, now)) : null,
    h(
      "dl",
      { class: "facts facts--mono evcard__facts" },
      fact("Pod", code(publishedPod(run))),
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

/**
 * No run in the timeline. With the newest run of GET /api/runs known (its events still loading), that
 * run is named from its summary; otherwise the card says what it knows: since when there was none
 * (the API's start, if known; else only that the stream's replay held none) and when the last run was
 * recorded.
 */
export function renderNoAttack(opts: { apiStartedAt?: string; lastRunAt?: string; latest?: RunSummary; now: number; loading?: boolean }): HTMLElement {
  const empty = (...body: (Node | string | null)[]) => h("article", { class: "evcard evcard--empty" }, h("p", { class: "evcard__eyebrow" }, "Latest attack"), ...body);
  const l = opts.latest;
  if (l) {
    return empty(
      h("p", { class: "evcard__none" }, "Latest recorded run ", h("code", {}, l.run_id), ` (${l.scenario}`, l.started_at ? [", started ", whenEl(l.started_at, opts.now)] : null, ") - ", extLink(rawUrl(l.run_id), "raw JSON")),
      h("p", { class: "small" }, "Its events are loading into the record below."),
    );
  }
  if (opts.loading) return empty(h("p", {}, "Loading the latest recorded attack…"));
  return empty(
    h(
      "p",
      { class: "evcard__none" },
      opts.apiStartedAt ? ["No attack since the API started at ", timeEl(opts.apiStartedAt)] : "No attack in the stream's replay",
      opts.lastRunAt ? [" - last attack recorded ", whenEl(opts.lastRunAt, opts.now)] : null,
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
      fact("Pod", code(publishedPod(run))),
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
    isPinnedImageRef(image)
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
  /** The run it belongs to, when the timeline attributed it to one, and that run's scenario. */
  run?: string;
  scenario?: string;
}

/**
 * The last feed items, newest first: run states, Falco rules, Talon actions and the end of each
 * terminal command. Only events the timeline holds; nothing else is ever added to fill the list.
 */
export function tickerItems(view: TimelineView, max = TICKER_ITEMS): TickerItem[] {
  const out: TickerItem[] = [];
  let owner: RunView | undefined;
  const add = (ev: StreamEvent, text: string) => out.push({ at: ts(ev.data.at), key: `${ev.id ?? ""}|${ev.type}|${ev.data.at}|${text}`, type: ev.type, text, ...(owner ? { run: owner.runId, scenario: owner.scenario } : {}) });
  for (const [ev, r] of [...view.runs.flatMap((x) => x.events.map((e) => [e, x] as const)), ...view.unmatched.map((e) => [e, undefined] as const)]) {
    owner = r;
    switch (ev.type) {
      case "run":
        add(ev, `${ev.data.scenario}: ${STATE_WORD[ev.data.state] ?? ev.data.state}`);
        break;
      case "falco":
        add(ev, `Falco: ${ev.data.rule}`);
        break;
      case "talon":
        add(ev, `Talon: ${humanAction(ev.data.action, ev.data.actionner)}${ev.data.status === "success" ? "" : ` (${ev.data.status})`}`);
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
      opts.connected && opts.tickAt ? [" (server time ", timeEl(opts.tickAt, plTime(opts.tickAt), { class: "ticker__server" }), ")"] : null,
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
        timeEl(i.at, plClock(i.at, opts.now, { ms: true })),
        h("span", { class: "ticker__ago", "data-ago": String(i.at) }, ` (${relativeTime(new Date(i.at).toISOString(), opts.now)})`),
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
  if (l.tickAt) parts.push(["server time ", timeEl(l.tickAt, plTime(l.tickAt), { class: "liveness__server" })]);
  if (l.postureAt) parts.push(["posture refreshed ", whenEl(l.postureAt, now)]);
  if (l.kubeBench) parts.push(["kube-bench ", whenEl(l.kubeBench, now)]);
  if (l.trivy) parts.push(["Trivy ", whenEl(l.trivy, now)]);
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
  /** GET /api/runs is being asked for the newest run. */
  setLoading(loading: boolean): void;
  /** The newest run GET /api/runs knows, named on the card until its events arrive. */
  setLatest(summary: RunSummary): void;
  /** Runs the status strip announces (the visitor's own), and any terminal run while the visitor's own start is in flight: the ticker's announcer keeps quiet about them. */
  setQuiet(runIds: readonly string[], startingTerminal?: boolean): void;
  /**
   * Whether #evidence can be seen (its section is not folded away). While it cannot, only the hero's
   * card is drawn; the ticker, the liveness line and the full record are drawn on the way back, and
   * what arrived meanwhile is not announced as new.
   */
  setActive(active: boolean): void;
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
  section: { ticker: HTMLElement; liveness: HTMLElement; detail: HTMLElement; announce: HTMLElement },
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
  let latest: RunSummary | undefined;
  let tickerShape = "";
  let livenessShown = false;
  let fallback: ReturnType<typeof setTimeout> | undefined;
  const openedAt = Date.now();
  let seen = new Set<string>();
  // New items are marked and spoken only once the replay is in: replayed history stays silent.
  let primed = false;
  let lastKey = "";
  let active = true;
  let quiet: ReadonlySet<string> = new Set();
  let startingTerminal = false;

  const ctxFor = (run: RunView, now: number): EvidenceContext => ({ title: titles.get(run.scenario) ?? run.scenario, now, details: details.get(run.scenario), commands });

  const drawRun = (force = false) => {
    const run = view.runs[0];
    const key = run ? `${run.runId}|${run.events.length}|${run.current}|${run.active}|${titles.get(run.scenario) ?? ""}|${details.has(run.scenario)}|${commands.size}` : `none|${decided}|${loading}|${latest?.run_id ?? ""}|${live.apiStartedAt ?? ""}|${lastRunAt ?? ""}`;
    if (!force && key === lastKey) return;
    lastKey = key;
    const now = Date.now();
    card.dataset.state = run ? "run" : "empty";
    if (run) replace(card, renderEvidenceCard(run, ctxFor(run, now)));
    else if (decided) replace(card, renderNoAttack({ apiStartedAt: live.apiStartedAt, lastRunAt, latest, now, loading }));
    drawDetail();
  };

  const drawDetail = () => {
    if (!active) return;
    const run = view.runs[0];
    if (run) replace(section.detail, renderEvidenceDetail(run, ctxFor(run, Date.now())));
    else if (decided) replace(section.detail, h("p", { class: "small" }, "The full record of the next attack appears here as it happens."));
  };

  const drawTicker = () => {
    const items = tickerItems(view);
    const now = Date.now();
    // The list is rebuilt only when what it lists changes. Otherwise (a tick, a reconnect, the clock)
    // only its texts change in place, so a screen reader, a selection or a focused link is left alone.
    const since = live.apiStartedAt ?? openedAt;
    const shape = items.length ? items.map((i) => i.key).join("\n") : `empty|${connected}|${since}|${live.tickAt !== undefined}`;
    const wasPrimed = primed;
    primed ||= decided;
    if (!active) return;
    if (shape === tickerShape) {
      refreshRelative(section.ticker, now);
      const server = section.ticker.querySelector<HTMLTimeElement>(".ticker__server");
      if (server && live.tickAt) {
        setText(server, plTime(live.tickAt));
        server.dateTime = new Date(live.tickAt).toISOString();
      }
      return;
    }
    tickerShape = shape;
    // Items that were not on screen before are marked new (a short fade where motion is allowed) and
    // spoken once through the visually hidden status line.
    const fresh = wasPrimed ? items.filter((i) => !seen.has(i.key)) : [];
    seen = new Set(items.map((i) => i.key));
    replace(section.ticker, renderTicker(items, { now, since, connected, tickAt: live.tickAt, fresh: new Set(fresh.map((i) => i.key)) }));
    const spoken = fresh.filter((i) => !i.run || !(quiet.has(i.run) || (startingTerminal && i.scenario === "terminal")));
    if (spoken.length) replace(section.announce, `New event${spoken.length === 1 ? "" : "s"}: ${spoken.map((i) => i.text).join("; ")}`);
  };

  const drawLiveness = () => {
    if (!livenessShown || !active) return;
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

  // Relative texts ("6 minutes ago") follow the clock, rewritten in place: nothing is redrawn on a
  // timer, so a link focused in the card keeps its focus.
  setInterval(() => {
    const now = Date.now();
    for (const el of active ? [card, section.detail, section.ticker, section.liveness] : [card]) refreshRelative(el, now);
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
    setLatest(summary) {
      latest = summary;
      loading = false;
      drawRun();
    },
    setQuiet(ids, starting = false) {
      quiet = new Set(ids);
      startingTerminal = starting;
    },
    setActive(on) {
      if (on === active) return;
      active = on;
      if (!on) return;
      // Whatever reached the ticker while it was folded is on it now, but not "new".
      seen = new Set(tickerItems(view).map((i) => i.key));
      tickerShape = "";
      drawTicker();
      drawLiveness();
      drawDetail();
    },
  };
}
