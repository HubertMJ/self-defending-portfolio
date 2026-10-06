// The attacker's terminal (ADR 0033, part A). The visitor types real command ids into a real
// hardened pod and reads the real output stream back, with the shop window changing beside them and
// the session ending under them when the cluster answers. Everything the visitor types is resolved
// against the catalogue locally; only a known command id is ever sent (the API accepts ids, never a
// visitor's free text), and an unknown line is answered here and goes nowhere.
//
// Keyboard- and screen-reader-usable: the output is an aria-live log, the input is a labelled text
// box with Tab-completion from the catalogue, and the same commands are tappable chips grouped by
// objective for touch screens. prefers-reduced-motion drops the caret blink and smooth scrolling.

import type { ApiClient } from "../lib/api";
import { type CatalogueCommand, type DefenceLayer, type Objective, type ScenarioDetails, isRunId } from "../lib/contract";
import { type Child, h, prefersReducedMotion, replace } from "../lib/dom";
import { type SiemRow, lastAlert, lastResponse, paletteTone } from "../lib/runstatus";
import type { CommandRun, RunView, TimelineView } from "../lib/timeline";
import { formatDuration, ts } from "../lib/timeline";
import { type LitLayer, litFromCommands, renderDefenceMap } from "./defencemap";
import { breakable, offlinePanel, pulse } from "./common";
import { renderVictim } from "./victim";

export interface TerminalHandle {
  update(view: TimelineView): void;
  /** The API's stored history of this run is incomplete (GET /api/runs/{id} said `truncated`). */
  historyTruncated(runId: string): void;
  /** The "This run" panel's SIEM row (lib/runstatus.ts siemRow). */
  setSiem(row: SiemRow): void;
  /** Takes the visitor to the terminal with a command picked: opens a session if idle (one run), highlights its chip and fills it in once the pod is ready. */
  suggest(commandId: string): void;
  /** Back to the start panel for another session ("Run again"). */
  again(): void;
  /** Brings the "This run" timeline into view and pulses it ("Watch the kill timeline"). */
  showTimeline(): void;
}

/** The visitor's own session as the status strip reads it (null: none, or no longer theirs). */
export interface OwnSession {
  runId: string;
  run?: RunView;
  commands: CatalogueCommand[];
  idleSeconds?: number;
}

interface Catalogue {
  details: ScenarioDetails;
  commands: CatalogueCommand[];
  objectives: Objective[];
  /** The run's limits from the details; undefined only from an API that does not send them. */
  idleSeconds?: number;
  timeoutSeconds?: number;
}

/** Resolve a typed line to a catalogue command: exact input or alias, trimmed, case-insensitive. */
function resolve(cat: Catalogue, line: string): CatalogueCommand | undefined {
  const t = line.trim().toLowerCase();
  if (!t) return undefined;
  return cat.commands.find((c) => c.input.toLowerCase() === t || c.aliases.some((a) => a.toLowerCase() === t));
}

/** All catalogue spellings that start with the prefix, for Tab-completion. */
function completions(cat: Catalogue, prefix: string): string[] {
  const p = prefix.trim().toLowerCase();
  if (!p) return [];
  const all = cat.commands.flatMap((c) => [c.input, ...c.aliases]);
  return all.filter((s) => s.toLowerCase().startsWith(p));
}

export function mountTerminal(
  root: HTMLElement,
  api: ApiClient,
  hooks: {
    onStarted?: (runId: string) => void;
    blocked?: () => string | null;
    cooldownSeconds?: () => number;
    onRateLimited?: (seconds: number) => void;
    /** Whether this API has the terminal, with its objectives and run timeout: told once the catalogue has loaded or failed to. */
    onAvailable?: (available: boolean, objectives: Objective[], timeoutSeconds?: number, commands?: CatalogueCommand[], idleSeconds?: number) => void;
    /** The status strip (ui/runstatus.ts): carried under the input in a session and under the start button between sessions. */
    strip?: HTMLElement;
    /** Every change of the visitor's own session (not a watched one). */
    onSession?: (s: OwnSession) => void;
    /** The layers the visitor's last session lit, for "How it works". */
    onLit?: (lit: Map<DefenceLayer, LitLayer>) => void;
    /** How long until the run holding the one slot must end, in ms, when its limits are known. */
    blockedEndsIn?: () => number | undefined;
  } = {},
): TerminalHandle {
  const reduced = prefersReducedMotion();
  let catalogue: Catalogue | null = null;
  let session: { runId: string; token: string } | null = null;
  let starting = false;
  let watching: string | undefined; // another visitor's terminal run id, read-only
  let view: TimelineView = { runs: [], unmatched: [] };
  let endedShown = false;
  let ready = false; // the run reached pod_ready — commands are accepted only then
  let pendingSeq: number | undefined; // a command sent and not yet ended on the client
  let sending = false; // a POST of a command is in flight (its 202 not back yet)
  let leaveSent = false; // this session's DELETE has gone out (by the button, `exit`, or pagehide)
  // When this page's start timed out: the server may still have started the run, which then shows
  // up read-only (the 202 with its key never arrived), and the page says why.
  let startTimedOutAt: number | undefined;
  const ownRunLost = () => startTimedOutAt !== undefined && Date.now() - startTimedOutAt < 60_000;
  let mode: "idle" | "session" | "unavailable" = "unavailable";


  // Built once per session; patched after.
  let els: {
    out: HTMLElement;
    form: HTMLFormElement;
    input: HTMLInputElement;
    hint: HTMLElement;
    said: HTMLElement;
    chips: HTMLElement;
    palette: HTMLElement;
    shop: HTMLElement;
    objectives: HTMLElement;
    banner: HTMLElement;
    rows: { detection: HTMLElement; response: HTMLElement; siem: HTMLElement };
    timeline: HTMLElement;
    summary: HTMLElement;
    status: HTMLElement;
    clock: HTMLElement;
    left: HTMLElement;
    idleLeft: HTMLElement;
    send: HTMLButtonElement;
    exit: HTMLButtonElement;
  } | null = null;

  // The bar's two countdowns, ticked once a second while the session is live. Run timestamps are the
  // API's clock; `skew` is the page's clock minus the API's, estimated as the least lag seen between
  // an event's `at` and the moment the page saw it, so a visitor's wrong clock does not move them.
  let clockTimer: ReturnType<typeof setInterval> | undefined;
  let skew = Infinity;

  // ---- load the catalogue ----
  // Only the API saying "no such scenario" (a JSON 404) means this build has no terminal; a network
  // error, a 5xx or a 429 from the request limiter is passing, so it gets an offline state that
  // retries (30 s, then twice as long, three times) and a button, and the page is not degraded.
  let catalogueTries = 0;
  let catalogueTimer: ReturnType<typeof setTimeout> | undefined;
  const loadCatalogue = async () => {
    clearTimeout(catalogueTimer);
    const r = await api.scenarioDetails("terminal");
    if (r.ok && (r.value.commands?.length ?? 0) > 0) {
      catalogue = {
        details: r.value,
        commands: r.value.commands ?? [],
        objectives: r.value.objectives ?? [],
        // No default: an API that sends no limits gets no countdowns and words without numbers
        // (the staleness bound then falls back to the contract's ceiling, timeline.ts staleRunMs).
        idleSeconds: r.value.idle_seconds,
        timeoutSeconds: r.value.timeout_seconds,
      };
      if (mode === "session") {
        // Another visitor's run reached the page first and is already shown read-only: fill in what
        // needed the catalogue there, rather than replacing the session with the start panel.
        buildChips();
        renderObjectives();
        patchFromView();
      } else {
        renderIdle();
      }
      hooks.onAvailable?.(true, catalogue.objectives, catalogue.timeoutSeconds, catalogue.commands, catalogue.idleSeconds);
    } else if (r.ok || (r.status === 404 && r.json)) {
      renderUnavailable();
    } else {
      catalogueTries += 1;
      if (catalogueTries <= 3) catalogueTimer = setTimeout(() => void loadCatalogue(), 15_000 * 2 ** catalogueTries);
      if (mode !== "session") renderOffline(r.message);
    }
  };

  const renderOffline = (detail: string) => {
    mode = "unavailable";
    replace(
      root,
      offlinePanel({
        title: "The terminal cannot reach the API right now",
        body: "Its command list did not load. This is usually brief; the one-click attacks below may still work.",
        detail,
        onRetry: () => void loadCatalogue(),
      }),
    );
  };

  // No terminal on this API build: keep it quiet and point at the one-click demo below, which is the
  // main thing when the terminal is not there (review item 20) — not a loud "offline / Retry" block.
  const renderUnavailable = () => {
    mode = "unavailable";
    hooks.onAvailable?.(false, []);
    replace(
      root,
      h(
        "div",
        { class: "term-fallback" },
        h("p", {}, "This build of the site is talking to an API without the interactive terminal. The one-click attacks below run the same scenarios and show the detection and response live."),
        h("p", {}, h("a", { href: "#justshowme-title" }, "Jump to the one-click attacks ↓")),
      ),
    );
  };

  // ---- idle (not started) ----
  // Built once when the terminal goes idle, then patched in place: rebuilding it on every event of the
  // feed replaced the button under the visitor's keyboard focus and wiped the note under it.
  let idle: { label: HTMLElement; btn: HTMLButtonElement; note: HTMLElement; eta: HTMLElement; shown: string | null; clock?: ReturnType<typeof setInterval> } | null = null;

  /** Why the start button is blocked right now ("Starting…", another run, a cooldown), or null. */
  const blockedNow = (): string | null => (starting ? "Starting…" : (hooks.blocked?.() ?? null));

  const renderIdle = () => {
    if (!catalogue) return;
    mode = "idle";
    clearInterval(clockTimer);
    clockTimer = undefined;
    const label = h("span", { class: "btn__label" }, "Open the terminal");
    const btn = h("button", { type: "button", class: "btn btn--attack term-start__btn" }, h("span", { class: "btn__icon", "aria-hidden": "true" }, "▶"), label);
    btn.addEventListener("click", () => void start());
    const note = h("p", { class: "small term-start__blocked", role: "status" });
    // When the slot frees up, from the busy run's limits: ticked with the button, never announced.
    const eta = h("p", { class: "small term-start__eta", hidden: true });
    replace(
      root,
      h(
        "div",
        { class: "term-start" },
        h("p", { class: "term-start__lead" }, "A throwaway pod in ", h("code", {}, "sandbox"), " with the SDP Shop running inside it. Type commands into it and read the real output — the quiet moves get you further; the loud ones end your session. Costs one attack from your budget."),
        h(
          "ol",
          { class: "term-start__objectives", "aria-label": "What you can try" },
          catalogue.objectives.map((o) => h("li", {}, o.title)),
        ),
        btn,
        note,
        eta,
        hooks.strip ?? null,
      ),
    );
    if (idle?.clock !== undefined) clearInterval(idle.clock);
    idle = { label, btn, note, eta, shown: null };
    syncIdle();
  };

  /** Patches the start button's label and state; a note stays until what blocked the start changes. */
  const syncIdle = () => {
    if (!idle) return;
    if (mode !== "idle") {
      clearInterval(idle.clock);
      idle = null;
      return;
    }
    const blocked = blockedNow();
    const text = blocked ?? "Open the terminal";
    if (idle.label.textContent !== text) idle.label.textContent = text;
    idle.btn.setAttribute("aria-disabled", String(blocked !== null));
    if (blocked !== idle.shown) {
      if (blocked === null) setNote("");
      idle.shown = blocked;
    }
    // "A run is in progress" says when it must end at the latest (its session or idle limit).
    const left = blocked === "A run is in progress" ? hooks.blockedEndsIn?.() : undefined;
    const etaText = left === undefined ? "" : left > 0 ? `That run ends within ${clockText(left)} at the latest; the button unlocks then.` : "That run should end any moment now.";
    if (idle.eta.textContent !== etaText) idle.eta.textContent = etaText;
    idle.eta.hidden = etaText === "";
    // A cooldown ends on its own, with no event to say so: re-check every second while blocked.
    if (blocked !== null && idle.clock === undefined) idle.clock = setInterval(syncIdle, 1000);
    else if (blocked === null && idle.clock !== undefined) {
      clearInterval(idle.clock);
      idle.clock = undefined;
    }
  };

  const setNote = (msg: string) => {
    if (idle && idle.note.textContent !== msg) idle.note.textContent = msg;
  };

  const start = async () => {
    if (!catalogue || starting) return;
    const blocked = blockedNow();
    if (blocked !== null) {
      // A press on a blocked button says why, rather than doing nothing.
      const wait = hooks.cooldownSeconds?.() ?? 0;
      setNote(wait > 0 ? `Rate limit reached: you can start again in ${wait} s.` : "Another run is in progress — only one runs at a time. The button unlocks when it finishes.");
      return;
    }
    starting = true;
    syncIdle();
    const r = await api.attackTerminal();
    starting = false;
    if (r.kind === "accepted") {
      if (!isRunId(r.run.run_id)) {
        // The server accepted a run but named it something we will not put in a URL; say so plainly
        // rather than sending a request that could escape the run path.
        syncIdle();
        setNote("The server accepted a run but returned an unusable id. Reload and try again.");
        return;
      }
      if (idle?.clock !== undefined) clearInterval(idle.clock);
      idle = null;
      session = { runId: r.run.run_id, token: r.run.token };
      watching = undefined; // this run is mine, not one I am watching
      resetSessionState();
      hooks.onStarted?.(r.run.run_id);
      renderSession();
    } else if (r.kind === "unavailable") {
      renderUnavailable();
    } else {
      if (r.kind === "rate-limited") hooks.onRateLimited?.(r.retryAfterSeconds);
      if (r.kind === "offline" && r.message === "timed out") startTimedOutAt = Date.now();
      syncIdle();
      // The note is set after the sync, so the cooldown it explains does not clear it.
      if (idle) idle.shown = blockedNow();
      setNote(
        r.kind === "busy" ? "Another run is in progress — only one runs at a time. Try again when it finishes." : r.kind === "rate-limited" ? `Rate limit reached: try again in ${Math.ceil(r.retryAfterSeconds)} s.` : r.kind === "error" ? `The server refused the request (HTTP ${r.status}).` : startTimedOutAt !== undefined && ownRunLost() ? "The start request timed out. The server may have started the run anyway: if it shows up here, it is read-only, because its key never reached this page." : "The attack API is not reachable right now.",
      );
    }
  };

  const resetSessionState = () => {
    endedShown = false;
    ready = false;
    pendingSeq = undefined;
    sending = false;
    leaveSent = false;
    rendered.clear();
  };

  // ---- running session skeleton ----
  // The terminal pane on the left (bar, output, input, the status strip), the "This run" panel on the
  // right (detection, response and SIEM rows, the objectives, this run's own timeline, the shop),
  // sticky and never taller than the screen; the command palette full width under both. Only things
  // about this session sit beside it: the seven-layer map is in "How it works" (ADR 0035 amendment).
  const renderSession = () => {
    mode = "session";
    const out = h("div", { class: "term__out", role: "log", "aria-live": "polite", "aria-label": "Terminal output", tabindex: "0" });
    const input = h("input", { type: "text", class: "term__input", id: "term-input", autocomplete: "off", autocapitalize: "off", autocorrect: "off", spellcheck: "false", "aria-label": "Command to run in the pod", "aria-describedby": "term-hint", placeholder: "starting the pod…", disabled: true }) as HTMLInputElement;
    input.disabled = true;
    const hint = h("p", { class: "term__hint", id: "term-hint" });
    // What a screen reader is told (a Tab's choices, a note): a live region that is always live, so
    // nothing depends on switching aria-live on in the same moment the text changes.
    const said = h("p", { class: "visually-hidden", "aria-live": "polite" });
    const prompt = h("span", { class: "term__prompt", "aria-hidden": "true" }, "sandbox$");
    const send = h("button", { type: "submit", class: "btn btn--small term__send" }, "Run") as HTMLButtonElement;
    const form = h("form", { class: "term__form" }, prompt, input, send) as HTMLFormElement;
    const chips = h("div", { class: "term__chips" });
    const palette = h(
      "div",
      { class: "term__palette" },
      h(
        "div",
        { class: "term__palettehead" },
        h("h4", { class: "term__palettetitle" }, "Commands"),
        h(
          "ul",
          { class: "term__legend", "aria-label": "What each colour means" },
          h("li", { class: "term__legend--allowed" }, "allowed"),
          h("li", { class: "term__legend--detected" }, "Falco answers"),
          h("li", { class: "term__legend--prevented" }, "prevented"),
          h("li", { class: "term__legend--siem" }, "only the SIEM sees it"),
        ),
      ),
      chips,
    );
    const shop = h("div", { class: "term__shop" });
    const objectives = h("div", { class: "term__objectives" });
    const summary = h("div", { class: "term__summary", hidden: true });
    // The visitor's own session is announced by the status strip; a watched one by this line.
    const status = h("p", { class: "term__status", ...(watching ? { role: "status", "aria-live": "polite" } : {}) });
    // role=timer is not live: a screen reader reads it when asked, never every second.
    const left = h("span", { class: "term__left", title: "Time left before the session limit deletes the pod" });
    const idleLeft = h("span", { class: "term__idleleft", title: "Time left before the session ends for want of a command" });
    const clock = h("span", { class: "term__clock", role: "timer", "data-live": "false" }, left, idleLeft);
    const exit = h("button", { type: "button", class: "btn btn--ghost btn--small term__exit" }, "Leave");
    exit.addEventListener("click", () => void leave());
    const row = (label: string, key: string) => {
      const dd = h("dd", {}, "—");
      return { el: h("div", { class: "thisrun__row", "data-row": key, "data-tone": "idle" }, h("dt", {}, label), dd), dd };
    };
    const detection = row("Detection", "detection");
    const response = row("Response", "response");
    const siem = row("SIEM", "siem");
    const timeline = h("ol", { class: "thisrun__timeline", "aria-label": "This run, event by event" });
    const timelineWrap = h("div", { class: "thisrun__timelinewrap", tabindex: "-1" }, h("h4", { class: "thisrun__subhead" }, "Timeline of this run"), timeline);
    const sideBody = h("div", { class: "thisrun__body", id: "thisrun-body" }, objectives, timelineWrap, h("details", { class: "thisrun__shop", open: true }, h("summary", {}, "The shop, from the pod's own :8080"), shop));
    // On a phone the panel is one card above the input: its rows always, the rest on request.
    const more = h("button", { type: "button", class: "btn btn--ghost btn--small thisrun__more", "aria-expanded": "false", "aria-controls": "thisrun-body" }, "Details");
    // The aside fills its grid cell without adding to its height; the panel inside is sticky and no
    // taller than the screen or the terminal beside it.
    const panel = h(
      "div",
      { class: "thisrun", "data-open": "false" },
      h("div", { class: "thisrun__head" }, h("h3", { class: "thisrun__title", id: "thisrun-title" }, watching ? "This run (watching)" : "This run"), more),
      h("dl", { class: "thisrun__rows" }, detection.el, response.el, siem.el),
      sideBody,
    );
    const side = h("aside", { class: "term__side", "aria-labelledby": "thisrun-title" }, panel);
    more.addEventListener("click", () => {
      const open = panel.dataset.open !== "true";
      panel.dataset.open = String(open);
      more.setAttribute("aria-expanded", String(open));
      replace(more, open ? "Less" : "Details");
    });

    form.addEventListener("submit", (e) => {
      e.preventDefault();
      void submit(input.value);
    });
    input.addEventListener("keydown", (e) => {
      if (e.key !== "Tab" || e.shiftKey) return;
      const typed = input.value.trim();
      const opts = catalogue ? completions(catalogue, input.value) : [];
      const prefix = commonPrefix(opts);
      const next = prefix.length > typed.length ? prefix : opts.length === 1 ? opts[0] : typed;
      // Tab completes only when it changes the text. Otherwise — nothing to complete, a complete
      // command already (`ps`, though `ps aux` also exists), or the choices already listed — it moves
      // focus as it always does, so the input never traps the keyboard.
      const listed = els?.hint.dataset.opts === opts.join("\u0000");
      if (opts.length === 0 || (next === typed && (resolve(catalogue!, typed) !== undefined || listed))) return;
      e.preventDefault();
      input.value = next;
      showHint(opts, true);
    });
    input.addEventListener("input", () => showHint(catalogue ? completions(catalogue, input.value) : []));

    const banner = bannerLine();
    els = { out, form, input, hint, said, chips, palette, shop, objectives, banner, rows: { detection: detection.dd, response: response.dd, siem: siem.dd }, timeline, summary, status, clock, left, idleLeft, send, exit };
    replace(
      root,
      h(
        "div",
        { class: "terminal", "data-reduced": String(reduced) },
        h(
          "div",
          { class: "term__grid" },
          h(
            "section",
            { class: "term__pane", "aria-label": "Attacker's terminal" },
            h("div", { class: "term__bar" }, h("span", { class: "term__dots", "aria-hidden": "true" }, h("i"), h("i"), h("i")), h("span", { class: "term__bartitle" }, "sh — scenario pod"), clock, status, watching ? null : exit),
            out,
            form,
            hint,
            said,
            watching ? null : (hooks.strip ?? null),
          ),
          side,
        ),
        palette,
        summary,
      ),
    );
    buildChips();
    renderObjectives();
    renderSiem();
    // The output starts with a short banner so the log is never empty for a screen reader.
    replace(out, banner);
    patchFromView();
  };

  const bannerLine = () =>
    watching
      ? h("p", { class: "term__line term__line--sys" }, ownRunLost() ? "Read-only: this may be the run you just started — its start timed out before the page got the key to type into it. " : "Another visitor's session, read-only. ", "Their pod runs as uid 10001, non-root, with no network and a read-only root filesystem; each command and its output appears here as they type.")
      : h("p", { class: "term__line term__line--sys" }, "Pod starting. You will be uid 10001, non-root, no network, read-only root filesystem. When it is ready, try ", h("code", {}, "id"), " or tap a command below.");

  /** The banner's ready moment: "Pod starting…" does not stay at the top of the session. */
  const bannerReady = () => {
    if (!els || watching) return;
    replace(els.banner, "Pod ready. You are uid 10001, non-root, with no network and a read-only root filesystem. Try ", h("code", {}, "id"), " or tap a command below.");
  };

  // The completion hint. Read out only when the visitor asks for it (Tab), so routine typing does
  // not chatter to a screen reader.
  const showHint = (opts: string[], announce = false) => {
    if (!els) return;
    const text = opts.length && opts.length <= 6 ? `completes to: ${opts.join("  ·  ")}` : "";
    els.hint.textContent = text;
    els.hint.dataset.opts = text ? opts.join("\u0000") : "";
    if (announce) say(text);
  };

  const say = (text: string) => {
    if (els && els.said.textContent !== text) els.said.textContent = text;
  };

  /** True once the session can take no more commands: the run ended, or this page left it. */
  const over = (): boolean => endedShown || leaveSent || myRun()?.active === false;

  const leave = async () => {
    if (!session || watching || leaveSent || over()) return;
    leaveSent = true;
    syncControls();
    await api.leaveRun(session.runId, session.token);
    // The run's `finished` event arrives on the stream and drives the summary; nothing else to do.
  };

  const buildChips = () => {
    if (!els || !catalogue) return;
    const groups = new Map<string, CatalogueCommand[]>();
    for (const c of catalogue.commands) {
      // The API sends "" for a command with no objective; treat empty as none, so those commands
      // group under "Other moves" (last) instead of sorting first (review item 3).
      const key = c.objective ? c.objective : "other";
      (groups.get(key) ?? groups.set(key, []).get(key)!).push(c);
    }
    const title = (id: string) => catalogue!.objectives.find((o) => o.id === id)?.title ?? "Other moves";
    const order = [...catalogue.objectives.map((o) => o.id), "other"];
    const rank = (k: string) => {
      const i = order.indexOf(k);
      return i === -1 ? order.length : i;
    };
    replace(
      els.chips,
      [...groups.entries()]
        .sort((a, b) => rank(a[0]) - rank(b[0]))
        .map(([id, cmds]) =>
          h(
            "div",
            { class: "term__chipgroup" },
            h("p", { class: "term__chiphead" }, title(id)),
            h(
              "div",
              { class: "term__chiprow" },
              cmds.map((c) => {
                const b = h("button", { type: "button", class: `term__chip term__chip--${paletteTone(c)}`, "data-id": c.id, title: c.explain, disabled: true }, breakable(c.input));
                b.addEventListener("click", () => void submit(c.input));
                return b;
              }),
            ),
          ),
        ),
    );
  };

  // ---- submitting a command ----
  const submit = async (raw: string) => {
    if (!catalogue || !session || watching) return;
    const line = raw.trim();
    if (!line) return;
    if (over()) {
      noteHint("the session is over — start another below");
      return;
    }
    if (!ready) {
      noteHint("the pod is still starting — one moment");
      return;
    }
    // One command at a time: a line typed (or a chip tapped) while one is being sent or runs is held
    // back with a note — not queued, and never a second POST before the first one's 202.
    if (sending || pendingSeq !== undefined) {
      noteHint("wait for the current command to finish");
      return;
    }
    if (els) els.input.value = "";
    showHint([]);
    // `exit` does what it does in a shell: it ends the session (the Leave button).
    if (/^(exit|logout)$/i.test(line)) {
      appendLocal(line, "logout — ending the session");
      void leave();
      return;
    }
    const cmd = resolve(catalogue, line);
    if (!cmd) {
      // An unknown line is answered here and never sent anywhere.
      appendLocal(line, "sh: " + line.split(/\s+/)[0] + ": not in this sandbox's catalogue. Tab shows what is.");
      return;
    }
    sending = true;
    syncControls();
    const r = await api.runCommand(session.runId, session.token, cmd.id);
    sending = false;
    if (r.kind === "accepted") {
      // Cleared when this command's exited/killed event arrives — which may already have, before the
      // 202 did: then it is cleared right here.
      pendingSeq = r.seq;
      resolvePending();
      return; // output arrives over the event stream
    }
    syncControls();
    const why =
      r.kind === "conflict"
        ? "the pod is not ready, the session is over, or a command is still running"
        : r.kind === "rate-limited"
          ? /too many commands/i.test(r.reason)
            ? "you have run the most commands a session allows"
            : `too many requests from your address — try again in ${r.retryAfterSeconds} s`
          : r.kind === "unauthorized" ? "this session is not yours" : r.kind === "not-found" ? (/unknown command/i.test(r.reason) ? "the API does not know that command; its catalogue may have changed, reload the page" : "the run has ended") : r.kind === "too-large" ? "that was too long" : r.kind === "error" ? `the server refused it (HTTP ${r.status})` : "the API is not reachable";
    appendLocal(line, `sh: not run (${why})`);
  };

  /**
   * The controls follow the session: nothing is offered before pod_ready or after the end, and the
   * Run button and the chips rest while a command is being sent or runs.
   */
  const syncControls = () => {
    if (!els || watching) return;
    const closed = !ready || over();
    const busy = closed || sending || pendingSeq !== undefined;
    els.input.disabled = closed;
    els.send.disabled = busy;
    for (const b of els.chips.querySelectorAll<HTMLButtonElement>(".term__chip")) b.disabled = busy;
    els.chips.setAttribute("aria-disabled", String(busy));
    els.exit.disabled = over();
  };

  /** Releases the one-command lock once the sent command has ended, whichever of the 202 and its end came first. */
  const resolvePending = () => {
    if (pendingSeq !== undefined && myRun()?.commands.find((c) => c.seq === pendingSeq)?.endedAt !== undefined) pendingSeq = undefined;
    syncControls();
  };

  /** A transient note in the hint line, cleared on the next keystroke. */
  const noteHint = (msg: string) => {
    if (!els) return;
    els.hint.textContent = msg;
    els.hint.dataset.opts = "";
    say(msg);
  };

  /** A line the page answered itself (unknown command, or a rejected send): shown, never sent. */
  const appendLocal = (input: string, answer: string) => {
    if (!els) return;
    els.out.appendChild(h("div", { class: "term__cmd" }, promptEcho(input), h("p", { class: "term__line term__line--err" }, answer)));
    scrollOut();
    if (els.input) els.input.focus();
  };

  const promptEcho = (input: string) => h("p", { class: "term__line term__line--in" }, h("span", { class: "term__prompt", "aria-hidden": "true" }, "sandbox$ "), breakable(input));

  // ---- rendering the live session from the timeline view ----
  const myRun = (): RunView | undefined => {
    if (session) return view.runs.find((r) => r.runId === session!.runId);
    if (watching) return view.runs.find((r) => r.runId === watching);
    return undefined;
  };

  /**
   * Per-command DOM. Output that only grew at the end is appended (never re-rendered, so a screen
   * reader hears each line once); output whose history changed — a backfill filled in a chunk the
   * live feed had missed — rebuilds that command's block.
   */
  const rendered = new Map<number, { block: HTMLElement; out: HTMLElement; foot: HTMLElement; chunks: string[]; footKey: string }>();

  const patchFromView = () => {
    if (!els) return;
    const run = myRun();
    if (session && !watching && catalogue) hooks.onSession?.({ runId: session.runId, run, commands: catalogue.commands, idleSeconds: catalogue.idleSeconds });
    if (!run) return;
    const newest = run.events[run.events.length - 1];
    if (newest) skew = Math.min(skew, Date.now() - ts(newest.data.at));
    // Enable input the moment the pod is ready; keep it disabled (and chips inert) before that.
    const nowReady = run.states.pod_ready !== undefined;
    if (nowReady && !ready && !watching) enableInput();
    ready = ready || nowReady;
    for (const c of run.commands) appendCommand(c);
    resolvePending();
    patchShop(run);
    renderObjectives(run);
    renderRows(run);
    renderTimeline(run);
    if (!watching) hooks.onLit?.(litFromRun(run));
    applySuggestion(run);
    renderStatus(run);
    tickClock();
    if (!run.active && !endedShown) renderSummary(run);
  };

  /**
   * Session time left (the API's deadline runs from the run's start, before the pod exists) and idle
   * time left (from pod_ready, then from each command's start: the API's idle timer restarts when a
   * command arrives, not when it ends). Shown from pod_ready to the end, to watchers too; "m:ss" in a
   * monospaced bar, so a tick never moves anything.
   */
  const tickClock = () => {
    if (!els || !catalogue) return;
    const run = myRun();
    const readyAt = run?.states.pod_ready;
    const live = run !== undefined && readyAt !== undefined && run.active && !over();
    const { timeoutSeconds: limit, idleSeconds: idle } = catalogue;
    if (!live || (limit === undefined && idle === undefined)) {
      if (clockTimer !== undefined) clearInterval(clockTimer);
      clockTimer = undefined;
      // Before pod_ready the clock keeps its place, invisible; after the end, the status says why.
      els.clock.dataset.live = "false";
      els.clock.hidden = run !== undefined && (!run.active || over());
      return;
    }
    const now = Date.now() - (Number.isFinite(skew) ? skew : 0);
    const begun = run.states.queued ?? run.states.started ?? readyAt;
    const lastStart = Math.max(readyAt, ...run.commands.map((c) => c.startedAt ?? 0));
    // Patched only when the text changes; what a screen reader gets is worded for hearing.
    const set = (el: HTMLElement, text: string, ...kids: Child[]) => {
      if (el.dataset.text === text) return;
      el.dataset.text = text;
      replace(el, ...kids);
    };
    const hidden = (t: string) => h("span", { class: "visually-hidden" }, t);
    if (limit !== undefined) {
      const v = clockText(begun + limit * 1000 - now);
      set(els.left, v, hidden("Session time: "), `${v} left`);
    }
    if (idle !== undefined) {
      const v = clockText(lastStart + idle * 1000 - now);
      set(els.idleLeft, v, hidden("Idle limit in "), h("span", { "aria-hidden": "true" }, "idle "), v);
    }
    els.clock.dataset.live = "true";
    els.clock.hidden = false;
    clockTimer ??= setInterval(tickClock, 1000);
  };

  /** Why the run ended, from its `detail`, in the words the bar and the summary share. */
  const endReason = (run: RunView): string | undefined => {
    if (run.current !== "finished") return undefined;
    const idle = catalogue?.idleSeconds;
    switch (run.detail) {
      case "idle":
        return `ended after ${idle !== undefined ? `${idle} s` : "the idle limit"} without a command`;
      case "deadline":
        return `reached ${sessionLimit()}`;
      case "left":
        return watching ? "the visitor left" : "you left";
      case "killed":
        return "the cluster deleted the pod";
    }
    return undefined;
  };

  /** "the 5-minute session limit" from the details' timeout_seconds. */
  const sessionLimit = (): string => {
    const t = catalogue?.timeoutSeconds;
    if (t === undefined) return "the session's time limit";
    return t % 60 === 0 ? `the ${t / 60}-minute session limit` : `the ${t}-second session limit`;
  };

  const enableInput = () => {
    if (!els) return;
    els.input.placeholder = "type a command, then Enter (Tab to complete)";
    ready = true;
    bannerReady();
    syncControls();
    setTimeout(() => els && !els.input.disabled && els.input.focus(), 0);
  };

  const chunkLine = (x: CommandRun["chunks"][number]) => h("p", { class: x.stream === "stderr" ? "term__line term__line--err" : "term__line" }, x.text.replace(/\n$/, ""));

  /** Patches a command's block: new output appended, changed history rebuilt, in seq order. */
  const appendCommand = (c: CommandRun) => {
    if (!els) return;
    const cmd = catalogue?.commands.find((x) => x.id === c.id);
    let rec = rendered.get(c.seq);
    if (!rec) {
      const out = h("div", { class: "term__cmdout" });
      const foot = h("div", { class: "term__cmdfoot" });
      const block = h("div", { class: "term__cmd", "data-seq": String(c.seq), "data-outcome": cmd?.outcome ?? "" }, promptEcho(cmd?.input ?? c.id), out, foot);
      // A command the live feed missed entirely (backfilled later) goes before the ones after it.
      const later = [...rendered.entries()].filter(([seq]) => seq > c.seq).sort((a, b) => a[0] - b[0])[0];
      if (later) els.out.insertBefore(block, later[1].block);
      else els.out.appendChild(block);
      rec = { block, out, foot, chunks: [], footKey: "" };
      rendered.set(c.seq, rec);
    }
    const keys = c.chunks.map((x) => `${x.stream}\u0000${x.text}`);
    const grew = rec.chunks.length <= keys.length && rec.chunks.every((k, i) => k === keys[i]);
    if (!grew) replace(rec.out, ...c.chunks.map(chunkLine));
    else for (const x of c.chunks.slice(rec.chunks.length)) rec.out.appendChild(chunkLine(x));
    rec.chunks = keys;
    // The footer once the command has ended — `exited` (with or without a code) or `killed` — and
    // again whenever what it says changes (a run that ends after a code-less exit explains it).
    if (c.endedAt !== undefined) {
      const sys = (t: string) => h("p", { class: "term__line term__line--sys" }, t);
      const foot: HTMLElement[] = [];
      if (c.truncated) foot.push(sys("… output truncated"));
      if (c.killed) foot.push(h("p", { class: "term__line term__line--kill" }, "— the pod was deleted under this command; the session is over —"));
      else if (c.exitCode === undefined) foot.push(sys(noCodeReason(c)));
      else if (c.exitCode !== 0 && !c.stderr) foot.push(sys(`exit ${c.exitCode}`));
      if (cmd && c.achieved) {
        const title = catalogue?.objectives.find((o) => o.id === cmd.objective)?.title ?? cmd.objective;
        // Reached (it exited 0) by the command the cluster then deleted the pod for: not a win in green.
        const run = myRun();
        const costly = c.killed || (run !== undefined && responseOf(run, "terminate")?.cmd?.seq === c.seq);
        foot.push(
          costly
            ? h("p", { class: "term__line term__line--costly" }, `✓ objective reached: ${title} — and it cost ${watching ? "the visitor" : "you"} the pod`)
            : h("p", { class: "term__line term__line--win" }, `✓ objective reached: ${title}`),
        );
      }
      if (cmd) foot.push(h("p", { class: "term__explain" }, cmd.explain));
      const key = foot.map((p) => p.textContent).join("\u0000");
      if (key !== rec.footKey) {
        rec.footKey = key;
        replace(rec.foot, ...foot);
      }
    }
    scrollOut();
  };

  /**
   * Why a command `exited` with no exit code. The API sends that when it cut the exec short: the
   * command's own bound (5 s, or 10 s for a TTY command such as `sh -i`), the visitor leaving, or the
   * run's end (idle, the deadline) under a command that was still running. The run's end is told by
   * the run itself — over, for one of those reasons, with this its last command — not by a time
   * window, since `finished` follows the pod's deletion by a few seconds.
   */
  const noCodeReason = (c: CommandRun): string => {
    const run = myRun();
    const last = run?.commands[run.commands.length - 1] === c;
    const why = run && !run.active && last ? run.detail : undefined;
    if (why === "left") return "— stopped: the session was left while it ran —";
    if (why === "idle" || why === "deadline") return "— stopped: it ended with the session —";
    const tty = catalogue?.commands.find((x) => x.id === c.id)?.tty === true;
    const bound = tty ? 10 : 5;
    const ranFor = c.startedAt !== undefined && c.endedAt !== undefined ? c.endedAt - c.startedAt : 0;
    if (ranFor >= bound * 1000 - 500) return `— timed out: ${tty ? "a command with a terminal" : "a command"} gets ${bound} seconds —`;
    return "— stopped before it reported an exit code —";
  };

  const patchShop = (run: RunView) => {
    if (!els) return;
    replace(els.shop, renderVictim(run, watching !== undefined));
  };

  const renderStatus = (run: RunView) => {
    if (!els) return;
    const why = endReason(run);
    const text = !run.active
      ? why ? `session over — ${why}` : "session over"
      : watching
        ? ownRunLost()
          ? "read-only — the start timed out"
          : "watching another visitor — read-only"
        : run.quarantinedAt !== undefined
          ? "quarantined — still yours, but cut off"
          : !ready
            ? "starting the pod…"
            : `live · ${run.commands.length} command${run.commands.length === 1 ? "" : "s"}`;
    // Only write when it changes, so role=status does not re-announce on every event (item 22).
    if (els.status.textContent !== text) els.status.textContent = text;
  };

  // ---- the "This run" panel ----
  let siem: SiemRow = { text: "nothing to correlate yet", tone: "idle" };

  /** Patches a row only when its words change, so nothing flickers on every event. */
  const setRow = (dd: HTMLElement, tone: string, key: string, ...kids: Child[]) => {
    const row = dd.parentElement as HTMLElement;
    row.dataset.tone = tone;
    if (dd.dataset.key === key) return;
    dd.dataset.key = key;
    replace(dd, ...kids);
  };

  const renderRows = (run: RunView) => {
    if (!els) return;
    const alert = lastAlert(run);
    const resp = lastResponse(run);
    const enter = watching ? "their Enter" : "your Enter";
    if (alert) setRow(els.rows.detection, "detect", `a:${alert.rule}:${alert.afterEnterMs}`, "Falco: ", h("strong", {}, alert.rule), alert.afterEnterMs !== undefined ? `, ${formatDuration(alert.afterEnterMs)} after ${enter}` : "");
    else setRow(els.rows.detection, "idle", `n:${run.active}`, run.active ? "Falco: nothing yet" : "Falco: no alert this run");
    if (resp) setRow(els.rows.response, "respond", `r:${resp.action}:${resp.afterAlertMs}`, "Talon: ", h("strong", {}, resp.action === "terminate" ? "deleted the pod" : "quarantined the pod"), resp.afterAlertMs !== undefined ? `, ${formatDuration(resp.afterAlertMs)} after the alert` : "");
    else if (alert && !run.active) setRow(els.rows.response, "missed", "missed", "Talon: no response");
    else setRow(els.rows.response, "idle", "none", alert ? "Talon: deciding…" : "Talon: nothing to answer yet");
  };

  const renderSiem = () => {
    if (!els) return;
    const kids: Child[] = siem.incidentId ? [h("a", { href: `#incident-${siem.incidentId}`, class: "thisrun__incident" }, siem.text, " ↓")] : [siem.text];
    setRow(els.rows.siem, siem.tone, `${siem.tone}:${siem.text}:${siem.incidentId ?? ""}`, ...kids);
  };

  /**
   * This run, event by event, on the API's clock: the pod created and ready, each command, Falco's
   * alert, Talon's response, the end. The kill timeline of the visitor's own session, compact.
   */
  const renderTimeline = (run: RunView) => {
    if (!els || !catalogue) return;
    const items: { at: number; kind: string; tone: string; text: Child[] }[] = [];
    const add = (at: number | undefined, kind: string, tone: string, ...text: Child[]) => {
      if (at !== undefined && at > 0) items.push({ at, kind, tone, text });
    };
    add(run.states.started ?? run.states.queued, "start", "info", "pod created");
    add(run.states.pod_ready, "ready", "info", "pod ready");
    for (const c of run.commands) {
      const cmd = catalogue.commands.find((x) => x.id === c.id);
      add(c.startedAt, "command", cmd ? paletteTone(cmd) : "allowed", h("code", {}, breakable(cmd?.input ?? c.id)), c.killed ? " — killed" : c.exitCode !== undefined && c.exitCode !== 0 ? ` — exit ${c.exitCode}` : "");
    }
    for (const f of run.falco.filter((x) => x.arm !== "unguarded")) add(ts(f.at), "falco", "detect", "Falco: ", f.rule);
    const resp = lastResponse(run);
    if (resp) add(resp.at, "talon", "respond", resp.action === "terminate" ? "Talon deleted the pod" : "Talon quarantined the pod", resp.afterAlertMs !== undefined ? ` (+${formatDuration(resp.afterAlertMs)})` : "");
    const end = run.states.finished ?? run.states.failed ?? run.states.timeout;
    add(end, "end", "info", endReason(run) ? `session over — ${endReason(run)}` : "session over");
    items.sort((a, b) => a.at - b.at);
    const t0 = items[0]?.at ?? 0;
    const key = items.map((i) => `${i.kind}:${i.at}:${i.text.map((t) => (t instanceof Node ? t.textContent : String(t ?? ""))).join("")}`).join("|");
    if (els.timeline.dataset.key === key) return;
    els.timeline.dataset.key = key;
    replace(
      els.timeline,
      items.map((i) => h("li", { class: "thisrun__event", "data-kind": i.kind, "data-tone": i.tone }, h("span", { class: "thisrun__at" }, `+${formatDuration(i.at - t0)}`), h("span", { class: "thisrun__what" }, ...i.text))),
    );
  };

  // ---- a command picked for the visitor (the SIEM scenario's button) ----
  let suggested: string | undefined;

  /** Highlights the picked command's chip and fills it in, once the pod is ready; cleared once it has run. */
  const applySuggestion = (run?: RunView) => {
    if (!els || !catalogue || watching) return;
    if (suggested && run?.commands.some((c) => c.id === suggested)) suggested = undefined;
    for (const b of els.chips.querySelectorAll<HTMLElement>(".term__chip")) {
      if (b.dataset.id === suggested) b.dataset.suggested = "true";
      else delete b.dataset.suggested;
    }
    const cmd = suggested ? catalogue.commands.find((c) => c.id === suggested) : undefined;
    if (cmd && ready && !over() && !els.input.disabled && els.input.value === "") {
      els.input.value = cmd.input;
      noteHint(`picked for you: ${cmd.input} — press Enter to run it`);
    }
  };

  /** Lit-layer map from a run's finished commands, marking the one that ended the run. */
  const litFromRun = (run: RunView) => {
    const enderSeq = enderOf(run)?.cmd?.seq;
    const entries = run.commands
      .filter((c) => c.endedAt !== undefined)
      .map((c) => {
        const cmd = catalogue!.commands.find((x) => x.id === c.id);
        return cmd ? { layer: cmd.layer, outcome: cmd.outcome, control: cmd.control, input: cmd.input, ended: c.seq === enderSeq } : null;
      })
      .filter((x): x is NonNullable<typeof x> => x !== null);
    return litFromCommands(entries);
  };

  /**
   * A response of one kind on a terminal run and the command it answered. A run can be answered more
   * than once (a quarantine, the shell goes on, a terminate later), so each kind is looked up on its
   * own: the API's `responded` with that action (the first quarantine, which cut the pod off; the last
   * terminate, which ended the run), else the guarded Talon action of that kind. The command is the
   * one the API named (command_seq), else the last command started before the response.
   */
  const responseOf = (run: RunView, kind: "terminate" | "quarantine"): { at: number; cmd?: CommandRun } | undefined => {
    const pick = <T>(xs: T[]) => (kind === "terminate" ? [...xs].reverse() : xs);
    const r = pick(run.responses).find((x) => x.action === kind);
    const t = r ? undefined : pick(run.talon).find((x) => x.arm !== "unguarded" && (kind === "terminate" ? /terminate/i : /label|quarantine/i).test(`${x.actionner ?? ""} ${x.action}`));
    const at = r?.at ?? (t && ts(t.at));
    if (at === undefined) return undefined;
    const seq = r ? r.seq : t?.command_seq;
    const cmd = seq !== undefined ? run.commands.find((c) => c.seq === seq) : [...run.commands].reverse().find((c) => c.startedAt !== undefined && c.startedAt <= at);
    return { at, cmd };
  };

  /** The command whose terminate ended the run, or undefined (the run was not killed). */
  const enderOf = (run: RunView): { at: number; cmd?: CommandRun } | undefined =>
    !run.active && run.detail === "killed" ? responseOf(run, "terminate") : undefined;

  /** From the visitor's Enter (the command's start) to a response; never a zero or negative time. */
  const afterEnter = (r: { at: number; cmd?: CommandRun } | undefined): number | undefined => {
    const start = r?.cmd?.startedAt;
    return r && start !== undefined && r.at > start ? r.at - start : undefined;
  };

  const renderObjectives = (run?: RunView) => {
    if (!els || !catalogue) return;
    const reached = new Set<string>();
    if (run) for (const c of run.commands) if (c.achieved) { const cmd = catalogue.commands.find((x) => x.id === c.id); if (cmd?.objective) reached.add(cmd.objective); }
    replace(
      els.objectives,
      h("h4", { class: "term__objhead" }, `Objectives · ${reached.size}/${catalogue.objectives.length}`),
      h(
        "ul",
        { class: "term__objlist", role: "list" },
        catalogue.objectives.map((o) =>
          h("li", { class: "term__obj", "data-done": String(reached.has(o.id)) }, h("span", { class: "term__objmark", "aria-hidden": "true" }, reached.has(o.id) ? "✓" : "○"), o.title),
        ),
      ),
    );
  };

  const renderSummary = (run: RunView) => {
    if (!els || !catalogue) return;
    endedShown = true;
    syncControls();
    const lit = litFromRun(run);
    const reached = new Set<string>();
    for (const c of run.commands) {
      if (!c.achieved) continue;
      const cmd = catalogue.commands.find((x) => x.id === c.id);
      if (cmd?.objective) reached.add(cmd.objective);
    }
    // Survived: from the moment the pod could take a command (pod_ready) to the run's end.
    const start = run.states.pod_ready ?? run.states.started ?? run.states.queued;
    const endT = run.states.finished ?? run.states.failed ?? run.states.timeout;
    const survived = start !== undefined && endT !== undefined ? endT - start : undefined;
    // The outcome is read from the run (its detail, and each response with the command it answered),
    // not from a command's state: on a terminate the killing command usually `exited` 0 first.
    const detail = run.detail;
    const killedRun = detail === "killed";
    const ender = enderOf(run);
    const quarantine = responseOf(run, "quarantine");
    const input = (c?: CommandRun) => (c ? h("code", {}, breakable(catalogue?.commands.find((x) => x.id === c.id)?.input ?? c.id)) : null);
    // A watcher reads the same summary about someone else: "the visitor", not "you".
    const other = watching !== undefined;
    const you = other ? "the visitor" : "you";
    const You = other ? "The visitor" : "You";
    const failed = run.current === "failed" || run.current === "timeout";
    const outcome: (Node | string | null)[] = failed
      ? [`The session could not run: ${detail || (run.current === "timeout" ? "it timed out" : "the API reported a failure")}.`]
      : killedRun
        ? quarantine
          ? ["Quarantined after ", input(quarantine.cmd) ?? "a command", `, ${you} kept the shell; then the cluster deleted the pod under ${other ? "them" : "you"} after `, input(ender?.cmd) ?? "a later command", "."]
          : [`The cluster deleted the pod under ${other ? "them" : "you"} after `, input(ender?.cmd) ?? "a command", " — marked below."]
        : detail === "idle"
          ? [`${You} went quiet: the session ${endReason(run)}, and the pod was reclaimed.`]
          : detail === "deadline"
            ? [`The session ran to ${sessionLimit()}, and the pod was reclaimed.`]
            : detail === "left"
              ? [`${You} left; the pod was cleaned up.`]
              : quarantine
                ? [`${You} ${other ? "was" : "were"} quarantined, then the session ended.`]
                : ["The session ended."];
    const enter = other ? "their Enter" : "your Enter";
    // Reached means the command exited 0 (the API's rule) — which a credential read or a dropped
    // binary does before the kill lands. Each reached objective says how long the pod lasted after.
    const firstReach = new Map<string, CommandRun>();
    for (const c of run.commands) {
      const o = c.achieved ? catalogue.commands.find((x) => x.id === c.id)?.objective : undefined;
      if (o && !firstReach.has(o)) firstReach.set(o, c);
    }
    const reachedLines = catalogue.objectives
      .filter((o) => firstReach.has(o.id))
      .map((o) => {
        const c = firstReach.get(o.id) as CommandRun;
        const after = endT !== undefined && c.endedAt !== undefined && endT > c.endedAt ? formatDuration(endT - c.endedAt) : undefined;
        // Measured from the command's exit, and said so: "Killed after your Enter" counts from its start.
        return h("li", {}, h("strong", {}, o.title), " — ", input(c), " exited 0", after ? `; the ${killedRun ? "pod was deleted" : "session went on"} ${after} after that exit` : "", ".");
      });
    // "Killed N ms after your Enter": the terminate's response time minus the start of the command it
    // answered, with Falco-to-response beside it — that command's alert, else the last one before.
    const killMs = afterEnter(ender);
    const quarantineMs = afterEnter(quarantine);
    const alerts = run.falco.filter((f) => f.arm !== "unguarded");
    const alert = ender ? (alerts.find((f) => f.command_seq !== undefined && f.command_seq === ender.cmd?.seq) ?? [...alerts].reverse().find((f) => ts(f.at) <= ender.at)) : undefined;
    const falcoToResp = ender && alert && ender.at > ts(alert.at) ? ender.at - ts(alert.at) : undefined;

    replace(
      els.summary,
      h("h3", { class: "term__sumtitle" }, "Session over"),
      h("p", { class: "term__sumlead" }, ...outcome),
      h(
        "dl",
        { class: "term__sumstats" },
        stat("Objectives reached", `${reached.size} of ${catalogue.objectives.length}`),
        stat("Commands run", String(run.commands.length)),
        survived !== undefined ? stat("Survived", formatDuration(survived)) : null,
        quarantineMs !== undefined ? stat(`Quarantined after ${enter}`, formatDuration(quarantineMs)) : null,
        killMs !== undefined ? stat(`Killed after ${enter}`, formatDuration(killMs)) : null,
        falcoToResp !== undefined ? stat("Falco to response", formatDuration(falcoToResp)) : null,
      ),
      reachedLines.length ? h("ul", { class: "term__sumreached", "aria-label": "Objectives reached" }, reachedLines) : null,
      lit.size ? h("h4", { class: "term__sumhead" }, "Which layer answered which move") : null,
      lit.size ? renderDefenceMap({ lit, only: "lit" }) : null,
      h("p", { class: "small" }, "All seven layers, with the ones this session touched lit, are in ", h("a", { href: "#how" }, "How it works ↓"), "."),
      h(
        "div",
        { class: "term__again" },
        (() => {
          const b = h("button", { type: "button", class: "btn btn--ghost" }, other ? "Start your own session" : "Run another session");
          b.addEventListener("click", () => again());
          return b;
        })(),
        h("p", { class: "small" }, "Think you got further than this page says is possible? ", h("a", { href: "https://github.com/HubertMJ/self-defending-portfolio/issues", rel: "noopener noreferrer", target: "_blank" }, "Open an issue"), "."),
      ),
    );
    els.summary.hidden = false;
    // Only scroll the visitor's own session into view; a watcher's page must not jump (item 12).
    if (!watching) els.summary.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "nearest" });
  };

  const scrollOut = () => {
    if (!els) return;
    els.out.scrollTop = els.out.scrollHeight;
  };

  // ---- public update ----
  const update = (v: TimelineView) => {
    view = v;
    const active = v.activeRun;
    // Am I watching an active terminal run I did not start? (Not while my own start is in flight —
    // the run's first events can arrive before attackTerminal() has returned my token.)
    if (!session && !starting && active && active.scenario === "terminal") {
      if (watching !== active.runId) {
        watching = active.runId;
        renderSessionReadOnly(); // rebuilds and resets per-run state, so a second watched run is not blank (item 9)
      }
    } else if (watching && (!active || active.scenario !== "terminal" || !active.active)) {
      // The watched run ended; patch its final state then let it rest.
      patchFromView();
      watching = undefined;
    }
    if (session || watching) {
      patchFromView();
    } else if (mode === "idle") {
      // Refresh the start button's blocked state as other runs come and go — in place.
      syncIdle();
    }
  };

  const renderSessionReadOnly = () => {
    resetSessionState();
    renderSession();
    if (els) {
      els.input.disabled = true;
      els.send.disabled = true;
      els.form.hidden = true;
      els.chips.hidden = true;
      els.palette.hidden = true;
    }
  };

  // The visitor closing the tab ends their run, freeing the single slot at once rather than after the
  // idle timeout (review item 10). keepalive lets the DELETE outlive the page.
  const onPageHide = (e: Event) => {
    // Only a page that is really unloading: one going into the back/forward cache (persisted) may
    // come back to its session, so it keeps the run, and the idle timer frees the slot if it does not.
    if ((e as PageTransitionEvent).persisted !== false) return;
    // Once only, and only while the run is live: not after it ended (the API would answer 409).
    if (session && !watching && !over()) void leave();
  };
  if (typeof addEventListener === "function") addEventListener("pagehide", onPageHide);

  void loadCatalogue();
  const truncatedNoted = new Set<string>();
  const historyTruncated = (runId: string) => {
    if (!els || truncatedNoted.has(runId) || (session?.runId ?? watching) !== runId) return;
    truncatedNoted.add(runId);
    els.out.appendChild(h("p", { class: "term__line term__line--sys" }, "— the API kept only part of this run's history (its per-run limit), so some of what came before may be missing here —"));
  };

  /** Back to the start panel; the button there takes the focus, so a keyboard is not lost. */
  const again = () => {
    if (!catalogue) return;
    if (session && !watching && !over()) return; // a live session is not thrown away by a stray press
    session = null;
    endedShown = false;
    if (watching) return;
    renderIdle();
    root.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "nearest" });
    idle?.btn.focus({ preventScroll: true });
  };

  return {
    update,
    historyTruncated,
    setSiem(row) {
      siem = row;
      renderSiem();
    },
    suggest(commandId) {
      suggested = commandId;
      root.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "start" });
      if (mode === "idle") void start();
      else applySuggestion(myRun());
    },
    again,
    showTimeline() {
      const wrap = els?.timeline.parentElement;
      if (!wrap) return;
      const side = wrap.closest<HTMLElement>(".thisrun");
      if (side && side.dataset.open !== "true") side.querySelector<HTMLButtonElement>(".thisrun__more")?.click();
      wrap.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "nearest" });
      wrap.focus({ preventScroll: true });
      pulse(wrap);
    },
  };
}

/** "4:32": minutes and seconds left, never below zero. */
function clockText(ms: number): string {
  const s = Math.max(0, Math.ceil(ms / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

function stat(label: string, value: string): HTMLElement {
  return h("div", {}, h("dt", {}, label), h("dd", {}, value));
}

function commonPrefix(xs: string[]): string {
  if (xs.length === 0) return "";
  let p = xs[0];
  for (const s of xs) {
    while (!s.toLowerCase().startsWith(p.toLowerCase())) p = p.slice(0, -1);
  }
  return p;
}
