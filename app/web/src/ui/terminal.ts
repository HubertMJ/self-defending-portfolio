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
import type { CatalogueCommand, Objective, Posture, ScenarioDetails } from "../lib/contract";
import { h, prefersReducedMotion, replace } from "../lib/dom";
import type { CommandRun, RunView, TimelineView } from "../lib/timeline";
import { formatDuration, ts } from "../lib/timeline";
import { litFromCommands, renderDefenceMap } from "./defencemap";
import { renderVictim } from "./victim";

export interface TerminalHandle {
  update(view: TimelineView): void;
}

interface Catalogue {
  details: ScenarioDetails;
  commands: CatalogueCommand[];
  objectives: Objective[];
  idleSeconds: number;
  timeoutSeconds: number;
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
  hooks: { onStarted?: (runId: string) => void; blocked?: () => string | null; cooldownSeconds?: () => number; onRateLimited?: (seconds: number) => void } = {},
): TerminalHandle {
  const reduced = prefersReducedMotion();
  let catalogue: Catalogue | null = null;
  let posture: Posture | undefined;
  let session: { runId: string; token: string } | null = null;
  let starting = false;
  let watching: string | undefined; // another visitor's terminal run id, read-only
  let view: TimelineView = { runs: [], unmatched: [] };
  let endedShown = false;
  let ready = false; // the run reached pod_ready — commands are accepted only then
  let pendingSeq: number | undefined; // a command sent and not yet ended on the client
  let mode: "idle" | "session" | "unavailable" = "unavailable";

  /** The run id shape the API uses; a value from the 202 that does not match is never put in a URL. */
  const VALID_RUN_ID = /^[A-Za-z0-9_-]{1,64}$/;

  // Built once per session; patched after.
  let els: {
    out: HTMLElement;
    form: HTMLFormElement;
    input: HTMLInputElement;
    hint: HTMLElement;
    chips: HTMLElement;
    shop: HTMLElement;
    objectives: HTMLElement;
    map: HTMLElement;
    summary: HTMLElement;
    status: HTMLElement;
    send: HTMLButtonElement;
  } | null = null;

  // Posture (for the result map's evidence) is fetched once, lazily, the first time it is needed —
  // not eagerly on load, where the posture panel and the defence map already fetch it (item 14).
  let postureAsked = false;
  const ensurePosture = () => {
    if (postureAsked) return;
    postureAsked = true;
    void api.posture().then((r) => {
      if (r.ok) {
        posture = r.value;
        if (mode === "session") renderMap(myRun());
      }
    });
  };

  // ---- load the catalogue ----
  const loadCatalogue = async () => {
    const r = await api.scenarioDetails("terminal");
    if (r.ok && (r.value.commands?.length ?? 0) > 0) {
      catalogue = {
        details: r.value,
        commands: r.value.commands ?? [],
        objectives: r.value.objectives ?? [],
        idleSeconds: r.value.idle_seconds ?? 30,
        timeoutSeconds: r.value.timeout_seconds ?? 120,
      };
      renderIdle();
    } else {
      renderUnavailable();
    }
  };

  // No terminal on this API build: keep it quiet and point at the one-click demo below, which is the
  // main thing when the terminal is not there (review item 20) — not a loud "offline / Retry" block.
  const renderUnavailable = () => {
    mode = "unavailable";
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
  let idle: { label: HTMLElement; btn: HTMLButtonElement; note: HTMLElement; shown: string | null; clock?: ReturnType<typeof setInterval> } | null = null;

  /** Why the start button is blocked right now ("Starting…", another run, a cooldown), or null. */
  const blockedNow = (): string | null => (starting ? "Starting…" : (hooks.blocked?.() ?? null));

  const renderIdle = () => {
    if (!catalogue) return;
    mode = "idle";
    const label = h("span", { class: "btn__label" }, "Open the terminal");
    const btn = h("button", { type: "button", class: "btn btn--attack term-start__btn" }, h("span", { class: "btn__icon", "aria-hidden": "true" }, "▶"), label);
    btn.addEventListener("click", () => void start());
    const note = h("p", { class: "small term-start__blocked", role: "status" });
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
      ),
    );
    if (idle?.clock !== undefined) clearInterval(idle.clock);
    idle = { label, btn, note, shown: null };
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
      if (!VALID_RUN_ID.test(r.run.run_id)) {
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
      syncIdle();
      // The note is set after the sync, so the cooldown it explains does not clear it.
      if (idle) idle.shown = blockedNow();
      setNote(
        r.kind === "busy" ? "Another run is in progress — only one runs at a time. Try again when it finishes." : r.kind === "rate-limited" ? `Rate limit reached: try again in ${Math.ceil(r.retryAfterSeconds)} s.` : r.kind === "error" ? `The server refused the request (HTTP ${r.status}).` : "The attack API is not reachable right now.",
      );
    }
  };

  const resetSessionState = () => {
    endedShown = false;
    ready = false;
    pendingSeq = undefined;
    rendered.clear();
  };

  // ---- running session skeleton ----
  const renderSession = () => {
    mode = "session";
    const out = h("div", { class: "term__out", role: "log", "aria-live": "polite", "aria-label": "Terminal output", tabindex: "0" });
    const input = h("input", { type: "text", class: "term__input", id: "term-input", autocomplete: "off", autocapitalize: "off", autocorrect: "off", spellcheck: "false", "aria-label": "Command to run in the pod", "aria-describedby": "term-hint", placeholder: "starting the pod…", disabled: true }) as HTMLInputElement;
    input.disabled = true;
    const hint = h("p", { class: "term__hint", id: "term-hint" });
    const prompt = h("span", { class: "term__prompt", "aria-hidden": "true" }, "sandbox$");
    const send = h("button", { type: "submit", class: "btn btn--small term__send" }, "Run") as HTMLButtonElement;
    const form = h("form", { class: "term__form" }, prompt, input, send) as HTMLFormElement;
    const chips = h("div", { class: "term__chips" });
    const shop = h("div", { class: "term__shop" });
    const objectives = h("div", { class: "term__objectives" });
    const map = h("div", { class: "term__map" });
    const summary = h("div", { class: "term__summary", hidden: true });
    const status = h("p", { class: "term__status", role: "status", "aria-live": "polite" });
    const exit = h("button", { type: "button", class: "btn btn--ghost btn--small term__exit" }, "Leave");
    exit.addEventListener("click", () => void leave());

    form.addEventListener("submit", (e) => {
      e.preventDefault();
      void submit(input.value);
    });
    input.addEventListener("keydown", (e) => {
      if (e.key !== "Tab" || e.shiftKey) return;
      const typed = input.value.trim();
      const opts = catalogue ? completions(catalogue, input.value) : [];
      // Let Tab move focus normally when there is nothing to complete, or the text already is a
      // complete command — so a finished word never traps focus on the input (review item 23).
      if (opts.length === 0 || (opts.length === 1 && opts[0].toLowerCase() === typed.toLowerCase())) return;
      e.preventDefault();
      const prefix = commonPrefix(opts);
      if (prefix.length > typed.length) input.value = prefix;
      else if (opts.length === 1) input.value = opts[0];
      showHint(opts, true);
    });
    input.addEventListener("input", () => showHint(catalogue ? completions(catalogue, input.value) : []));

    els = { out, form, input, hint, chips, shop, objectives, map, summary, status, send };
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
            h("div", { class: "term__bar" }, h("span", { class: "term__dots", "aria-hidden": "true" }, h("i"), h("i"), h("i")), h("span", { class: "term__bartitle" }, "sh — scenario pod"), status, watching ? null : exit),
            out,
            form,
            hint,
            chips,
          ),
          h("aside", { class: "term__side" }, h("h4", { class: "term__sideheading" }, "The shop, from the pod's own :8080"), shop, objectives, h("h4", { class: "term__sideheading" }, "Which layer answers each move"), map),
        ),
        summary,
      ),
    );
    buildChips();
    renderObjectives();
    renderMap();
    // The output starts with a short banner so the log is never empty for a screen reader.
    replace(out, bannerLine());
    patchFromView();
  };

  const bannerLine = () =>
    h("p", { class: "term__line term__line--sys" }, "Pod starting. You will be uid 10001, non-root, no network, read-only root filesystem. When it is ready, try ", h("code", {}, "id"), " or tap a command below.");

  // The completion hint. aria-live only while the visitor is actively completing (Tab), so routine
  // typing does not chatter to a screen reader (review item 23).
  const showHint = (opts: string[], announce = false) => {
    if (!els) return;
    els.hint.setAttribute("aria-live", announce ? "polite" : "off");
    els.hint.textContent = opts.length && opts.length <= 6 ? `completes to: ${opts.join("  ·  ")}` : "";
  };

  const leave = async () => {
    if (!session || watching) return;
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
                const b = h("button", { type: "button", class: `term__chip term__chip--${c.outcome}`, title: c.explain }, c.input);
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
    const run = myRun();
    if (run && !run.active) {
      noteHint("the session is over — start another below");
      return;
    }
    if (!ready) {
      noteHint("the pod is still starting — one moment");
      return;
    }
    // One command at a time: a line typed while one runs is held back with a note, not queued and not
    // dropped under the still-streaming block (review item 11).
    if (pendingSeq !== undefined) {
      noteHint("wait for the current command to finish");
      return;
    }
    if (els) els.input.value = "";
    showHint([]);
    const cmd = resolve(catalogue, line);
    if (!cmd) {
      // An unknown line is answered here and never sent anywhere.
      appendLocal(line, "sh: " + line.split(/\s+/)[0] + ": not in this sandbox's catalogue. Tab shows what is.");
      return;
    }
    setInFlight(true);
    const r = await api.runCommand(session.runId, session.token, cmd.id);
    if (r.kind === "accepted") {
      pendingSeq = r.seq; // cleared when this command's exited/killed event arrives
      return; // output arrives over the event stream
    }
    setInFlight(false);
    const why =
      r.kind === "conflict" ? "the pod is not ready, the session is over, or a command is still running" : r.kind === "rate-limited" ? "you have run the most commands a session allows" : r.kind === "unauthorized" ? "this session is not yours" : r.kind === "not-found" ? "the run has ended" : r.kind === "too-large" ? "that was too long" : r.kind === "error" ? `the server refused it (HTTP ${r.status})` : "the API is not reachable";
    appendLocal(line, `sh: not run (${why})`);
  };

  /** Toggle the "a command is in flight" lock on the Run button. */
  const setInFlight = (on: boolean) => {
    if (els) els.send.disabled = on || els.input.disabled;
  };

  /** A transient note in the hint line, cleared on the next keystroke. */
  const noteHint = (msg: string) => {
    if (!els) return;
    els.hint.setAttribute("aria-live", "polite");
    els.hint.textContent = msg;
  };

  /** A line the page answered itself (unknown command, or a rejected send): shown, never sent. */
  const appendLocal = (input: string, answer: string) => {
    if (!els) return;
    els.out.appendChild(h("div", { class: "term__cmd" }, promptEcho(input), h("p", { class: "term__line term__line--err" }, answer)));
    scrollOut();
    if (els.input) els.input.focus();
  };

  const promptEcho = (input: string) => h("p", { class: "term__line term__line--in" }, h("span", { class: "term__prompt", "aria-hidden": "true" }, "sandbox$ "), input);

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
    if (!run) return;
    // Enable input the moment the pod is ready; keep it disabled (and chips inert) before that.
    const nowReady = run.states.pod_ready !== undefined;
    if (nowReady && !ready && !watching) enableInput();
    ready = ready || nowReady;
    for (const c of run.commands) appendCommand(c);
    if (pendingSeq !== undefined) {
      const p = run.commands.find((c) => c.seq === pendingSeq);
      if (p && p.endedAt !== undefined) {
        pendingSeq = undefined;
        setInFlight(false);
      }
    }
    patchShop(run);
    renderObjectives(run);
    renderMap(run);
    renderStatus(run);
    if (!run.active && !endedShown) renderSummary(run);
  };

  const enableInput = () => {
    if (!els) return;
    els.input.disabled = false;
    els.input.placeholder = "type a command, then Enter (Tab to complete)";
    els.send.disabled = false;
    els.chips.removeAttribute("aria-disabled");
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
      if (cmd && c.achieved) foot.push(h("p", { class: "term__line term__line--win" }, `✓ objective reached: ${catalogue?.objectives.find((o) => o.id === cmd.objective)?.title ?? cmd.objective}`));
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
   * command's 5 s limit, the visitor leaving, or the run's end (idle, the deadline) under a command
   * that was still running.
   */
  const noCodeReason = (c: CommandRun): string => {
    const run = myRun();
    const end = run && (run.states.finished ?? run.states.failed ?? run.states.timeout);
    const endedWithRun = run !== undefined && !run.active && end !== undefined && c.endedAt !== undefined && end - c.endedAt < 3000;
    if (endedWithRun && run.detail === "left") return "— stopped: the session was left while it ran —";
    if (endedWithRun) return "— stopped: it ended with the session —";
    const ranFor = c.startedAt !== undefined && c.endedAt !== undefined ? c.endedAt - c.startedAt : 0;
    if (ranFor >= 4500) return "— timed out: a command gets 5 seconds —";
    return "— stopped before it reported an exit code —";
  };

  const patchShop = (run: RunView) => {
    if (!els) return;
    replace(els.shop, renderVictim(run, watching !== undefined));
  };

  const renderStatus = (run: RunView) => {
    if (!els) return;
    const text = watching
      ? "watching another visitor — read-only"
      : !run.active
        ? "session over"
        : run.quarantinedAt !== undefined
          ? "quarantined — still yours, but cut off"
          : !ready
            ? "starting the pod…"
            : `live · ${run.commands.length} command${run.commands.length === 1 ? "" : "s"}`;
    // Only write when it changes, so role=status does not re-announce on every event (item 22).
    if (els.status.textContent !== text) els.status.textContent = text;
  };

  /** The live defence map in the side panel: lights each layer as commands finish (review item 17). */
  const renderMap = (run?: RunView) => {
    if (!els || !catalogue) return;
    ensurePosture();
    const lit = run ? litFromRun(run) : new Map();
    replace(els.map, renderDefenceMap({ posture, lit }));
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
    els.input.disabled = true;
    els.send.disabled = true;
    const lit = litFromRun(run);
    const reached = new Set<string>();
    for (const c of run.commands) {
      if (!c.achieved) continue;
      const cmd = catalogue.commands.find((x) => x.id === c.id);
      if (cmd?.objective) reached.add(cmd.objective);
    }
    const start = run.states.started ?? run.states.queued;
    const endT = run.states.finished ?? run.states.failed ?? run.states.timeout;
    const survived = start !== undefined && endT !== undefined ? endT - start : undefined;
    // The outcome is read from the run (its detail, and each response with the command it answered),
    // not from a command's state: on a terminate the killing command usually `exited` 0 first.
    const detail = run.detail;
    const killedRun = detail === "killed";
    const ender = enderOf(run);
    const quarantine = responseOf(run, "quarantine");
    const input = (c?: CommandRun) => (c ? h("code", {}, catalogue?.commands.find((x) => x.id === c.id)?.input ?? c.id) : null);
    const outcome: (Node | string | null)[] = killedRun
      ? quarantine
        ? ["Quarantined after ", input(quarantine.cmd) ?? "a command", ", you kept the shell; then the cluster deleted the pod under you after ", input(ender?.cmd) ?? "a later command", "."]
        : ["The cluster deleted the pod under you after ", input(ender?.cmd) ?? "a command", " — marked below."]
      : detail === "idle"
        ? ["You went quiet; the pod was reclaimed after the idle timeout."]
        : detail === "deadline"
          ? [`The pod reached its ${catalogue.timeoutSeconds}-second deadline.`]
          : detail === "left"
            ? ["You left; the pod was cleaned up."]
            : quarantine
              ? ["You were quarantined, then the session ended."]
              : ["The session ended."];
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
        quarantineMs !== undefined ? stat("Quarantined after your Enter", formatDuration(quarantineMs)) : null,
        killMs !== undefined ? stat("Killed after your Enter", formatDuration(killMs)) : null,
        falcoToResp !== undefined ? stat("Falco to response", formatDuration(falcoToResp)) : null,
      ),
      h("h4", { class: "term__sumhead" }, "Which layer answered which move"),
      renderDefenceMap({ posture, lit }),
      h(
        "div",
        { class: "term__again" },
        (() => {
          const b = h("button", { type: "button", class: "btn btn--ghost" }, "Run another session");
          b.addEventListener("click", () => {
            session = null;
            endedShown = false;
            renderIdle();
          });
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
    }
  };

  // The visitor closing the tab ends their run, freeing the single slot at once rather than after the
  // idle timeout (review item 10). keepalive lets the DELETE outlive the page.
  const onPageHide = () => {
    if (session && !watching) void api.leaveRun(session.runId, session.token);
  };
  if (typeof addEventListener === "function") addEventListener("pagehide", onPageHide);

  void loadCatalogue();
  return { update };
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
