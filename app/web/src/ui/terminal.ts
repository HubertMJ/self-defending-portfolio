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
import { formatDuration, guardedFalco, guardedTalon, ts } from "../lib/timeline";
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
  hooks: { onStarted?: (runId: string) => void; blocked?: () => string | null } = {},
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
  const renderIdle = () => {
    if (!catalogue) return;
    mode = "idle";
    const blocked = hooks.blocked?.() ?? null;
    const btn = h("button", { type: "button", class: "btn btn--attack term-start__btn", "aria-disabled": String(starting || blocked !== null) }, h("span", { class: "btn__icon", "aria-hidden": "true" }, "▶"), h("span", { class: "btn__label" }, starting ? "Starting…" : blocked ?? "Open the terminal"));
    btn.addEventListener("click", () => void start());
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
        blocked ? h("p", { class: "small term-start__blocked" }, blocked === "Open the terminal" ? "" : blocked) : null,
      ),
    );
  };

  const start = async () => {
    if (!catalogue || starting || (hooks.blocked?.() ?? null) !== null) return;
    starting = true;
    renderIdle();
    const r = await api.attackTerminal();
    starting = false;
    if (r.kind === "accepted") {
      if (!VALID_RUN_ID.test(r.run.run_id)) {
        // The server accepted a run but named it something we will not put in a URL; say so plainly
        // rather than sending a request that could escape the run path.
        renderIdle();
        appendStartNote("The server accepted a run but returned an unusable id. Reload and try again.");
        return;
      }
      session = { runId: r.run.run_id, token: r.run.token };
      watching = undefined; // this run is mine, not one I am watching
      resetSessionState();
      hooks.onStarted?.(r.run.run_id);
      renderSession();
    } else if (r.kind === "unavailable") {
      renderUnavailable();
    } else {
      renderIdle();
      const msg =
        r.kind === "busy" ? "Another run is in progress — only one runs at a time. Try again when it finishes." : r.kind === "rate-limited" ? `Rate limit reached: try again in ${Math.ceil(r.retryAfterSeconds)} s.` : r.kind === "error" ? `The server refused the request (HTTP ${r.status}).` : "The attack API is not reachable right now.";
      appendStartNote(msg);
    }
  };

  const appendStartNote = (msg: string) => {
    const note = root.querySelector(".term-start");
    if (note) note.appendChild(h("p", { class: "small term-start__blocked" }, msg));
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
      const opts = catalogue ? completions(catalogue, input.value) : [];
      if (opts.length === 0) return;
      e.preventDefault();
      // Complete to the longest shared prefix; only jump to a full match on a second Tab, so a
      // completed word does not trap focus on the input (review item 23).
      const prefix = commonPrefix(opts);
      if (prefix.length > input.value.trim().length) input.value = prefix;
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

  /** Per-command DOM, so output is appended (never re-rendered) as it streams (review item 22). */
  const rendered = new Map<number, { out: HTMLElement; foot: HTMLElement; stdout: number; stderr: number; done: boolean }>();

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

  /** Appends a command's prompt, then only the output text that has arrived since the last patch. */
  const appendCommand = (c: CommandRun) => {
    if (!els) return;
    const cmd = catalogue?.commands.find((x) => x.id === c.id);
    let rec = rendered.get(c.seq);
    if (!rec) {
      const out = h("div", { class: "term__cmdout" });
      const foot = h("div", { class: "term__cmdfoot" });
      els.out.appendChild(h("div", { class: "term__cmd", "data-seq": String(c.seq), "data-outcome": cmd?.outcome ?? "" }, promptEcho(cmd?.input ?? c.id), out, foot));
      rec = { out, foot, stdout: 0, stderr: 0, done: false };
      rendered.set(c.seq, rec);
    }
    if (c.stdout.length > rec.stdout) {
      rec.out.appendChild(h("p", { class: "term__line" }, c.stdout.slice(rec.stdout).replace(/\n$/, "")));
      rec.stdout = c.stdout.length;
    }
    if (c.stderr.length > rec.stderr) {
      rec.out.appendChild(h("p", { class: "term__line term__line--err" }, c.stderr.slice(rec.stderr).replace(/\n$/, "")));
      rec.stderr = c.stderr.length;
    }
    const ended = c.exitCode !== undefined || c.killed;
    if (ended && !rec.done) {
      rec.done = true;
      const foot: (Node | string)[] = [];
      if (c.truncated) foot.push(h("p", { class: "term__line term__line--sys" }, "… output truncated"));
      if (c.killed) foot.push(h("p", { class: "term__line term__line--kill" }, "— the pod was deleted under this command; your session is over —"));
      else if (c.exitCode !== undefined && c.exitCode !== 0 && !c.stderr) foot.push(h("p", { class: "term__line term__line--sys" }, `exit ${c.exitCode}`));
      if (cmd && c.achieved) foot.push(h("p", { class: "term__line term__line--win" }, `✓ objective reached: ${catalogue?.objectives.find((o) => o.id === cmd.objective)?.title ?? cmd.objective}`));
      if (cmd) foot.push(h("p", { class: "term__explain" }, cmd.explain));
      replace(rec.foot, ...foot);
    }
    scrollOut();
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
    const enderSeq = enderSeqOf(run);
    const entries = run.commands
      .filter((c) => c.exitCode !== undefined || c.killed)
      .map((c) => {
        const cmd = catalogue!.commands.find((x) => x.id === c.id);
        return cmd ? { layer: cmd.layer, outcome: cmd.outcome, control: cmd.control, input: cmd.input, ended: c.seq === enderSeq } : null;
      })
      .filter((x): x is NonNullable<typeof x> => x !== null);
    return litFromCommands(entries);
  };

  /** The seq of the command that ended the run (a terminate), or undefined. */
  const enderSeqOf = (run: RunView): number | undefined => {
    if (run.active || run.detail !== "killed") return undefined;
    // The Talon terminate carries the command_seq it acted on; fall back to the last detected-terminate.
    const t = guardedTalon(run);
    if (t?.command_seq) return t.command_seq;
    for (let i = run.commands.length - 1; i >= 0; i--) {
      const cmd = catalogue?.commands.find((x) => x.id === run.commands[i].id);
      if (cmd?.outcome === "detected" && cmd.response === "terminate") return run.commands[i].seq;
    }
    return undefined;
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
    // The outcome is read from the run (its detail and whether it was quarantined), not from a
    // command's state: on a terminate the killing command usually `exited` 0 first (review item 1).
    const detail = run.detail;
    const killedRun = detail === "killed";
    const outcome = killedRun
      ? "The cluster deleted the pod under you — the command that did it is marked below."
      : detail === "idle"
        ? "You went quiet; the pod was reclaimed after the idle timeout."
        : detail === "deadline"
          ? `The pod reached its ${catalogue.timeoutSeconds}-second deadline.`
          : detail === "left"
            ? "You left; the pod was cleaned up."
            : run.quarantinedAt !== undefined
              ? "You were quarantined, then the session ended."
              : "The session ended.";
    // "Killed N ms after your Enter": the response time (the guarded Talon action's time, else the
    // run's `responded`) minus the start of the command it acted on; Falco-to-response beside it.
    const enderSeq = enderSeqOf(run);
    const ender = enderSeq !== undefined ? run.commands.find((c) => c.seq === enderSeq) : undefined;
    const gt = guardedTalon(run);
    const gf = guardedFalco(run);
    const respAt = (gt && ts(gt.at)) ?? run.states.responded;
    const killMs = killedRun && ender?.startedAt !== undefined && respAt !== undefined ? Math.max(0, respAt - ender.startedAt) : undefined;
    const falcoToResp = gf && respAt !== undefined ? Math.max(0, respAt - ts(gf.at)) : run.timings.respondMs;

    replace(
      els.summary,
      h("h3", { class: "term__sumtitle" }, "Session over"),
      h("p", { class: "term__sumlead" }, outcome),
      h(
        "dl",
        { class: "term__sumstats" },
        stat("Objectives reached", `${reached.size} of ${catalogue.objectives.length}`),
        stat("Commands run", String(run.commands.length)),
        survived !== undefined ? stat("Survived", formatDuration(survived)) : null,
        killMs !== undefined ? stat("Killed after your Enter", formatDuration(killMs)) : null,
        killedRun && falcoToResp !== undefined ? stat("Falco to response", formatDuration(falcoToResp)) : null,
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
      // Refresh the start button's blocked state as other runs come and go (item 11).
      renderIdle();
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
