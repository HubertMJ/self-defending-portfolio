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
import { formatDuration } from "../lib/timeline";
import { litFromCommands, renderDefenceMap } from "./defencemap";
import { offlinePanel } from "./common";
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
  let renderedSeq = 0;
  let endedShown = false;

  // Built once per session; patched after.
  let els: {
    out: HTMLElement;
    form: HTMLFormElement;
    input: HTMLInputElement;
    hint: HTMLElement;
    chips: HTMLElement;
    shop: HTMLElement;
    objectives: HTMLElement;
    summary: HTMLElement;
    status: HTMLElement;
  } | null = null;

  void api.posture().then((r) => {
    if (r.ok) posture = r.value;
  });

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
      renderUnavailable(r.ok ? "This API build does not publish the terminal catalogue yet." : r.message);
    }
  };

  const renderUnavailable = (detail: string) => {
    replace(
      root,
      offlinePanel({
        title: "The terminal is not available",
        body: "The terminal needs the interactive scenario, which this cluster's API does not expose yet. The four one-click attacks below still work.",
        detail,
        onRetry: () => void loadCatalogue(),
      }),
    );
  };

  // ---- idle (not started) ----
  const renderIdle = () => {
    if (!catalogue) return;
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
      session = { runId: r.run.run_id, token: r.run.token };
      watching = undefined; // this run is mine, not one I am watching
      endedShown = false;
      renderedSeq = 0;
      hooks.onStarted?.(r.run.run_id);
      renderSession();
    } else {
      renderIdle();
      const msg =
        r.kind === "busy" ? "Another run is in progress — only one runs at a time. Try again when it finishes." : r.kind === "rate-limited" ? `Rate limit reached: try again in ${Math.ceil(r.retryAfterSeconds)} s.` : r.kind === "unavailable" ? "This API build has no terminal scenario." : "The attack API is not reachable right now.";
      const note = root.querySelector(".term-start");
      if (note) note.appendChild(h("p", { class: "small term-start__blocked" }, msg));
    }
  };

  // ---- running session skeleton ----
  const renderSession = () => {
    const out = h("div", { class: "term__out", role: "log", "aria-live": "polite", "aria-label": "Terminal output", tabindex: "0" });
    const input = h("input", { type: "text", class: "term__input", id: "term-input", autocomplete: "off", autocapitalize: "off", autocorrect: "off", spellcheck: "false", "aria-describedby": "term-hint", placeholder: "type a command, then Enter (Tab to complete)" }) as HTMLInputElement;
    const hint = h("p", { class: "term__hint", id: "term-hint" });
    const prompt = h("span", { class: "term__prompt", "aria-hidden": "true" }, "sandbox$");
    const form = h("form", { class: "term__form" }, prompt, input, h("button", { type: "submit", class: "btn btn--small term__send" }, "Run")) as HTMLFormElement;
    const chips = h("div", { class: "term__chips" });
    const shop = h("div", { class: "term__shop" });
    const objectives = h("div", { class: "term__objectives" });
    const summary = h("div", { class: "term__summary", hidden: true });
    const status = h("p", { class: "term__status", role: "status", "aria-live": "polite" });

    form.addEventListener("submit", (e) => {
      e.preventDefault();
      void submit(input.value);
    });
    input.addEventListener("keydown", (e) => {
      if (e.key !== "Tab" || e.shiftKey) return;
      const opts = catalogue ? completions(catalogue, input.value) : [];
      if (opts.length === 0) return;
      e.preventDefault();
      input.value = commonPrefix(opts).length > input.value.trim().length ? commonPrefix(opts) : opts[0];
      showHint(opts);
    });
    input.addEventListener("input", () => showHint(catalogue ? completions(catalogue, input.value) : []));

    els = { out, form, input, hint, chips, shop, objectives, summary, status };
    replace(
      root,
      h(
        "div",
        { class: "term", "data-reduced": String(reduced) },
        h(
          "div",
          { class: "term__grid" },
          h(
            "section",
            { class: "term__pane", "aria-label": "Attacker's terminal" },
            h("div", { class: "term__bar" }, h("span", { class: "term__dots", "aria-hidden": "true" }, h("i"), h("i"), h("i")), h("span", { class: "term__bartitle" }, "sh — scenario pod"), status),
            out,
            form,
            hint,
            chips,
          ),
          h("aside", { class: "term__side" }, h("h4", { class: "term__sideheading" }, "The shop, from the pod's own :8080"), shop, objectives),
        ),
        summary,
      ),
    );
    buildChips();
    renderObjectives();
    // The output starts with a short banner so the log is never empty for a screen reader.
    replace(out, bannerLine());
    if (!watching) setTimeout(() => input.focus(), 0);
    patchFromView();
  };

  const bannerLine = () =>
    h("p", { class: "term__line term__line--sys" }, "Connected to a fresh pod. You are uid 10001, non-root, no network, read-only root filesystem. Try ", h("code", {}, "id"), " or tap a command below.");

  const showHint = (opts: string[]) => {
    if (!els) return;
    els.hint.textContent = opts.length && opts.length <= 6 ? `↹ ${opts.join("  ·  ")}` : "";
  };

  const buildChips = () => {
    if (!els || !catalogue) return;
    const groups = new Map<string, CatalogueCommand[]>();
    for (const c of catalogue.commands) {
      const key = c.objective ?? "other";
      (groups.get(key) ?? groups.set(key, []).get(key)!).push(c);
    }
    const title = (id: string) => catalogue!.objectives.find((o) => o.id === id)?.title ?? "Other moves";
    const order = [...catalogue.objectives.map((o) => o.id), "other"];
    replace(
      els.chips,
      [...groups.entries()]
        .sort((a, b) => order.indexOf(a[0]) - order.indexOf(b[0]))
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
    if (els) els.input.value = "";
    showHint([]);
    const cmd = resolve(catalogue, line);
    if (!cmd) {
      // An unknown line is answered here and never sent anywhere.
      appendLocal(line, "sh: " + line.split(/\s+/)[0] + ": not in this sandbox's catalogue. Tab shows what is.");
      return;
    }
    const r = await api.runCommand(session.runId, session.token, cmd.id);
    if (r.kind === "accepted") return; // output arrives over the event stream
    const why =
      r.kind === "conflict" ? "a command is still running, or the session is over" : r.kind === "rate-limited" ? "you have run too many commands" : r.kind === "unauthorized" ? "this session is not yours" : r.kind === "not-found" ? "the run has ended" : r.kind === "too-large" ? "that was too long" : "the API is not reachable";
    appendLocal(line, `sh: not run (${why})`);
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

  const patchFromView = () => {
    if (!els) return;
    const run = myRun();
    if (!run) return;
    // Append any command blocks not yet rendered (streaming output in order).
    for (let i = renderedSeq; i < run.commands.length; i++) els.out.appendChild(commandBlock(run.commands[i]));
    // The last (still-streaming) block is re-rendered in place so output grows.
    if (run.commands.length) {
      const last = run.commands[run.commands.length - 1];
      const node = els.out.querySelector(`[data-seq="${last.seq}"]`);
      if (node) node.replaceWith(commandBlock(last));
    }
    renderedSeq = run.commands.length;
    scrollOut();
    patchShop(run);
    renderObjectives(run);
    renderStatus(run);
    if (!run.active && !endedShown) renderSummary(run);
  };

  const commandBlock = (c: CommandRun): HTMLElement => {
    const cmd = catalogue?.commands.find((x) => x.id === c.id);
    const body: (Node | string)[] = [];
    if (c.stdout) body.push(h("p", { class: "term__line" }, c.stdout.replace(/\n$/, "")));
    if (c.stderr) body.push(h("p", { class: "term__line term__line--err" }, c.stderr.replace(/\n$/, "")));
    if (c.truncated) body.push(h("p", { class: "term__line term__line--sys" }, "… output truncated"));
    if (c.killed) body.push(h("p", { class: "term__line term__line--kill" }, "— the pod was deleted under this command; your session is over —"));
    else if (c.exitCode !== undefined && c.exitCode !== 0 && !c.stderr) body.push(h("p", { class: "term__line term__line--sys" }, `exit ${c.exitCode}`));
    if (cmd && c.achieved) body.push(h("p", { class: "term__line term__line--win" }, `✓ objective reached: ${catalogue?.objectives.find((o) => o.id === cmd.objective)?.title ?? cmd.objective}`));
    if (cmd && (c.exitCode !== undefined || c.killed)) body.push(h("p", { class: "term__explain" }, cmd.explain));
    return h("div", { class: "term__cmd", "data-seq": String(c.seq), "data-outcome": cmd?.outcome ?? "" }, promptEcho(cmd?.input ?? c.id), ...body);
  };

  const patchShop = (run: RunView) => {
    if (!els) return;
    replace(els.shop, renderVictim(run, watching !== undefined));
  };

  const renderStatus = (run: RunView) => {
    if (!els) return;
    if (watching) {
      els.status.textContent = "watching another visitor — read-only";
      return;
    }
    if (!run.active) {
      els.status.textContent = "session over";
    } else if (run.quarantinedAt !== undefined) {
      els.status.textContent = "quarantined — still yours, but cut off";
    } else {
      els.status.textContent = `live · ${run.commands.length} command${run.commands.length === 1 ? "" : "s"}`;
    }
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
    // Which layer answered which command, from the catalogue.
    const entries = run.commands
      .map((c) => {
        const cmd = catalogue!.commands.find((x) => x.id === c.id);
        return cmd ? { layer: cmd.layer, outcome: cmd.outcome, control: cmd.control, input: cmd.input } : null;
      })
      .filter((x): x is NonNullable<typeof x> => x !== null);
    const lit = litFromCommands(entries);
    const reached = new Set<string>();
    for (const c of run.commands) {
      if (!c.achieved) continue;
      const cmd = catalogue.commands.find((x) => x.id === c.id);
      if (cmd?.objective) reached.add(cmd.objective);
    }
    const start = run.states.started ?? run.states.queued;
    const endT = run.states.finished ?? run.states.failed ?? run.states.timeout;
    const survived = start !== undefined && endT !== undefined ? endT - start : undefined;
    // The ender: the command that ended the run (killed) and how long after its start the kill landed.
    const ender = run.commands.find((c) => c.killed);
    const killMs = ender && ender.startedAt !== undefined && ender.endedAt !== undefined ? ender.endedAt - ender.startedAt : run.timings.respondMs;
    const detail = run.detail;
    const outcome = ender ? "The cluster deleted the pod under you." : detail === "idle" ? "You went quiet; the pod was reclaimed." : detail === "deadline" ? "The pod hit its 120-second deadline." : detail === "left" ? "You left; the pod was cleaned up." : run.quarantinedAt !== undefined ? "You were quarantined, then the session ended." : "The session ended.";

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
        ender && killMs !== undefined ? stat("Killed after your Enter", formatDuration(killMs)) : null,
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
    els.summary.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "nearest" });
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
        renderSessionReadOnly();
      }
    } else if (watching && (!active || active.scenario !== "terminal" || !active.active)) {
      // The watched run ended; patch its final state then let it rest.
      patchFromView();
      watching = undefined;
    }
    if (session || watching) patchFromView();
  };

  const renderSessionReadOnly = () => {
    renderSession();
    if (els) {
      els.input.disabled = true;
      els.form.hidden = true;
      els.chips.hidden = true;
    }
  };

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
