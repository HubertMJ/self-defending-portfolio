// The live run console: one run, large, with the evidence that it really happened.
//
//   * the detection pipeline, hop by hop, lit on the replay schedule of lib/pipeline.ts with the real
//     latency next to it, and a kill-timer from the exec to the response;
//   * the victim app in a browser window (ui/victim.ts);
//   * the pod as the API server saw it: name, UID, image digest, phases, the quarantine label;
//   * what was executed and under which restrictions (GET /api/scenarios/{id}/details);
//   * for a quarantine, the proof that the pod was isolated rather than killed;
//   * "verify it yourself": ids, UTC timestamps, the raw run as JSON, the rules at the commit, and the
//     cosign command for the scenario image;
//   * in Technical Mode (.tech-only), the raw events, Falco's output fields, Talon's parameters and
//     the policies involved.
//
// It shows the active run, or the newest one, or one picked from the history. The skeleton of a run is
// built once and the pipeline and timer are patched in place on every animation frame, so the CSS
// transitions of a hop lighting up run once instead of restarting with every event; the slower panels
// are rebuilt only when what they show has changed.

import type { ApiClient, Result } from "../lib/api";
import type { Scenario, ScenarioDetails } from "../lib/contract";
import { type Child, clockTime, h, prefersReducedMotion, replace } from "../lib/dom";
import { type Hop, type Schedule, TIMER_END, TIMER_START, humanAction, runHops, scheduleHops, timerReading } from "../lib/pipeline";
import { type RunView, type TimelineView, QUARANTINE_LABEL, formatDuration, guardedFalco, guardedTalon, ts } from "../lib/timeline";
import { copyButton, extLink, sourceUrl } from "./common";
import { heldMs, heldText, renderTwin } from "./twin";
import { labelOf, renderVictim, victimState } from "./victim";

/** The workflow identity that signs the scenario image (ADR 0011, build-images.yml). */
export const COSIGN_IDENTITY =
  "https://github.com/HubertMJ/self-defending-portfolio/.github/workflows/build-images.yml@refs/heads/main";
export const COSIGN_ISSUER = "https://token.actions.githubusercontent.com";

export interface ConsoleHandle {
  update(view: TimelineView): void;
  /** Show this run (from the history); undefined follows the live run again. */
  select(runId: string | undefined): void;
  /** A run this page launched: shown as "your run", not as another visitor's. */
  markOwn(runId: string): void;
  /** Scrolls the console into view if it is not, and moves focus to its heading. */
  reveal(): void;
  setScenarios(list: Scenario[]): void;
}

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

interface Panels {
  runId: string;
  root: HTMLElement;
  hops: HTMLElement[];
  timer: HTMLElement;
  timerValue: HTMLElement;
  timerLabel: HTMLElement;
  badge: HTMLElement;
  replayBtn: HTMLButtonElement;
  head: HTMLElement;
  victim: HTMLElement;
  pod: HTMLElement;
  executed: HTMLElement;
  proof: HTMLElement;
  verify: HTMLElement;
  raw: HTMLElement;
  keys: Map<string, string>;
}

type Kids = (Child | Child[])[];

const shortDigest = (image: string): string => {
  const at = image.indexOf("@sha256:");
  if (at < 0) return image;
  return `${image.slice(0, at).split("/").pop()}@sha256:${image.slice(at + 8, at + 20)}…`;
};

/** A real duration next to something a visitor can feel (FIX 3: "a blink is about 100 ms"). */
export function humanSpeed(ms: number): string {
  if (ms < 60) return "faster than you could blink";
  if (ms < 180) return "about as fast as a blink (~100 ms)";
  if (ms < 450) return "quicker than a camera shutter";
  if (ms < 1200) return "in under a second";
  if (ms < 3000) return "in a couple of seconds";
  return "slower than it should be — look at the gaps below";
}

/** argv as a shell would need it typed: arguments with spaces or quotes are single-quoted. */
export function shellJoin(argv: readonly string[]): string {
  return argv.map((a) => (/^[\w@%+=:,./-]+$/.test(a) ? a : `'${a.replace(/'/g, `'\\''`)}'`)).join(" ");
}

/**
 * Splits a shell script into lines at its top-level `&&` and `;` -- outside quotes only -- keeping
 * `&&` at the end of its line and dropping the `;`. A line break is what both already mean to sh
 * (a command list may continue after `&&` on the next line, and a newline ends a command like `;`),
 * so the lines are the same script, laid out to be read. Nothing inside quotes is touched.
 */
export function scriptLines(script: string): string[] {
  const lines: string[] = [];
  let cur = "";
  let quote: string | null = null;
  for (let i = 0; i < script.length; i++) {
    const c = script[i];
    if (quote) {
      if (c === quote) quote = null;
      else if (c === "\\" && quote === '"') {
        cur += c + (script[i + 1] ?? "");
        i += 1;
        continue;
      }
      cur += c;
      continue;
    }
    if (c === "'" || c === '"') quote = c;
    if (c === "&" && script[i + 1] === "&") {
      lines.push(`${cur.trim()} &&`);
      cur = "";
      i += 1;
      continue;
    }
    if (c === ";") {
      lines.push(cur.trim());
      cur = "";
      continue;
    }
    cur += c;
  }
  if (cur.trim()) lines.push(cur.trim());
  return lines.filter((l) => l !== "");
}

/**
 * How the exec reads best: for `sh -c <script>` the script argument as indented lines (scriptLines)
 * rather than one shell-quoted line full of '\'' escapes; anything else is the quoted argv.
 */
export function commandText(argv: readonly string[]): string {
  if (argv.length === 3 && /^(\/bin\/)?(ba)?sh$/.test(argv[0]) && argv[1] === "-c") {
    return `${argv[0]} -c\n${scriptLines(argv[2]).map((l) => `  ${l}`).join("\n")}`;
  }
  return shellJoin(argv);
}

/** A command as a terminal block, one script line per row (commandText). */
function term(argv: readonly string[]): HTMLElement {
  return h(
    "pre",
    { class: "term term--script" },
    h(
      "code",
      {},
      commandText(argv)
        .split("\n")
        .map((line, i) => h("span", { class: "term__line" }, i === 0 ? h("span", { class: "term__prompt", "aria-hidden": "true" }, "$ ") : null, line.trimStart())),
    ),
  );
}

export function cosignCommand(image: string): string {
  return [`cosign verify ${image}`, `  --certificate-identity ${COSIGN_IDENTITY}`, `  --certificate-oidc-issuer ${COSIGN_ISSUER}`].join(" \\\n");
}

export function mountConsole(root: HTMLElement, api: ApiClient): ConsoleHandle {
  const reduced = prefersReducedMotion();
  const own = new Set<string>();
  const scenarios = new Map<string, Scenario>();
  const details = new Map<string, Result<ScenarioDetails> | "loading">();
  /** Local time each hop of each run was first seen with data: `${runId}:${index}`. */
  const known = new Map<string, number>();
  /** Runs being replayed slowly on request: start time of the replay. */
  const replays = new Map<string, number>();
  let selected: string | undefined;
  let lastActive: string | undefined;
  let view: TimelineView = { runs: [], unmatched: [] };
  let panels: Panels | undefined;
  let frame: number | undefined;
  // The twin's "held for" counter: no event arrives while the unguarded pod stays compromised, so it
  // is re-read every second while the run is live.
  let twinClock: ReturnType<typeof setInterval> | undefined;
  const syncTwinClock = (run: RunView | undefined) => {
    const live = run !== undefined && run.armPods !== undefined && run.active;
    if (live && twinClock === undefined) {
      twinClock = setInterval(() => {
        const r = current();
        const el = panels?.victim.querySelector(".twin__held");
        const ms = r && heldMs(r, Date.now());
        if (el && ms !== undefined) el.textContent = heldText(ms);
      }, 1000);
    } else if (!live && twinClock !== undefined) {
      clearInterval(twinClock);
      twinClock = undefined;
    }
  };

  const heading = h("h3", { class: "console__title", id: "console-title", tabindex: "-1" }, "Live run");
  const body = h("div", { class: "console__body" });
  replace(root, h("div", { class: "console__top" }, heading), body);

  // The terminal has its own panel (ui/terminal.ts); the console never shows a terminal run.
  const showable = (r: RunView | undefined): r is RunView => r !== undefined && r.scenario !== "terminal";
  const current = (): RunView | undefined => {
    const picked = selected ? view.runs.find((r) => r.runId === selected) : undefined;
    if (showable(picked)) return picked;
    if (showable(view.activeRun)) return view.activeRun;
    return view.runs.find(showable);
  };

  const timings = (run: RunView, hops: Hop[]) => {
    const replayAt = replays.get(run.runId);
    const now = Date.now();
    return hops.map((hp, i) => {
      if (hp.at === undefined) return {};
      const k = `${run.runId}:${i}`;
      if (!known.has(k)) known.set(k, now);
      return { real: hp.at, known: replayAt ?? (known.get(k) as number) };
    });
  };

  const scheduleFor = (run: RunView, hops: Hop[]): { t: ReturnType<typeof timings>; s: Schedule } => {
    const t = timings(run, hops);
    const isReplay = replays.has(run.runId);
    // FIX 3: real time first. Every hop lights the moment its event arrives — so the visitor sees how
    // fast the cluster actually is — and the slowed, dwelled replay happens only on request (the
    // "Replay slowly" button), never under prefers-reduced-motion.
    const s = scheduleHops(t, { instant: !isReplay });
    return { t, s };
  };

  const loadDetails = (scenario: string) => {
    if (details.has(scenario)) return;
    details.set(scenario, "loading");
    void api.scenarioDetails(scenario).then((r) => {
      details.set(scenario, r);
      render();
    });
  };

  // ---------- pipeline + timer (patched every frame while something is moving) ----------

  const tick = () => {
    frame = undefined;
    const run = current();
    if (!run || !panels || panels.runId !== run.runId) return;
    const hops = runHops(run);
    const { t, s } = scheduleFor(run, hops);
    const now = Date.now();
    let moving = false;
    let frontier = -1;
    hops.forEach((hp, i) => {
      const el = panels!.hops[i];
      const light = s.lightAt[i];
      let state: string;
      if (light !== undefined && light <= now) {
        state = "lit";
        frontier = i;
      } else if (light !== undefined) {
        state = "pending";
        moving = true;
      } else {
        state = "pending";
      }
      el.dataset.state = state;
      const time = el.querySelector(".hop__t") as HTMLElement;
      const what = el.querySelector(".hop__what") as HTMLElement;
      if (what.textContent !== hp.what) what.textContent = hp.what;
      // The last two hops depend on the response (delete vs quarantine), known only once it comes.
      const who = el.querySelector(".hop__who")?.firstChild;
      if (who && who.textContent !== hp.who) who.textContent = hp.who;
      time.textContent = state === "lit" ? hopTime(hops, i) : "";
    });
    // Hops with no data before the frontier were skipped by the cluster's report, not pending.
    hops.forEach((_, i) => {
      const el = panels!.hops[i];
      if (i < frontier && el.dataset.state === "pending" && s.lightAt[i] === undefined) el.dataset.state = "skipped";
    });
    const next = panels.hops.find((el) => el.dataset.state === "pending");
    if (next && run.active) next.dataset.state = "waiting";
    for (const el of panels.hops) {
      const sr = el.querySelector(".hop__sr") as HTMLElement;
      const word = el.dataset.state === "lit" ? " (done)" : el.dataset.state === "waiting" ? " (in progress)" : el.dataset.state === "skipped" ? " (not reported)" : " (pending)";
      if (sr.textContent !== word) sr.textContent = word;
    }

    // Kill-timer.
    const reading = timerReading(t, s, TIMER_START, TIMER_END, now);
    const contained = s.lightAt[TIMER_END] !== undefined && (s.lightAt[TIMER_END] as number) <= now;
    const failed = !run.active && !contained && (run.current === "failed" || run.current === "timeout");
    panels.timer.dataset.state = contained ? "stopped" : failed ? "failed" : reading !== undefined ? "running" : "idle";
    panels.timerValue.textContent = reading === undefined ? (failed ? "—" : "0.000") : (reading / 1000).toFixed(3);
    panels.timerLabel.textContent = contained
      ? hops[TIMER_END].what === "quarantine label set"
        ? "from the syscall Falco caught to the pod quarantined"
        : "from the syscall Falco caught to the pod deleted"
      : failed
        ? "the response never arrived"
        : reading !== undefined
          ? "detected, waiting for the response…"
          : run.active
            ? "starts when Falco catches the attack"
            : "Falco reported no detection";

    // Replay badge. By default the run played in real time; the slowed replay runs only on request.
    const isReplay = replays.has(run.runId);
    const replaying = isReplay && moving;
    let badge = "";
    if (s.realSpanMs !== undefined && frontier >= TIMER_START + 1) {
      const real = formatDuration(s.realSpanMs);
      // The same stretch as the kill-timer (detected syscall to the response in the API server), so
      // the badge and the big number can never disagree.
      const span = `real: ${real} from the detected syscall to ${hops[TIMER_END].what}`;
      if (isReplay) {
        badge = `${replaying ? "Replaying" : "Replayed"} at 1/${s.slowdown} speed · ${span}`;
      } else if (contained) {
        // FIX 3: once it is over, state how fast it really was, next to something human.
        badge = `Real time · ${span} · ${humanSpeed(s.realSpanMs)}`;
      } else {
        badge = `Playing in real time · ${span}`;
      }
    } else if (run.active && !isReplay) {
      badge = "Playing in real time";
    }
    if (panels.badge.textContent !== badge) panels.badge.textContent = badge;
    panels.badge.hidden = badge === "";
    // Offered once the run is over and there is a response chain to replay; never under reduced motion.
    panels.replayBtn.hidden = reduced || run.active || moving || hops.every((hp) => hp.at === undefined);

    if (!moving && replays.has(run.runId)) replays.delete(run.runId);
    if (moving || (run.active && reading !== undefined && !contained)) {
      frame = requestAnimationFrame(tick);
    }
  };

  // Times on the wire: the first hop as a clock time, the run-up to the detection relative to the
  // pod's creation, the detected syscall as t = 0 and the response chain relative to it.
  const hopTime = (hops: Hop[], i: number): string => {
    const hp = hops[i];
    if (hp.at === undefined) return "";
    if (i === 0) return clockTime(hp.at);
    const zero = hops[TIMER_START].at;
    if (i < TIMER_START || zero === undefined) {
      const create = hops[0].at;
      return create !== undefined ? `+${formatDuration(hp.at - create)}` : clockTime(hp.at);
    }
    if (i === TIMER_START) return "t = 0";
    const d = hp.at - zero;
    const le = hp.bound ? "≤ " : "";
    return d < 0 ? `${le}−${formatDuration(-d)}` : `${le}+${formatDuration(d)}`;
  };

  const scheduleTick = () => {
    if (frame !== undefined) cancelAnimationFrame(frame);
    frame = requestAnimationFrame(tick);
  };

  // ---------- skeleton ----------

  const build = (run: RunView): Panels => {
    const hops = runHops(run);
    const hopEls = hops.map((hp, i) =>
      h(
        "li",
        { class: `hop hop--${hp.stage}`, "data-hop": hp.key, "data-state": "pending" },
        h("span", { class: "hop__wire", "aria-hidden": "true" }),
        h("span", { class: "hop__node", "aria-hidden": "true" }, String(i + 1)),
        h("span", { class: "hop__who" }, hp.who, h("span", { class: "hop__sr visually-hidden" }, " (pending)")),
        h("span", { class: "hop__what" }, hp.what),
        h("span", { class: "hop__t" }),
      ),
    );
    const timerValue = h("span", { class: "killtimer__value" }, "0.000");
    const timerLabel = h("span", { class: "killtimer__label" });
    const timer = h(
      "div",
      { class: "killtimer", role: "timer", "aria-labelledby": "killtimer-title", "data-state": "idle" },
      h("span", { class: "killtimer__title", id: "killtimer-title" }, "Kill-timer"),
      h("span", { class: "killtimer__digits" }, timerValue, h("span", { class: "killtimer__unit" }, "s")),
      timerLabel,
    );
    const badge = h("p", { class: "replay-badge", hidden: true });
    const replayBtn = h("button", { type: "button", class: "btn btn--ghost btn--small", hidden: true }, "Replay slowly");
    replayBtn.addEventListener("click", () => {
      replays.set(run.runId, Date.now());
      scheduleTick();
    });
    const p: Panels = {
      runId: run.runId,
      root: h("div", { class: "console__run", "data-run": run.runId }),
      hops: hopEls,
      timer,
      timerValue,
      timerLabel,
      badge,
      replayBtn,
      head: h("div", { class: "console__head" }),
      victim: h("div", { class: "console__victim" }),
      pod: h("section", { class: "card card--pod", "aria-labelledby": "pod-title" }),
      executed: h("section", { class: "card card--exec", "aria-labelledby": "exec-title" }),
      proof: h("section", { class: "card card--proof", "aria-labelledby": "proof-title" }),
      verify: h("div", { class: "console__verify" }),
      raw: h("div", { class: "console__raw tech-only" }),
      keys: new Map(),
    };
    replace(
      p.root,
      p.head,
      h(
        "div",
        { class: "trace" },
        timer,
        h(
          "div",
          { class: "trace__main" },
          h("ol", { class: "pipeline", "aria-label": "Detection pipeline, hop by hop" }, hopEls),
          h("div", { class: "trace__meta" }, badge, replayBtn),
        ),
      ),
      h("div", { class: "console__grid" }, p.victim, h("div", { class: "console__side" }, p.pod, p.executed)),
      p.proof,
      p.verify,
      p.raw,
    );
    return p;
  };

  /** Rebuilds a panel only when its key changed. */
  const patch = (p: Panels, name: keyof Panels & string, key: string, make: () => Kids | Node | null) => {
    if (p.keys.get(name) === key) return;
    p.keys.set(name, key);
    const el = p[name] as HTMLElement;
    const out = make();
    if (out === null) replace(el);
    else replace(el, ...(Array.isArray(out) ? out : [out]));
    el.hidden = out === null;
  };

  // ---------- panels ----------

  const headPanel = (run: RunView): Kids => {
    const sc = scenarios.get(run.scenario);
    const failed = run.current === "failed" || run.current === "timeout";
    const tone = failed ? "critical" : run.active ? "warning" : "good";
    const who = run.active ? (own.has(run.runId) ? "Your run" : "Another visitor’s run · you are watching it live") : null;
    return [
      h(
        "div",
        { class: "console__name" },
        h("p", { class: "console__scenario" }, sc?.title ?? run.scenario),
        h("span", { class: `chip chip--state chip--${tone}` }, STATE_WORD[run.current] ?? run.current),
        who ? h("span", { class: `console__who${own.has(run.runId) ? "" : " console__who--other"}` }, who) : null,
      ),
      h(
        "p",
        { class: "console__sub" },
        selected && selected !== view.activeRun?.runId && view.runs[0]?.runId !== selected ? "From the history. " : run.active ? "Happening now. " : "Most recent run. ",
        "Run ",
        h("code", {}, run.runId),
        run.pod ? [" · pod ", h("code", {}, run.pod)] : null,
        selected ? [" ", followButton()] : null,
      ),
      failed && run.detail ? h("p", { class: "console__fail" }, run.detail) : null,
    ];
  };

  const followButton = () => {
    const b = h("button", { type: "button", class: "linkish" }, "Back to the latest run");
    b.addEventListener("click", () => select(undefined));
    return b;
  };

  const podPanel = (run: RunView): Kids => {
    const rows = run.pods.map((p) => {
      const changes = Object.entries(p.labels_delta).filter(([k, v]) => k !== QUARANTINE_LABEL || v === "true" || v === null);
      return h(
        "li",
        { class: "phase", "data-phase": p.deleted ? "deleted" : p.phase.toLowerCase() },
        h("time", { datetime: p.at }, clockTime(Date.parse(p.at))),
        h("span", { class: "phase__name" }, p.deleted ? "Deleted" : p.phase),
        p.reason && p.reason !== p.phase ? h("span", { class: "phase__reason" }, p.reason) : null,
        changes.map(([k, v]) => h("span", { class: `phase__label${k === QUARANTINE_LABEL ? " phase__label--q" : ""}` }, v === null ? `− ${k}` : `${k}=${v}`)),
      );
    });
    return [
      h("h4", { class: "card__title", id: "pod-title" }, "The pod, as the API server saw it"),
      h(
        "dl",
        { class: "facts" },
        h("div", {}, h("dt", {}, "Name"), h("dd", {}, run.pod ? h("code", {}, run.pod) : "–")),
        h("div", {}, h("dt", {}, "UID"), h("dd", {}, run.podUid ? h("code", { title: run.podUid }, run.podUid) : "–")),
        h("div", {}, h("dt", {}, "Image"), h("dd", {}, run.image ? h("code", { title: run.image }, shortDigest(run.image)) : "–")),
        h("div", {}, h("dt", {}, "Container"), h("dd", {}, run.containerId ? h("code", {}, run.containerId) : "–")),
      ),
      rows.length
        ? h("ol", { class: "phases", "aria-label": "Pod lifecycle" }, rows)
        : h("p", { class: "card__empty" }, run.active ? "Waiting for the pod watch…" : "No pod lifecycle was reported for this run."),
    ];
  };

  const executedPanel = (run: RunView): Kids => {
    const sc = scenarios.get(run.scenario);
    const d = details.get(run.scenario);
    const title = h("h4", { class: "card__title", id: "exec-title" }, "What was executed");
    if (d === undefined || d === "loading") return [title, h("p", { class: "card__empty" }, "Loading the scenario’s definition…")];
    if (!d.ok) {
      return [
        title,
        h("p", { class: "card__empty" }, "This API version does not publish scenario details. The definition is in the repository:"),
        h("p", {}, extLink("https://github.com/HubertMJ/self-defending-portfolio/blob/main/cluster/infra/sandbox/scenarios/scenarios.yaml", "scenarios.yaml")),
        sc ? h("p", { class: "small" }, "Detected by ", h("code", {}, sc.detection), ", answered with ", sc.response, ".") : null,
      ];
    }
    const v = d.value;
    const ps = v.pod_security;
    const facts: [boolean | undefined, string][] = [
      [ps.runAsNonRoot, ps.runAsUser !== undefined ? `non-root, uid ${ps.runAsUser}` : "non-root"],
      [ps.readOnlyRootFilesystem, ps.readOnlyRootFilesystem === false ? "writable root filesystem (this scenario needs it)" : "read-only root filesystem"],
      [ps.allowPrivilegeEscalation === undefined ? undefined : !ps.allowPrivilegeEscalation, ps.allowPrivilegeEscalation ? "privilege escalation allowed" : "no privilege escalation"],
      [ps.capabilities_drop.includes("ALL"), ps.capabilities_drop.includes("ALL") ? "no Linux capabilities" : `capabilities dropped: ${ps.capabilities_drop.join(", ") || "none"}`],
      [ps.seccomp !== undefined, `seccomp ${ps.seccomp ?? "unset"}`],
      [ps.automountServiceAccountToken === false, ps.automountServiceAccountToken === false ? "no service-account token" : "service-account token mounted"],
    ];
    const res = Object.entries(v.resources);
    const rule = (label: string, r: ScenarioDetails["falco_rule"]) => {
      if (!r) return null;
      // A stock Falco rule lives in the Falco image, not in this repository: named, not linked.
      const url = r.file ? sourceUrl(v.commit, r.file, r.line) : null;
      return h("li", {}, h("span", { class: "rule__k" }, label), url ? extLink(url, r.name) : [r.name, r.file ? "" : " (stock rule of the Falco image)"]);
    };
    return [
      title,
      v.pre_exec_command.length
        ? h(
            "ol",
            { class: "steps" },
            h("li", {}, h("p", { class: "steps__k" }, "Prepare, no terminal"), term(v.pre_exec_command)),
            h("li", {}, h("p", { class: "steps__k" }, v.exec_tty ? "Attack, in an interactive terminal" : "Attack"), term(v.exec_command)),
          )
        : term(v.exec_command),
      h(
        "ul",
        { class: "guards", "aria-label": "Restrictions the pod ran under" },
        facts.filter(([ok]) => ok !== undefined).map(([ok, text]) => h("li", { "data-ok": String(ok) }, h("span", { class: "guards__mark", "aria-hidden": "true" }, ok ? "✓" : "!"), text)),
      ),
      res.length ? h("p", { class: "small" }, "Resources: ", res.flatMap(([k, x], i) => [i ? ", " : "", h("code", {}, `${k} ${x}`)])) : null,
      h("ul", { class: "rules" }, rule("Falco rule", v.falco_rule), rule("Talon rule", v.talon_rule)),
      v.policies.length
        ? h(
            "div",
            { class: "tech-only" },
            h("p", { class: "small" }, "Policies the pod had to pass:"),
            h(
              "ul",
              { class: "rules" },
              v.policies.map((p) => {
                const url = p.file ? sourceUrl(v.commit, p.file) : null;
                return h("li", {}, h("span", { class: "rule__k" }, p.kind), url ? extLink(url, p.name) : p.name);
              }),
            ),
          )
        : null,
    ];
  };

  const proofPanel = (run: RunView): Kids | null => {
    const sc = scenarios.get(run.scenario);
    const gt = guardedTalon(run);
    const quarantine = run.quarantinedAt !== undefined || sc?.response === "quarantine" || (gt !== undefined && /label/i.test(gt.actionner ?? gt.action));
    if (!quarantine) return null;
    const before = run.victim.find((v) => v.status === "up" && v.arm !== "unguarded");
    // The cut is the first probe that failed after the label landed, not any earlier timeout.
    const after = run.victim.find((v) => v.status === "unreachable" && v.arm !== "unguarded" && (run.quarantinedAt === undefined || ts(v.at) >= run.quarantinedAt));
    const lastPod = run.pods[run.pods.length - 1];
    const stillRunning = run.quarantinedAt !== undefined && run.pods.some((p) => p.labels_delta[QUARANTINE_LABEL] === "true" && /running/i.test(p.phase));
    const check = (ok: boolean, title: string, detail: Child[]) =>
      h("li", { "data-ok": String(ok) }, h("span", { class: "guards__mark", "aria-hidden": "true" }, ok ? "✓" : "…"), h("strong", {}, title), h("span", { class: "proof__detail" }, ...detail));
    return [
      h("h4", { class: "card__title", id: "proof-title" }, "Proof of quarantine"),
      h("p", { class: "small" }, "The pod is not killed: it keeps running, cut off from the network, so it can be inspected."),
      h(
        "ol",
        { class: "proof" },
        check(run.quarantinedAt !== undefined, "Label set by Talon", [
          h("code", {}, `${QUARANTINE_LABEL}: false → true`),
          run.quarantinedAt !== undefined ? ` at ${clockTime(run.quarantinedAt)}` : "",
        ]),
        check(stillRunning, "Pod still running", [stillRunning ? "phase Running after the label: isolated, not deleted" : lastPod ? `last phase seen: ${lastPod.phase}` : "waiting for the pod watch"]),
        check(after !== undefined, "Cilium dropped the probe", [
          before ? `the API's probe answered in ${before.probe_ms} ms before the label; ` : "",
          after ? `after it, no answer within ${after.probe_ms > 0 ? `${after.probe_ms} ms` : "its full timeout"} — the quarantine policy cut the pod off` : "waiting for the next probe",
        ]),
      ),
      lastPod?.deleted ? h("p", { class: "small" }, `The API deleted the quarantined pod at the end of the run (${clockTime(Date.parse(lastPod.at))}).`) : null,
    ];
  };

  const verifyPanel = (run: RunView, hops: Hop[]): Kids => {
    const d = details.get(run.scenario);
    const det = d && d !== "loading" && d.ok ? d.value : undefined;
    const image = det?.image.ref || run.image || "";
    const rows = hops.filter((hp) => hp.raw);
    const runUrl = `/api/runs/${encodeURIComponent(run.runId)}`;
    const ruleLinks = det
      ? [det.falco_rule, det.talon_rule].flatMap((r) => {
          const url = r ? sourceUrl(det.commit, r.file, r.line) : null;
          return r && url ? [h("li", {}, extLink(url, `${r.file}#L${r.line}`), ` (${r.name})`)] : [];
        })
      : [];
    return [
      h(
        "details",
        { class: "verify", open: run.runId === openVerify ? true : null },
        h("summary", {}, "Verify it yourself"),
        h(
          "div",
          { class: "verify__body" },
          h("p", { class: "small" }, "Everything above comes from these records. They are the same ones the cluster wrote; nothing on this page is generated in your browser."),
          h(
            "dl",
            { class: "facts facts--wide" },
            h("div", {}, h("dt", {}, "Run id"), h("dd", {}, h("code", {}, run.runId))),
            h("div", {}, h("dt", {}, "Pod"), h("dd", {}, run.pod ? h("code", {}, run.pod) : "–")),
            h("div", {}, h("dt", {}, "Pod UID"), h("dd", {}, run.podUid ? h("code", {}, run.podUid) : "–")),
            h("div", {}, h("dt", {}, "Raw run"), h("dd", {}, h("a", { href: runUrl }, runUrl), " (JSON, kept for the last 50 runs)")),
          ),
          rows.length
            ? h(
                "table",
                { class: "utc" },
                h("caption", {}, "Timestamps, UTC, as reported"),
                h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Hop"), h("th", { scope: "col" }, "UTC"), h("th", { scope: "col" }, "Source"))),
                h(
                  "tbody",
                  {},
                  rows.map((hp) => h("tr", {}, h("th", { scope: "row" }, `${hp.who}: ${hp.what}`), h("td", {}, h("code", {}, hp.raw as string)), h("td", {}, hp.source ?? ""))),
                ),
              )
            : null,
          ruleLinks.length ? [h("p", { class: "small" }, `Rules at commit ${det?.commit}:`), h("ul", { class: "rules" }, ruleLinks)] : null,
          image
            ? [
                h("p", { class: "small" }, "The scenario image is signed in CI. Check the signature and who made it:"),
                h("div", { class: "cmd" }, h("pre", { class: "term" }, h("code", {}, cosignCommand(image))), copyButton(() => cosignCommand(image).replace(/ \\\n\s*/g, " "))),
              ]
            : null,
        ),
      ),
    ];
  };
  let openVerify: string | undefined;

  const rawPanel = (run: RunView): Kids => {
    const falco = guardedFalco(run);
    const talon = guardedTalon(run);
    return [
      h("h4", { class: "card__title" }, "Technical detail"),
      h(
        "div",
        { class: "techgrid" },
        falco?.fields
          ? h(
              "section",
              { class: "card" },
              h("h5", {}, "Falco output fields"),
              h("dl", { class: "facts facts--mono" }, Object.entries(falco.fields).map(([k, v]) => h("div", {}, h("dt", {}, k), h("dd", {}, h("code", {}, v))))),
              h("p", { class: "small" }, "Priority ", h("strong", {}, falco.priority), ", rule ", h("code", {}, falco.rule)),
            )
          : falco
            ? h("section", { class: "card" }, h("h5", {}, "Falco output"), h("code", { class: "run__output" }, falco.output))
            : null,
        talon
          ? h(
              "section",
              { class: "card" },
              h("h5", {}, "Talon"),
              h(
                "dl",
                { class: "facts facts--mono" },
                h("div", {}, h("dt", {}, "action"), h("dd", {}, h("code", {}, talon.action))),
                talon.actionner ? h("div", {}, h("dt", {}, "actionner"), h("dd", {}, h("code", {}, talon.actionner))) : null,
                h("div", {}, h("dt", {}, "status"), h("dd", {}, h("code", {}, talon.status))),
                h("div", {}, h("dt", {}, "target"), h("dd", {}, h("code", {}, `${talon.namespace}/${talon.pod}`))),
                talon.output ? h("div", {}, h("dt", {}, "output"), h("dd", {}, h("code", {}, talon.output))) : null,
              ),
              h("p", { class: "small" }, humanAction(talon.action, talon.actionner), "."),
            )
          : null,
      ),
      h(
        "details",
        { class: "rawlog" },
        h("summary", {}, `Raw events (${run.events.length})`),
        h(
          "ol",
          { class: "rawlog__list" },
          run.events.map((e) => h("li", {}, h("span", { class: `tag tag--${e.type}` }, e.type), h("pre", {}, h("code", {}, JSON.stringify(e.data, null, 2))))),
        ),
      ),
    ];
  };

  // ---------- render ----------

  const render = () => {
    const run = current();
    if (!run) {
      panels = undefined;
      syncTwinClock(undefined);
      root.dataset.state = "empty";
      replace(body, h("p", { class: "empty" }, "No run yet. Launch an attack above and it plays out here, hop by hop."));
      return;
    }
    root.dataset.state = run.active ? "live" : "done";
    if (!panels || panels.runId !== run.runId) {
      panels = build(run);
      replace(body, panels.root);
    }
    loadDetails(run.scenario);
    const p = panels;
    const hops = runHops(run);
    const d = details.get(run.scenario);
    const dKey = d === undefined || d === "loading" ? "l" : d.ok ? "ok" : "no";
    patch(p, "head", `${run.current}|${run.active}|${own.has(run.runId)}|${run.pod}|${selected}|${scenarios.size}|${view.activeRun?.runId}`, () => headPanel(run));
    const vKey = run.victim.map((v) => `${v.arm ?? ""}${v.status}${v.checksum}${v.until}`).join(",");
    const twin = run.armPods !== undefined;
    patch(p, "victim", `${twin ? `twin|${run.unguardedPods.length}|` : ""}${vKey}|${run.active}|${run.pod}|${run.pods[run.pods.length - 1]?.phase}`, () => (twin ? renderTwin(run) : renderVictim(run, run.active && !own.has(run.runId))));
    patch(p, "pod", `${run.pods.length}|${run.pod}`, () => podPanel(run));
    patch(p, "executed", `${dKey}|${scenarios.size}`, () => executedPanel(run));
    patch(p, "proof", `${run.pods.length}|${vKey}|${run.flows.length}|${run.talon.length}|${scenarios.size}`, () => proofPanel(run));
    patch(p, "verify", `${dKey}|${hops.map((x) => x.raw).join()}|${run.podUid}`, () => verifyPanel(run, hops));
    patch(p, "raw", `${run.events.length}`, () => rawPanel(run));
    p.root.dataset.victim = victimState(run);
    p.root.dataset.victimLabel = labelOf(victimState(run));
    syncTwinClock(run);
    scheduleTick();
  };

  const select = (runId: string | undefined) => {
    selected = runId;
    render();
  };

  // Keep the "Verify it yourself" disclosure open across rebuilds of the same run.
  root.addEventListener("toggle", (e) => {
    const t = e.target as HTMLElement;
    if (t instanceof HTMLDetailsElement && t.classList.contains("verify")) openVerify = t.open ? panels?.runId : undefined;
  }, true);

  render();

  return {
    update(v) {
      view = v;
      const active = v.activeRun?.runId;
      // A new live run takes over the console, whatever was picked from the history.
      if (active && active !== lastActive) selected = undefined;
      lastActive = active;
      render();
    },
    select,
    markOwn(runId) {
      own.add(runId);
      selected = undefined;
      render();
    },
    reveal() {
      const r = root.getBoundingClientRect();
      // "In view" means its heading is near the top: on a phone a console that merely starts on screen
      // shows nothing but its title.
      const visible = r.top >= 0 && r.top < innerHeight * 0.25;
      if (!visible) root.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "start" });
      heading.focus({ preventScroll: true });
    },
    setScenarios(list) {
      scenarios.clear();
      for (const s of list) scenarios.set(s.id, s);
      render();
    },
  };
}
