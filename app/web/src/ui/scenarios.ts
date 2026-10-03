// The scenario launcher: one card per entry in GET /api/scenarios, each launching
// POST /api/attack/{id}. The server is the authority on whether a run may start (409 while one is
// active, 429 past the rate limit); the client mirrors that state so the buttons say so up front,
// but never relies on it.

import type { ApiClient, AttackResult } from "../lib/api";
import type { Scenario } from "../lib/contract";
import { h, replace } from "../lib/dom";
import { staleRunMs } from "../lib/timeline";
import { attackUrl, offlinePanel } from "./common";

export interface LauncherState {
  /** A run reported active by the event stream, with how long it may last without an end event. */
  activeRun?: { runId: string; scenario: string; since: number; staleMs?: number };
  /** Epoch ms until which the server asked us to wait (429 Retry-After). */
  cooldownUntil?: number;
  /** A POST in flight. */
  pending?: string;
}

export interface Launcher {
  setActiveRun(run: LauncherState["activeRun"]): void;
  reload(): Promise<void>;
}

const RESPONSE_LABEL: Record<string, string> = {
  terminate: "Terminate the pod",
  quarantine: "Quarantine the pod",
};

export function formatCountdown(seconds: number): string {
  const s = Math.max(0, Math.ceil(seconds));
  const m = Math.floor(s / 60);
  return m > 0 ? `${m}:${String(s % 60).padStart(2, "0")}` : `${s} s`;
}

/** Why launching is blocked right now, or null if it is not. */
export function blockedReason(state: LauncherState, now: number): string | null {
  if (state.pending) return "Starting…";
  // A lock older than any run can last is a lost "finished" event, not a run (see staleRunMs).
  if (state.activeRun && now - state.activeRun.since < (state.activeRun.staleMs ?? staleRunMs(state.activeRun.scenario))) return "A run is in progress";
  if (state.cooldownUntil && state.cooldownUntil > now) return "Rate limited";
  return null;
}

export function describeAttackResult(r: AttackResult, scenarioTitle: string): { tone: "ok" | "warn" | "error"; text: string } {
  switch (r.kind) {
    case "accepted":
      return { tone: "ok", text: `“${scenarioTitle}” queued as run ${r.run.run_id}. Watch it play out in the live run below.` };
    case "busy":
      return { tone: "warn", text: "Another visitor’s run is in progress. Only one attack runs at a time; the buttons unlock when it finishes." };
    case "rate-limited":
      // The countdown itself is rendered live at the end of this line (see mountScenarios).
      return { tone: "warn", text: `Rate limit reached: a few attacks per 10 minutes per network address, shared by everyone behind the same NAT. You can launch again in ${formatCountdown(r.retryAfterSeconds)}.` };
    case "unknown-scenario":
      return { tone: "error", text: "That scenario no longer exists on the server. The list has been reloaded." };
    case "offline":
      return { tone: "error", text: "The attack API is not reachable right now, so nothing was started." };
    case "error":
      return { tone: "error", text: `The server refused the request (${r.message}). Nothing was started.` };
  }
}

export function mountScenarios(
  root: HTMLElement,
  statusEl: HTMLElement,
  api: ApiClient,
  onLoaded?: (scenarios: Scenario[]) => void,
  onAccepted?: (runId: string) => void,
): Launcher {
  const state: LauncherState = {};
  let scenarios: Scenario[] = [];
  const buttons = new Map<string, HTMLButtonElement>();
  // The live countdown sits inside the status line, after the sentence that explains it. It is
  // aria-hidden: the sentence already says how long, and a screen reader must not hear every second.
  const countdown = h("span", { class: "launch-status__countdown", "aria-hidden": "true" });
  let ticker: ReturnType<typeof setInterval> | undefined;

  const say = (tone: "ok" | "warn" | "error" | "info", text: string) => {
    statusEl.dataset.tone = tone;
    replace(statusEl, h("span", {}, text), state.cooldownUntil ? countdown : null);
  };

  const sync = () => {
    const now = Date.now();
    const reason = blockedReason(state, now);
    for (const [id, btn] of buttons) {
      const blocked = reason !== null;
      btn.setAttribute("aria-disabled", String(blocked));
      const running = state.activeRun?.scenario === id || state.pending === id;
      btn.dataset.running = String(running);
      replace(btn.querySelector(".btn__label") as HTMLElement, running ? "Running…" : blocked ? reason : "Launch attack");
    }
    for (const t of root.querySelectorAll<HTMLButtonElement>(".scenario__twin")) t.setAttribute("aria-disabled", String(reason !== null));
    if (state.cooldownUntil && state.cooldownUntil > now) {
      replace(countdown, `Unlocks in ${formatCountdown((state.cooldownUntil - now) / 1000)}`);
      if (!countdown.isConnected) statusEl.append(countdown);
      if (!ticker) ticker = setInterval(sync, 1000);
    } else {
      replace(countdown);
      if (state.cooldownUntil) {
        state.cooldownUntil = undefined;
        say("info", "You can launch another attack.");
      }
      if (ticker) {
        clearInterval(ticker);
        ticker = undefined;
      }
    }
  };

  const launch = async (s: Scenario, opts: { compare?: boolean } = {}) => {
    if (blockedReason(state, Date.now())) return;
    state.pending = s.id;
    sync();
    const result = await api.attack(s.id, opts);
    state.pending = undefined;
    const msg = describeAttackResult(result, s.title);
    if (result.kind === "accepted") {
      // Lock immediately; the stream's "queued" event confirms it a moment later.
      state.activeRun ??= { runId: result.run.run_id, scenario: s.id, since: Date.now() };
      onAccepted?.(result.run.run_id);
    } else if (result.kind === "rate-limited") {
      state.cooldownUntil = Date.now() + result.retryAfterSeconds * 1000;
    } else if (result.kind === "unknown-scenario") {
      void reload();
    }
    say(msg.tone, msg.text);
    sync();
  };

  // Only an API that knows `?compare=1` gets the twin button: an older one ignores the parameter and
  // would start an ordinary run instead. Such an API also predates the terminal, and its scenarios
  // carry no `interactive` field — that is how it is told apart.
  let compare = false;

  const card = (s: Scenario): HTMLElement => {
    const url = attackUrl(s.technique);
    const btn = h(
      "button",
      { type: "button", class: "btn btn--attack", "aria-describedby": `scn-${s.id}-summary` },
      h("span", { class: "btn__icon", "aria-hidden": "true" }, "▶"),
      h("span", { class: "btn__label" }, "Launch attack"),
    );
    btn.addEventListener("click", () => void launch(s));
    buttons.set(s.id, btn);
    // "Run it with and without the response": the same attack in sandbox and in sandbox-unguarded (C).
    const twin = compare ? h("button", { type: "button", class: "btn btn--ghost btn--small scenario__twin" }, "With & without the response") : null;
    twin?.addEventListener("click", () => void launch(s, { compare: true }));
    const response = RESPONSE_LABEL[s.response] ?? s.response;
    return h(
      "li",
      { class: "scenario", "data-scenario": s.id },
      h(
        "p",
        { class: "scenario__technique" },
        url
          ? h("a", { href: url, rel: "noopener noreferrer", target: "_blank" }, `MITRE ATT&CK ${s.technique}`, h("span", { class: "visually-hidden" }, " (opens in a new tab)"))
          : s.technique,
      ),
      h("h3", { class: "scenario__title" }, s.title),
      h("p", { class: "scenario__summary", id: `scn-${s.id}-summary` }, s.summary),
      h(
        "dl",
        { class: "scenario__meta" },
        h("div", {}, h("dt", {}, "Detected by"), h("dd", {}, h("code", {}, s.detection))),
        h("div", {}, h("dt", {}, "Response"), h("dd", { class: `response response--${s.response}` }, response)),
      ),
      h("div", { class: "scenario__actions" }, btn, twin),
    );
  };

  const reload = async () => {
    root.setAttribute("aria-busy", "true");
    const res = await api.scenarios();
    root.setAttribute("aria-busy", "false");
    buttons.clear();
    if (!res.ok) {
      root.dataset.state = "offline";
      replace(
        root,
        offlinePanel({
          title: "The attack launcher is offline",
          body: "Scenarios come from the cluster's API, which is not reachable right now. No attack can be started until it is back.",
          detail: res.message,
          onRetry: () => void reload(),
        }),
      );
      return;
    }
    scenarios = res.value;
    compare = scenarios.some((s) => typeof s.interactive === "boolean");
    onLoaded?.(scenarios);
    // The interactive scenario (the terminal) has its own panel above; the launcher is the one-click
    // demo — "Just show me" — so it shows only the non-interactive scenarios.
    const cards = scenarios.filter((s) => !s.interactive);
    root.dataset.state = cards.length ? "live" : "empty";
    replace(
      root,
      cards.length
        ? h("ul", { class: "scenarios", role: "list" }, cards.map(card))
        : h("p", { class: "empty" }, "No scenarios are configured on the server."),
    );
    sync();
  };

  void reload();

  return {
    setActiveRun(run) {
      const wasActive = state.activeRun;
      state.activeRun = run;
      if (wasActive && !run) say("info", "The run has finished. You can launch another attack.");
      sync();
    },
    reload,
  };
}
