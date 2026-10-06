// The one choice of what the page shows (lib/scope.ts): "This session" (the default) or "All activity,
// last 24 h". Drawn where the lists are (the run history, the evidence ticker, the SIEM's board), each
// copy a segmented pair of buttons with aria-pressed, named for what it scopes, all copies the same
// choice: a press on one moves them all, and the choice is kept in localStorage. One polite, visually
// hidden line says what the page now shows, once per change.

import { h, replace } from "../lib/dom";
import { type Scope, SCOPE_WORD, loadScope, saveScope } from "../lib/scope";

export interface ScopeHandle {
  readonly scope: Scope;
  /** A new copy of the control, in step with every other; `what` names what it scopes ("runs"). */
  control(what: string): HTMLElement;
  set(scope: Scope): void;
}

function storage(): Storage | undefined {
  try {
    return typeof localStorage === "undefined" ? undefined : localStorage;
  } catch {
    return undefined;
  }
}

/** `onChange`: every change of the choice (not the initial one, which `scope` reads). */
export function mountScope(onChange: (scope: Scope) => void): ScopeHandle {
  let scope = loadScope(storage());
  const buttons: HTMLButtonElement[] = [];
  // The one announcement of a change: the buttons' pressed state is per copy, this line is the page's.
  const live = h("p", { class: "visually-hidden scope-live", "aria-live": "polite", "aria-atomic": "true" });
  if (typeof document !== "undefined") document.body.append(live);

  const paint = () => {
    for (const b of buttons) b.setAttribute("aria-pressed", String(b.dataset.scope === scope));
  };

  const set = (next: Scope) => {
    if (next === scope) return;
    scope = next;
    saveScope(next, storage());
    paint();
    replace(live, next === "all" ? "Showing all activity of the last 24 hours, every visitor's." : "Showing this session: your runs and any run in progress now.");
    onChange(next);
  };

  return {
    get scope() {
      return scope;
    },
    control(what) {
      const opts = (["session", "all"] as const).map((s) => {
        const b = h("button", { type: "button", class: "scope__opt", "data-scope": s, "aria-pressed": String(s === scope) }, SCOPE_WORD[s]);
        b.addEventListener("click", () => set(s));
        buttons.push(b);
        return b;
      });
      return h("div", { class: "scope", role: "group", "aria-label": `Which ${what} to show` }, h("span", { class: "scope__label", "aria-hidden": "true" }, "Show"), opts);
    },
    set,
  };
}
