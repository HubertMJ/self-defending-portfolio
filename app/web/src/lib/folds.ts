// Which sections start folded: none since 2026-10-17 (the owner: a visitor should not have to open
// each section by hand); the site redesign of 2026-10-12 had folded everything below the attack.
// A visitor's own choice is kept per section in localStorage under "sdp:collapsed:<id>": "1" folded,
// "0" open; no key means the default. theme.ts reads the same keys before first paint,
// so a page never jumps when ui/sections.ts mounts its buttons; without JavaScript nothing folds.

export const FOLD_KEY = "sdp:collapsed:";

/** The sections folded unless the visitor opened them: none, every section starts open. */
export const FOLDED_BY_DEFAULT: readonly string[] = [];

/** Whether a section starts folded, from its stored choice ("1", "0" or null) and the default. */
export function startsFolded(id: string, stored: string | null): boolean {
  if (stored === "1") return true;
  if (stored === "0") return false;
  return FOLDED_BY_DEFAULT.includes(id);
}
