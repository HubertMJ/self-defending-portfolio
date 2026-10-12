// Which sections start folded (site redesign 2026-10-12, ADR 0035 amendment): everything below the
// attack. A visitor's own choice is kept per section in localStorage under "sdp:collapsed:<id>":
// "1" folded, "0" open; no key means the default. theme.ts reads the same keys before first paint,
// so a page never jumps when ui/sections.ts mounts its buttons; without JavaScript nothing folds.

export const FOLD_KEY = "sdp:collapsed:";

/** The sections folded unless the visitor opened them. #attack stays open: it is the page. */
export const FOLDED_BY_DEFAULT: readonly string[] = ["correlation", "how", "evidence", "posture", "verify", "about", "skills", "projects"];

/** Whether a section starts folded, from its stored choice ("1", "0" or null) and the default. */
export function startsFolded(id: string, stored: string | null): boolean {
  if (stored === "1") return true;
  if (stored === "0") return false;
  return FOLDED_BY_DEFAULT.includes(id);
}
