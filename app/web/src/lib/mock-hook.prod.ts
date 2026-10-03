// What the production build resolves `./lib/mock-hook` to (scripts/build.mjs, ADR 0035): the same
// signature, no mock. `?mock=1` on the live site is then an ordinary query string.

import type { MockHook } from "./mock-hook";

export function installMock(_search: string): MockHook | null {
  return null;
}
