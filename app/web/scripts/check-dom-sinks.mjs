// Fails if src/ uses a DOM API that parses strings as HTML or code. The page enforces Trusted Types
// (security-headers.conf), so such a call would already throw in the browser; this catches it in
// review instead of in production. All DOM is built through src/lib/dom.ts.

import { readFile, readdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const src = join(dirname(fileURLToPath(import.meta.url)), "..", "src");
const SINKS = /\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write(ln)?|srcdoc|createContextualFragment|eval|new\s+Function|setHTMLUnsafe|parseHTMLUnsafe)\b/;

let bad = 0;
for (const entry of await readdir(src, { recursive: true, withFileTypes: true })) {
  if (!entry.isFile() || !entry.name.endsWith(".ts")) continue;
  const file = join(entry.parentPath, entry.name);
  const lines = (await readFile(file, "utf8")).split("\n");
  lines.forEach((line, i) => {
    if (line.trim().startsWith("//")) return;
    if (SINKS.test(line)) {
      console.error(`${file}:${i + 1}: HTML/code sink: ${line.trim()}`);
      bad += 1;
    }
  });
}
if (bad) process.exit(1);
console.log("dom sinks: none");
