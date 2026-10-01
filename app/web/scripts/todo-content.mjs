// Lists the placeholder copy the owner still has to write (marked TODO-CONTENT in src/index.html).
// `--strict` exits non-zero while any remain, for a pre-release check.

import { readFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const file = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "index.html");
const lines = (await readFile(file, "utf8")).split("\n");
const hits = lines.flatMap((l, i) => (l.includes("TODO-CONTENT:") && l.includes("<!--") ? [`src/index.html:${i + 1}: ${l.trim().replace(/^<!--\s*|\s*-->$/g, "")}`] : []));
console.log(hits.length ? hits.join("\n") : "no TODO-CONTENT left");
if (process.argv.includes("--strict") && hits.length) process.exit(1);
