// Loads src/diagram/*.ts for a Node script: esbuild bundles the entry in memory and the module is
// imported from a data: URL, so the scripts (build.mjs, diagram.mjs) and the page share the one
// TypeScript model without a compiled copy on disk.

import * as esbuild from "esbuild";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

/** The exports of src/diagram/<name>.ts. */
export async function loadDiagram(name = "index") {
  const r = await esbuild.build({
    absWorkingDir: root,
    entryPoints: [`src/diagram/${name}.ts`],
    bundle: true,
    write: false,
    format: "esm",
    platform: "neutral",
    target: ["es2022"],
    logLevel: "warning",
  });
  const code = r.outputFiles[0].text;
  return import(`data:text/javascript;base64,${Buffer.from(code, "utf8").toString("base64")}`);
}
