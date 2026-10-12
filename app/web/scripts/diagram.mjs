// Writes docs/architecture/overview.svg from src/diagram/model.ts (`npm run diagram`). A unit test
// (test/unit/diagram.test.ts) fails when the committed file differs from what this writes, so the
// drawing on GitHub is always the model's, like `npm run catalogue` and the terminal catalogue.
//
//   node scripts/diagram.mjs            write the file
//   node scripts/diagram.mjs --check    exit 1 if the committed file is stale

import { readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadDiagram } from "./diagram-lib.mjs";

const web = join(dirname(fileURLToPath(import.meta.url)), "..");
const repo = join(web, "..", "..");
const out = join(repo, "docs", "architecture", "overview.svg");

/** Argo CD Applications: one file per app under cluster/apps/, the kustomization aside. */
export async function countArgoApps() {
  const files = await readdir(join(repo, "cluster", "apps"));
  return files.filter((f) => f.endsWith(".yaml") && f !== "kustomization.yaml").length;
}

const { renderDocsSvg, validateModel, FULL_MODEL } = await loadDiagram();
const problems = [...validateModel(), ...validateModel(FULL_MODEL)];
if (problems.length) {
  console.error(problems.join("\n"));
  process.exit(1);
}
const svg = renderDocsSvg({ argoApps: await countArgoApps() });
if (process.argv.includes("--check")) {
  const current = await readFile(out, "utf8").catch(() => "");
  if (current !== svg) {
    console.error("docs/architecture/overview.svg is stale: run `npm run diagram` in app/web");
    process.exit(1);
  }
  console.log("overview.svg: current");
} else {
  await writeFile(out, svg);
  console.log(`wrote ${out}`);
}
