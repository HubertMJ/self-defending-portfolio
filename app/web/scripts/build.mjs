// Builds src/ into dist/: content-hashed JS and CSS under dist/assets/, index.html with the hashed
// names substituted, and static/ copied as-is. The hashed names are what lets nginx serve
// /assets/* as immutable for a year while index.html is revalidated on every visit.
//
//   node scripts/build.mjs                    production build into dist/ (what the image ships)
//   node scripts/build.mjs --mock             the same page with the in-page mock (?mock=1) into dist-mock/
//   node scripts/build.mjs --outdir <dir>     into <dir> instead (relative to app/web)
//   node scripts/build.mjs --watch [--mock]   rebuild on change (pair with `npm run serve`)
//
// The mock is dev/test only (ADR 0035): without --mock, src/lib/mock-hook.ts is swapped for
// mock-hook.prod.ts at module resolution, so MockBackend and the fixtures are never bundled, and the
// mock banner is cut from index.html.

import * as esbuild from "esbuild";
import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { stripTodoContent } from "./strip-todo-content.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const arg = (name) => {
  const i = process.argv.indexOf(name);
  return i > 0 ? process.argv[i + 1] : undefined;
};
const watch = process.argv.includes("--watch");
const mock = process.argv.includes("--mock");
const out = resolve(root, arg("--outdir") ?? (mock ? "dist-mock" : "dist"));

/** Resolves the one import of the mock (./lib/mock-hook) to its null stub in a production build. */
const noMockPlugin = {
  name: "no-mock",
  setup(build) {
    build.onResolve({ filter: /(^|\/)mock-hook$/ }, (args) => ({ path: `${resolve(args.resolveDir, args.path)}.prod.ts` }));
  },
};

/** The mock banner has no use without the mock: the production page does not carry it. */
function stripMockBanner(html) {
  const stripped = html.replace(/<p class="mock-banner" id="mock-banner"[^>]*>[\s\S]*?<\/p>\n*/, "");
  if (stripped.includes("mock-banner")) throw new Error("build: the mock banner is still in index.html; update stripMockBanner");
  return stripped;
}

/** Rewrites {{name.ext}} placeholders in index.html to the hashed file esbuild produced. */
const htmlPlugin = {
  name: "html",
  setup(build) {
    build.onEnd(async (result) => {
      if (result.errors.length) return;
      const names = {};
      for (const [file, meta] of Object.entries(result.metafile.outputs)) {
        if (!meta.entryPoint) continue;
        const ext = file.endsWith(".css") ? "css" : "js";
        const entry = basename(meta.entryPoint).replace(/\.(ts|css)$/, "");
        names[`${entry}.${ext}`] = basename(file);
      }
      const template = await readFile(join(root, "src/index.html"), "utf8");
      const substituted = template.replace(/\{\{([\w.-]+)\}\}/g, (_, key) => {
        if (!names[key]) throw new Error(`index.html references {{${key}}} but no such entry was built`);
        return names[key];
      });
      // A production build ships no placeholder copy (FIX 2); the watch build keeps it so the owner
      // sees, while authoring, what is still to write. `npm run todo-content` lists it from source either way.
      const page = watch ? substituted : stripTodoContent(substituted);
      const html = mock ? page : stripMockBanner(page);
      await writeFile(join(out, "index.html"), html);
      await cp(join(root, "static"), out, { recursive: true });
      // The mock banner's styles, linked by lib/mock-hook.ts; only the mock build has them.
      if (mock) await cp(join(root, "src/mock.css"), join(out, "assets", "mock.css"));
      console.log(`built: ${Object.values(names).join(", ")}`);
    });
  },
};

await rm(out, { recursive: true, force: true });
await mkdir(join(out, "assets"), { recursive: true });

const options = {
  absWorkingDir: root,
  entryPoints: ["src/main.ts", "src/theme.ts", "src/styles.css"],
  outdir: join(out, "assets"),
  entryNames: "[name]-[hash]",
  bundle: true,
  minify: !watch,
  sourcemap: watch ? "inline" : false,
  // theme.ts runs as a classic blocking script; main.ts as a module. IIFE suits both.
  format: "iife",
  target: ["es2022", "chrome110", "firefox110", "safari16"],
  metafile: true,
  legalComments: "none",
  logLevel: "warning",
  plugins: mock ? [htmlPlugin] : [noMockPlugin, htmlPlugin],
};

if (watch) {
  const ctx = await esbuild.context(options);
  await ctx.watch();
  console.log(`watching src/ into ${out} ...`);
} else {
  await esbuild.build(options);
}
