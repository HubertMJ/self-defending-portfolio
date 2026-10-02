// Builds src/ into dist/: content-hashed JS and CSS under dist/assets/, index.html with the hashed
// names substituted, and static/ copied as-is. The hashed names are what lets nginx serve
// /assets/* as immutable for a year while index.html is revalidated on every visit.
//
//   node scripts/build.mjs            production build into dist/
//   node scripts/build.mjs --watch    rebuild on change (pair with `npm run serve`)

import * as esbuild from "esbuild";
import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { stripTodoContent } from "./strip-todo-content.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "dist");
const watch = process.argv.includes("--watch");

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
      const html = watch ? substituted : stripTodoContent(substituted);
      await writeFile(join(out, "index.html"), html);
      await cp(join(root, "static"), out, { recursive: true });
      console.log(`built: ${Object.values(names).join(", ")}`);
    });
  },
};

await rm(out, { recursive: true, force: true });
await mkdir(join(out, "assets"), { recursive: true });

const options = {
  absWorkingDir: root,
  entryPoints: ["src/main.ts", "src/theme.ts", "src/styles.css"],
  outdir: "dist/assets",
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
  plugins: [htmlPlugin],
};

if (watch) {
  const ctx = await esbuild.context(options);
  await ctx.watch();
  console.log("watching src/ ...");
} else {
  await esbuild.build(options);
}
