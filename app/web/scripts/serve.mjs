// A small static server for dist/ that behaves like the production nginx for everything the page
// can observe: the same response headers (parsed from security-headers.conf, so the CSP cannot
// drift between the two), the same cache headers, and the same text/plain 404 for /api/*. Used by
// `npm run serve`, the dev loop and the Playwright suite. Not used in the image.
//
//   node scripts/serve.mjs [--port 4173]
//   then open http://localhost:4173/?mock=1 for mock mode, or / for the offline state.

import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dist = join(root, "dist");
const portArg = process.argv.indexOf("--port");
const port = Number(portArg > 0 ? process.argv[portArg + 1] : process.env.PORT ?? 4173);

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".txt": "text/plain; charset=utf-8",
  ".json": "application/json",
};

async function securityHeaders() {
  const conf = await readFile(join(root, "security-headers.conf"), "utf8");
  const headers = {};
  for (const m of conf.matchAll(/^add_header\s+([\w-]+)\s+"([^"]*)"\s+always;/gm)) headers[m[1]] = m[2];
  if (!headers["Content-Security-Policy"]) throw new Error("security-headers.conf: no CSP found");
  return headers;
}

const base = await securityHeaders();

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://localhost");
  const send = (status, body, headers) => {
    res.writeHead(status, { ...base, ...headers });
    res.end(req.method === "HEAD" ? undefined : body);
  };
  if (req.method !== "GET" && req.method !== "HEAD") return send(405, "method not allowed\n", { "Content-Type": "text/plain" });
  if (url.pathname === "/api" || url.pathname.startsWith("/api/")) {
    return send(404, "not found\n", { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
  }
  let path = normalize(decodeURIComponent(url.pathname));
  if (path.includes("..") || /\/\./.test(path)) return send(404, "not found\n", { "Content-Type": "text/plain" });
  if (path.endsWith("/")) path += "index.html";
  const file = join(dist, path);
  try {
    if (!(await stat(file)).isFile()) throw new Error("not a file");
    const body = await readFile(file);
    const cache = path.startsWith("/assets/") ? "public, max-age=31536000, immutable" : "no-cache";
    send(200, body, { "Content-Type": TYPES[extname(file)] ?? "application/octet-stream", "Cache-Control": cache });
  } catch {
    // As nginx.conf: an error is never cacheable (a cached 404 for a hashed asset outlives a deploy).
    send(404, "not found\n", { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
  }
});

server.listen(port, "127.0.0.1", () => console.log(`serving dist/ on http://127.0.0.1:${port}`));
