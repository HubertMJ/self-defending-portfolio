// A small static server for dist/ that behaves like the production nginx for everything the page
// can observe: the same response headers (parsed from security-headers.conf, so the CSP cannot
// drift between the two), the same cache headers, and the same text/plain 404 for /api/*. Used by
// `npm run serve`, the dev loop and the Playwright suite. Not used in the image.
//
//   node scripts/serve.mjs [--port 4173] [--stub-events]
//   then open http://localhost:4173/?mock=1 for mock mode, or / for the offline state.
//
// --stub-events serves GET /api/events the way the API does (same headers, the retry + 2 KiB
// preamble, a replayed run event, a heartbeat comment every 2 s), so the Playwright suite can drive
// the browser's real EventSource rather than only the in-page mock: the mock replaces the
// EventSource factory, so on its own it could never notice that the real one is never created.

import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dist = join(root, "dist");
const portArg = process.argv.indexOf("--port");
const port = Number(portArg > 0 ? process.argv[portArg + 1] : process.env.PORT ?? 4173);
const stubEvents = process.argv.includes("--stub-events");

// One replayed event in the API's exact shape (app/api/internal/runner RunEvent).
const replayedRun = JSON.stringify({ run_id: "stub0000000000000000", scenario: "shell-in-container", state: "finished", at: "2026-10-01T12:00:00Z", detail: "" });

function eventStream(req, res) {
  res.writeHead(200, { ...base, "Content-Type": "text/event-stream", "Cache-Control": "no-store, no-transform", "X-Accel-Buffering": "no" });
  res.write("retry: 5000\n\n:" + " ".repeat(2048) + "\n\n");
  res.write(`id: 1\nevent: run\ndata: ${replayedRun}\n\n`);
  const heartbeat = setInterval(() => res.write(": heartbeat\n\n"), 2000);
  req.on("close", () => clearInterval(heartbeat));
}

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
  if (stubEvents && url.pathname === "/api/events") return eventStream(req, res);
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
