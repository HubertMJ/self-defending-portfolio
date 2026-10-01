// A small static server for dist/ that behaves like the production nginx for everything the page
// can observe: the same response headers (parsed from security-headers.conf, so the CSP cannot
// drift between the two), the same cache headers, and the same text/plain 404 for /api/*. Used by
// `npm run serve`, the dev loop and the Playwright suite. Not used in the image.
//
//   node scripts/serve.mjs [--port 4173] [--stub-events]
//   then open http://localhost:4173/?mock=1 for mock mode, or / for the offline state.
//
// --stub-events serves GET /api/events the way the API does (same headers, the retry + 2 KiB
// preamble, a replayed run, a heartbeat comment every 2 s), so the Playwright suite can drive the
// browser's real EventSource rather than only the in-page mock: the mock replaces the EventSource
// factory, so on its own it could never notice that the real one is never created. The replayed run
// carries every event type of the extended contract (pod lifecycle, victim probes, Falco output
// fields, Talon's actionner), in the API's exact field names, so the real parsing path sees them
// too. Everything else under /api stays a text/plain 404, which is how the page meets an API without
// the details/runs/limits endpoints: it must degrade, not break.

import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dist = join(root, "dist");
const portArg = process.argv.indexOf("--port");
const port = Number(portArg > 0 ? process.argv[portArg + 1] : process.env.PORT ?? 4173);
const stubEvents = process.argv.includes("--stub-events");

// One finished "shell-in-container" run, as the extended API replays it: [event name, payload].
function replayedRun() {
  const t0 = Date.parse("2026-10-01T12:00:00Z");
  const at = (ms) => new Date(t0 + ms).toISOString().replace("Z", "123Z"); // RFC 3339 with sub-ms digits
  const run_id = "stub0000000000000000";
  const pod = "scenario-shell-in-container-stub0";
  const scenario = "shell-in-container";
  const image = "ghcr.io/hubertmj/self-defending-portfolio/scenario@sha256:abe9585fe91fec1881895ae79418f6b756a4ca094c9e5e7f0b3dd8a1a76cdea0";
  const podEv = (ms, phase, extra = {}) => ["pod", { run_id, pod, uid: "0f6b2d1c-6a8e-4c39-b1f2-6c0d2e9a7b11", phase, reason: "", container_id: "", image, labels_delta: {}, deleted: false, at: at(ms), ...extra }];
  const cid = "9b2e7c4d1a0f";
  return [
    ["run", { run_id, scenario, state: "queued", at: at(0), detail: "" }],
    ["run", { run_id, scenario, state: "started", at: at(60), detail: "pod created", pod }],
    podEv(90, "Pending", { labels_delta: { "sdp.hubertjablon.ski/quarantine": "false", "sdp.hubertjablon.ski/run-id": run_id } }),
    podEv(1750, "Running", { container_id: cid }),
    ["run", { run_id, scenario, state: "pod_ready", at: at(1790), detail: cid, pod }],
    ["victim", { run_id, pod, at: at(1850), status: "up", title: "SDP Shop", banner: "Open for business", probe_ms: 4, checksum: "5e0c1a77d3b2f190" }],
    ["victim", { run_id, pod, at: at(1990), status: "defaced", title: "H4CK3D - SDP Shop", banner: "Page defaced from an interactive shell", probe_ms: 3, checksum: "d3fac3d0badc0de1" }],
    ["falco", { at: at(1931), rule: "Terminal shell in container", priority: "Notice", namespace: "sandbox", pod, output: `Notice A shell was spawned in a container with an attached terminal | user=<NA> user_uid=10001 process=sh command=sh -c id; hostname; sleep 60 container_id=${cid} k8s_ns=sandbox k8s_pod_name=${pod}`, fields: { "evt.type": "execve", "proc.name": "sh", "proc.cmdline": "sh -c id; hostname; sleep 60", "proc.pname": "runc", "user.name": "<NA>", "user.uid": 10001, "container.id": cid, "container.image.repository": "ghcr.io/hubertmj/self-defending-portfolio/scenario", "k8s.pod.name": pod, "k8s.ns.name": "sandbox" }, api_received_at: at(1957) }],
    ["run", { run_id, scenario, state: "detected", at: at(1960), detail: "Terminal shell in container", pod }],
    ["talon", { at: at(1986), action: "Terminate Pod", actionner: "kubernetes:terminate", namespace: "sandbox", pod, status: "success", output: `the pod '${pod}' in the namespace 'sandbox' has been terminated`, api_received_at: at(1999) }],
    podEv(2004, "Terminating", { container_id: cid }),
    ["run", { run_id, scenario, state: "responded", at: at(2010), detail: "terminate", pod }],
    podEv(2051, "Deleted", { container_id: cid, deleted: true, labels_delta: {} }),
    ["victim", { run_id, pod, at: at(2350), status: "gone", title: "", banner: "", probe_ms: 0, checksum: "" }],
    ["run", { run_id, scenario, state: "finished", at: at(2600), detail: "", pod }],
  ];
}

function eventStream(req, res) {
  res.writeHead(200, { ...base, "Content-Type": "text/event-stream", "Cache-Control": "no-store, no-transform", "X-Accel-Buffering": "no" });
  res.write("retry: 5000\n\n:" + " ".repeat(2048) + "\n\n");
  replayedRun().forEach(([event, data], i) => res.write(`id: ${i + 1}\nevent: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
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
