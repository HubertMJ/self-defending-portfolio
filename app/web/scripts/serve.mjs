// A small static server for dist/ that behaves like the production nginx for everything the page
// can observe: the same response headers (parsed from security-headers.conf, so the CSP cannot
// drift between the two), the same cache headers, and the same text/plain 404 for /api/*. Used by
// `npm run serve`, the dev loop and the Playwright suite. Not used in the image.
//
//   node scripts/serve.mjs [--port 4173] [--dir dist|dist-mock] [--stub-events | --live-api | --terminal-api]
//   then open http://localhost:4173/?mock=1 for mock mode (with --dir dist-mock, the `npm run build:mock`
//   output: the production dist/ has no mock, ADR 0035), or / for the offline state.
//
// --stub-events serves GET /api/events the way the API does (same headers, the retry + 2 KiB
// preamble, a replayed run, a heartbeat comment every 2 s), so the Playwright suite can drive the
// browser's real EventSource rather than only the in-page mock: the mock replaces the EventSource
// factory, so on its own it could never notice that the real one is never created. The replayed run
// carries every event type of the extended contract (pod lifecycle, victim probes, Falco output
// fields, Talon's actionner), in the API's exact field names, so the real parsing path sees them
// too. Everything else under /api stays a text/plain 404, which is how the page meets an API without
// the details/runs/limits endpoints: it must degrade, not break.
//
// --live-api answers like the API deployed today, before the interactive work: the same event stream,
// /api/scenarios with the four one-click scenarios (no `interactive` field), posture, limits, details
// for those four, POST /api/attack/{id} accepted for them (`?compare=1` ignored, as that API does) —
// and a JSON 404 for everything the interactive work added: the terminal's details and attack,
// /api/stats, and /api/runs/{id} of a run it does not keep. The page must then offer the one-click
// demo as its attack section, with no terminal and no twin.
//
// --terminal-api answers like the interactive API (app/api/internal/runner/terminal.go and the
// server's handlers) and replays what a visitor sees who opens the page in the middle of someone
// else's terminal session: the stream's replay holds the run only from its quarantine on (`wget`,
// then `id`), GET /api/runs/{id} has the whole history with the same event ids, and the session then
// goes on live — `cat /etc/shadow` exits 0, Falco, Talon's terminate, the kill — each event exactly
// as the API publishes it. Every connection gets its own run, so parallel tests do not share one.
// With --slow-details the terminal's catalogue answers 1.5 s late, after the replay has arrived.
//
// --terminal-api also answers what ADR 0035 added: /api/stats with `last_run_at` and `last_24h`,
// /api/provenance, the /api/runs list, a posture naming its failures (/api/posture with Kyverno
// violations, failing kube-bench checks, Trivy's last scan, Falco's counted_since), /build.json, and
// on `/api/events?tick=1` an `event: tick` frame (no id) after the replay and then every 2 s instead
// of the heartbeat comment. `--terminal-api --no-cred` is the interactive API before ADR 0035: the
// /api/stats of today's shape (no `last_run_at`, no `last_24h`), none of the rest, no tick (a new
// page on the API deployed today).
//
// `--terminal-api --twin` replays, instead of the terminal session, a one-click run started side by
// side (ADR 0031): the guarded pod in `sandbox`, answered by Talon, and its twin in
// `sandbox-unguarded`, detected by Falco with nothing answering. The run is contained and still going
// (the API publishes `finished` only once the twin's hold is over), the case the evidence card, the
// history and the console must name the pod in and label each event of.

import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dirArg = process.argv.indexOf("--dir");
const dir = dirArg > 0 ? process.argv[dirArg + 1] : "dist";
if (dir !== "dist" && dir !== "dist-mock") throw new Error(`serve.mjs: --dir must be dist or dist-mock, not ${dir}`);
const dist = join(root, dir);
const portArg = process.argv.indexOf("--port");
const port = Number(portArg > 0 ? process.argv[portArg + 1] : process.env.PORT ?? 4173);
const liveApi = process.argv.includes("--live-api");
const terminalApi = process.argv.includes("--terminal-api");
const slowDetails = process.argv.includes("--slow-details");
const twin = terminalApi && process.argv.includes("--twin");
const cred = terminalApi && !process.argv.includes("--no-cred");
// This stub API "started" when the server did; the provenance and the ticks say so.
const startedAt = new Date().toISOString();
const stubEvents = liveApi || terminalApi || process.argv.includes("--stub-events");

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
  // The defacement is the pre_exec; the shell Falco detects comes ~1.5 s after it.
  return [
    ["run", { run_id, scenario, state: "queued", at: at(0), detail: "" }],
    ["run", { run_id, scenario, state: "started", at: at(60), detail: "pod created", pod }],
    podEv(90, "Pending", { labels_delta: { "sdp.hubertjablon.ski/quarantine": "false", "sdp.hubertjablon.ski/run-id": run_id } }),
    podEv(1750, "Running", { container_id: cid }),
    ["run", { run_id, scenario, state: "pod_ready", at: at(1790), detail: cid, pod }],
    ["victim", { run_id, pod, at: at(1850), status: "up", title: "SDP Shop", banner: "Open for business", probe_ms: 4, checksum: "5e0c1a77d3b2f190" }],
    ["victim", { run_id, pod, at: at(1990), status: "defaced", title: "H4CK3D - SDP Shop", banner: "Page defaced, attacker opening a shell", probe_ms: 3, checksum: "d3fac3d0badc0de1" }],
    ["falco", { at: at(3431), rule: "Terminal shell in container", priority: "Notice", namespace: "sandbox", pod, output: `Notice A shell was spawned in a container with an attached terminal | user=<NA> user_uid=10001 process=sh command=sh -c id; hostname; sleep 60 container_id=${cid} k8s_ns=sandbox k8s_pod_name=${pod}`, fields: { "evt.type": "execve", "proc.name": "sh", "proc.cmdline": "sh -c id; hostname; sleep 60", "proc.pname": "runc", "user.name": "<NA>", "user.uid": 10001, "container.id": cid, "container.image.repository": "ghcr.io/hubertmj/self-defending-portfolio/scenario", "k8s.pod.name": pod, "k8s.ns.name": "sandbox" }, api_received_at: at(3457) }],
    ["run", { run_id, scenario, state: "detected", at: at(3460), detail: "Terminal shell in container", pod }],
    ["talon", { at: at(3560), action: "Terminate Pod", actionner: "kubernetes:terminate", namespace: "sandbox", pod, status: "success", output: `the pod '${pod}' in the namespace 'sandbox' has been terminated`, api_received_at: at(3571) }],
    podEv(2004, "Terminating", { container_id: cid }),
    ["run", { run_id, scenario, state: "responded", at: at(3510), detail: "terminate", pod }],
    podEv(2051, "Deleted", { container_id: cid, deleted: true, labels_delta: {} }),
    ["victim", { run_id, pod, at: at(3850), status: "gone", title: "", banner: "", probe_ms: 0, checksum: "" }],
    ["run", { run_id, scenario, state: "finished", at: at(4100), detail: "", pod }],
  ];
}

/**
 * --twin: a side-by-side "network-tool" run, 6 s before `now` to now, as [event, data] in publish
 * order. Every run event names both pods, every per-pod event says its arm (app/api runner/compare.go).
 */
function twinRun(now) {
  const t0 = now - 6000;
  const at = (ms) => new Date(t0 + ms).toISOString();
  const run_id = "7e57aaaaaaaaaaaa";
  const scenario = "network-tool";
  const guarded = `scenario-network-tool-${run_id.slice(0, 10)}`;
  const unguarded = `${guarded}-u`;
  const pods = { guarded, unguarded };
  const image = "ghcr.io/hubertmj/self-defending-portfolio/scenario@sha256:abe9585fe91fec1881895ae79418f6b756a4ca094c9e5e7f0b3dd8a1a76cdea0";
  const cid = "9b2e7c4d1a0f";
  const run = (ms, state, detail = "") => ["run", { run_id, scenario, state, at: at(ms), detail, pods }];
  const podEv = (ms, arm, phase, extra = {}) => ["pod", { run_id, pod: pods[arm], uid: `0f6b2d1c-6a8e-4c39-b1f2-6c0d2e9a7b1${arm === "guarded" ? 1 : 2}`, phase, reason: "", container_id: cid, image, labels_delta: {}, deleted: false, at: at(ms), arm, ...extra }];
  const victim = (ms, arm, status, title, checksum) => ["victim", { run_id, pod: pods[arm], at: at(ms), status, title, banner: "", probe_ms: status === "unreachable" ? 300 : 4, checksum, arm }];
  const falco = (ms, arm) => {
    const ns = arm === "guarded" ? "sandbox" : "sandbox-unguarded";
    return ["falco", { at: at(ms), rule: "SDP network tool in sandbox", priority: "Warning", namespace: ns, pod: pods[arm], output: `Warning SDP network tool in sandbox | process=wget k8s_ns=${ns} k8s_pod_name=${pods[arm]}`, fields: { "proc.name": "wget", "k8s.pod.name": pods[arm], "k8s.ns.name": ns }, api_received_at: at(ms + 25), arm }];
  };
  return [
    run(0, "queued"),
    run(60, "started", "pod created"),
    podEv(90, "guarded", "Pending", { container_id: "" }),
    podEv(95, "unguarded", "Pending", { container_id: "" }),
    podEv(1750, "guarded", "Running"),
    podEv(1760, "unguarded", "Running"),
    run(1790, "pod_ready", cid),
    victim(1850, "guarded", "up", "SDP Shop", "5e0c1a77d3b2f190"),
    victim(1860, "unguarded", "up", "SDP Shop", "5e0c1a77d3b2f190"),
    victim(1990, "guarded", "compromised", "SDP Shop", "c0ffee00c0ffee00"),
    victim(2000, "unguarded", "compromised", "SDP Shop", "c0ffee00c0ffee00"),
    falco(2100, "guarded"),
    run(2130, "detected", "SDP network tool in sandbox"),
    falco(2120, "unguarded"),
    podEv(2240, "guarded", "Running", { labels_delta: { "sdp.hubertjablon.ski/quarantine": "true" } }),
    ["talon", { at: at(2245), action: "Quarantine Pod", actionner: "kubernetes:label", namespace: "sandbox", pod: guarded, status: "success", output: `the pod '${guarded}' in the namespace 'sandbox' has been labeled`, api_received_at: at(2260), arm: "guarded" }],
    run(2270, "responded", "quarantine"),
    victim(2700, "guarded", "unreachable", "", ""),
  ];
}

/**
 * Another visitor's terminal session, from 8 s before `now` to 2.5 s after, as [offset ms, event,
 * data] in publish order. `wget` (exit 1) is quarantined, `id` runs in the quarantined pod, then
 * `cat /etc/shadow` exits 0 before Talon's terminate deletes the pod and the run ends `killed`.
 */
function terminalSession(now, run_id) {
  const t0 = now - 8000;
  const at = (ms) => new Date(t0 + ms).toISOString();
  const pod = `terminal-${run_id.slice(0, 10)}`;
  const out = [];
  const add = (ms, event, data) => out.push([ms, event, data]);
  const run = (ms, state, detail = "", seq) => add(ms, "run", { run_id, scenario: "terminal", state, at: at(ms), detail, ...(state === "queued" ? {} : { pod }), ...(seq ? { command_seq: seq } : {}) });
  const cmd = (ms, seq, id, state, extra = {}) => add(ms, "command", { run_id, seq, id, state, at: at(ms), ...extra });
  const podEv = (ms, phase, extra = {}) => add(ms, "pod", { run_id, pod, uid: "5d0f6b2c-1a2b-4c3d-9e8f-0a1b2c3d4e5f", phase, reason: "", container_id: "9b2e7c4d1a0f", image: "ghcr.io/hubertmj/self-defending-portfolio/scenario@sha256:abe9585fe91fec1881895ae79418f6b756a4ca094c9e5e7f0b3dd8a1a76cdea0", labels_delta: {}, deleted: false, at: at(ms), ...extra });
  const victim = (ms, status, probe_ms = 3, shop = {}) => add(ms, "victim", { run_id, pod, at: at(ms), status, title: "", banner: "", probe_ms, checksum: "", ...shop });
  const falco = (ms, rule, seq) => add(ms, "falco", { at: at(ms - 20), rule, priority: "Warning", namespace: "sandbox", pod, output: `${rule} | k8s_ns=sandbox k8s_pod_name=${pod}`, fields: { "proc.name": "x", "k8s.pod.name": pod, "k8s.ns.name": "sandbox" }, api_received_at: at(ms), command_seq: seq });
  const talon = (ms, action, seq) => add(ms, "talon", { at: at(ms - 5), action: action === "label" ? "Quarantine Pod" : "Terminate Pod", actionner: `kubernetes:${action}`, namespace: "sandbox", pod, status: "success", output: "", api_received_at: at(ms), command_seq: seq });
  run(0, "queued");
  run(40, "started", "pod created");
  podEv(60, "Pending", { container_id: "", labels_delta: { "sdp.hubertjablon.ski/quarantine": "false", "sdp.hubertjablon.ski/run-id": run_id } });
  podEv(1800, "Running");
  run(1900, "pod_ready", "9b2e7c4d1a0f");
  victim(1950, "up", 4, { title: "SDP Shop", checksum: "5e0c1a77d3b2f190" });
  // `wget` fails (exit 1, on stderr) and is quarantined: the shell goes on, the shop goes dark.
  cmd(3000, 1, "beacon", "started");
  cmd(3010, 1, "beacon", "output", { stream: "stderr", chunk: "wget: can't connect to remote host (127.0.0.1): Connection refused\n" });
  cmd(3040, 1, "beacon", "exited", { exit_code: 1 });
  falco(3060, "SDP network tool in sandbox", 1);
  run(3075, "detected", "SDP network tool in sandbox", 1);
  podEv(3205, "Running", { labels_delta: { "sdp.hubertjablon.ski/quarantine": "true" } });
  talon(3210, "label", 1);
  run(3220, "responded", "quarantine", 1);
  victim(3900, "unreachable", 300);
  cmd(6000, 2, "whoami", "started");
  cmd(6010, 2, "whoami", "output", { stream: "stdout", chunk: "uid=10001 gid=10001 groups=10001,42\n" });
  cmd(6030, 2, "whoami", "exited", { exit_code: 0, achieved: true });
  // Live from here (now + 1.5 s): the read lands, then the kill.
  cmd(9500, 3, "read-shadow", "started");
  cmd(9510, 3, "read-shadow", "output", { stream: "stdout", chunk: "root:*:19000:0:::::\n" });
  cmd(9540, 3, "read-shadow", "exited", { exit_code: 0, achieved: true });
  falco(9560, "Read sensitive file untrusted", 3);
  run(9580, "detected", "Read sensitive file untrusted", 3);
  talon(9640, "terminate", 3);
  run(9650, "responded", "terminate", 3);
  podEv(9660, "Terminating");
  victim(9700, "gone", 0);
  podEv(9760, "Deleted", { deleted: true });
  run(9800, "finished", "killed");
  return out.map(([ms, event, data]) => [ms - 8000, event, data]);
}

// --terminal-api: each connection's session, by run id, with the hub ids it was sent with.
const sessions = new Map();
let nextSession = 0;
let nextEventId = 1000;

function eventStream(req, res, tick) {
  res.writeHead(200, { ...base, "Content-Type": "text/event-stream", "Cache-Control": "no-store, no-transform", "X-Accel-Buffering": "no" });
  res.write("retry: 5000\n\n:" + " ".repeat(2048) + "\n\n");
  const frame = (id, event, data) => res.write(`id: ${id}\nevent: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  (twin ? twinRun(Date.now()) : replayedRun()).forEach(([event, data], i) => frame(i + 1, event, data));
  const timers = [];
  if (terminalApi && !twin) {
    const run_id = `7e57${String(++nextSession).padStart(12, "0")}`;
    const events = terminalSession(Date.now(), run_id).map(([ms, event, data]) => ({ ms, id: ++nextEventId, event, data }));
    sessions.set(run_id, { connected: Date.now(), events });
    // The replay buffer reaches back only to the quarantine's `responded`; the rest arrives live.
    const from = events.findIndex((e) => e.event === "run" && e.data.state === "responded");
    for (const e of events.slice(from)) {
      if (e.ms <= 0) frame(e.id, e.event, e.data);
      else timers.push(setTimeout(() => frame(e.id, e.event, e.data), e.ms));
    }
  }
  // ADR 0035's opt-in tick: no id line, so Last-Event-ID and the replay are unaffected.
  const tickFrame = () => res.write(`event: tick\ndata: ${JSON.stringify({ at: new Date().toISOString(), started_at: startedAt })}\n\n`);
  if (tick) tickFrame();
  const heartbeat = setInterval(() => (tick ? tickFrame() : res.write(": heartbeat\n\n")), 2000);
  req.on("close", () => {
    clearInterval(heartbeat);
    timers.forEach(clearTimeout);
  });
}

const CATALOGUE = JSON.parse(await readFile(join(root, "src", "lib", "terminal-catalogue.json"), "utf8"));

const STUB_COMMIT = "0448cff5a1b2c3d4e5f60718293a4b5c6d7e8f90";
const STUB_DIGEST = (c) => `sha256:${c.repeat(64)}`;

/** What ADR 0035 added to the interactive API, as --terminal-api answers it; undefined for anything else. */
function credAnswer(method, path) {
  if (method !== "GET") return undefined;
  const now = Date.now();
  if (path === "/api/stats") {
    return [200, {
      since: "2026-10-03T06:44:28Z",
      runs: 19,
      by_scenario: { terminal: { runs: 12, detected: 9, responded: 9 }, "shell-in-container": { runs: 7, detected: 7, responded: 7 } },
      response_ms: { last: 110, p50: 140, min: 90, max: 420 },
      unanswered: 0,
      commands: {},
      objectives: {},
      terminal: { runs: 12, best_objectives: 2, median_survival_s: 41 },
      ...(cred ? { last_run_at: new Date(now - 8000).toISOString(), last_24h: { since: startedAt, runs: 3, detected: 2, responded: 2, falco_alerts: 4, talon_actions: 3 } } : {}),
    }];
  }
  if (!cred) return undefined;
  if (path === "/api/provenance") {
    return [200, {
      generated_at: new Date(now).toISOString(),
      api: { commit: STUB_COMMIT, ci_run_id: "18234567890", started_at: startedAt, images: [`ghcr.io/hubertmj/self-defending-portfolio/api@${STUB_DIGEST("b")}`] },
      web: { images: [`ghcr.io/hubertmj/self-defending-portfolio/web@${STUB_DIGEST("1")}`] },
      images_observed_at: new Date(now - 20_000).toISOString(),
    }];
  }
  if (path === "/build.json") return [200, { commit: STUB_COMMIT, ci_run_id: "18234567890" }];
  if (path === "/api/runs") {
    const runs = [...sessions.entries()].reverse().map(([run_id, s]) => ({ run_id, scenario: "terminal", state: "responded", started_at: new Date(s.connected - 8000).toISOString(), ended_at: null, detected: true, responded: true, events: s.events.length, truncated: false }));
    return [200, { runs, kept: 50 }];
  }
  if (path === "/api/posture") {
    return [200, {
      ...LIVE_POSTURE,
      kyverno: {
        policies: [...LIVE_POSTURE.kyverno.policies, { name: "restrict-image-registries", pass: 61, fail: 7, warn: 0 }],
        violations: [{ policy: "restrict-image-registries", rule: "autogen-validate-registries", kind: "ReplicaSet", namespace: "falco-response", count: 7, running: false, file: "cluster/infra/kyverno-policies/restrict-image-registries.yaml" }],
        violations_truncated: false,
      },
      trivy: { ...LIVE_POSTURE.trivy, last_scan: "2026-10-01T10:10:31Z" },
      kube_bench: {
        ...LIVE_POSTURE.kube_bench,
        fail: 3,
        failing: [
          { id: "1.1.9", title: "Ensure that the Container Network Interface file permissions are set to 600 or more restrictive", remediation: "Run the below command (based on the file location on your system) on the control plane node. For example, chmod 600 <path/to/cni/files>" },
          { id: "1.1.10", title: "Ensure that the Container Network Interface file ownership is set to root:root", remediation: "Run the below command (based on the file location on your system) on the control plane node. For example, chown root:root <path/to/cni/files>" },
          { id: "1.2.26", title: "Ensure that the --etcd-cafile argument is set as appropriate", remediation: "Follow the Kubernetes documentation and set up the TLS connection between the apiserver and etcd." },
        ],
      },
      falco: { alerts_24h: 4, counted_since: startedAt },
      talon: { actions_24h: 3 },
    }];
  }
  return undefined;
}

/** The interactive API of --terminal-api (what the page reads while watching), else undefined. */
function terminalApiAnswer(method, path) {
  const added = credAnswer(method, path);
  if (added) return added;
  if (method === "GET" && path === "/api/scenarios") {
    return [200, [...LIVE_SCENARIOS.map((s) => ({ ...s, interactive: false })), { id: "terminal", title: "Attacker's terminal", summary: "Type into a hardened pod.", technique: "T1059.004", detection: "", response: "", victim: true, interactive: true }]];
  }
  if (method === "GET" && path === "/api/scenarios/terminal/details") {
    return [200, { pre_exec_command: [], exec_command: [], pod_security: { runAsUser: 10001, runAsNonRoot: true, capabilities_drop: ["ALL"] }, resources: {}, image: { ref: "", digest: "" }, policies: [], commit: "", victim: true, interactive: true, ...CATALOGUE }];
  }
  const runId = /^\/api\/runs\/([0-9a-f]{16})$/.exec(path)?.[1];
  if (method === "GET" && runId) {
    const session = sessions.get(runId);
    if (!session) return [404, { error: "unknown run (only the last 50 runs are kept)" }];
    // The run store holds what was published so far, with the stream's own ids.
    const elapsed = Date.now() - session.connected;
    return [200, { run_id: runId, scenario: "terminal", events: session.events.filter((e) => e.ms <= elapsed).map((e) => ({ id: e.id, type: e.event, data: e.data })), truncated: false }];
  }
  return liveApiAnswer(method, path);
}

// GET /api/scenarios of today's API: the scenarios package's Public shape before `interactive`.
const LIVE_SCENARIOS = [
  ["shell-in-container", "Shell in a container", "T1059.004", "Terminal shell in container", "terminate"],
  ["network-tool", "Download tool in a container", "T1071.001", "SDP network tool in sandbox", "quarantine"],
  ["sensitive-file-read", "Read /etc/shadow", "T1003.008", "Read sensitive file untrusted", "terminate"],
  ["drop-and-execute", "Drop and run a new binary", "T1105", "Drop and execute new binary in container", "terminate"],
].map(([id, title, technique, detection, response]) => ({ id, title, summary: `${title}: one fixed attack, detected and answered.`, technique, detection, response, victim: true }));

const LIVE_POSTURE = {
  generated_at: "2026-10-01T11:59:00Z",
  kyverno: { policies: [{ name: "verify-portfolio-images", pass: 14, fail: 0, warn: 0 }] },
  trivy: { images: 27, critical: 0, high: 3, medium: 41, low: 88 },
  kube_bench: { last_run: "2026-10-01T07:00:00Z", pass: 98, fail: 4, warn: 21, info: 2 },
  falco: { alerts_24h: 17 },
  talon: { actions_24h: 9 },
};

/** The JSON API of --live-api, or undefined for a path it leaves to the static server. */
function liveApiAnswer(method, path) {
  const id = (re) => re.exec(path)?.[1];
  const known = (x) => LIVE_SCENARIOS.some((s) => s.id === x);
  if (method === "GET" && path === "/api/scenarios") return [200, LIVE_SCENARIOS];
  if (method === "GET" && path === "/api/posture") return [200, LIVE_POSTURE];
  if (method === "GET" && path === "/api/limits") {
    return [200, { per_visitor: { limit: 3, window_s: 600, remaining: 3, reset_in_s: 0 }, global: { limit: 30, window_s: 3600, remaining: 30 }, active_run: false, stream_slots_remaining: 60 }];
  }
  const details = id(/^\/api\/scenarios\/([^/]+)\/details$/);
  if (method === "GET" && details) {
    if (!known(details)) return [404, { error: "unknown scenario" }];
    return [200, { pre_exec_command: [], exec_command: ["sh", "-c", "id"], pod_security: { runAsUser: 10001, runAsNonRoot: true, capabilities_drop: ["ALL"] }, resources: {}, image: { ref: "ghcr.io/hubertmj/self-defending-portfolio/scenario@sha256:abe9585fe91fec1881895ae79418f6b756a4ca094c9e5e7f0b3dd8a1a76cdea0", digest: "" }, policies: [], commit: "", victim: true }];
  }
  const attack = id(/^\/api\/attack\/([^/]+)$/);
  if (method === "POST" && attack) return known(attack) ? [202, { run_id: "0f0e0d0c0b0a0908", scenario: attack, state: "queued" }] : [404, { error: "unknown scenario" }];
  if (method === "GET" && /^\/api\/runs\/[^/]+$/.test(path)) return [404, { error: "unknown run (only the last 50 runs are kept)" }];
  if (path.startsWith("/api/")) return [404, { error: "not found" }];
  return undefined;
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
  if (stubEvents && url.pathname === "/api/events") return eventStream(req, res, cred && url.searchParams.get("tick") === "1");
  if (slowDetails && url.pathname === "/api/scenarios/terminal/details") await new Promise((r) => setTimeout(r, 1500));
  const answer = terminalApi ? terminalApiAnswer(req.method, url.pathname) : liveApi ? liveApiAnswer(req.method, url.pathname) : undefined;
  if (answer) return send(answer[0], JSON.stringify(answer[1]), { "Content-Type": "application/json", "Cache-Control": "no-store" });
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

server.listen(port, "127.0.0.1", () => console.log(`serving ${dir}/ on http://127.0.0.1:${port}`));
