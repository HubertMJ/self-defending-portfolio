// Fixture data for mock mode and tests. Shapes follow the phase 5/6 contract and its extension field
// for field; timings and ids are illustrative, not measurements from the live cluster. The scenario
// list mirrors the live catalogue (cluster/infra/sandbox/scenarios/scenarios.yaml) -- ids, titles,
// techniques, rules and responses -- so mock mode shows what the live page shows; the live page always
// renders whatever /api/scenarios returns.

import type { BuildInfo, CatalogueCommand, Objective, Posture, Provenance, Scenario, ScenarioDetails, SourceRef, Stats, VictimStatus } from "./contract";
import catalogue from "./terminal-catalogue.json";
import correlationFixture from "./correlation-fixture.json";

/** Names this module's data in the mock's responses; a marker the production bundle must not contain (ADR 0035). */
export const FIXTURE_MARKER = "sdp-fixture-data-not-from-the-cluster";

export const SCENARIOS: Scenario[] = [
  {
    id: "shell-in-container",
    title: "Shell in a container",
    summary:
      "Opens an interactive shell inside a running, fully hardened pod - the first thing an attacker does after landing remote code execution. Falco sees a shell with a terminal attached; Talon deletes the pod within seconds.",
    technique: "T1059.004",
    detection: "Terminal shell in container",
    response: "terminate",
  },
  {
    id: "network-tool",
    title: "Download tool in a container",
    summary:
      "Runs wget inside a pod, the way an attacker fetches a second stage or talks to a command-and-control server. Falco flags the network tool; Talon quarantines the pod - it keeps running, but loses all network access, both ways.",
    technique: "T1071.001",
    detection: "SDP network tool in sandbox",
    response: "quarantine",
  },
  {
    id: "sensitive-file-read",
    title: "Read /etc/shadow",
    summary:
      "Reads the system password database from inside a pod, as an attacker hunting for credentials would. Falco flags an untrusted program opening a sensitive file; Talon deletes the pod.",
    technique: "T1003.008",
    detection: "Read sensitive file untrusted",
    response: "terminate",
  },
  {
    id: "drop-and-execute",
    title: "Drop and run a new binary",
    summary:
      "Writes a new executable into a running container and starts it - the classic \"download a payload and run it\" step. Falco sees a process whose binary was not part of the image; Talon deletes the pod.",
    technique: "T1105",
    detection: "Drop and execute new binary in container",
    response: "terminate",
  },
  {
    id: "terminal",
    title: "Attacker's terminal",
    summary:
      "Your hands on a real hardened pod: type commands, read the real output, and watch the shop window change — until the cluster stops you. Different moves end differently; the quiet ones get you further.",
    technique: "T1059.004",
    // The terminal's own detection/response are empty: each command carries its own (ADR 0033).
    detection: "",
    response: "",
    victim: true,
    interactive: true,
  },
];

/** The commit the mock pretends the API was built from; a real one, so the mock's links resolve. */
export const MOCK_COMMIT = "a7cc041";
export const SCENARIO_IMAGE =
  "ghcr.io/hubertmj/self-defending-portfolio/scenario@sha256:abe9585fe91fec1881895ae79418f6b756a4ca094c9e5e7f0b3dd8a1a76cdea0";

// The exec commands of the live catalogue: each first changes the victim shop, then attacks.
// shell-in-container defaces the shop in a pre_exec (no TTY), then opens the shell Falco detects.
const PRE_EXEC: Record<string, string[]> = {
  "shell-in-container": ["sh", "-c", "cd /srv/shop && echo '<h1>SDP Shop has been defaced</h1><p>Owned through remote code execution.</p>' > .index && mv .index index.html && echo '{\"status\":\"defaced\",\"title\":\"H4CK3D - SDP Shop\",\"banner\":\"Page defaced, attacker opening a shell\"}' > .state && mv .state state.json && sleep 1.5"],
};
const EXEC: Record<string, string[]> = {
  "shell-in-container": ["sh", "-c", "id; hostname; sleep 60"],
  "network-tool": ["sh", "-c", "cd /srv/shop && echo '{\"status\":\"compromised\",\"title\":\"SDP Shop\",\"banner\":\"Beaconing to a command-and-control server\"}' > .state && mv .state state.json && sleep 1 && exec wget -q -T 2 -O /dev/null http://127.0.0.1:9/"],
  "sensitive-file-read": ["sh", "-c", "cd /srv/shop && echo '{\"status\":\"compromised\",\"title\":\"SDP Shop\",\"banner\":\"Customer data exfiltrated\"}' > .state && mv .state state.json && sleep 1 && exec cat /etc/shadow"],
  "drop-and-execute": ["sh", "-c", "cd /srv/shop && echo '{\"status\":\"compromised\",\"title\":\"SDP Shop\",\"banner\":\"Compromised: unknown binary running\"}' > .state && mv .state state.json && sleep 1 && cp /bin/busybox /tmp/busybox && exec /tmp/busybox sleep 60"],
};

const FALCO_RULE: Record<string, SourceRef> = {
  "shell-in-container": { name: "Terminal shell in container", file: "", line: 0 },
  "network-tool": { name: "SDP network tool in sandbox", file: "cluster/infra/falco/kustomization.yaml", line: 151 },
  "sensitive-file-read": { name: "Read sensitive file untrusted", file: "", line: 0 },
  "drop-and-execute": { name: "Drop and execute new binary in container", file: "", line: 0 },
};

const TALON_RULE: Record<string, SourceRef> = {
  "shell-in-container": { name: "Kill terminal shell in sandbox", file: "cluster/infra/falco-response/talon/rules.yaml", line: 35 },
  "network-tool": { name: "Quarantine network tool in sandbox", file: "cluster/infra/falco-response/talon/rules.yaml", line: 47 },
  "sensitive-file-read": { name: "Kill sensitive file read in sandbox", file: "cluster/infra/falco-response/talon/rules.yaml", line: 68 },
  "drop-and-execute": { name: "Kill drifted binary in sandbox", file: "cluster/infra/falco-response/talon/rules.yaml", line: 80 },
};

/** GET /api/scenarios/{id}/details, as the extended API is expected to answer it. */
export function scenarioDetails(id: string): ScenarioDetails | null {
  if (!EXEC[id]) return null;
  return {
    pre_exec_command: PRE_EXEC[id] ?? [],
    exec_command: EXEC[id],
    pod_security: {
      runAsUser: 10001,
      runAsNonRoot: true,
      readOnlyRootFilesystem: id !== "drop-and-execute",
      allowPrivilegeEscalation: false,
      capabilities_drop: ["ALL"],
      seccomp: "RuntimeDefault",
      automountServiceAccountToken: false,
    },
    resources: { "requests.cpu": "10m", "requests.memory": "16Mi", "limits.cpu": "100m", "limits.memory": "32Mi" },
    // (the API sends {requests: {...}, limits: {...}}; parseScenarioDetails flattens it to these keys)
    image: { ref: SCENARIO_IMAGE, digest: SCENARIO_IMAGE.slice(SCENARIO_IMAGE.indexOf("@") + 1) },
    falco_rule: FALCO_RULE[id],
    talon_rule: TALON_RULE[id],
    policies: [
      { kind: "ClusterPolicy", name: "pod-security-restricted", file: "cluster/infra/kyverno-policies/pod-security-restricted.yaml" },
      { kind: "ClusterPolicy", name: "verify-portfolio-images", file: "cluster/infra/kyverno-policies/verify-portfolio-images.yaml" },
      { kind: "ClusterPolicy", name: "require-pod-resources", file: "cluster/infra/kyverno-policies/require-pod-resources.yaml" },
      { kind: "CiliumNetworkPolicy", name: "sandbox-dns-only", file: "cluster/infra/sandbox/ciliumnetworkpolicy.yaml" },
      { kind: "CiliumClusterwideNetworkPolicy", name: "quarantine", file: "cluster/infra/sandbox/quarantine-ccnp.yaml" },
    ],
    commit: MOCK_COMMIT,
    exec_tty: id === "shell-in-container",
    victim: true,
  };
}

/** What the victim app reports in each phase of a scenario (the scenario image's /state.json). */
export function victimScript(id: string): { status: VictimStatus; title: string; banner: string; checksum: string }[] {
  const shop = { status: "up" as const, title: "SDP Shop", banner: "Open for business", checksum: "5e0c1a77d3b2f190" };
  switch (id) {
    case "shell-in-container":
      return [shop, { status: "defaced", title: "H4CK3D - SDP Shop", banner: "Page defaced, attacker opening a shell", checksum: "d3fac3d0badc0de1" }];
    case "network-tool":
      return [shop, { status: "compromised", title: "SDP Shop", banner: "Beaconing to a command-and-control server", checksum: "5e0c1a77d3b2f190" }];
    case "sensitive-file-read":
      return [shop, { status: "compromised", title: "SDP Shop", banner: "Customer data exfiltrated", checksum: "5e0c1a77d3b2f190" }];
    default:
      return [shop, { status: "compromised", title: "SDP Shop", banner: "Compromised: unknown binary running", checksum: "5e0c1a77d3b2f190" }];
  }
}

export function posture(now: number = Date.now()): Posture {
  return {
    generated_at: new Date(now - 23_000).toISOString(),
    kyverno: {
      policies: [
        { name: "verify-portfolio-images", pass: 14, fail: 0, warn: 0 },
        { name: "disallow-latest-tag", pass: 61, fail: 0, warn: 0 },
        { name: "require-pod-resources", pass: 58, fail: 0, warn: 3 },
        { name: "pod-security-restricted", pass: 52, fail: 2, warn: 0 },
        { name: "restrict-image-registries", pass: 61, fail: 0, warn: 0 },
      ],
    },
    trivy: {
      images: 27,
      critical: 0,
      high: 3,
      medium: 41,
      low: 88,
      own: { images: 3, critical: 0, high: 0, fixable: 0 },
      third_party: { images: 24, critical: 0, high: 3, fixable: 3 },
      by_image: [
        { image: "quay.io/cilium/cilium:v1.19.8", own: false, critical: 0, high: 2, fixable: 2 },
        { image: "docker.io/rancher/mirrored-coredns-coredns:1.14.6", own: false, critical: 0, high: 1, fixable: 1 },
        { image: "ghcr.io/hubertmj/self-defending-portfolio/api:main", own: true, critical: 0, high: 0, fixable: 0 },
        { image: "ghcr.io/hubertmj/self-defending-portfolio/scenario:main", own: true, critical: 0, high: 0, fixable: 0 },
        { image: "ghcr.io/hubertmj/self-defending-portfolio/web:main", own: true, critical: 0, high: 0, fixable: 0 },
      ],
    },
    kube_bench: { last_run: new Date(now - 5 * 3600_000).toISOString(), pass: 98, fail: 4, warn: 21, info: 2, not_applicable: 17 },
    falco: { alerts_24h: 17 },
    talon: { actions_24h: 9 },
  };
}

/** The Falco output line each scenario would produce, abbreviated the way the API truncates it. */
export function falcoOutput(scenario: Scenario, pod: string): string {
  const f = falcoFields(scenario, pod);
  return `${scenario.detection} | evt_type=${f["evt.type"]} user=${f["user.name"]} user_uid=${f["user.uid"]} process=${f["proc.name"]} proc_exepath=/bin/${f["proc.name"]} parent=${f["proc.pname"]} command=${f["proc.cmdline"]} container_id=${f["container.id"]} k8s_ns=sandbox k8s_pod_name=${pod}`;
}

/** The allow-listed output_fields of the same alert. */
export function falcoFields(scenario: Scenario, pod: string): Record<string, string> {
  const common = { "user.name": "<NA>", "user.uid": "10001", "container.id": "4f1c2a9e8b7d", "container.image.repository": "ghcr.io/hubertmj/self-defending-portfolio/scenario", "k8s.pod.name": pod, "k8s.ns.name": "sandbox" };
  switch (scenario.id) {
    case "shell-in-container":
      return { ...common, "evt.type": "execve", "proc.name": "sh", "proc.cmdline": "sh -c id; hostname; sleep 60", "proc.pname": "runc" };
    case "network-tool":
      return { ...common, "evt.type": "execve", "proc.name": "wget", "proc.cmdline": "wget -q -T 2 -O /dev/null http://127.0.0.1:9/", "proc.pname": "runc" };
    case "sensitive-file-read":
      return { ...common, "evt.type": "openat", "proc.name": "cat", "proc.cmdline": "cat /etc/shadow", "proc.pname": "runc", "fd.name": "/etc/shadow" };
    default:
      return { ...common, "evt.type": "execve", "proc.name": "busybox", "proc.cmdline": "busybox sleep 60", "proc.pname": "sh" };
  }
}

// ---- Terminal scenario (ADR 0033) ----
//
// The catalogue is the real one: terminal-catalogue.json is generated from the `terminal` scenario of
// cluster/infra/sandbox/scenarios/scenarios.yaml by scripts/terminal-catalogue.mjs (and checked
// against it by the unit tests when SDP_SCENARIOS_YAML points at that file). Only the output each
// command prints in `?mock=1` (TERMINAL_OUTPUT below) is written here. The live page always renders
// whatever GET /api/scenarios/terminal/details returns.

export const TERMINAL_OBJECTIVES: Objective[] = catalogue.objectives;
export const TERMINAL_COMMANDS = catalogue.commands as CatalogueCommand[];

export function terminalDetails(): ScenarioDetails {
  return {
    pre_exec_command: [],
    exec_command: [],
    pod_security: {
      runAsUser: 10001, runAsNonRoot: true, readOnlyRootFilesystem: true, allowPrivilegeEscalation: false,
      capabilities_drop: ["ALL"], seccomp: "RuntimeDefault", automountServiceAccountToken: false,
    },
    resources: { "requests.cpu": "10m", "requests.memory": "16Mi", "limits.cpu": "100m", "limits.memory": "32Mi" },
    image: { ref: SCENARIO_IMAGE, digest: SCENARIO_IMAGE.slice(SCENARIO_IMAGE.indexOf("@") + 1) },
    policies: [
      { kind: "ClusterPolicy", name: "pod-security-restricted", file: "cluster/infra/kyverno-policies/pod-security-restricted.yaml" },
      { kind: "ClusterPolicy", name: "verify-portfolio-images", file: "cluster/infra/kyverno-policies/verify-portfolio-images.yaml" },
      { kind: "CiliumNetworkPolicy", name: "sandbox-dns-only", file: "cluster/infra/sandbox/ciliumnetworkpolicy.yaml" },
      { kind: "CiliumClusterwideNetworkPolicy", name: "quarantine", file: "cluster/infra/sandbox/quarantine-ccnp.yaml" },
    ],
    commit: MOCK_COMMIT,
    victim: true,
    interactive: true,
    timeout_seconds: catalogue.timeout_seconds,
    idle_seconds: catalogue.idle_seconds,
    objectives: TERMINAL_OBJECTIVES,
    commands: TERMINAL_COMMANDS,
  };
}

/** What each catalogue command prints in `?mock=1`: stdout/stderr lines and the exit code. */
export interface MockCommandOutput {
  stdout?: string[];
  stderr?: string[];
  exit: number;
}

/**
 * `${FLAG}` (a whole line) is replaced with the run's own flag, which the mock generates per terminal
 * run, and `${LABEL}` (anywhere in a line) with the DNS label dns-exfil makes of it, `sdp-<16 hex>`.
 */
export const TERMINAL_OUTPUT: Record<string, MockCommandOutput> = {
  whoami: { stdout: ["uid=10001 gid=10001 groups=10001,42"], exit: 0 },
  hostname: { stdout: ["scenario-terminal"], exit: 0 },
  ps: { stdout: ["  PID USER     TIME  COMMAND", "    1 10001     0:00 /usr/local/bin/victim -docroot /srv/shop", "   14 10001     0:00 ps"], exit: 0 },
  "ls-shop": { stdout: ["total 16", "-rw-r--r--    1 10001    10001          412 index.html", "-rw-r--r--    1 10001    10001           96 state.json", "-rw-------    1 10001    10001           25 .flag"], exit: 0 },
  caps: { stdout: ["CapInh:\t0000000000000000", "CapPrm:\t0000000000000000", "CapEff:\t0000000000000000", "CapBnd:\t0000000000000000", "CapAmb:\t0000000000000000"], exit: 0 },
  // Two redirections and nothing printed: the shop window is the only output.
  deface: { exit: 0 },
  "read-flag": { stdout: ["${FLAG}"], exit: 0 },
  // cat exits 0 before Talon's delete lands; the kill ends the run, not this command.
  "read-shadow": { stdout: ["root:*:19000:0:::::", "daemon:!:19000::::::", "nobody:!:19000::::::"], exit: 0 },
  "touch-bin": { stderr: ["touch: /bin/backdoor: Read-only file system"], exit: 1 },
  "read-token": { stderr: ["cat: can't open '/var/run/secrets/kubernetes.io/serviceaccount/token': No such file or directory"], exit: 1 },
  "chown-root": { stderr: ["chown: /srv/shop/index.html: Operation not permitted"], exit: 1 },
  beacon: { stderr: ["wget: can't connect to remote host (127.0.0.1): Connection refused"], exit: 1 },
  // CoreDNS answers the sinkhole zone itself; the resolver's address is scrubbed by the API (ADR 0021).
  "dns-exfil": { stdout: ["query ${LABEL}.x.exfil.sdp.test.", "Server:\t\t[ip]", "Address:\t[ip]:53", "", "** server can't find ${LABEL}.x.exfil.sdp.test.: NXDOMAIN", ""], exit: 0 },
  // `busybox echo` exits 0 before the kill; sh -i (TTY) has no output and is killed outright.
  "drop-run": { stdout: ["dropped and ran"], exit: 0 },
  shell: { exit: 0 },
};

export function stats(now: number = Date.now()): Stats {
  return {
    since: new Date(now - 36 * 86_400_000).toISOString(),
    runs: 1287,
    by_scenario: {
      "shell-in-container": { runs: 361, detected: 361, responded: 358 },
      // The owner's example in the contract: "call home: 0 of 412 attempts".
      "network-tool": { runs: 412, detected: 412, responded: 409 },
      "sensitive-file-read": { runs: 274, detected: 274, responded: 271 },
      "drop-and-execute": { runs: 203, detected: 203, responded: 201 },
      terminal: { runs: 37, detected: 29, responded: 27 },
    },
    response_ms: { last: 118, p50: 176, min: 94, max: 612 },
    unanswered: 11,
    // Command counters: allowed+prevented+detected == attempts (the outcome is fixed; that it holds
    // is the point). attempts is counted per command start, as the API's stats collector does.
    commands: {
      whoami: { attempts: 34, allowed: 34, prevented: 0, detected: 0 },
      hostname: { attempts: 12, allowed: 12, prevented: 0, detected: 0 },
      ps: { attempts: 15, allowed: 15, prevented: 0, detected: 0 },
      "ls-shop": { attempts: 21, allowed: 21, prevented: 0, detected: 0 },
      caps: { attempts: 7, allowed: 7, prevented: 0, detected: 0 },
      deface: { attempts: 31, allowed: 31, prevented: 0, detected: 0 },
      "read-flag": { attempts: 22, allowed: 22, prevented: 0, detected: 0 },
      "touch-bin": { attempts: 12, allowed: 0, prevented: 12, detected: 0 },
      "read-token": { attempts: 9, allowed: 0, prevented: 9, detected: 0 },
      "chown-root": { attempts: 6, allowed: 0, prevented: 6, detected: 0 },
      beacon: { attempts: 18, allowed: 0, prevented: 0, detected: 18 },
      "read-shadow": { attempts: 15, allowed: 0, prevented: 0, detected: 15 },
      shell: { attempts: 6, allowed: 0, prevented: 0, detected: 6 },
      "drop-run": { attempts: 8, allowed: 0, prevented: 0, detected: 8 },
    },
    // Objective counters are per run ("tried by X of the 37 terminal runs"), so none exceeds 37. A
    // command that exits 0 reaches its objective even when the kill follows: `cat /etc/shadow` and the
    // dropped binary both do, so credentials and execution are reached, while `wget` always fails
    // (exit 1) and phone-home stays at 0.
    objectives: {
      recon: { attempts: 36, achieved: 36 },
      tamper: { attempts: 29, achieved: 29 },
      credentials: { attempts: 30, achieved: 30 },
      execution: { attempts: 13, achieved: 8 },
      exfiltration: { attempts: 18, achieved: 0 },
    },
    terminal: { runs: 37, best_objectives: 4, median_survival_s: 48 },
  };
}

/** The mock's GET /api/provenance (ADR 0035): made-up digests, labelled as the mock's by the banner. */
export function provenance(now: number = Date.now()): Provenance {
  return {
    generated_at: new Date(now).toISOString(),
    api: { commit: "a7cc041e5d2b9f30c1a4e6b8d0f2a3c5e7f9b1d3", ci_run_id: "18000000001", started_at: new Date(now - 3 * 3600_000).toISOString(), images: [`ghcr.io/hubertmj/self-defending-portfolio/api@sha256:${"a".repeat(64)}`] },
    web: { images: [`ghcr.io/hubertmj/self-defending-portfolio/web@sha256:${"c".repeat(64)}`] },
    images_observed_at: new Date(now - 30_000).toISOString(),
  };
}

export const BUILD_INFO: BuildInfo = { commit: "a7cc041e5d2b9f30c1a4e6b8d0f2a3c5e7f9b1d3", ci_run_id: "18000000001" };

/** The ADR 0035 additions to the mock's /api/stats and /api/posture, on top of stats() and posture(). */
export function statsWindow(now: number = Date.now()): Pick<Stats, "last_run_at" | "last_24h"> {
  return { last_run_at: new Date(now - 40 * 60_000).toISOString(), last_24h: { since: new Date(now - 3 * 3600_000).toISOString(), runs: 6, detected: 5, responded: 5, falco_alerts: 17, talon_actions: 9 } };
}

export function postureAdditions(now: number = Date.now()): Posture {
  const p = posture(now);
  return {
    ...p,
    // The live names, long and unbreakable, so the layout is tested with them (a running pod: red).
    kyverno: {
      policies: p.kyverno.policies.map((x) => (x.name === "pod-security-restricted" ? { ...x, fail: 0 } : x.name === "restrict-image-registries" ? { ...x, fail: 2 } : x)),
      violations: [{ policy: "restrict-image-registries", rule: "autogen-validate-registries", kind: "ReplicaSet", namespace: "falco-response", count: 2, running: true, file: "cluster/infra/kyverno-policies/restrict-image-registries.yaml" }],
      violations_truncated: false,
    },
    trivy: { ...p.trivy, last_scan: new Date(now - 2 * 3600_000).toISOString() },
    falco: { ...p.falco, counted_since: new Date(now - 3 * 3600_000).toISOString() },
  };
}

// ---- Correlation (ADR 0036) ----
//
// GET /api/correlation and /api/correlation/rules in `?mock=1`: correlation-fixture.json, which
// scripts/serve.mjs --siem serves too, its times moved so that its anchor is the moment of the answer.

const CORRELATION_TIME_KEYS = new Set(["at", "first_at", "last_at", "since", "checked_at", "applied_at"]);

/** A copy of `v` with every time field moved by `deltaMs` (the fixture's times are relative to its anchor). */
export function shiftTimes(v: unknown, deltaMs: number): unknown {
  if (Array.isArray(v)) return v.map((x) => shiftTimes(x, deltaMs));
  if (typeof v !== "object" || v === null) return v;
  return Object.fromEntries(
    Object.entries(v).map(([k, x]) => [k, CORRELATION_TIME_KEYS.has(k) && typeof x === "string" && !Number.isNaN(Date.parse(x)) ? new Date(Date.parse(x) + deltaMs).toISOString() : shiftTimes(x, deltaMs)]),
  );
}

/** The mock's GET /api/correlation; `available: false` (and nothing else) with `&mock-siem=0`. */
export function correlation(now: number = Date.now(), available = true): unknown {
  if (!available) return { available: false, checked_at: new Date(now).toISOString() };
  return shiftTimes(correlationFixture.correlation, now - Date.parse(correlationFixture.anchor));
}

export const RULE_INDEX: unknown = correlationFixture.rules;

/**
 * An incident the mock's SIEM files for a terminal run of this page view (UX stage 1), in the shape
 * app/api/internal/incidents builds: the DNS exfil once its command exited 0, a contained intrusion
 * once Talon answered a detected command. `seq` and `startedAt` are the command's; ids are derived
 * from the run id, so a run files each kind once.
 */
export function runIncident(kind: "dns-exfil" | "contained-intrusion", runId: string, pod: string, seq: number, startedAt: number, opts: { command?: string; rule?: string; action?: "terminate" | "quarantine" } = {}): unknown {
  const at = (ms: number) => new Date(startedAt + ms).toISOString();
  const ref = `sandbox/${pod}`;
  if (kind === "dns-exfil") {
    return {
      id: `d${runId.slice(1)}`,
      kind,
      severity: "critical",
      title: `Exfiltration over DNS: this run's secret left ${ref} in a DNS query; Falco: no event`,
      run_id: runId,
      arm: "",
      first_at: at(0),
      last_at: at(437),
      attack: ["T1048.003", "T1071.004"],
      falco_events: 0,
      flag_match: true,
      ttd_ms: null,
      tti_ms: null,
      steps: [
        { at: at(0), source: "api", rule: "Terminal exfiltration command", rule_id: "8e4f5061-7283-4d94-bea5-c6d7e8f90a12", command_seq: seq, detail: `command dns-exfil (T1048.003, exfiltration) started on ${ref}` },
        { at: at(437), source: "hubble", rule: "DNS query carries an exfil label", rule_id: "7d3e4f50-6172-4c83-ad94-b5c6d7e8f901", command_seq: seq, detail: `DNS query under the exfil zone from ${ref}, FORWARDED egress UDP/53` },
      ],
      evidence: [{ type: "finding", id: `f${runId.slice(1)}` }],
    };
  }
  const quarantine = opts.action === "quarantine";
  return {
    id: `c${runId.slice(1)}`,
    kind,
    severity: "high",
    title: `Contained intrusion: ${opts.rule ?? "Falco alert"} on ${ref}, ${quarantine ? "quarantined" : "terminated"} by Talon in 12 ms`,
    run_id: runId,
    arm: "",
    first_at: at(0),
    last_at: at(480),
    attack: ["T1003.008"],
    falco_events: 1,
    flag_match: null,
    ttd_ms: 443,
    tti_ms: 12,
    steps: [
      { at: at(0), source: "api", rule: "", rule_id: "", command_seq: seq, detail: `command ${opts.command ?? "?"} started on ${ref}` },
      // Talon's record carries whole seconds: the page lists it by the end of its second.
      { at: new Date(Math.floor((startedAt + 455) / 1000) * 1000).toISOString(), source: "talon", rule: "Talon - pod terminated", rule_id: "", command_seq: seq, detail: `Talon: ${quarantine ? "Quarantine" : "Terminate"} Pod success on ${ref}` },
      { at: at(443), source: "falco", rule: "Credential file read in a sandbox pod", rule_id: "5b1c2d3e-4f50-4a61-8b72-93a4b5c6d7e8", command_seq: seq, detail: `Falco: ${opts.rule ?? "alert"} on ${ref}` },
      { at: at(455), source: "k8s-audit", rule: "", rule_id: "", command_seq: seq, detail: `${quarantine ? "patch" : "delete"} pods on ${ref} by Talon, response 200` },
    ],
    evidence: [{ type: "finding", id: `e${runId.slice(1)}` }],
  };
}
