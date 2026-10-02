// Fixture data for mock mode and tests. Shapes follow the phase 5/6 contract and its extension field
// for field; timings and ids are illustrative, not measurements from the live cluster. The scenario
// list mirrors the live catalogue (cluster/infra/sandbox/scenarios/scenarios.yaml) -- ids, titles,
// techniques, rules and responses -- so mock mode shows what the live page shows; the live page always
// renders whatever /api/scenarios returns.

import type { CatalogueCommand, Objective, Posture, Scenario, ScenarioDetails, SourceRef, Stats, VictimStatus } from "./contract";

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
    kube_bench: { last_run: new Date(now - 5 * 3600_000).toISOString(), pass: 98, fail: 4, warn: 21, info: 2 },
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

// ---- Terminal scenario (ADR 0033; CLUSTER writes the real catalogue in scenarios.yaml) ----
//
// This fixture follows the contract's schema so the page can be built and tested offline. The live
// page always renders whatever GET /api/scenarios/terminal/details returns; these values only drive
// `?mock=1`. Objectives are in kill-chain order; the quiet commands come first by design.

export const TERMINAL_OBJECTIVES: Objective[] = [
  { id: "recon", title: "Look around" },
  { id: "tamper", title: "Change the shop" },
  { id: "flag", title: "Read the run's flag" },
  { id: "beacon", title: "Call home" },
  { id: "credentials", title: "Steal credentials" },
  { id: "execute", title: "Run your own code" },
];

export const TERMINAL_COMMANDS: CatalogueCommand[] = [
  {
    id: "whoami", input: "id", aliases: ["whoami"], objective: "recon", technique: "T1033",
    command: ["id"], tty: false, outcome: "allowed", layer: "pod-security",
    control: "Pod Security: the pod runs as a non-root user",
    explain: "You are uid 10001, not root. Nothing in this pod runs privileged — admission would have rejected it.",
  },
  {
    id: "hostname", input: "hostname", aliases: [], objective: "recon", technique: "T1082",
    command: ["hostname"], tty: false, outcome: "allowed", layer: "runtime",
    control: "Nothing: reading your own hostname trips no rule",
    explain: "Just the pod's name. No cluster name, no node, no neighbours — the pod can see only itself.",
  },
  {
    id: "ps", input: "ps -o pid,user,args", aliases: ["ps"], objective: "recon", technique: "T1057",
    command: ["ps", "-o", "pid,user,args"], tty: false, outcome: "allowed", layer: "runtime",
    control: "Nothing: listing your own processes trips no rule",
    explain: "Only the shop server and your own shell. No sidecars, no agents sharing this pod.",
  },
  {
    id: "ls-shop", input: "ls -la /srv/shop", aliases: ["ls"], objective: "recon", technique: "T1083",
    command: ["ls", "-la", "/srv/shop"], tty: false, outcome: "allowed", layer: "runtime",
    control: "Nothing: the shop's own files are yours to list",
    explain: "The shop serves these two files, plus a 0600 flag you cannot read as it is — but can as this user.",
  },
  {
    id: "caps", input: "grep Cap /proc/self/status", aliases: ["capabilities"], objective: "recon", technique: "T1082",
    command: ["grep", "Cap", "/proc/self/status"], tty: false, outcome: "allowed", layer: "pod-security",
    control: "Pod Security: every Linux capability is dropped",
    explain: "CapEff is all zeros. No raw sockets, no mount, no ptrace — a whole class of attacks is simply off the table.",
  },
  {
    id: "deface", input: "deface the shop", aliases: ["deface"], objective: "tamper", technique: "T1491.002",
    command: ["sh", "-c", "cd /srv/shop && printf '%s' '<h1>Owned</h1>' > .i && mv .i index.html && printf '%s' '{\"status\":\"defaced\",\"title\":\"H4CK3D\",\"banner\":\"You changed the shop from inside the pod\"}' > .s && mv .s state.json"],
    tty: false, outcome: "allowed", layer: "runtime",
    control: "Nothing watches an app rewriting its own web root",
    explain: "The shop window changes beside you — and no rule fires. Nothing here watches the app write its own docroot; that is the app's job to do.",
  },
  {
    id: "read-flag", input: "cat /srv/shop/.flag", aliases: ["flag"], objective: "flag", technique: "T1552.001",
    command: ["cat", "/srv/shop/.flag"], tty: false, outcome: "allowed", layer: "runtime",
    control: "Nothing: reading a file in your own volume trips no rule",
    explain: "You read the run's flag. Detection is not prevention — but reading it is not getting it out: this pod has no network to send it over.",
  },
  {
    id: "touch-bin", input: "touch /bin/backdoor", aliases: [], technique: "T1222.002",
    command: ["touch", "/bin/backdoor"], tty: false, outcome: "prevented", layer: "pod-security",
    control: "Pod Security: a read-only root filesystem",
    explain: "Read-only file system. The write just fails — nothing is killed, because there was nothing to detect: the kernel refused it.",
  },
  {
    id: "read-token", input: "cat /var/run/secrets/kubernetes.io/serviceaccount/token", aliases: ["token"], technique: "T1528",
    command: ["cat", "/var/run/secrets/kubernetes.io/serviceaccount/token"], tty: false, outcome: "prevented", layer: "pod-security",
    control: "No service-account token is mounted",
    explain: "No such file. The pod has no token, so there is nothing to steal and nothing to talk to the API server with.",
  },
  {
    id: "ping", input: "ping -c1 127.0.0.1", aliases: [], technique: "T1016",
    command: ["ping", "-c1", "127.0.0.1"], tty: false, outcome: "prevented", layer: "pod-security",
    control: "Pod Security: no NET_RAW capability",
    explain: "ping needs a raw socket, which needs a capability this pod does not have. It fails before a packet is built.",
  },
  {
    id: "beacon", input: "wget -q -T 2 -O- http://127.0.0.1:9/", aliases: ["wget", "beacon"], objective: "beacon", technique: "T1071.001",
    command: ["wget", "-q", "-T", "2", "-O-", "http://127.0.0.1:9/"], tty: false, outcome: "detected", layer: "network",
    control: "Falco → Talon quarantine, then Cilium cuts the pod off",
    detection: "SDP network tool in sandbox", response: "quarantine",
    explain: "Falco saw a network tool start and Talon quarantined the pod. The run goes on — your shell still works in a quarantined pod — but the shop is now unreachable: Cilium drops every packet.",
  },
  {
    id: "read-shadow", input: "cat /etc/shadow", aliases: ["shadow"], objective: "credentials", technique: "T1003.008",
    command: ["cat", "/etc/shadow"], tty: false, outcome: "detected", layer: "runtime",
    control: "Falco → Talon terminate",
    detection: "Read sensitive file untrusted", response: "terminate",
    explain: "Falco saw an untrusted program read a sensitive file. Talon deleted the pod — your session ends here. (Every account was locked anyway.)",
  },
  {
    id: "shell", input: "sh -i", aliases: ["shell"], objective: "execute", technique: "T1059.004",
    command: ["sh", "-i"], tty: true, outcome: "detected", layer: "runtime",
    control: "Falco → Talon terminate",
    detection: "Terminal shell in container", response: "terminate",
    explain: "An interactive shell with a terminal attached is exactly what Falco's stock rule catches. Talon deleted the pod.",
  },
  {
    id: "drop-run", input: "drop a binary and run it", aliases: ["drop"], objective: "execute", technique: "T1105",
    command: ["sh", "-c", "cp /bin/busybox /srv/shop/bb && exec /srv/shop/bb sleep 60"],
    tty: false, outcome: "detected", layer: "runtime",
    control: "Falco → Talon terminate",
    detection: "Execution from the shop volume in sandbox", response: "terminate",
    explain: "You ran a binary from the writable shop volume. A custom Falco rule catches execution from that volume; Talon deleted the pod.",
  },
];

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
    timeout_seconds: 120,
    idle_seconds: 30,
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

/** `${FLAG}` is replaced with the run's own flag, which the mock generates per terminal run. */
export const TERMINAL_OUTPUT: Record<string, MockCommandOutput> = {
  whoami: { stdout: ["uid=10001 gid=10001 groups=10001,42"], exit: 0 },
  hostname: { stdout: ["scenario-terminal"], exit: 0 },
  ps: { stdout: ["  PID USER     ARGS", "    1 10001    /usr/local/bin/victim -docroot /srv/shop", "   14 10001    sh", "   21 10001    ps -o pid,user,args"], exit: 0 },
  "ls-shop": { stdout: ["total 16", "drwxrwxrwx 2 10001 10001 4096 index.html", "-rw-r--r-- 1 10001 10001  412 index.html", "-rw-r--r-- 1 10001 10001   96 state.json", "-rw------- 1 10001 10001   25 .flag"], exit: 0 },
  caps: { stdout: ["CapInh: 0000000000000000", "CapPrm: 0000000000000000", "CapEff: 0000000000000000", "CapBnd: 0000000000000000", "CapAmb: 0000000000000000"], exit: 0 },
  deface: { exit: 0 },
  "read-flag": { stdout: ["${FLAG}"], exit: 0 },
  "touch-bin": { stderr: ["touch: /bin/backdoor: Read-only file system"], exit: 1 },
  "read-token": { stderr: ["cat: can't open '/var/run/secrets/kubernetes.io/serviceaccount/token': No such file or directory"], exit: 1 },
  ping: { stderr: ["ping: permission denied (are you root?)"], exit: 1 },
  beacon: { stderr: ["wget: can't connect to remote host (127.0.0.1): Connection refused"], exit: 1 },
  "read-shadow": { stdout: ["root:*:19000:0:::::", "daemon:!:19000::::::", "nobody:!:19000::::::"], exit: 0 },
  shell: { stdout: ["/bin/sh: can't access tty; job control turned off"], exit: 137 },
  "drop-run": { exit: 137 },
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
    commands: {
      whoami: { attempts: 34, allowed: 34, prevented: 0, detected: 0 },
      deface: { attempts: 31, allowed: 31, prevented: 0, detected: 0 },
      "read-flag": { attempts: 22, allowed: 22, prevented: 0, detected: 0 },
      "touch-bin": { attempts: 12, allowed: 0, prevented: 12, detected: 0 },
      "read-token": { attempts: 9, allowed: 0, prevented: 9, detected: 0 },
      beacon: { attempts: 18, allowed: 0, prevented: 0, detected: 18 },
      "read-shadow": { attempts: 15, allowed: 0, prevented: 0, detected: 15 },
      shell: { attempts: 13, allowed: 0, prevented: 0, detected: 13 },
      "drop-run": { attempts: 8, allowed: 0, prevented: 0, detected: 8 },
    },
    objectives: {
      recon: { attempts: 37, achieved: 34 },
      tamper: { attempts: 31, achieved: 31 },
      flag: { attempts: 22, achieved: 22 },
      beacon: { attempts: 18, achieved: 18 },
      credentials: { attempts: 15, achieved: 15 },
      execute: { attempts: 0, achieved: 0 },
    },
    terminal: { runs: 37, best_objectives: 5, median_survival_s: 48 },
  };
}
