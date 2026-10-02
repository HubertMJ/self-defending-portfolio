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

// Mirrors cluster/infra/sandbox/scenarios/scenarios.yaml (scenario `terminal`): same ids, objectives
// and commands as the real catalogue, so the mock exercises exactly what the live API serves.
export const TERMINAL_OBJECTIVES: Objective[] = [
  { id: "recon", title: "Look around" },
  { id: "tamper", title: "Deface the shop" },
  { id: "credentials", title: "Steal credentials" },
  { id: "execution", title: "Run your own code" },
  { id: "exfiltration", title: "Phone home" },
];

export const TERMINAL_COMMANDS: CatalogueCommand[] = [
  {
    id: "whoami", input: "id", aliases: ["whoami"], objective: "recon", technique: "T1033",
    command: ["id"], tty: false, outcome: "allowed", layer: "runtime",
    control: "Falco is watching; plain recon matches no rule",
    explain: "You are an unprivileged user (uid 10001) in a hardened pod. Falco sees this and lets it pass — looking around is not, by itself, an attack.",
  },
  {
    id: "hostname", input: "hostname", aliases: [], objective: "recon", technique: "T1082",
    command: ["hostname"], tty: false, outcome: "allowed", layer: "runtime",
    control: "Falco is watching; plain recon matches no rule",
    explain: "The pod name, nothing more. No node name, no cluster detail — the pod was built without that information to leak.",
  },
  {
    id: "ps", input: "ps", aliases: ["ps aux"], objective: "recon", technique: "T1057",
    command: ["ps"], tty: false, outcome: "allowed", layer: "runtime",
    control: "Falco is watching; plain recon matches no rule",
    explain: "Only the shop server and your own command run here: one container, one job, nothing else to pivot to.",
  },
  {
    id: "ls-shop", input: "ls -la /srv/shop", aliases: [], objective: "recon", technique: "T1083",
    command: ["ls", "-la", "/srv/shop"], tty: false, outcome: "allowed", layer: "runtime",
    control: "Falco is watching; plain recon matches no rule",
    explain: "The shop's files, writable by you because this directory is the one writable spot in the pod. Note the .flag — that is a goal.",
  },
  {
    id: "caps", input: "grep Cap /proc/self/status", aliases: [], objective: "recon", technique: "T1082",
    command: ["grep", "Cap", "/proc/self/status"], tty: false, outcome: "allowed", layer: "pod-security",
    control: "Pod Security: every Linux capability dropped",
    explain: "CapEff is all zeros: the pod holds no Linux capabilities at all. That is why the next few tricks will not work.",
  },
  {
    id: "deface", input: "deface the shop", aliases: ["deface"], objective: "tamper", technique: "T1491.001",
    command: ["sh", "-c", "cd /srv/shop && printf '%s' '<h1>SDP Shop has been defaced</h1><p>Owned through the attacker terminal.</p>' > .i && mv .i index.html && printf '%s' '{\"status\":\"defaced\",\"title\":\"H4CK3D - SDP Shop\",\"banner\":\"Defaced from the terminal\"}' > .s && mv .s state.json && echo 'shop defaced'"],
    tty: false, outcome: "allowed", layer: "runtime",
    control: "Falco is watching; an app rewriting its own files is not drift",
    explain: "The shop window next to you just changed — you rewrote its page. Nothing stopped you: writing to your own working directory is normal for an app, so no rule here watches for it.",
  },
  {
    id: "read-flag", input: "cat /srv/shop/.flag", aliases: [], objective: "credentials", technique: "T1552.001",
    command: ["cat", "/srv/shop/.flag"], tty: false, outcome: "allowed", layer: "runtime",
    control: "Falco is watching; reading a file you can already open is not flagged",
    explain: "You found this run's flag. Reading it was allowed — but detection is not prevention, and reading a secret inside the pod is not the same as getting it out past a default-deny network.",
  },
  {
    id: "read-shadow", input: "cat /etc/shadow", aliases: [], objective: "credentials", technique: "T1003.008",
    command: ["cat", "/etc/shadow"], tty: false, outcome: "detected", layer: "runtime",
    control: "Falco rule Read sensitive file untrusted → terminate",
    detection: "Read sensitive file untrusted", response: "terminate",
    explain: "Falco caught an untrusted program opening the password database and Talon deleted the pod. What you got was worthless anyway: every account in the image is locked, there is no hash in the file.",
  },
  {
    id: "touch-bin", input: "touch /bin/backdoor", aliases: [], technique: "T1543",
    command: ["touch", "/bin/backdoor"], tty: false, outcome: "prevented", layer: "pod-security",
    control: "Pod Security: read-only root filesystem",
    explain: "“Read-only file system.” The root filesystem is immutable, so you cannot plant a backdoor in /bin. Nothing had to kill you — the write simply never happened.",
  },
  {
    id: "read-token", input: "cat /var/run/secrets/kubernetes.io/serviceaccount/token", aliases: [], technique: "T1528",
    command: ["cat", "/var/run/secrets/kubernetes.io/serviceaccount/token"], tty: false, outcome: "prevented", layer: "pod-security",
    control: "Pod Security: no ServiceAccount token mounted",
    explain: "“No such file or directory.” There is no token to steal: the pod was created with none, so it cannot talk to the Kubernetes API no matter what you run.",
  },
  {
    id: "chown-root", input: "chown 0 /srv/shop/index.html", aliases: [], technique: "T1222.002",
    command: ["chown", "0", "/srv/shop/index.html"], tty: false, outcome: "prevented", layer: "pod-security",
    control: "Pod Security: no CAP_CHOWN (all capabilities dropped)",
    explain: "“Operation not permitted.” Changing a file's owner needs a Linux capability the pod does not have; with every capability dropped, a whole class of tricks is off the table before any rule has to fire.",
  },
  {
    id: "beacon", input: "wget -q -T 2 -O- http://127.0.0.1:9/", aliases: ["wget"], objective: "exfiltration", technique: "T1071.001",
    command: ["wget", "-q", "-T", "2", "-O-", "http://127.0.0.1:9/"], tty: false, outcome: "detected", layer: "network",
    control: "Falco rule SDP network tool in sandbox → quarantine",
    detection: "SDP network tool in sandbox", response: "quarantine",
    explain: "A network tool started: Falco flagged it and Talon quarantined the pod. The run goes on — you still have a shell — but Cilium has cut every connection, both ways, so the shop next to you just went unreachable. You are trapped with nothing to call out to.",
  },
  {
    id: "shell", input: "sh -i", aliases: ["bash -i"], objective: "execution", technique: "T1059.004",
    command: ["sh", "-i"], tty: true, outcome: "detected", layer: "runtime",
    control: "Falco rule Terminal shell in container → terminate",
    detection: "Terminal shell in container", response: "terminate",
    explain: "A second interactive shell with a terminal attached is exactly the signature Falco watches for; Talon deleted the pod within a second or two. This ends your run.",
  },
  {
    id: "drop-run", input: "cp /bin/busybox /srv/shop/busybox && /srv/shop/busybox echo", aliases: ["drop and execute"], objective: "execution", technique: "T1105",
    command: ["sh", "-c", "cp /bin/busybox /srv/shop/busybox && exec /srv/shop/busybox echo 'dropped and ran'"],
    tty: false, outcome: "detected", layer: "runtime",
    control: "Falco rule SDP execution from shop volume → terminate",
    detection: "SDP execution from shop volume", response: "terminate",
    explain: "You copied a binary into the writable shop volume and ran it. The stock drift rule misses this — that volume is not the container's overlay layer — so a custom rule watches for execution from it. Falco caught it and Talon deleted the pod.",
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
  ps: { stdout: ["  PID USER     TIME  COMMAND", "    1 10001     0:00 /usr/local/bin/victim -docroot /srv/shop", "   14 10001     0:00 ps"], exit: 0 },
  "ls-shop": { stdout: ["total 16", "-rw-r--r--    1 10001    10001          412 index.html", "-rw-r--r--    1 10001    10001           96 state.json", "-rw-------    1 10001    10001           25 .flag"], exit: 0 },
  caps: { stdout: ["CapInh:\t0000000000000000", "CapPrm:\t0000000000000000", "CapEff:\t0000000000000000", "CapBnd:\t0000000000000000", "CapAmb:\t0000000000000000"], exit: 0 },
  deface: { stdout: ["shop defaced"], exit: 0 },
  "read-flag": { stdout: ["${FLAG}"], exit: 0 },
  // cat exits 0 before Talon's delete lands; the kill ends the run, not this command.
  "read-shadow": { stdout: ["root:*:19000:0:::::", "daemon:!:19000::::::", "nobody:!:19000::::::"], exit: 0 },
  "touch-bin": { stderr: ["touch: /bin/backdoor: Read-only file system"], exit: 1 },
  "read-token": { stderr: ["cat: can't open '/var/run/secrets/kubernetes.io/serviceaccount/token': No such file or directory"], exit: 1 },
  "chown-root": { stderr: ["chown: /srv/shop/index.html: Operation not permitted"], exit: 1 },
  beacon: { stderr: ["wget: can't connect to remote host (127.0.0.1): Connection refused"], exit: 1 },
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
      deface: { attempts: 31, allowed: 31, prevented: 0, detected: 0 },
      "read-flag": { attempts: 22, allowed: 22, prevented: 0, detected: 0 },
      "touch-bin": { attempts: 12, allowed: 0, prevented: 12, detected: 0 },
      "read-token": { attempts: 9, allowed: 0, prevented: 9, detected: 0 },
      "chown-root": { attempts: 6, allowed: 0, prevented: 6, detected: 0 },
      beacon: { attempts: 18, allowed: 0, prevented: 0, detected: 18 },
      "read-shadow": { attempts: 15, allowed: 0, prevented: 0, detected: 15 },
      shell: { attempts: 13, allowed: 0, prevented: 0, detected: 13 },
      "drop-run": { attempts: 8, allowed: 0, prevented: 0, detected: 8 },
    },
    // Objective counters, in the catalogue's order. `execution` has been tried but reached by no one
    // (every attempt was detected and killed), so the page shows it as "0 of N".
    objectives: {
      recon: { attempts: 121, achieved: 118 },
      tamper: { attempts: 31, achieved: 31 },
      credentials: { attempts: 37, achieved: 22 },
      execution: { attempts: 21, achieved: 0 },
      exfiltration: { attempts: 18, achieved: 0 },
    },
    terminal: { runs: 37, best_objectives: 3, median_survival_s: 48 },
  };
}
