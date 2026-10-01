// Fixture data for mock mode and tests. Shapes follow the phase 5/6 contract and its extension field
// for field; timings and ids are illustrative, not measurements from the live cluster. The scenario
// list mirrors the live catalogue (cluster/infra/sandbox/scenarios/scenarios.yaml) -- ids, titles,
// techniques, rules and responses -- so mock mode shows what the live page shows; the live page always
// renders whatever /api/scenarios returns.

import type { Posture, Scenario, ScenarioDetails, SourceRef, VictimStatus } from "./contract";

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
];

/** The commit the mock pretends the API was built from; a real one, so the mock's links resolve. */
export const MOCK_COMMIT = "a7cc041";
export const SCENARIO_IMAGE =
  "ghcr.io/hubertmj/self-defending-portfolio/scenario@sha256:abe9585fe91fec1881895ae79418f6b756a4ca094c9e5e7f0b3dd8a1a76cdea0";

const EXEC: Record<string, string[]> = {
  "shell-in-container": ["sh", "-c", "id; hostname; sleep 60"],
  "network-tool": ["wget", "-q", "-T", "2", "-O", "/dev/null", "http://127.0.0.1:9/"],
  "sensitive-file-read": ["cat", "/etc/shadow"],
  "drop-and-execute": ["sh", "-c", "cp /bin/busybox /tmp/busybox && exec /tmp/busybox sleep 60"],
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
      return [shop, { status: "defaced", title: "H4CK3D - SDP Shop", banner: "Page defaced from an interactive shell", checksum: "d3fac3d0badc0de1" }];
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
    trivy: { images: 27, critical: 0, high: 3, medium: 41, low: 88 },
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
