// Fixture data for mock mode and tests. Shapes follow the phase 5/6 contract field for field; the
// values are illustrative, not measurements from the live cluster. Scenario ids match the ones the
// contract fixes; titles, rules and techniques are what the scenarios session is expected to ship
// and are only placeholders here -- the live page always renders whatever /api/scenarios returns.

import type { Posture, Scenario } from "./contract";

export const SCENARIOS: Scenario[] = [
  {
    id: "shell-in-container",
    title: "Shell in a running container",
    summary: "Opens an interactive shell inside a sandbox pod, the first move after most container compromises.",
    technique: "T1059.004",
    detection: "Terminal shell in container",
    response: "terminate",
  },
  {
    id: "network-tool",
    title: "Network reconnaissance tool",
    summary: "Runs a network scanner from inside the sandbox to map what the pod can reach.",
    technique: "T1046",
    detection: "Launch Suspicious Network Tool in Container",
    response: "quarantine",
  },
  {
    id: "sensitive-file-read",
    title: "Read of a sensitive file",
    summary: "Reads /etc/shadow from a process that has no business opening credential files.",
    technique: "T1003.008",
    detection: "Read sensitive file untrusted",
    response: "terminate",
  },
  {
    id: "package-manager-drift",
    title: "Package manager at runtime",
    summary: "Installs software into a running container, drifting it away from the signed image.",
    technique: "T1105",
    detection: "Launch Package Management Process in Container",
    response: "terminate",
  },
];

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
  const base = `${scenario.detection} (user=scenario user_uid=65532 container_id=4f1c2a9e8b7d k8s.ns=sandbox k8s.pod=${pod}`;
  switch (scenario.id) {
    case "shell-in-container":
      return `${base} shell=sh parent=runc cmdline=sh -i terminal=34816)`;
    case "network-tool":
      return `${base} proc=nc cmdline=nc -zv 10.43.0.1 443)`;
    case "sensitive-file-read":
      return `${base} file=/etc/shadow proc=cat cmdline=cat /etc/shadow)`;
    default:
      return `${base} proc=apk cmdline=apk add curl)`;
  }
}
