# ADR 0017: Attack scenarios: a safety model for letting anonymous visitors attack the cluster

Date: 2026-10-01 · Status: accepted

## Context
Phase 5 lets any visitor of https://hubertjablon.ski press a button that runs an attack inside the
cluster and watch Falco detect it and Falco Talon respond. The portfolio API (session A of the phase
5/6 contract) executes the scenarios; this ADR fixes what a scenario may be, so that "an anonymous
person on the internet can make my cluster run attacks" stays a demo rather than an incident.

The threats are the obvious ones: a scenario that escapes its pod or namespace, reaches something
outside the cluster (or attacks a third party from it), exhausts the single 8 GB node, persists after
the run, or carries real malicious code that is dangerous on its own. Less obvious: a scenario that
only works because it was given privileges, which would teach the opposite of the project's message,
and a scenario that silently stops being detected after a Falco upgrade.

Options considered: realistic tooling (nmap, a reverse shell, a cryptominer binary, an EICAR-style
test file, a package-manager install) vs. behaviour-only scenarios built from busybox; a scenario
image vs. reusing the web image; scenarios as code in the API vs. as data in a ConfigMap; per-scenario
privileges (root, writable root filesystem, host access) vs. restricted pods everywhere.

## Decision

**Scenarios are data, reviewed next to the namespace they run in.** The four scenarios are one file,
`cluster/infra/sandbox/scenarios/scenarios.yaml`, rendered into ConfigMap `scenarios` in
`portfolio-api` (key `scenarios.yaml`, fixed name). Each entry is the contract's shape: id, title,
summary, MITRE technique, the Falco rule that detects it, the Talon response, `timeout_seconds`, a
PodSpec and an optional exec. The API adds only metadata (namespace `sandbox`, run-id label, quarantine
label `"false"`) and `activeDeadlineSeconds`, and must not hardcode ids. Changing what visitors can do
is a commit to that file, in the same directory as the sandbox's quota, network policy and Talon Role.

**Every scenario pod is a fully hardened pod.** PSS `restricted` (uid 10001, no privilege escalation,
all capabilities dropped, seccomp RuntimeDefault), no ServiceAccount token, no service links, the
scenario image only, resources stated. The point of the demo is that a perfectly ordinary hardened pod
is still detected and answered at run time; a scenario that needs privileges does not get them. Two
relaxations exist, both inside `restricted`, each documented on the scenario:
- `sensitive-file-read` has `supplementalGroups: [42]` (Alpine's `shadow` group), because a non-root
  process cannot open `/etc/shadow` and Falco's rule only fires on a *successful* open. The image keeps
  Alpine's `root:shadow 0640`; the file's mode is never loosened. Every account in the image is locked,
  so what the visitor sees holds no hash.
- `drop-and-execute` has `readOnlyRootFilesystem: false`, because Falco's drift rule only sees binaries
  in the overlayfs upper layer (an emptyDir is not overlayfs). It is bounded by an 8 MiB
  ephemeral-storage limit; the pod is non-root and can write `/tmp` and nothing that belongs to the
  image.

`make validate` renders each PodSpec as the Pod the API will create and runs the Kyverno gate over it
(`scripts/lib/scenario_pods.py`, wired into `scripts/validate-cluster.sh`), and checks every entry
against the contract (fields, fixed ids, response values, timeout <= 120 s, digest-pinned scenario
image, exec shape). A scenario that the cluster would refuse fails in CI, not on a visitor's click.

**No attack tooling, no payloads, no targets.** The scenario image (`app/scenario/Dockerfile`) is Alpine
3.24.2 by digest with the package manager, TLS libraries and build tools removed: busybox and musl. The
scenarios are behaviours - a terminal shell, `wget`, `cat /etc/shadow`, a copy of busybox executed from
`/tmp` - not malware; nothing in the image is harmful outside the demo, and the only "downloaded"
binary is a copy of one the image already has. Alpine rather than `busybox:musl` so the image has a
package database: it goes through the same Trivy gate, SBOM and keyless signature as every other image
(ADR 0011), and a database-less image would always scan "clean" without having been looked at.
Rejected: nmap, netcat reverse shells, miner binaries or EICAR files - each is either a real capability
handed to an anonymous visitor or a file that other scanners (and the node's owner) rightly treat as
malicious; a package-manager scenario - it needs root and egress to a mirror, both of which the sandbox
deliberately lacks.

**Nothing leaves the pod.** `sandbox` is default-deny with DNS as the only allowed flow (ADR 0013). The
network-tool scenario targets the pod's own loopback (`127.0.0.1:9`), so `wget` fails with "connection
refused" before any packet leaves the pod, and no DNS query is made: detection is on the process start.
No scenario names an external host or a cluster service.

**The blast radius is a quota.** `cluster/infra/sandbox/resourcequota.yaml`: 3 pods, 500m CPU and 512 MiB
(requests and limits), 128 MiB ephemeral storage, and zero Services, PVCs and ReplicationControllers for
the whole namespace; `limitrange.yaml` fills defaults and caps a container at 200m / 128 MiB / 16 MiB.
Scenario pods ask for 10m / 16 MiB and are capped at 100m / 32 MiB. On top of that, enforced by the API
per the contract: one run at a time, 3 runs per 10 minutes per client IP and 30 per hour in total,
`activeDeadlineSeconds` = `timeout_seconds` <= 120 s, and the pod deleted at the end of every run.
Whatever the API does, the quota is what the cluster will actually grant.

**Detection is tested, not assumed.** `tests/scenarios/offline.sh` checks without a cluster that Falco
loads the rules, that every scenario's rule and every Talon match is a loaded, enabled rule at a
forwarded priority, that Talon loads its rules, and that each scenario meets its rule's preconditions
under its own pod security context (and fails them without the relaxation it was given).
`tests/scenarios/run.sh` runs every scenario against the live cluster the way the API does and asserts
the alert, the Talon action and the end state.

## Consequences
- A visitor can make the cluster run, at most, one hardened busybox pod at a time for at most two
  minutes, inside 500m CPU and 512 MiB, with no network beyond its own loopback and DNS.
- The scenarios are not "real" attacks in the tooling sense; they are the behaviours real attacks
  exhibit. That is a deliberate trade: the demo shows detection and response, not offensive tooling.
- The two relaxations are visible in the ConfigMap and in this ADR; both stay within PSS `restricted`
  and pass every Kyverno policy. Neither applies to any other pod in the cluster.
- The scenario image digest is a placeholder (all zeros) until the first build of `app/scenario` on
  main. Until then `make validate` judges the scenario pods with hello's signed image standing in for
  the signature check only, and says so; `tests/scenarios/run.sh` refuses to run without a real digest
  or `SCENARIO_IMAGE`.
- Deploying the ConfigMap is the portfolio-api Application's job (an extra source,
  `cluster/infra/sandbox/scenarios`), because the namespace is that Application's; the sandbox
  Application does not render it.
