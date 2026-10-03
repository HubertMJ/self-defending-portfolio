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
against the contract (fields, fixed ids, response values, timeout <= 120 s - 300 s since the 2026-10-03
amendment - digest-pinned scenario image, exec shape). A scenario that the cluster would refuse fails in CI,
not on a visitor's click.

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
`activeDeadlineSeconds` = `timeout_seconds` <= 120 s (300 s since the 2026-10-03 amendment), and the pod
deleted at the end of every run.
Whatever the API does, the quota is what the cluster will actually grant.

**Detection is tested, not assumed.** `tests/scenarios/offline.sh` checks without a cluster that Falco
loads the rules, that every scenario's rule and every Talon match is a loaded, enabled rule at a
forwarded priority, that Talon loads its rules, and that each scenario meets its rule's preconditions
under its own pod security context (and fails them without the relaxation it was given).
`tests/scenarios/run.sh` runs every scenario against the live cluster the way the API does and asserts
the alert, the Talon action and the end state.

## Consequences
- A visitor can make the cluster run, at most, one hardened busybox pod at a time for at most two
  minutes (five since the 2026-10-03 amendment), inside 500m CPU and 512 MiB, with no network beyond its own
  loopback and DNS.
- The scenarios are not "real" attacks in the tooling sense; they are the behaviours real attacks
  exhibit. That is a deliberate trade: the demo shows detection and response, not offensive tooling.
- The two relaxations are visible in the ConfigMap and in this ADR; both stay within PSS `restricted`
  and pass every Kyverno policy. Neither applies to any other pod in the cluster.
- The scenario image digest is a placeholder (all zeros) until the first build of `app/scenario` on
  main (ADR 0016: images reach main in two merges). `scripts/check-image-digests.sh` fails
  `make validate` and CI while it is, so the catalogue cannot reach the cluster unpinned; with
  `ALLOW_PLACEHOLDER_DIGESTS=1` on a branch, `scripts/lib/scenario_pods.py` judges the scenario pods
  with hello's image standing in for the signature check only, and says so.
  `tests/scenarios/run.sh` refuses to run without a real digest or `SCENARIO_IMAGE`.
- Deploying the ConfigMap is the portfolio-api Application's job (an extra source,
  `cluster/infra/sandbox/scenarios`), because the namespace is that Application's; the sandbox
  Application does not render it.

## Amendment 2026-10-02: an interactive terminal and an unguarded twin (ADR 0031, 0032)

The safety model now covers two additions, each inside the same envelope this ADR set:

**The interactive terminal (ADR 0032).** A fifth scenario, `terminal`, lets the visitor run commands by hand
against a hardened pod instead of pressing one button. It does not widen the attack surface:
- the API accepts **command ids only**, never free text, so a visitor's typing never reaches the cluster as a
  command (contract hard rule); an unknown line is answered by the web, locally, and never sent;
- every command is a behaviour under the same `restricted`, signed, token-less, quota-bound, default-deny pod
  as the one-click scenarios; none prints the environment, names a host outside the pod, or resolves a name;
- the two relaxations it uses are the ones this ADR already documents - `supplementalGroups: [42]` (as
  `sensitive-file-read`) and a writable volume for a dropped binary - plus a per-run flag the API injects and
  the pod never serves. No new capability, no token, no weakened policy;
- the pod lives at most `timeout_seconds` (120; 300 since the 2026-10-03 amendment) and ends on idle, on the
  visitor leaving, on a kill, or at the deadline; the single-run slot and the sandbox quota bound it exactly as
  before.
Every command's claimed outcome is proven offline under the pod's own security context (`tests/scenarios/offline.sh`).

**The unguarded twin (ADR 0031).** `sandbox-unguarded` is a second sandbox with every preventive layer of this
ADR intact - `restricted`, signed images only, the quota and LimitRange, default-deny networking - and only the
automatic response absent (no Talon Role, no Talon rule matches it). It does not relax the safety model; it
removes the response so the response's worth is visible by contrast, while the pod stays just as contained.

## Amendment 2026-10-03: a scenario lives at most 300 s; the terminal 300 s, idle 90 s

The contract's ceiling on `timeout_seconds` - and with it `activeDeadlineSeconds` - is now **300 s** (was 120).
Visitors' terminal sessions, the owner's own included, ended "session over" while they were still reading:
the explanation shown after each command takes longer to read than the 30 s idle allowed, and two minutes
were not enough to try more than a few moves. The terminal now runs up to 300 s and ends after 90 s without a
command. The four one-click scenarios keep their 90 s; nothing about them changes.

The bound moved everywhere it is stated, together: the API's `scenarios.MaxTimeout`, `make validate`'s
`scripts/lib/scenario_pods.py`, and the cluster's own `require-sandbox-deadline` (ADR 0031 amendment). Two
checks were added while at it. The API's catalogue validation now **refuses** an entry over the bound (it used
to cap it silently, leaving the cluster to refuse the pod mid-run) and an interactive entry whose idle time
is not below its timeout (an idle timer that can never fire); `make validate` applies the same two rules. And
because the victim server exits on its own after 120 s by default (ADR 0022), the terminal's pod passes it a
lifetime as long as its timeout, which `make validate` now checks for every victim scenario - otherwise the
shop would die at two minutes in a five-minute session.

What it costs, accepted by the owner: the API runs **one run at a time** for everyone, so while one visitor
has a terminal open, another may wait up to five minutes before they can start anything, watching that
session read-only meanwhile. The rest of the envelope is unchanged - one hardened busybox pod at a time, the
same quota, no network beyond its loopback and DNS - so the Consequences above hold with "two minutes" read as
"five". The rate limits (3 per 10 minutes per visitor, 30 per hour) are unchanged: a slot held for five minutes
serves at most 12 terminal sessions an hour, fewer than the global budget allows.

## Amendment 2026-10-03: one command resolves a name, inside the cluster only (ADR 0034)

The 2026-10-02 amendment says no terminal command "resolves a name". One command now does, deliberately:
`dns-exfil` (ADR 0034) is the scenario the eBPF layer cannot see and the SIEM catches by correlation, and a
DNS lookup carrying the run's flag is its whole point. The exception is bounded so the envelope does not
grow:

- **Only under the reserved `.test` TLD, in one zone CoreDNS answers itself.** The name is
  `<label>.x.exfil.sdp.test.` (fully qualified, no search-domain expansion); CoreDNS serves `exfil.sdp.test`
  as a sinkhole (NXDOMAIN) and never forwards it, so the query ends inside the cluster and the flag never
  reaches a resolver outside the homelab. A live test proves no `exfil.sdp.test` query leaves CoreDNS.
- **The argv is fixed** like every command's (by id, no free text, no visitor input); the only variable part
  is the run's own flag, read from the pod's own file, which is meant to be read (ADR 0032).
- **No new reach.** The pod's DNS egress existed before (it is what makes quarantine observable); the twin
  has none and the lookup is dropped there; a quarantined pod's lookup is dropped too.

Every other command still prints no environment, names no host outside the pod and resolves no name.
