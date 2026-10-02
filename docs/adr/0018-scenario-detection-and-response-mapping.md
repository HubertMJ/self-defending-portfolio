# ADR 0018: Attack scenarios: which Falco rule detects each one, and what Talon does about it

Date: 2026-10-01 · Status: accepted

## Context
ADR 0013 set up Falco 0.45.0 (modern eBPF), Falcosidekick and Falco Talon 0.3.0 with two response rules
scoped to `sandbox`: kill on "Terminal shell in container", quarantine on the custom "SDP network tool
in sandbox". Phase 5 adds four visitor-triggered scenarios (ADR 0017) with fixed ids for three of them
(`shell-in-container` -> terminate, `network-tool` -> quarantine, `sensitive-file-read` -> terminate)
and a fourth drift/execution scenario of this session's choice.

Each scenario must fire one specific, explainable rule *reliably* under PSS `restricted` (non-root, no
capabilities, no privilege escalation, read-only root filesystem where possible), and each rule must
map to exactly one Talon action. Custom rules are a maintenance cost and a credibility cost ("they
wrote a rule that matches their own demo"), so stock rules are preferred where one fits.

Options considered for the fourth scenario: a package manager in a container (the stock "Launch
Package Management Process in Container" is not in the 0.45.0 image's default ruleset, and installing
needs root and egress), execution from `/dev/shm` (stock, but the container runtime mounts `/dev/shm`
`noexec`, so the exec fails), fileless execution via `memfd_create` (stock, but needs a purpose-built
binary in the image), and drop-and-execute (stock, CRITICAL, needs only a copy of an existing binary).

## Decision

| id | exec (container `target`) | Falco rule (0.45.0) | priority | Talon rule -> action |
|---|---|---|---|---|
| `shell-in-container` | `sh -c 'id; hostname; sleep 60'`, **tty** | Terminal shell in container (stock) | NOTICE | Kill terminal shell in sandbox -> `kubernetes:terminate` |
| `network-tool` | `wget -q -T 2 -O /dev/null http://127.0.0.1:9/` | SDP network tool in sandbox (custom, ADR 0013) | WARNING | Quarantine network tool in sandbox -> `kubernetes:label` quarantine=true |
| `sensitive-file-read` | `cat /etc/shadow` | Read sensitive file untrusted (stock) | WARNING | Kill sensitive file read in sandbox -> `kubernetes:terminate` |
| `drop-and-execute` | `sh -c 'cp /bin/busybox /tmp/busybox && exec /tmp/busybox sleep 60'` | Drop and execute new binary in container (stock) | CRITICAL | Kill drifted binary in sandbox -> `kubernetes:terminate` |

MITRE techniques in the ConfigMap: T1059.004, T1071.001, T1003.008, T1105.

**No new Falco rule.** Three scenarios use stock rules from the image's `/etc/falco/falco_rules.yaml`, all
`maturity_stable` and enabled by default; the fourth uses the existing custom rule. Why each matches
under `restricted`, from the compiled conditions (`falco -L`):
- *Terminal shell*: `proc.name in (shell_binaries) and proc.tty != 0 and container_entrypoint` - the
  exec's argv0 is busybox `sh` and the API execs with a TTY. Without `tty: true` this does not fire.
- *Network tool*: `k8s.ns.name = "sandbox" and proc.name in (wget, nc, curl)`; `proc.name` is the base
  name of the executed path, so busybox's `wget` symlink matches. Fires on process start; the transfer
  itself fails on loopback.
- *Sensitive file*: `open_read` requires `fd.num >= 0`, i.e. a successful open; `cat` is on none of the
  trusted-reader lists. Non-root cannot open `/etc/shadow`, so the pod has the `shadow` group as a
  supplemental group (ADR 0017); the failed-open path (`open_file_failed`) is deliberately not used
  because the stock rule ignores it.
- *Drop and execute*: `proc.is_exe_upper_layer = true` - the executable was written into the
  container's overlayfs upper layer after start. Needs a writable root filesystem (an emptyDir is not
  overlayfs); k3s's containerd uses the overlayfs snapshotter. The copied busybox is named `busybox`
  so it runs (busybox dispatches on argv[0]) and sleeps until the kill.

No scenario triggers another scenario's rule: only `shell-in-container` has a TTY, only `network-tool`
starts wget/nc/curl, only `sensitive-file-read` opens a sensitive file, and only `drop-and-execute`
runs a binary from the upper layer (its `cp` is the image's own).

**Two new Talon rules, same action as the DoD.** `talon/rules.yaml` gains "Kill sensitive file read in
sandbox" and "Kill drifted binary in sandbox", both matching on `k8s.ns.name=sandbox` and reusing the
existing `Terminate Pod` action (grace 0, standalone pods included). Terminate rather than quarantine:
a credential read and an executed foreign binary are post-compromise steps, there is nothing in the pod
worth keeping, and a quarantine label is a Pod UPDATE through `verify-portfolio-images` (failurePolicy
Fail) that would sit in front of the kill. Quarantine stays the answer for the network tool only,
where "still running, cut off" is the more instructive end state. Talon's RBAC does not change: the
Role in `sandbox` already has pods get/patch/delete (no events: Talon's k8sevents notifier is off since
the ADR 0013 correction). All four Falco priorities are at
or above Falcosidekick's `notice` cut-off.

**Checked offline and live.** `tests/scenarios/offline.sh` (`make scenario-offline`) validates the
stock and custom rules with the pinned Falco binary, asserts that every scenario `detection` and every
Talon match is loaded, enabled and forwarded, runs `falco-talon rules check`, and verifies each
scenario's rule preconditions under the pod's own security context in a local container.
`tests/scenarios/run.sh` (`make scenario-test`) is the end-to-end proof on the cluster: alert in the
Falco log, a successful action naming the pod in Talon's JSON log, and the end state (pod gone, or labelled,
Running and unable to resolve names).

Not done offline, and why: replaying a capture (`falco -e`). There is none to replay; recording one
needs the probe loaded (BPF/PERFMON and CAP_SYS_RESOURCE for the ring buffers, which the build sandbox
lacks), and a capture taken outside Kubernetes carries no CRI pod metadata, so the sandbox-scoped
custom rule could not match it. The live run covers that link.

## Consequences
- Upgrading Falco can rename, disable or re-prioritise a stock rule; `make scenario-offline` turns that
  into a red check instead of a scenario that silently stops responding. The drift rule also depends on
  the overlayfs snapshotter; a snapshotter change on the node would break it, which the live test shows.
- "Read sensitive file untrusted" and "Drop and execute new binary in container" now terminate any pod
  in `sandbox` that triggers them, including tests/runtime victims; nothing legitimate runs there.
- The API correlates by pod name and must treat the exec's exit status as noise: `wget` fails by design
  and a terminated pod ends every exec with an error. The ConfigMap header says so.
- The scenario list is the API's input; this mapping table is its explanation. A fifth scenario is a
  ConfigMap entry, a Talon rule if a new response is needed, and a precondition check in
  `tests/scenarios/offline.sh` (the script fails on a rule it has no check for).

## Amendment 2026-10-01: the execs mark the victim first (ADR 0022)

Every scenario pod now serves a fake shop that the visitor watches (ADR 0022), and every exec changes
it before the detected step: `sh -c 'cd /srv/shop && echo ... > .state && mv .state state.json && sleep 1
&& exec <program>'`. The detected program and its arguments are the ones in the table above, started
with `exec` so the process Falco sees is unchanged in name, arguments and parent; shell-in-container
defaces the page in a separate `pre_exec` without a TTY, and its exec is unchanged (ADR 0022,
amendment). No Falco or Talon rule changed. The
marking shells have no TTY, so they do not trip "Terminal shell in container", and the sensitive file is
still opened by `cat`, never by a shell redirect (shells are on that rule's trusted list).
`tests/scenarios/offline.sh` checks the exec'd program, not argv0, and also checks the mutation.

## Amendment 2026-10-02: the interactive terminal's detections, and a rule for execution from the shop volume (ADR 0032)

The fifth scenario, `terminal` (ADR 0032), is not one exec mapped to one rule but a catalogue of commands, each
with its own outcome. The mapping for its *detected* commands, and the one new rule they need:

| terminal command | Falco rule | priority | Talon rule -> action |
|---|---|---|---|
| `read-shadow` (`cat /etc/shadow`) | Read sensitive file untrusted (stock) | WARNING | Kill sensitive file read in sandbox -> terminate |
| `beacon` (`wget http://127.0.0.1:9/`) | SDP network tool in sandbox (custom) | WARNING | Quarantine network tool in sandbox -> quarantine |
| `shell` (`sh -i`, tty) | Terminal shell in container (stock) | NOTICE | Kill terminal shell in sandbox -> terminate |
| `drop-run` (busybox from `/srv/shop`) | **SDP execution from shop volume (new custom)** | CRITICAL | **Kill execution from shop volume in sandbox -> terminate** |

The terminal reuses three existing rules; only `drop-run` needs a new one. The stock "Drop and execute new
binary in container" keys on `proc.is_exe_upper_layer`, which is true only for the container's overlay upper
layer. The terminal pod keeps a read-only root filesystem, so a dropped binary must go into the shop's emptyDir
(`/srv/shop`), which is a separate mount, not the overlay - the stock rule is blind to it. The new rule **"SDP
execution from shop volume"** (`proc.exepath startswith /srv/shop/`, CRITICAL) catches it; nothing the image
ships runs from there, so the only match is a drop-and-run. Its Talon rule **"Kill execution from shop volume in
sandbox"** terminates, like the drift rule, and pins `k8s.ns.name=sandbox`.

Both custom rules ("SDP network tool in sandbox" and the new one) now match `k8s.ns.name in
(sdp_sandbox_namespaces)` - `sandbox` and the unguarded twin `sandbox-unguarded` (ADR 0031) - so Falco detects
in both; the Talon rules still pin `k8s.ns.name=sandbox`, so only the guarded pod is acted on. The allowed and
prevented terminal commands map to no rule by design (the defence map shows which layer answered, or that none
did). `tests/scenarios/offline.sh` checks every terminal command's precondition under the pod's security
context, and that every scenario/terminal detection and Talon match is a loaded, enabled rule at or above
Falcosidekick's cut-off; a fifth-scenario detection with no offline check fails the script.
