# ADR 0032: The attacker's terminal, its detections, and bringing quarantine under three seconds

Date: 2026-10-02 · Status: accepted

## Context
The four one-click scenarios (ADR 0017, 0018) show detection and response, but the owner's verdict on the
live demo was that they "do not click": the visitor presses one button and watches, all four look the
same, and the defender always wins instantly, so nothing shows what the defence is worth. Two things this
ADR fixes, both under the CLUSTER half of the phase 5/6+ contract:

1. **Quarantine never showed its proof.** On a `network-tool` run Talon set the quarantine label, but the
   pod kept answering for tens of seconds; the API deleted it (QuarantineLinger, 5 s) long before Cilium
   cut it off, so no `unreachable` victim event ever fired. Measured on the node (2026-10-02): the
   CiliumEndpoint still carried `quarantine=false` 2 s after the label, and `tests/scenarios/run.sh` has
   seen 22-36 s from the label to DNS failing. For those seconds a "quarantined" pod is not isolated, and
   the visitor never sees the cut. The API and WEB halves of this fix are in their own ADRs (the linger
   change, and lighting hop 8 from the first `unreachable`); this ADR is the isolation latency itself.

2. **Every scenario was passive and identical.** The contract adds a fifth, interactive scenario: a real
   terminal the visitor types into, against a real hardened pod, reading real output until the cluster
   stops them - so that different actions end differently and the order of moves matters.

## Decision, part 1: label-to-isolation under three seconds

**Why it was slow.** Talon quarantines by adding `sdp.hubertjablon.ski/quarantine=true`, which the standing
CiliumClusterwideNetworkPolicy selects (ADR 0013). A Cilium policy selector matches an endpoint's *security
identity*, and an identity is the set of a pod's identity-relevant labels. So the label is necessarily
identity-relevant, and adding it forces the endpoint onto a new identity. From Cilium 1.19.8's source, a
new identity costs two things before the new policy applies:

- *allocation.* In `agent` identity-management mode the agent allocates the identity through a CiliumIdentity
  object and plumbs it into the SelectorCache (`pkg/allocator`, `pkg/identity/cache`). For an identity never
  seen before, that is an API-server round trip plus policy-map regeneration.
- *the grace period.* `pkg/endpoint`'s `identityLabelsChanged` sleeps `identity-change-grace-period` (default
  5 s) whenever the identity actually changes (`allocatedIdentity.ID != oldIdentity.ID`), so that other
  nodes can whitelist the upcoming identity before it is used.

Both costs were paid in full on every quarantine, because every scenario pod carried a unique
`sdp.hubertjablon.ski/run-id` (and `scenario`) label. Those labels were identity-relevant, so **every pod was
a brand-new identity**, and the quarantined pod (run-id + `quarantine=true`) was a brand-new identity again -
freshly allocated, with its policy computed from scratch, after the full 5 s grace period.

**The fix is two values in the Cilium config, kept identical in `cluster/apps/cilium.yaml` and the Ansible
cilium role (`scripts/check-cilium-values.sh` enforces equality):**

- `labels: "k8s:!sdp.hubertjablon.ski/run-id k8s:!sdp.hubertjablon.ski/scenario"`. Cilium's `labels` option
  appends to the default identity label list (`daemon/cmd/daemon_main.go` -> `labelsfilter.ParseLabelPrefixCfg`
  with an empty label-prefix-file; confirmed in `pkg/labelsfilter/filter.go`). These two entries are *ignore*
  rules, so the default whitelist flag stays off and every other label - the reserved labels, the namespace,
  `app.kubernetes.io/*`, and crucially `sdp.hubertjablon.ski/quarantine` - stays identity-relevant. Only the
  two per-run churn labels are removed. The result: all scenario pods in a namespace share **one stable
  identity**, and the quarantined identity (that identity plus `quarantine=true`) is stable too, so it can be
  reused across runs instead of a fresh identity per pod. It is **not** cached forever: Cilium's operator GCs an
  identity no endpoint has used (chart defaults `identityGCInterval` 15m, `identityHeartbeatTimeout` 30m), so on
  a quiet site the quarantined identity is reaped and the next quarantine allocates it cold again. What the
  change removes is the *guaranteed* cold allocation on every single run (unique `run-id` meant the quarantined
  identity was always new); within the GC window a quarantine is now a warm label flip. `run.sh` measures both a
  first (possibly cold) and an immediate second (warm) quarantine against the bound, rather than assuming warm.
- `identityChangeGracePeriod: "500ms"` (was the 5 s default). The grace period exists so other nodes can
  whitelist the new identity first. **This is a single-node cluster: there is no other node to wait for.**
  500 ms is enough to order the identity change ahead of the endpoint's datapath regeneration without the
  pathological zero; it removes ~4.5 s of pure sleep from the path.

**What is and isn't proven.** The 22-36 s was measured end to end (label to DNS failing); its exact breakdown -
how much was identity allocation, how much the 5 s grace, how much policy regeneration - was *not* isolated on
the node, so this ADR does not claim allocation alone caused it. What is claimed, and what `run.sh` holds to the
3 s bound live, is the before/after: the two changes above remove the 5 s grace (all but 500 ms) and the
per-run guaranteed cold allocation, and the quarantine label still changing the identity means an endpoint
still pays 500 ms + regeneration - a small, bounded cost on a warm identity. The expectation is well under the
3 s the contract asks for; the live integration is the measurement, cold and warm.

**Selecting the victim by a stable label.** The victim's one allowed flow (`sandbox-victim-from-api`, ADR
0022) and the API's matching egress rule selected scenario pods by `run-id Exists`. A CiliumNetworkPolicy
endpointSelector matches identity labels, and `run-id` is no longer one, so both now select the stable
`app.kubernetes.io/managed-by: portfolio-api` label the API already stamps on every pod it creates. The API's
egress rule also gains the twin namespace (ADR 0031).

**The test measures it the way the visitor sees it.** `tests/scenarios/run.sh` now stands up a pod in
`portfolio-api` with the API's identity and polls the victim's `/state.json` on :8080 exactly as the API does,
proves it answers before the attack, and then measures the time from the quarantine label to the first failed
poll - the precise moment the shop goes "unreachable" on the page - asserting it is within `QUARANTINE_BOUND`
(3 s). The victim's DNS egress failing is kept as corroboration with a looser bound. This is a live check;
it cannot run offline (no cluster, no Cilium datapath).

## Decision, part 2: the interactive terminal

A fifth scenario, `id: terminal`, `interactive: true`, in `cluster/infra/sandbox/scenarios/scenarios.yaml`.
The four one-click scenarios are unchanged and stay as "just show me". The terminal's shape (contract):
`timeout_seconds: 120`, `idle_seconds: 30`, an `objectives[]` list in kill-chain order, and a `commands[]`
catalogue. The API runs a command only on the visitor's request, **by id** - the only thing it accepts, never
free text (contract hard rule) - so a visitor's typing never reaches the cluster as a command.

**The pod** is the same hardened victim shop as the others: PSS `restricted`, read-only root filesystem, no
ServiceAccount token, the shop on :8080 polled by the API. Two differences, both already precedented:
`supplementalGroups: [42]` (the `shadow` group, as `sensitive-file-read`, so `cat /etc/shadow` can succeed and
be detected), and a 2 MiB shop emptyDir instead of 1 MiB (the `drop-run` command copies busybox into it). Per
run the API injects `SDP_FLAG` (`SDP{` + 16 hex + `}`) as an env var on container `target`; the victim writes
it to `/srv/shop/.flag` (0600) on start and never serves it (ADR 0022 amendment).

**The catalogue** is 14 commands grouped by the kill chain, each with an `outcome` (allowed | prevented |
detected), the `layer` that answers, a one-line `control`, and an `explain`. The spread is deliberate: the
quiet moves (recon, deface, read the flag) are allowed or prevented and the run continues, so a visitor who
does them first gets further; the loud ones end the run. Highlights:

- **allowed, visible:** `deface` rewrites the shop's own `index.html`/`state.json`; the shop window changes and
  no rule fires, because nothing watches an app writing its own docroot - the explanation says so.
- **allowed, objective:** `cat /srv/shop/.flag` prints the run's flag; the explanation says detection is not
  prevention, and that reading a secret in the pod is not the same as getting it out past a default-deny
  network.
- **prevented, by the pod itself:** `touch /bin/backdoor` (read-only root filesystem), reading the
  ServiceAccount token (there is none), `chown` (no CAP_CHOWN - every capability dropped). Each fails with the
  kernel's own message and nothing is killed.
- **detected, quarantine:** `wget ... http://127.0.0.1:9/` - the pod is quarantined and **the run goes on**
  (exec still works in a quarantined pod), with the shop going unreachable next to the visitor.
- **detected, terminate:** `cat /etc/shadow`, `sh -i` (a TTY shell), and `drop-run` - copy busybox into the
  shop volume and execute it.

**One new custom Falco rule.** `drop-run` executes from `/srv/shop`, an emptyDir. The stock "Drop and execute
new binary in container" rule keys on `proc.is_exe_upper_layer`, which is only the container's overlay upper
layer; an emptyDir is a separate mount, so a binary run from it slips past. `cluster/infra/falco` gains
**"SDP execution from shop volume"** (`proc.exepath startswith /srv/shop/`, CRITICAL), and
`cluster/infra/falco-response/talon/rules.yaml` gains **"Kill execution from shop volume in sandbox"**
(terminate). Nothing the image ships runs from `/srv/shop` (the server is `/usr/local/bin/victim`, busybox is
`/bin`), so for the catalogue's `drop-run` - which `exec`s the copied binary directly - the only way to match is
to drop and run something: the behaviour.

**What this rule does not catch, by design.** It keys on `proc.exepath`, the path of the executable the kernel
actually runs, so it sees a dropped *binary* run directly. It does not see a *script* fed to an interpreter:
`sh /srv/shop/x` runs `/bin/sh` (exepath `/bin/sh`, the script is only an argument); a shebang script records
the interpreter as the executable, not the script; and a binary launched through the dynamic loader
(`/lib/ld-musl-*.so.1 /srv/shop/x`) has the loader as its exepath. Those are real gaps, not covered here. The
tempting fix - also matching `/srv/shop` anywhere in `proc.cmdline` - is deliberately rejected: the `deface`
command's cmdline legitimately contains `/srv/shop`, so cmdline matching would fire on an allowed command and
make the rule lie. The honest rule catches the direct-execution case the catalogue demonstrates and is clear
about the rest; closing the interpreter gaps is a separate decision (more rules, or a broader drift approach),
not a quiet widening of this one. Both this rule and the existing "SDP network tool in sandbox" now match
`k8s.ns.name in (sdp_sandbox_namespaces)` - `sandbox` and the twin `sandbox-unguarded` (ADR 0031) - so
detection is identical in both; the Talon rules pin `k8s.ns.name=sandbox`,
so only the guarded pod is acted on.

**No new capability, no token, no name leak.** No command prints the environment, names a host outside the
pod, or resolves a name; `beacon` targets the pod's own loopback. The flag is the visitor's own run's secret
and is meant to be read; it is never served, only readable by a command inside the pod.

**Proven offline.** `tests/scenarios/offline.sh` gains a terminal section that runs every command under the
pod's own security context (built from `app/scenario`) and asserts its claimed outcome: an `allowed` command
really succeeds (and `read-flag` prints the flag, `deface` changes the shop), a `prevented` one really fails
with the pod's own refusal and writes nothing, and a `detected` one really meets its Falco rule's preconditions
(a successful sensitive-file open, a network tool's process name, a TTY for the shell, a binary executed from
`/srv/shop` with `/srv/shop` proven to be a separate mount so the stock drift rule is blind to it). The flag's
mode and the fact it is never served are also unit-tested in `app/scenario/victim`. `scripts/lib/scenario_pods.py`
validates every new catalogue field (ids, unique inputs, outcomes, layers, per-command detections) in
`make validate`.

## Consequences
- Taking `run-id`/`scenario` out of the identity means scenario pods are no longer each a unique Cilium
  identity. That is the point: the per-run churn guaranteed a cold quarantined identity on every run. The
  quarantined identity is now warm between runs within Cilium's identity GC window (15m/30m defaults); after a
  longer quiet spell the next quarantine is cold again, which `run.sh`'s first/second measurement exercises.
- The grace period is a cluster-wide Cilium setting. 500 ms is safe only because the cluster is one node; a
  multi-node cluster would want it back near the default. It is documented here and in both Cilium value files.
- The terminal lets a visitor run a dozen different commands against a real pod, each bounded by the same
  `restricted` pod, signed image, quota, default-deny network and Falco/Talon as the one-click scenarios. The
  API accepts ids only, so the visitor's free text never reaches the cluster.
- A new custom Falco rule is maintenance the next Falco bump must re-validate, which `make scenario-offline`
  turns into a red check rather than a silent miss. The terminal depends, like the drift scenario, on the
  overlayfs snapshotter and on emptyDir being a separate mount; the live test covers the link.
- Live checks integration must run (no cluster here): `tests/scenarios/run.sh` for the <3 s bound and the
  terminal's end states, and the live `make scenario-test`.
