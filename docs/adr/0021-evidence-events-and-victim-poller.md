# ADR 0021: Evidence events and the victim poller: what the API publishes to prove a run is real, and how it reads a pod an attacker controls

Date: 2026-10-01 · Status: accepted

## Context
The live attack demo (ADR 0015, 0017, 0018) streamed five run states and the Falco and Talon events.
To a visitor that is indistinguishable from an animation: nothing in it can be checked. The page is to
show verifiable evidence as it happens - the pod as a real API object with a UID and an image digest,
the exact rule that fired at the exact commit, the raw Falco fields - and a small "victim" web app
inside the scenario pod that visibly gets defaced, cut off by the quarantine policy, or killed.

Two constraints frame every choice below. Nothing published may describe the infrastructure: no node
names, no host or pod IPs, no `*.svc` hostnames, no tokens or ServiceAccount names (contract hard rule;
the cluster is a single home-lab node behind a tunnel). And the victim app runs in the pod the visitor
is attacking: whatever it serves is attacker-controlled input to the API.

## Decision

**Event shapes, additive only.** Existing events and fields keep their names; the web of the previous
release keeps working.
- `run`: `pod` from `started` on. `started` now means the API server admitted the pod; a new state
  `pod_ready` (detail: the container id, 12 characters) sits between it and the exec. The exec is sent
  after `pod_ready` instead of before `started`.
- `pod` (new): from a watch on the run's one pod (`fieldSelector=metadata.name=<pod>`, opened before
  the pod is created so the creation is its first event): phase as kubectl summarises it (Pending,
  ContainerCreating, Running, Succeeded, Failed, Terminating, Deleted), reason, UID, container id
  (12), image as `repository@sha256:...` (the repository from the pod spec, only the sha256 digest
  from the kubelet's `imageID`), labels changed since the
  previous event (Talon's quarantine label appears here as it lands), deleted. Published only when one
  of those changes. The view is built field by field from the pod object, so `nodeName`, `hostIP` and
  `podIP` cannot leak by being forgotten in a filter. RBAC: `watch` on pods, in `sandbox` only - the
  same objects the API could already get and list.
- `falco`: `fields`, an allow-list of eleven output fields (evt.type, proc.name, proc.cmdline,
  proc.pname, user.name, user.uid, container.id cut to 12, container.image.repository, k8s.pod.name,
  k8s.ns.name, fd.name), each string capped at 256 runes; `api_received_at`; `output` capped at 1024
  (was 300). Anything not on the list - hostname, k8s.pod.uid, whatever a future Falco adds - is
  dropped.
- `talon`: `actionner`, `api_received_at`, `output` (Talon's result text, or its error, capped at 300).
- Free text (Falco output and field values, Talon output) goes through a scrubber that drops
  invisible format characters (bidi overrides, zero-width spaces: a command line must not read
  differently from what ran) and replaces URLs, names ending in `.svc` or `.cluster.local` (any case),
  IPv4 addresses wherever they appear and IPv6 addresses standing as a token, loopback excepted.
  Loopback stays: `http://127.0.0.1:9/` is the evidence that the network-tool scenario sent nothing
  off the pod. The scrubber is a backstop for the abnormal case (a Talon error quoting the API server
  URL), not the policy - the allow-list is.
- **HTML is not escaped, on purpose.** Falco output, Falco fields, Talon output and the details'
  `exec_command` are evidence and are published verbatim - a scenario's command can contain markup
  it writes into the victim's page (`<h1>...`), and that is exactly what the visitor should read. The
  control is on the web side: every string from the API is rendered as text (`textContent`, never
  `innerHTML`), under the Trusted Types CSP of ADR 0019, which makes an accidental HTML sink throw
  instead of render. Escaping in the API would corrupt the evidence and would protect nothing a
  text-only renderer does not already protect. The victim app's own title and banner are different:
  they are attacker-chosen display text, not evidence, and are stripped of angle brackets.

**Victim poller.** A catalogue entry with `victim: true` (optional, default false) runs an image that
serves `/state.json` on :8080 (`{status, title, banner, checksum}`). From `pod_ready` until the run
ends, the API reads it every 500 ms and publishes `victim` events on change only (not per probe: 240
identical events per run would push the run out of the SSE replay buffer). The safety model, because
the body is written by whatever runs in the attacked pod:
- the address is the pod IP from the pod object, parsed as an IP (never a name to resolve), and never
  published; a `hostNetwork` pod (forbidden in `sandbox` by Pod Security anyway) is not probed;
- no Service or route exists for :8080; the sandbox network policy admits it from the API's pods only
  (the victim app branch owns those policies);
- one GET per probe on a fresh connection (no keep-alive: an established connection could outlive the
  quarantine policy and make the isolation look like it failed), no proxy, no compression;
- 300 ms for the whole exchange, response headers capped at 4 KiB, body capped at 4 KiB;
- redirects are not followed; only 200 with `application/json` is accepted;
- `status` must be `up`, `defaced` or `compromised`; title (80) and banner (120) are reduced to plain
  text (no control or invisible format characters, no angle brackets, whitespace collapsed, length capped); the checksum
  must be 1-16 lowercase hex or it is dropped.

Anything else is `unreachable` - which during a quarantine is the point: the probe failing is the
visible proof that Cilium cut the pod off. Two failures are not reported as `unreachable`: before the
app has answered once (it is starting, and serves 503 until its state exists), and a failure that turns
out to be the pod dying (Talon's delete breaks the probe a moment before the watch reports the
deletion, so after a good answer a failure waits one interval for that report and says `gone`).
`gone` is published only for a deletion the API did not make itself: the run's own cleanup of a
quarantined pod is not a kill.

**Read-only endpoints.**
- `GET /api/scenarios/{id}/details`: the exec command, the effective security context of the exec
  container (container settings over pod settings; `automountServiceAccountToken` is what the runner
  forces, false), requests and limits, the image reference and digest, the Falco and Talon rules and
  the sandbox's admission and network policies with file and line, the build commit, the victim flag.
  File and line come from `app/api/internal/ruleindex/index.json`, generated by
  `scripts/gen-rule-index.sh` and embedded: the image is built from `app/api` alone and has no copy
  of `cluster/`, and a hand-written line number is wrong after the next edit above it. The package
  test checks every entry against the files in a full checkout; `--check` reports a stale index.
  Stock Falco rules live in the Falco image, not here, and have an empty file.
- The commit is the build's `GIT_SHA` (a build argument in the final stage of `app/api/Dockerfile`,
  passed as `github.sha` for the api image only by `build-images.yml`), published only if it is hex.
- `GET /api/runs/{id}`: every event of one of the last 50 runs, as published, with the stream's ids.
  A store fed by a synchronous hub tap (never dropped, unlike a subscriber), bounded by count and by
  size, since event sizes are not ours to choose: 50 runs; per run 500 events and 256 KiB of event
  data, past which the run is marked `truncated`; 8 MiB over all runs, past which the oldest runs are
  dropped first (a run that alone exceeds it is truncated). Falco and Talon events are filed under the
  run whose pod they name.
- `GET /api/limits`: the asking visitor's attack budget (limit, window, remaining, seconds until one
  more is available), the global one, whether a run is active, and the visitor's free stream slots.
  Read-only: asking spends nothing but the ordinary request budget.

**Not done: Hubble flows.** A `flow` event needs a gRPC client for Hubble Relay (the cilium/cilium
observer API and its dependency tree in a service that today depends on client-go only), a network
policy path from the API to Relay, and a filter that strips every address from the flows. Too heavy
for what the quarantine already shows through the victim poller; left for a later decision.

## Consequences
- A visitor can check a run against things outside the page: the pod UID and image digest
  (`cosign verify` the digest), the rule at the linked commit, the full event list at
  `/api/runs/{id}`, and the timing between Falco's own timestamp and `api_received_at`.
- The API now reads a body produced by attacker-controlled code. The limits above bound what that
  can do to the API (300 ms, 4 KiB, no redirects, no reuse) and to the page (three statuses, short
  plain text); the reader is unit-tested against oversized, redirecting, slow, mistyped and
  markup-carrying answers.
- The watch adds one long-lived request per run against the API server, cancelled when the run ends.
- `started` changed meaning (pod admitted, not pod ready). A client that treated `started` as "pod
  running" is early by the pod's start-up time; the page of this release uses `pod_ready`.
- The run store, like the counters, is in memory: a restart forgets the run history (ADR 0015).
- The rule index must be regenerated when a rule or policy file changes above a recorded line; the
  unit test fails until it is.

## Amendment 2026-10-03: the fields published for provenance, posture detail and the run list (ADR 0035)

**Context.** ADR 0035 makes the page verifiable: what runs and from which commit, what fails in the posture
by name, a list of recent runs, and a server clock on the event stream. Each of those publishes something
new, and this ADR is where the line of what may be published is drawn.

**Decision.** The new fields are exactly those ADR 0035 lists: `/api/provenance` (the api's commit and CI run
id, validated; its start time; the sorted digests of the api and web images that Running pods run, and when
the pods were last listed), `/build.json` (the web image's commit and run id), `GET /api/runs` (per run: id,
scenario, state, start, end (either may be null), detected, responded, event count, truncated - no pod, no
command, no output), `kyverno.violations` (policy, rule, kind, namespace, count, `running`, the policy's file
in this repository), `kube_bench.failing` (check id, title, remediation), `trivy.last_scan`,
`falco.counted_since`, `/api/stats` `last_run_at` and `last_24h`, and the SSE `tick` (`at`, `started_at`).
They follow this ADR's rules: built field by field from an allow-list, free text (the kube-bench title and
remediation) through the scrubber and capped (200 and 300), at most 50 failing checks and 50 violation groups.
Added to what is never published: the names of the objects a violation is about (nothing but the sandbox pod
is ever named), Kyverno's messages, kube-bench's `audit`, `actual_value`, `expected_result`, `AuditEnv`,
`AuditConfig` and `reason`, and the api and web pods' names, and their namespaces as part of provenance; a
violation group may name any namespace, these included, since all are declared in the repository. kube-bench's
remediation text may carry k3s's default host paths (`/var/lib/rancher/k3s/...`): they describe k3s, not this
host, and are allowed.

**Consequences.** The posture names which policies and CIS checks fail; that is public in the repository
and in k3s's defaults already. The run history is still in memory (above); listing it adds no state.
