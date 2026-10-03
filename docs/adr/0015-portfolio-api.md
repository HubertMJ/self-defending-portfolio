# ADR 0015: The portfolio API: one Go process runs visitor-triggered attacks in `sandbox`, streams detection and response over SSE, and rations itself

Date: 2026-10-01 · Status: accepted

## Context
Phase 5 turns the cluster into the exhibit: a visitor of https://hubertjablon.ski picks one of four
controlled attacks, it runs in `sandbox`, and the page shows Falco detecting it and Falco Talon
answering it, live, next to the cluster's security posture (Kyverno, Trivy, kube-bench). The
phase 5/6 contract between the API, the scenarios and the frontend (built in parallel and merged
together) fixes the endpoints, the event shapes, the scenario format (a ConfigMap owned with the
scenario images) and the abuse limits; this ADR and ADR 0017 are where that contract is recorded,
and `app/web/src/lib/contract.ts` is its typed form.

That means an anonymous internet visitor can make the cluster create pods. Everything below is
about keeping that one capability narrow: what the backend may do, who may reach which part of it,
how often, and what happens when it dies halfway.

Options considered: a web framework vs. the standard library; WebSocket vs. Server-Sent Events;
reading the scenarios through the API server vs. a mounted ConfigMap; learning about detections by
watching Kubernetes Events or Falco's logs vs. receiving Falcosidekick's and Talon's webhooks;
shared state in Redis with several replicas vs. one replica with in-process state; one port vs. two.

## Decision

**Go, standard library, client-go** (`app/api`). `net/http` with Go 1.22 method-and-path patterns is
the whole router; the only dependencies are client-go 0.35.9 (the cluster is k3s 1.35) and
`sigs.k8s.io/yaml`. Static binary on distroless `static-debian13:nonroot`, uid 65532, read-only
root, no capabilities, ~10 MB. The image's build runs `go vet` and `go test -race`, so an image
whose tests fail does not exist. Built and signed like every image of ours (ADR 0016).

**Two listeners.** `:8080` serves `/api/*` to the Gateway; `:8081` serves `/internal/falco` and
`/internal/talon` to Falcosidekick and Talon. The CiliumNetworkPolicy admits 8080 from the Gateway
(`ingress`) and the kubelet (`host`) only, and 8081 from those two falco-response pods only. Neither
webhook is authenticated (Falcosidekick -> Talon is not either, ADR 0013), so the policy *is* the
authentication; with one port, a routing mistake would let a visitor forge "detected" and
"responded" onto everyone's live feed.

**SSE, not WebSocket.** The feed is one-way. SSE is plain HTTP through Cloudflare, cloudflared and
Envoy with no upgrade, `EventSource` reconnects by itself and sends `Last-Event-ID`, and the server
needs no frame protocol. The hub keeps the last 50 events: a new visitor sees the run in progress,
a reconnecting one resumes exactly where it was. A client that stops reading is dropped (it
reconnects and resumes) rather than slowing everyone else. A 15 s heartbeat keeps Envoy's and
Cloudflare's idle timers quiet; the HTTPRoute disables Envoy's 15 s request timeout for
`/api/events` alone; the API closes every stream after 30 minutes. Every hop between the pod and the browser (Envoy,
cloudflared, the Cloudflare edge) must pass the stream through as written, so the response says
exactly `Content-Type: text/event-stream` (no charset parameter), `Cache-Control: no-store,
no-transform` (no hop may compress it; a compressing proxy holds a few hundred bytes of events until
its block fills) and `X-Accel-Buffering: no`, and every stream opens with `retry` plus a 2 KiB comment
that fills any first-bytes buffer before the replay is written. Added after the first live run,
where the replay reached the pod's own port but not the browser.

**The run.** `POST /api/attack/{id}` -> `queued`; the pod is created in `sandbox` from the
scenario's template plus what the runner insists on: labels `sdp.hubertjablon.ski/run-id`,
`.../scenario`, `app.kubernetes.io/managed-by: portfolio-api` and `sdp.hubertjablon.ski/quarantine:
"false"` (Talon's label patch is a JSON Patch `replace`, ADR 0013), `restartPolicy: Never`,
`activeDeadlineSeconds` = the scenario timeout (at most 120 s; 300 s since ADR 0017's 2026-10-03
amendment), no ServiceAccount token, no service links. Ready -> `started`, and `exec.command` runs
through `pods/exec` (WebSocket with SPDY fallback, a TTY when the scenario asks, because Falco's
"Terminal shell in container" needs one). A Falco alert naming the pod -> `detected`; a successful Talon
action naming it -> `responded`; the pod is deleted (a quarantined one after 5 s, so the isolation is
observable) -> `finished`. No response within the timeout -> `timeout`; a pod that is refused or never
Ready -> `failed`. Every path ends with the pod deleted and the slot released; pods left by a crash are
deleted at the next start-up, and `activeDeadlineSeconds` ends them even if the API never comes back.
Correlation is by pod name, unique per run; nothing else is needed.

**Webhooks, not watches.** Falcosidekick already receives every alert and Talon already knows every
action; one more output each (`webhook`, to absolute names with a trailing dot, so the resolver asks
one question, and Talon's only DNS rule is that one name) delivers exactly what the page needs, in
order, within milliseconds, with no extra read permissions. Watching Events would need cluster-wide
event reads and would still not carry the Falco alert.

**Scenarios are a mounted ConfigMap.** Directory mount, `optional: true`, re-read when the file
changes: no ConfigMap RBAC, no restart for a new scenario, and the API starts (posture, feed) before
the catalogue exists. Each entry is validated before it can run - DNS-1123 id, `terminate` or
`quarantine`, a strictly decoded PodSpec (an unknown field is an error, not silently dropped), every
image from our registry path **with a digest**, no ephemeral containers - and an invalid entry is
skipped and logged, not fatal. This duplicates what Pod Security and Kyverno enforce in `sandbox` on
purpose: it fails before a pod exists, with a log line instead of an admission error mid-run.

**One replica, in-process state, `Recreate`.** The limits, the run slot, the replay buffer and the
correlation table live in memory. Two replicas would be two independent "one run at a time" limits,
and a webhook landing on the replica that does not own the run. Redis would fix that at the price
of another stateful workload, another image, another policy surface - for a single-node cluster
where the API is not the availability bottleneck. A restart forgets the rate-limit windows and the
24 h Falco/Talon counters; the sandbox ResourceQuota and the single slot bound what a burst right
after a restart can do.

**Abuse limits.** The key is `CF-Connecting-IP`, IPv6 collapsed to its /64. It is trusted because of
the path: Cloudflare's edge overwrites it, and 8080 accepts only the Gateway. A request without it
falls into one shared `direct:` bucket, which is stricter, not looser. Attacks: 3 per 10 minutes
per visitor, 30 per hour in total (sliding windows), one at a time; rate limits are checked before
the slot (a visitor over quota hears "429, Retry-After N", not a 409 that invites a retry loop),
and refused attempts are not counted. All endpoints: 120 requests per minute per visitor, the
tracked-key table capped so a flood of addresses cannot grow memory. Event streams: 4 per visitor,
200 in total. Bodies are bounded (empty for the trigger, 256 KiB for a webhook); servers have
header/read/idle timeouts.

**Same-origin only, without CORS.** No `Access-Control-Allow-*` header is ever sent, so browsers
refuse cross-origin reads. A simple cross-origin POST needs no preflight, though, so a POST with a
foreign `Origin` or `Sec-Fetch-Site: cross-site|same-site` is refused with 403: otherwise any page on
the internet could spend its visitors' attack quota. Requests with neither header are not browsers
and are judged by the limits alone. The HTTPRoute adds HSTS, `nosniff`, `Referrer-Policy:
no-referrer`, a `default-src 'none'` CSP and `Cross-Origin-Resource-Policy: same-origin`.

**RBAC, narrower than the contract allows.** Role in `sandbox`: pods `create, get, list, delete`,
`pods/exec create` (no `watch`; a WebSocket exec is authorised as `create` since 1.31). Role in
`kube-bench`: pods `list`, `pods/log get` (the benchmark's result is the Job log, ADR 0014).
ClusterRole: `list` on `policyreports`, `clusterpolicyreports` and `vulnerabilityreports` - the only
cluster-wide grant, because those reports live in every namespace (and, since the 2026-10-02
amendment, `list` on pods). Nothing else: no secrets, no ConfigMaps, no Jobs, nothing written or
exec'd in any other namespace. `portfolio-api` joins `hello` and `sandbox` in
`verify-portfolio-images` and `restrict-image-registries` (ADR 0016).

**Posture.** Kyverno results (source `kyverno`) per policy from PolicyReports and
ClusterPolicyReports; Trivy severity totals per distinct image (by digest, so three replicas of one
image count once), and since ADR 0023 the same totals split into own and third-party images with a
per-image CRITICAL/HIGH/fixable breakdown that adds up to them; kube-bench totals from the newest Succeeded pod's log (robust to glog lines and
to one document per target); Falco alerts and Talon actions over 24 h from the webhooks (1440
one-minute buckets, constant memory; alerts from every namespace count, only `sandbox` ones are
shown). Cached 60 s, one refresh at a time, detached from the request that triggered it; a source
that fails keeps its last value rather than failing the page.

## Consequences
- An anonymous visitor can cause, at most, three scenario pods per 10 minutes, thirty per hour for
  everyone, never two at once, each gone within 120 s (300 s since ADR 0017's 2026-10-03 amendment),
  each confined by Pod Security `restricted`, signed images only, the sandbox quota, default-deny
  networking and Falco/Talon. The API itself can create pods only in `sandbox`.
- The live feed is as trustworthy as the CiliumNetworkPolicies on 8081 and on Falcosidekick/Talon. A
  Cilium policy outage would let any pod forge feed entries (not actions: the API acts only on its
  own runs, and only by deleting their pods).
- `kubectl rollout restart` costs the visitor a few seconds of 503 and resets the windows and the
  24 h counters; accepted.
- Talon now has a second notifier and its first DNS rule. If the API is down, Talon's notification
  fails and is logged; the action itself is unaffected, as is the phase 4 DoD.
- `tests/abuse/run.sh` asserts the limits over HTTP against the live API (or a port-forward with
  synthetic visitor addresses); the Go tests cover the same arithmetic, the global limit included,
  with `-race`.
- Known gaps, recorded: the 24 h counters are not persistent; the posture page reflects only what the
  reports say, so it is as current as the last Trivy scan and kube-bench run. The scenario catalogue is
  the Application's second source, `cluster/infra/sandbox/scenarios` (owned with the scenarios).

## Amendment 2026-10-02: Trivy counts only images a pod runs

**Context.** The image tile said "Trivy, 37 running images" while far fewer ran. `posture` counted
every VulnerabilityReport, and Trivy Operator keeps a report for as long as its owner exists: a
Deployment keeps its old ReplicaSets (`revisionHistoryLimit`, 10 by default) at 0 replicas, so every
earlier revision's image stayed in the totals. One stale report, for a scaled-to-0 `trivy-operator`
ReplicaSet still on the upstream image, contributed 2 HIGH to a cluster whose running images had
none, until the ReplicaSet was deleted by hand. The word "running" on the page was not true.

**Decision.**
- **A report counts when a pod runs its image.** Each refresh lists every pod in the cluster (paged,
  250 at a time, inside the same 60 s cache) and collects the digests of
  `status.{initContainer,container,ephemeralContainer}Statuses[].imageID`. A report is kept when its
  `artifact.digest` is one of them. The digest alone is compared, so `docker.io` vs
  `index.docker.io` spellings never matter; on this cluster every report digest equals the
  containerd imageID digest of the pods it describes (checked live, 2026-10-02).
- **Never drop something that runs (ADR 0023).** Pods in any phase count: a pod object exists while
  its workload wants it, so a scaled-to-0 ReplicaSet has none, but the last completed kube-bench run
  keeps its image counted between CronJob runs. A container with no imageID yet (pod pending, image
  being pulled) is matched by its normalised `registry/repository:tag`, so a report of the same tag is
  kept until the digest is known. A report without a repository cannot be matched and is kept. If the
  pod list fails, the Trivy section keeps its previous value, as every failing source does - it is
  never computed against an empty pod list.
- **Why pods and not owners.** Resolving `trivy-operator.resource.kind/name` to a workload's
  replicas needs `list` on ReplicaSets, DaemonSets, StatefulSets, Jobs and CronJobs (five grants
  instead of one), and a ReplicaSet's replica count is not the same as "running": during a rollout a
  DaemonSet runs two digests under one owner. The pods' imageIDs are what the nodes actually run.
- **RBAC.** The ClusterRole `portfolio-api-posture-read` gains `list` on `pods` - no `get`,
  `watch` or subresource. What it reveals that was not visible before: other namespaces' pod specs
  and statuses. Pod specs here carry no secret values (Secrets are referenced or mounted, and remain
  unreadable to this ServiceAccount; the only literal `*KEY*` env is a file path), and the images are
  public. The `kube-bench` Role's `pods list` is now redundant but kept, so that Role still says on
  its own what the benchmark read needs.

**Consequences.**
- `trivy.images` and every total and split are over images pods run. Live on 2026-10-02 that took the
  tile from 36 to 32 images (own 18 to 14: four old `portfolio-api` ReplicaSets at 0 replicas); the
  severity totals were unchanged, because those old api digests had no findings. Third-party: 18.
- The API's blast radius (threat model AB10) grows by read access to pod specs cluster-wide.
- Unit tests: a scaled-to-0 ReplicaSet's report is excluded; init containers, a completed Job pod, a
  pod still pulling its image (matched by tag) and an unmatched report are kept; a failing pod list
  fails the section instead of reporting zero images.

## Amendment 2026-10-03: the 24 h counters persist (ADR 0035)

**Context.** The 24 h Falco and Talon counters were `webhook.Window`, in memory, so every rollout set the
posture's "alerts, 24 h" to zero next to the persisted hero numbers of ADR 0030: the page showed 19 runs
detected and answered beside "0 alerts". The known gap above ("the 24 h counters are not persistent") had
become a visible contradiction.

**Decision.** `webhook.Window` is removed. The webhook handlers count into hourly buckets kept by the stats
collector and persisted in `portfolio-stats` with everything else (ADR 0030, as amended); the posture reads
`falco.alerts_24h` and `talon.actions_24h` from those buckets on every request, outside the 60 s cache, and
adds `falco.counted_since`. The window is the current hour and the 23 before it, labelled with its start,
never as a bare "24 h". Alerts from every namespace still count. The posture also names what fails
(`kyverno.violations`, `kube_bench.failing`, `trivy.last_scan`), and the one pod list per refresh is shared
by Trivy, the violations' `running` flag and `/api/provenance`; the details, and what may and may not be
published, are in ADR 0035. No RBAC changes.

**Consequences.** A rollout no longer resets the 24 h numbers; a crash loses at most the last minute. What
stays in memory is the rate-limit windows and the per-run history (`/api/runs/{id}`, now also listed by
`GET /api/runs`), so a restart still forgets those, and the open item in the ADR index is narrowed to them.
