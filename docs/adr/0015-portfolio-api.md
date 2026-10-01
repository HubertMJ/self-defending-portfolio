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
`/api/events` alone; the API closes every stream after 30 minutes.

**The run.** `POST /api/attack/{id}` -> `queued`; the pod is created in `sandbox` from the
scenario's template plus what the runner insists on: labels `sdp.hubertjablon.ski/run-id`,
`.../scenario`, `app.kubernetes.io/managed-by: portfolio-api` and `sdp.hubertjablon.ski/quarantine:
"false"` (Talon's label patch is a JSON Patch `replace`, ADR 0013), `restartPolicy: Never`,
`activeDeadlineSeconds` = the scenario timeout (at most 120 s), no ServiceAccount token, no service
links. Ready -> `started`, and `exec.command` runs through `pods/exec` (WebSocket with SPDY fallback,
a TTY when the scenario asks, because Falco's "Terminal shell in container" needs one). A Falco alert
naming the pod -> `detected`; a successful Talon action naming it -> `responded`; the pod is deleted
(a quarantined one after 5 s, so the isolation is observable) -> `finished`. No response within the
timeout -> `timeout`; a pod that is refused or never Ready -> `failed`. Every path ends with the pod
deleted and the slot released; pods left by a crash are deleted at the next start-up, and
`activeDeadlineSeconds` ends them even if the API never comes back. Correlation is by pod name,
unique per run; nothing else is needed.

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
cluster-wide grant, because those reports live in every namespace. Nothing else: no secrets, no
ConfigMaps, no Jobs, no other namespace's pods. `portfolio-api` joins `hello` and `sandbox` in
`verify-portfolio-images` and `restrict-image-registries` (ADR 0016).

**Posture.** Kyverno results (source `kyverno`) per policy from PolicyReports and
ClusterPolicyReports; Trivy severity totals per distinct image (by digest, so three replicas of one
image count once); kube-bench totals from the newest Succeeded pod's log (robust to glog lines and
to one document per target); Falco alerts and Talon actions over 24 h from the webhooks (1440
one-minute buckets, constant memory; alerts from every namespace count, only `sandbox` ones are
shown). Cached 60 s, one refresh at a time, detached from the request that triggered it; a source
that fails keeps its last value rather than failing the page.

## Consequences
- An anonymous visitor can cause, at most, three scenario pods per 10 minutes, thirty per hour for
  everyone, never two at once, each gone within 120 s, each confined by Pod Security `restricted`,
  signed images only, the sandbox quota, default-deny networking and Falco/Talon. The API itself can
  create pods only in `sandbox`.
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
