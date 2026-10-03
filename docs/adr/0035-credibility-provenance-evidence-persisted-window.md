# ADR 0035: Credibility: provenance on the page, evidence by default, a persisted 24 h window, no mock in production

Date: 2026-10-03 · Status: accepted

## Context
An audit of the live page on 2026-10-03 ended with the owner's verdict "it looks like a mockup". Nothing on
it was false, but a sceptical visitor had no way to tell it from a well-made animation, and several things
on it contradicted each other or could not be checked:

- **Two numbers that disagree.** The hero's "detected" and "answered" come from `/api/stats`, which is
  persisted (ADR 0030). The posture's "Falco alerts, 24 h" and "Talon actions, 24 h" come from
  `webhook.Window`, 1440 one-minute buckets in memory (ADR 0015), so every rollout set them to zero. The
  audit saw 19 runs, each detected and answered, next to "0 alerts in 24 h". The runner can also publish
  `detected` before any Falco webhook, when Talon's notification arrives first, so even two windows of the
  same length are not equal at every instant.
- **Times nobody can place.** The hero's "last run" and "since", the kube-bench run and the posture's
  "report generated" were relative only ("6 h ago"); the run history showed local clock time with no zone;
  nothing linked a run to its raw events at `/api/runs/{id}`, which existed.
- **Red numbers without names.** "7 violations" and "3 failing" were shown in critical tiles with no way to
  see what failed. All seven violations were `restrict-image-registries` on seven ReplicaSets in
  `falco-response` scaled to 0: Talon revisions 1-4 (upstream falco-talon 0.3.0, before ADR 0023) and
  Falcosidekick revisions 1-3 (upstream, before ADR 0025), kept by the Deployments' default
  `revisionHistoryLimit` (10) - the same class of problem as the Trivy amendment of ADR 0015. The three
  kube-bench failures were CIS 1.1.9, 1.1.10 and 1.2.26.
- **"(pending)" forever.** A terminal session that only ran recon commands (which by design raise no
  alert) showed its detection and response stages as unreached, with "(pending)" for screen readers, after
  the run had ended.
- **A mock in production.** ADR 0033 shipped the in-page MockBackend, so `?mock=1` on the live site
  switched to simulated data behind a banner. It was labelled, but "this page can show fake data" is
  exactly the suspicion the page has to dispel, and the bundle carried the mock's fixtures and its
  275-line terminal catalogue.
- **No provenance.** The api image knew its commit (`GIT_SHA`, ADR 0021); the web image knew nothing, no
  image knew the CI run that built it, and the page's `cosign verify` line used an exact identity of its
  own instead of the regexp `scripts/verify-image.sh` and the admission policy use - a second copy that
  already differed from it.
- **Evidence far down, nothing alive.** The only real evidence (pod UID, image digest, Falco fields) was
  in the live run console, below the fold and only for scripted runs. When nobody attacked, nothing on the
  page changed: the stream's 15 s heartbeat is an SSE comment, invisible to the page.

The constraints are the ones the project already has: publish nothing that describes the infrastructure
(ADR 0021), the page never starts a run by itself (ADR 0017), no new RBAC for the API (ADR 0015, 0030),
persistence stays aggregate-only in the one `portfolio-stats` ConfigMap (ADR 0030), and the CSP does not
change (ADR 0019).

## Decision

### 1. Provenance: what is running, built from which commit, by which run
- **Build arguments and a label.** `build-images.yml` passes `GIT_SHA` (`github.sha`) and `CI_RUN_ID`
  (`github.run_id`) to the api and web images - the one named exception of ADR 0016 widens from api to
  api and web - and labels every image `ski.hubertjablon.ci.run-id` next to
  `org.opencontainers.image.revision`. The api image bakes both into its environment in the final stage;
  the web image declares them after its package upgrade and after the bundle is copied in, so the build
  stage and every earlier layer stay cached, and writes `/build.json`
  (`{"commit": "<40 hex>"|"", "ci_run_id": "<digits>"|""}`), each value validated in the Dockerfile and
  emptied when it does not match. nginx serves it like any other stable file (revalidated, never
  long-cached); `connect-src 'self'` already covers it.
- **`GET /api/provenance`** reports the api's commit and run id (validated: 7-40 hex, 1-20 digits, else
  empty), its start time, and the digests of the api and web images that Running pods run. The digests
  come from the pod list the posture refresh already makes (ADR 0015 amendment 2026-10-02): one list per
  refresh is shared by the Trivy section, the violations' `running` flag (below) and provenance, so there
  is no new read and no new grant. Only pods whose image repository is exactly ours plus `api` or `web`
  count; the answer carries digests and the time of the last successful list, never a pod name or a
  namespace. A failed list keeps the previous digests and their time, as every failing source does.
- **One identity, checked.** The page's `cosign verify` command is built from two constants in
  `app/web/src/lib/provenance.ts` that are character for character the defaults of
  `scripts/verify-image.sh` (issuer and identity regexp, including ADR 0016's `|build-web` TRANSITION
  alternative, shown verbatim until that cleanup). `scripts/check-web-identity.sh` fails `make validate`
  when they differ from it or from the admission policy's `subjectRegExp`/`issuer`, when another file under
  `app/web/src` carries its own copy, or when `provenance.ts` is missing - the way `check-web-csp.sh` guards
  the CSP. ADR 0016's TRANSITION removal now also edits this constant.
- **Rekor by digest.** Each digest links to `https://search.sigstore.dev/?hash=sha256:<hex>`. That is a real
  per-digest record, not a decoration: on 2026-10-03 Rekor's `POST /api/v1/index/retrieve` returned two
  entries for each of the live api and web digests. Commits and runs link to the public repository and its
  public Actions runs. All of these are links; the page fetches nothing cross-origin.

### 2. Publication: exactly these fields, and what never leaves
The new public fields, each optional for the page (an old API answers 404 or omits it, and the page hides
that piece):
- `/api/stats`: `last_run_at` (the time of the most recent `queued` run event) and `last_24h` (`since`,
  `runs`, `detected`, `responded`, `falco_alerts`, `talon_actions`).
- `/api/posture`: `kyverno.violations[]` grouped by policy, rule, kind, namespace and `running` (`count`,
  `running` true/false/null, `file` - the policy's path in this repository from the rule index), at most 50
  groups plus `violations_truncated`; `kube_bench.failing[]` (`id`, `title`, `remediation`, at most 50, in
  benchmark order) from the newest successful run; `trivy.last_scan`; `falco.counted_since`.
  `falco.alerts_24h` and `talon.actions_24h` keep their names and meaning and now come from the persisted
  window.
- `/api/provenance` (above), `/build.json` (above).
- `/api/runs`: the last 50 runs as summaries (id, scenario, state, start and end - either may be null -,
  detected, responded, event count, truncated) - no pod, no command, no output; the events stay at
  `/api/runs/{id}`.
- `/api/events?tick=1`: a `tick` event (`at`, `started_at`), below.

**Never published:** a resource's name (no ReplicaSet, Deployment or pod name of anything outside the
sandbox), the Kyverno message, kube-bench's `audit`, `actual_value`, `expected_result`, `AuditEnv`,
`AuditConfig` and `reason` (they quote this host's values), the api and web pods' names, and their
namespaces as part of provenance, and everything ADR 0021 already forbids (node names, host and pod IPs,
`*.svc` and `*.cluster.local` names, tokens, ServiceAccount names, Argo CD URLs). Every structure is built
field by field from an allow-list, never by copying a cluster object, and every free-text field (the
kube-bench title, capped at 200, and remediation, capped at 300) goes through the ADR 0021 scrubber and
truncation; after scrubbing, the name of the node the benchmark pod ran on is replaced by `[node]` in both,
since a check's text can quote it. A text over its cap is cut after its last sentence end when that keeps
at least 60% of the cap, else at its last white space, and inside a word only when one token alone is
longer than the cap; the cap counts runes, the ellipsis included. The kube-bench log committed as a test
fixture is redacted the same way (node `node-fixture`, address `192.0.2.10`, a documentation address).
The api and web namespaces are kept out of provenance only: a violation group may name any namespace,
`portfolio-api` and `hello` included, since every namespace here is declared in the public repository.

**kube-bench remediation text may name host file paths** (`/var/lib/rancher/k3s/...`, the CNI
configuration directory). They describe where k3s keeps its files on any host, not something particular to
this one, and ADR 0021 forbids addresses, names and credentials, not documented defaults; that is decided
here so a reviewer does not have to guess.

**A stale violation is attributed, not hidden.** A PolicyReport's `scope` names the object it judges
(kind, namespace, uid). A violation group is `running: true` when at least one Pending or Running pod is
that object or is owned by it (`ownerReferences` uid, for ReplicaSets, Jobs, StatefulSets and DaemonSets),
`false` when it is such a kind and no such pod exists, and `null` when the kind cannot own pods, the
report carries no uid, or this refresh's pod list failed. The page says "0 running: old revisions kept at
0 replicas" for the false case; it shows the amber "stale config, nothing running violates" only when every
group is `false`, red otherwise, and never reduces the count.

### 3. Persistence: one window for alerts, actions and runs
`portfolio-stats` (ADR 0030) gains hourly buckets (`H` = the unix hour; runs, detected, responded, Falco
alerts, Talon actions), `WindowSince` (when this window started counting) and `LastRunAt`. It stays one
aggregate blob in one ConfigMap with the same `get`/`update` grant; no visitor identifier, no address, no
per-run record.

- **One bucket set feeds both pages.** The stats collector replaces `webhook.Window`: the webhook
  handlers add alerts and actions to the current hour of the same buckets that hold runs, and the posture
  reads its 24 h counts from them. Those three posture values are recomputed on every request, cache hit or
  not (25 buckets), so they are never up to 60 s behind `/api/stats`.
- **The window is 23 to 24 hours, and says so.** It is the current hour plus the 23 before it.
  `since` is the later of the start of the oldest hour and `WindowSince`, so the first day after this ships
  reads "since 19:05", and the page labels the numbers with `since`, never as a bare "24 h".
- **Runs, detections and responses of one run share a bucket**, the hour the run was queued, and a response
  counts only together with a detection: when Talon's notification arrives first (the terminal path), its
  response is added to `last_24h` when the detection arrives, and a run that never gets a detection adds no
  response to the window (its Talon action still counts in `talon_actions`). So `runs >= detected >=
  responded` holds in every window. Alerts and actions are bucketed when they arrive. A run event stamped in
  the future is counted as now, for its bucket and for `LastRunAt`, so a skewed clock cannot park counts in an
  hour that has not started. Because alerts count from every namespace and each action precedes the response
  it reports, `actions_24h >= responded` always holds, and `alerts_24h >= detected` holds except while a
  detection published on the Talon-first path is still waiting for its Falco webhook (normally seconds) or, if
  that webhook is lost, until the run's hour leaves the window. That is the only exception.
- **Sanitised, not rejected, on load.** A bucket older than the window or more than one hour in the future is
  dropped, duplicate hours are summed, a `WindowSince` or `LastRunAt` in the future is clamped to now. An
  hourly section that is still malformed after that (a negative count, a count above 2^40, or more than 25
  buckets in range, counted after same-hour buckets are summed) is discarded on its own: the window restarts
  at now while the all-time totals still load. Only a malformed all-time section rejects the blob (counts as
  unparseable, ADR 0030), as before. A late first read merges as before: buckets are summed by hour, the
  earliest `WindowSince` and the latest `LastRunAt` win. Today's blob, without the new fields, loads with
  every all-time counter unchanged, no buckets and `WindowSince` = now.

### 4. Honest motion
- Absolute times are UTC and say "UTC"; a relative time ("6 h ago") appears only next to an absolute one.
  The run history shows UTC with milliseconds and links each run's raw JSON at `/api/runs/{id}`.
- `GET /api/events?tick=1` sends one tick right after the replay and then replaces each 15 s heartbeat comment
  with one: `event: tick` / `data: {"at": ..., "started_at": ...}` - the server's clock and the API's start -
  without an `id:` line, so resuming with `Last-Event-ID` is unaffected. It is opt-in: without `tick=1` the
  stream is byte for byte what it was, and a page that does not know the event ignores it.
- The page shows the newest run as an evidence card at the top (scenario, state, absolute time, the sandbox
  pod's name and UID, image digest, container id, the first Falco and Talon events with their own and the
  API's timestamps, the commands of a terminal run, the latencies, and "N more - raw JSON"), a ticker of the
  last eight real feed events, and a liveness line (API up since, server time from the tick, posture
  refreshed, kube-bench, Trivy). Everything comes from real events and real server timestamps. Nothing is
  padded, looped or animated for effect; when nothing has happened, the page says when the last thing did.
  All of it is read with GETs; nothing on page load starts a run (ADR 0017).

### 5. The mock does not ship
The production build resolves the one module through which the page reaches the MockBackend to a stub
that returns nothing (an esbuild alias), so the mock, its fixtures and its terminal catalogue are not in
the bundle at all; the `#mock-banner` markup is stripped from the production HTML. `npm run build:mock`
builds the same page with the mock into `dist-mock/` for development and the `?mock` end-to-end suite;
the layout and stub-API suites run against the production bundle. A `define` constant with a dead branch
was not enough: the fixtures module has top-level code a bundler keeps. Three checks enforce it: a unit
test that builds both bundles and requires the mock markers in one and none in the other, the image smoke
test (no served file carries the markers, `/?mock=1` serves the same page), and the live
acceptance check. This amends ADR 0033.

### 6. The seven stale ReplicaSets are pruned
Talon's Deployment (`talon-deployment.yaml`) and Falcosidekick's chart values set `revisionHistoryLimit: 1`.
The controller then deletes Talon revisions 1-4 and Falcosidekick revisions 1-3, the upstream images, and
keeps one previous revision of our own build for a rollback. 1 rather than 0 because the Falcosidekick
chart templates the field only under an `if`, so 0 cannot be expressed; 1 rather than 2 because 2 would
keep Talon revision 4 and Falcosidekick revision 3, which are still upstream images. The page keeps the
general "not running" explanation of section 2, because the next stale object will not announce itself.

## Alternatives considered
- **Persist the 1440 one-minute buckets.** A ConfigMap blob sixty times larger for a precision the page
  never shows.
- **Derive the 24 h numbers from the run history.** The history is in memory too (ADR 0021), so it is lost
  on the same restart.
- **Drop the 24 h tile.** Removes the contradiction and the only runtime signal that is not a visitor's
  own run.
- **A second ConfigMap for the window.** A second object means a second grant (ADR 0030 keeps the API to one).
- **Provenance from Argo CD, from the registry, or from the downward API.** Argo CD means new reads (and is
  B5's subject); the registry means new egress from the API; the downward API cannot expose the image
  digest. The pod list is already read.
- **Exclude the mock with a `define` flag or a runtime switch.** The fixtures survive a dead branch, and a
  runtime switch still ships the code.
- **Delete the stale ReplicaSets by hand.** The next rollout would start the history again, and the
  manual deletion of ADR 0015's Trivy amendment is exactly what not to repeat.

## Consequences
- The 24 h numbers move by hour: a run at 10:59 leaves the window an hour after one at 10:00. The first day
  after rollout shows "since <time>"; a crash loses at most the last minute of counts, as ADR 0030 already
  accepts for every counter. During a rollout overlap the ConfigMap is last-writer-wins (ADR 0030): alerts,
  actions and runs that reach the old pod in its last minute can be lost from the window.
- Rollback: the previous API ignores the unknown fields when it reads the blob, but its writes drop them,
  so the window starts again (the all-time counters survive). Rolling forward again sanitises whatever it
  finds.
- The workflow change and the new label give every image a new digest once and rebuild all fifteen; only
  api and web are re-pinned. A third-party image may fail its Trivy gate on that rebuild, as on any
  rebuild, without anything deployed changing.
- The page's digests can be up to 60 s stale (the posture cache) and are always labelled with the time of
  the pod list they come from. The api and web commits can differ: each image is rebuilt only when its
  directory changes (ADR 0016), and the page says so.
- The identity regexp is shown verbatim, `|build-web` included, until ADR 0016's cleanup removes it from
  the policy, `verify-image.sh`, `docs/bootstrap.md` and `provenance.ts` together.
- Only one previous revision of Talon and of Falcosidekick is kept for a rollback; an older one is a
  `git revert` and a sync away.
- The in-memory open item of ADR 0015 narrows again: the 24 h counters persist; the rate-limit windows and
  the per-run history do not.
- The posture now names failing checks and violating policies. That tells an attacker which CIS checks
  fail here; it is the honesty the page claims, and the same names are derivable from the public
  repository and the k3s defaults.

## Follow-ups
- B5 (a live cluster panel) and B6 (live architecture and About copy), out of this phase.
- Drop `|build-web` from the admission policy, `scripts/verify-image.sh`, `docs/bootstrap.md` and
  `app/web/src/lib/provenance.ts` in one commit (ADR 0016).
