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

## Amendment 2026-10-04: the verify panel follows the posture; the hero keeps one link to it

**Context.** Section 1 put a compact "Running now, signed in CI" strip in the hero, above the fold: each
image's commit, short digest, a Copy cosign button and its Rekor search. The owner did not want the
verify data at the top of the page.

**Decision.** The owner moved the verify data out of the hero: the evidence card is the above-the-fold
proof; the full verify panel follows the posture section; the hero keeps one link to it. The strip, its
markup and its styles are gone. The hero's only trace of provenance is a small text link "Verify it
yourself" next to "Read the source", pointing at `#verify`. The sections run hero, `#evidence`,
`#posture`, `#verify`, then the rest as before. The panel itself is unchanged: commits and CI runs,
every running digest, a cosign command per digest (only for a reference `isPinnedImageRef` accepts),
Rekor links, a curl line per public endpoint and the latest run's raw JSON, polled every 60 s and keeping
the last good answer on a failure.

**Consequences.** Nothing about the running images is visible without scrolling or following the link;
the evidence card, which the end-to-end suite requires above a 1280x720 fold with the installed fonts
and with a wide one, is what a first glance proves. The hero has room again: its height is no longer
bounded by a block of data that had to stay above the fold.

**Later the same day: the verify panel moves to the bottom, its link to the footer.** The owner then
found that the panel, right after the posture, still drew attention away from what the visitor should
see first (the evidence, the posture, the attack). The `#verify` section is now the last section of the
page, just before the footer: hero, `#evidence`, `#posture`, `#attack`, `#how`, `#about`, `#skills`,
`#projects`, `#verify` (in production `#about` is stripped while unwritten, so `#verify` follows
`#projects`). The "Verify it yourself" link left the hero, which no longer links to `#verify` at all; the
footer carries one plain link "Verify the running images", styled like the other footer links. The panel's
content, its polling and the `isPinnedImageRef` rule are unchanged. The end-to-end suite asserts the
section order, a hero with no provenance and no `#verify` link, and that the footer link brings
`#verify-title` into view.

## Amendment 2026-10-05: the attack first; every section below the hero folds

**Context.** The owner found that the page still led a visitor away from what it exists to show: the live
attack, the cluster's response and the SIEM's correlation (ADR 0036). Evidence and posture came first, and
every section was always open, so the attack started a long scroll down.

**Decision.** The sections run hero, `#attack` (the terminal, the one-click launcher, the live run
`#console` and the run history), `#correlation` (shown only while the SIEM answers), `#how`, `#about`,
`#evidence`, `#posture`, `#verify`, `#skills`, `#projects`; in production `#about` is stripped while
unwritten. The navigation follows the page (Attack it, How it works, About, Posture). The stylesheet's
counter numbers the eyebrows, so the numbers follow the order with no copy to change. `#verify` keeps the
footer's link as its only one; the hero still links to none of it, and its lead now opens with the attack.
The hero's evidence card stays where it was, the above-the-fold proof; its "full record" link reaches
`#evidence` further down.

Every section but the hero folds under its heading (`app/web/src/ui/sections.ts`). The h2's text moves
into a `<button>` with `aria-expanded` and `aria-controls` naming the section's `.section__body`, a chevron
and the page's focus ring; every section starts open, and a visitor's choice is kept per section in
`localStorage` (`sdp:collapsed:<id>`; a storage error leaves it unremembered). `theme.ts`, the
render-blocking script that already applies the stored theme, names the folded sections in
`html[data-folded]` before first paint and the stylesheet folds them, so nothing jumps when the buttons
arrive. A folded section shows its eyebrow and its title only. A link to a folded section, or to anything inside one, opens it before the
browser scrolls (a modified or non-primary click does not); so do a hash change and a page opened at a
hash. A reload or back/forward keeps the scroll position the browser restores. Without JavaScript nothing folds.
Folded is not hidden: `#correlation` hides itself while the SIEM is unavailable whether folded or not.

A folded section stops drawing what nobody can see. The posture is still fetched every minute (the
evidence's liveness line reads it) but drawn only when unfolded, with its live region off for that draw so unfolding does not read the
whole panel aloud; the correlation is still polled (it
decides shown or hidden and the verify panel's endpoint list) but drawn only when unfolded; a folded
`#evidence` draws neither its ticker, its liveness line nor its full record, while the hero's card goes on,
and what arrived meanwhile is not announced as new on unfolding. The attack section's terminal, launcher,
console and history keep running folded or not: a session must not stall because its panel was folded.

**Consequences.** The attack is right after the hero; the proof of what was recorded and the posture
remain one link or scroll away. The end-to-end suite asserts the order, the toggle (aria, hidden body,
kept over a reload, by keyboard), anchors opening a folded section, and toggles that fit 320 and 360 px
with a wide font forced in.

## Amendment 2026-10-06: times in Polish time, with CET or CEST

**Context.** Section 4 made every absolute time UTC and say "UTC". The owner asked for every time on the
page in Polish local time instead.

**Decision.** The owner decided (2026-10-06) that every absolute time on the page is shown in Polish time:
the zone is named explicitly, `Europe/Warsaw`, never the visitor's or the host's, so every visitor reads the
same text. One helper pair in `app/web/src/lib/dom.ts`, `plTime` and `plClock`, formats with
`Intl.DateTimeFormat` and `timeZone: "Europe/Warsaw"`, a 24-hour clock and the zone's label:
`2026-10-06 12:34:56 CEST`, `.123` with milliseconds where the record has them, the date dropped on the same
Polish day. The label is en-GB's short zone name (CET or CEST); an ICU without those names gives the
offset, and `GMT+1` and `GMT+2` are mapped to CET and CEST. The label is what tells the repeated hour
of the autumn switch apart (02:30 CEST, then 02:30 CET on 2026-10-25). Relative times ("6 hours ago") are
unchanged and still appear only next to an absolute time.

Machine-readable values stay UTC: the `datetime` attribute of every `<time>` (the ISO instant), data
attributes, the raw JSON at `/api/runs/{id}`, anything a visitor copies (curl, cosign), and the verify
table's raw timestamps, whose column now says "Raw (UTC)". The API is unchanged: it publishes RFC 3339
UTC, and no text it writes for incidents or steps embeds a clock time.

**Consequences.** The unit tests set the host's zone to `America/Los_Angeles` before the helpers load and
cover both switches (2026-10-25 and 2027-03-28) on each side; the end-to-end suite runs with `TZ=UTC` and
checks the server time's text against its `datetime`. Dropping the `timeZone` option or setting it to UTC
fails both. A Falco output line is shown verbatim, as Falco wrote it; its own leading clock, when present,
is Falco's and is not rewritten.

## Amendment 2026-10-06: the visitor's run, told back (UX stage 1)

**Context.** A visual audit of the live site (2026-10-06) and the owner found the page hard to follow,
even for the owner. When Falco and Talon ended a session, the only visible signs were a small line in
the terminal's title bar and a green "objective reached"; the announcements went only to visually
hidden live regions. Minutes later the SIEM's CRITICAL incident for the same run sat thousands of
pixels below with nothing pointing at it. Beside the terminal, a seven-card map of the deployment's
defence layers (most of them "never reached" from a sandbox) made the right column three times taller
than the terminal and left a void beside it. The SIEM board was a wall of routine contained
intrusions, and no scenario let a visitor cause the one incident the SIEM exists for. The owner asked
for a SIEM scenario a visitor can run on purpose, the automatic Falco + Talon incidents tucked away,
a visible message when an incident shows up during the visitor's run, and a layout fix for the attack
section. The owner kept every section expanded by default (amendment 2026-10-05 stands).

**Decision.**

*The visitor's run, told back.* One reading of the visitor's own session joins what the page already
has: the run's events from the stream (`pod_ready`, the Falco alert, the Talon response, the end) and
the incidents of `GET /api/correlation`, matched by the `run_id` every incident already carries (ADR
0036 §9; the same id is public in `/api/runs`). No API change was needed. `app/web/src/lib/runstatus.ts`
holds the pure state machines; `ui/runstatus.ts` draws them and hands the same reading to every part
that shows it.

- *Status strip and toast.* A strip under the terminal's input, at the pane's full width, says what just
  happened: "Pod starting…", "Pod ready. uid 10001, no network, read-only root. Type a command.",
  "Falco saw that — <rule> at +<ms>", "Talon deleted the pod <ms> later. Session over." (with *Watch the
  kill timeline* and *Run again*), "Talon quarantined the pod…", "Waiting for the SIEM (usually 1–3
  min)…" after a DNS exfil that exited 0, then "The SIEM caught your DNS exfil — CRITICAL. Falco never
  saw it." or "The SIEM filed this as <SEVERITY> — <kind>" (with *Open it*, a link to the card that opens
  a folded section and pulses the card; the card itself carries the id, so its badge and title land
  below the sticky header). *Run again* starts the next session at once (it costs one run, as the start
  panel says). A command Falco allows changes nothing. Each message is
  remembered with the update it first appeared in and the newest wins; messages that first appear
  together are ranked by how big the news is; a later, milder filing never replaces a more severe one
  (the strip then says how many more there are); a SIEM wait still running under a newer message is
  its second line. A new session starts from nothing. Between sessions the strip sits under the start
  button. When it is scrolled well out of view (under the sticky header counts; a strip just below the
  fold does not), a slim toast at the bottom of the screen says the same, except while the board's own
  or pinned tier or the linked card is on screen, and not again once its *Open it* has been followed. On
  a phone the toast is one line: the lead and *Open it*. Neither is a modal; both are dismissed together,
  a dismissed message stays away until the next one, and the focus goes back to the terminal.
- *One announcer.* One polite, atomic, visually hidden line outside the strip, always in the page,
  speaks each message once (rewritten only when its words change, so the first message is heard although
  the strip appears with it). The run history's and the evidence ticker's hidden announcers keep quiet
  about the visitor's runs, and about any terminal run while the visitor's own start is in flight (its
  first events can come before its id); the terminal bar's status line is live only while watching
  someone else; the ready banner in the output is swapped for the eye only; the strip and the toast are
  not live: nothing is read twice.
- *The page's clock.* The SIEM waits ("waiting", then "late" after six minutes) are timed on the page's
  own clock from the moment it first saw each expectation, never by comparing the visitor's clock with
  the API's timestamps. The API files all three expected kinds with the run's id for a terminal run.
- *Polling.* While a filing for the visitor's run is awaited (a DNS exfil, a Falco alert, a prevented
  command), `/api/correlation` is asked every 20 s instead of every minute, never while the SIEM is
  unavailable, and never more than nine minutes after the eager polling began. Only an answer changes
  what the page knows: `available: false` or a 404 makes the SIEM unavailable; a network error, a 5xx, a
  429 or a malformed answer keeps the last reading.

*The attack section.* Beside the terminal sits only what belongs to this session: a "This run" panel
with three rows (detection: Falco's rule and how long after the Enter; response: Talon's action and how
long after the alert; SIEM: waiting, or the filed incident's severity and kind, linked), the objectives
as compact pills, this run's own timeline event by event (pod created, ready, each command coloured by
its outcome, Falco, Talon, the end: the visitor's kill timeline, compact) and the shop in a fold, open.
The panel's grid cell is as tall as the terminal pane (the aside adds nothing to the row); the panel in
it is sticky and capped at the screen, so it can never outgrow the terminal; when it would scroll, the shop folds first (unless
the visitor chose) and a fade marks more below. The output has a minimum height, so the pane is the
tallest thing in the row. The detection row is red, as Falco's answer is everywhere else. The command chips leave the pane for a full-width
palette under both, grouped by objective, with a legend: grey allowed, red Falco answers, amber
prevented, green only the SIEM sees it (an allowed command whose control names the SIEM: the
catalogue's dns-exfil). On a phone the pane's parts become the grid's rows and the panel is one card
between the output and the input, its rows always shown and the rest behind *Details*. *Just show me*,
the live run console and the run history stay below; the history shows four runs and folds the rest.

The seven-layer map moves out of the terminal: "How it works" already showed the same seven cards, and
now lights the layers the visitor's last session touched, each with what it met ("Lit: the layers your
last terminal session touched"). The session summary keeps only the layers the session touched, with a
link to the whole map.

*The SIEM section.* `#correlation` opens with the scenario: "Make the SIEM catch what Falco cannot. Falco
watches syscalls and never reads DNS. Run DNS exfiltration in the terminal and the secret leaves as a
name lookup: Falco stays silent, Hubble logs the query, and one to three minutes later the SIEM ties it
to your run and raises a CRITICAL incident below." Its button scrolls to the terminal, opens a session
if idle (it says it costs one run), highlights the dns-exfil chip and fills it in once the pod is ready.
A state chip follows: not run yet → running… → waiting for the SIEM (≈2 min)… → found it, with a link to
the incident (and "the query did not go out", "still waiting", "the SIEM is not reachable" where those
are true). The board follows. The visitor's own incidents of this page view come first, in full, under
"From your run on this page" (one may be a contained intrusion Falco did see). Then three tiers. Pinned,
"Caught by correlation, not by Falco": the kinds dns-exfil, policy-probing and prevented-not-detected
and any incident with no Falco event, in full, by severity, with a distinct accent and the severity
first. Folded, "Contained automatically by Falco + Talon (N)": the contained intrusions, one
line each under a summary (count, median time to detect and to isolate over the ones listed). Then the
other kinds in full as before, the operator test-suite execs and the older incidents in their folds. The
SOC tiles follow the board, and the SIEM health pills and the ingest-lag line are one folded "SIEM
health" whose summary says every check is ok or names the ones that are not.

*Smaller fixes.* The page keeps a catalogue command's `explain` up to the API's own bound (2000
characters, `scenarios.go` maxExplain), not 400: the dns-exfil text's cut-off part was the sentence that
sends the visitor to the SIEM. An objective reached by the command the cluster then deleted the pod for
is amber, "and it cost you the pod", not a green win. The "Pod starting…" banner turns into a ready line
at `pod_ready`. A blocked start says when the busy run must end at the latest (its session or idle
limit). A Talon step in an incident's evidence carries whole seconds: it is shown "to the second" and
ordered by the end of its second (Talon logs after the API server acted), and the deltas count from the
first millisecond step. Under 760 px the header carries a compact jump bar (Attack it · SIEM · How it
works · Posture) as a second row that scrolls sideways inside itself; the SIEM link is shown only while
the section is; anchors land below the sticky header (`scroll-padding-top`). A page opened at an
anchor lands there again each time the live parts change the page's size (the hero's counters, the
terminal's panel, `#correlation` shown once the SIEM answers), until the visitor scrolls, touches or
types, or for 10 s; not on a reload or back/forward. The verify body and small
print break long hashes anywhere. The pulse is a short outline animation, a steady outline under
`prefers-reduced-motion`. Everything stays text through `h()` (no DOM sink), with no inline script or
style, and every published text is the API's own, already within ADR 0021.

**Consequences.** The visitor sees what happened to their own run where they are looking, and is led
from the terminal to the incident and back. The attack section's right column is session-scoped and
bounded; the board's first card is the one Falco missed. The unit tests drive the strip's and the
scenario chip's state machines with run events in the API's shapes and incidents in ADR 0036's
(including a replay seen at once, another run's incident, a later milder filing, a late or unavailable
SIEM); the mock's SIEM files a dns-exfil and a contained intrusion for the visitor's own terminal run
(`&mock-siem-delay=`), and the end-to-end suite runs the strip from ready to the SIEM's catch, the
toast, *Open it* and its pulse, the scenario button, the layout on a desktop and a phone, the jump bar
at 360 and 320 px and the reduced-motion pulse. Not in this stage: the hero, typography and contrast,
the evidence and posture sections.

## Amendment 2026-10-06: this session first, everything else behind one filter

**Context.** After UX stage 1 the owner still found the page chaotic: every visitor's runs of the
whole day were mixed into the run history, the live run console, the evidence card and ticker and the
SIEM's board, so nothing showed the link between what *this* visitor did and what got detected. The
incident cards' "SIEM evidence: correlation …, finding …, finding …" line was a wall of ids.

**Decision.** By default the page shows what the current visitor does, plus a run another visitor has
in progress right now, labelled as theirs. Every other run and incident of the window is behind one
choice, drawn as a segmented pair of buttons beside each list it scopes (the run history, the evidence
ticker, the SIEM's board), every copy the same control: "This session" (the default) | "All activity,
last 24 h". The choice is kept in `localStorage` as `sdp:scope` (beside the fold keys; a storage error
leaves it unremembered). Each copy is named for what it scopes, and one polite line says what the page
shows after each change. `app/web/src/lib/scope.ts` holds the pure rules, `ui/scope.ts` the control.

- *The visitor's runs* are this tab's: the terminal sessions it started (the strip's reading) and the
  one-click runs it launched (the POST's id). They are kept in `sessionStorage` (`sdp:own-runs`, the
  newest 20), so a reload still knows them; they are public ids (`/api/runs`), and only strings
  `isRunId` accepts are read back. After a reload they keep their "Your run" label, the board's own
  tier, and the scenario chip's "found it"; the terminal shows a live session of theirs from before
  the reload read-only as "your session from before the reload" (the page lost its key), not as
  another visitor's. Nothing in UX stage 1 changes: the strip, the This-run panel and the own tier work
  as before.
- *Live now.* A run in progress that is not the visitor's is shown as "Someone else is attacking right
  now": its card in the history, the console ("· you are watching it live"), the hero's card, its
  events on the ticker and any incident already filed for it. When it ends it drops out of this view.
- *Per part.* The run history lists the visitor's runs and the live one, each labelled, and says how
  many other visitors' runs the filter holds, in a line that ends in a button, "show all activity,
  last 24 h", as the ticker's and the board's do. Only records of a run count as other visitors' (not
  an operator's test exec, nor an event or incident tied to no run). The console shows a run picked
  from the history, the run in progress, or the visitor's newest, never an earlier visitor's on its
  own; after the visitor's terminal session it says that session is told beside the terminal. The hero's card shows the
  visitor's run in progress, else the live one, else the visitor's newest; its eyebrow and #evidence's
  full record say whose it is. The ticker lists only those runs' events (no unattributed event) and
  counts what it leaves out. The SIEM's board lists the visitor's incidents under "From your run on this
  page" and the live run's under "Someone else is attacking right now"; "All activity" is the board of
  UX stage 1 unchanged.
- *The empty state* (the owner's decision): when the visitor has done nothing and nobody else is
  running, the run history, the hero's card, the ticker and the board say "Nothing from you yet — launch
  an attack" (a link to the terminal), and the history, the card and the board then show exactly one
  clearly labelled example of an earlier visitor's run: the newest run the cluster answered, else the newest ("Example: an earlier visitor's
  run", the same on the card and its full record), and on the board the newest critical DNS exfil, else
  the newest critical incident, else the newest (never an operator's test exec nor one tied to no run), under "Example: from an
  earlier visitor's run". The ticker and the console show no example. A visitor whose runs the SIEM has
  not filed yet is told it usually takes 1–3 min. Everything else stays behind "All activity, last 24 h".
- *Aggregates stay global* and say so: the hero's counters are "Live, all visitors — not only yours"
  (each tile keeps its own window), the SOC tiles "SOC figures · last 24 h, all visitors", the ATT&CK
  matrix's caption "incidents in the last 24 h, all visitors". The rule library is no one's.
- *The SIEM evidence line* is one line of counts, "Evidence: 1 SA correlation · 4 findings", a
  `<details>` whose "show IDs" opens the SIEM's record ids as wrapped monospace chips with a link to
  `/api/correlation`, and stays open across the board's redraws; nothing scrolls sideways at 320 px.

Sections still start expanded (amendment 2026-10-05 stands). Everything stays text through `h()`, with
no inline script or style and no new published field.

**Consequences.** A first-time visitor sees a prompt and one example instead of a day of other people's
runs, and after their attack sees only their own run and what was detected for it. The unit tests cover
the stored scope and run ids (garbage, repeats, the cap, a throwing storage), the selection rules, each
scoped part and its empty state, the control's copies moving together and the compact evidence; the
end-to-end suite (mock) covers the default view, the filter revealing the history and persisting over a
reload, the empty state's prompt and one example, another visitor's live run labelled and dropping out
when it ends, the evidence line expanding, and no sideways scroll at 320 px. The tests of the whole
board and history choose "All activity" first.

## Amendment 2026-10-12: the hero is a live diagram, the evidence card moves to #evidence, sections fold by default

The owner's verdict on the live page: "the visitor gets a wall of text on arrival and gets lost; it does
not truly show what we want to show." Measured on 2026-10-12 the page was 14 315 px on a 1440 px desktop
and 23 405 px on a 390 px phone, ten sections one under another, and above the fold the hero carried a
four-sentence lead, two buttons, four stat tiles, an objectives list and — in its right column — the
"evidence card": another visitor's raw run with a pod UID, an image digest, a container id and raw
Falco/Talon lines. Nothing was false, but it explained nothing to a newcomer and buried the one thing
the project is: a cluster that answers an attack, live.

**The hero is the diagram, and the diagram is the evidence.** Above the fold now: the name, one sentence,
one primary button ("Attack this cluster"), one line of live counters, and a live architecture diagram
that fills the width. The diagram is drawn from one model (`app/web/src/diagram/model.ts`) by a pure
layout module; the same model generates `docs/architecture/overview.svg` (`npm run diagram`, checked by a
unit test), so the drawing on GitHub and the one on the page never drift. On load the diagram lights the
path of the newest real run the page knows — the request in, Falco's detection, Talon's answer back to
the pod — with the real detection-to-response time in its status line; this is the evidence, shown as a
mechanism rather than a JSON dump. It does not loop: a path lights from a run's events and stays, the
packet animation plays once per change and not at all under `prefers-reduced-motion`. Every node is a
button (keyboard-reachable) that opens a caption: one or two sentences and a link to the file in the
repository, the same blurbs the "How it works" defence map uses.

**The evidence card leaves the hero.** The detailed record — pod UID, image digest, Falco fields, the
command list — stays, but only in `#evidence`, where a visitor who wants the raw material finds it. The
hero carries no provenance (the rule of 2026-10-04 stands): no commit, digest, cosign, Rekor or
`#verify` link in `#top`.

**The guided tour.** `#attack` opens with a six-step tour (sections revealed in order, never an overlay):
look around (`id` or any look-around command), break something (both the `deface` and the flag read),
hide it in DNS (`dns-exfil`), get caught (a terminal session in which `sh -i` ran and Talon then
terminated the pod — a one-click run the cluster killed does not count), see what the answer is worth (the one-click
side-by-side run against the unguarded twin), and see it in the SIEM (the `dns-exfil` incident the SIEM
files a minute or two later, which opens `#correlation`). Progress is derived from the visitor's own runs
and the SIEM's incidents for them — not a stored counter — so a reload re-derives it and nothing is
ticked that did not happen; only "skip" is stored. The tour costs two runs of the per-visitor limit, and
says so; it degrades to nothing without the terminal.

**Sections fold by default.** Everything below `#attack` (`#correlation`, `#how`, `#evidence`,
`#posture`, `#verify`, `#about`, `#skills`, `#projects`) starts folded for any visitor without a stored
choice for that section — a first visit, and every later one until they open it
(`app/web/src/lib/folds.ts`) — so the page is short and the one path is clear; a visitor's own choice,
stored per section as "1" (folded) or "0" (open), always wins, and `theme.ts` applies the defaults and
the choices before first paint so nothing jumps. Should the module throw before the sections' buttons
exist, `main.ts` clears that pre-paint stand-in, so a page never shows folded sections with nothing to
open them. Without JavaScript nothing folds and everything shows, as before. The objectives list moves out of the hero into a fold in `#attack`; a short About bar (an
`<aside>`, the first sentence of the About text verbatim) sits after the attack, the full About folded
below. The amendment of 2026-10-05 ("the attack first; every section below the hero folds") is widened:
the sections do not merely fold on request, they start folded.

**Measured after.** The desktop page is about 5 000 px on first load (from 14 315), the phone under
8 000 px (from 23 405); the page order is unchanged, and `#top` still carries no provenance. The page's
diagram model names namespaces and components but no port, VLAN or address (ADR 0021); the docs file
is drawn from a fuller model that only the build script and the docs renderer import.

**Tests.** The unit suite covers the diagram models' consistency (the page's, with no port, VLAN or
address, and the docs'), the layout's tree (a node per element, `role="group"` for the interactive SVG
and `role="img"` for the docs file, no HTML sink), the hero path lit from a run's events with each edge's
stage and the lit nodes in words, `mountDiagram`'s caption by click, Enter, Space and Escape with
`aria-expanded`, the SIEM state kept across `setRun`, the committed `overview.svg` equalling the
generated one, the tour's progress derived from events (both tamper commands; a terminal shell session
for "caught"), and the fold defaults. The hero-stats tests cover the one-line figures. The end-to-end
suite (mock build) asserts: the above-the-fold shape at 1280x720 and 1440x900 (one primary button, the
whole diagram and its caption, no evidence card and no provenance in `#top`) and the first nodes with
the buttons on one row at 390x844; the page-height budgets on a first visit (desktop 1440 ≤ 5 500 px, which leaves room for other system fonts,
phone 390 ≤ 9 000 px); the diagram's nodes reached by Tab, opened with Enter or Space, closed with
Escape, `aria-expanded` following; the tour advancing through its steps from real commands in the
mock terminal, its skip remembered, its progress re-derived; the sections folded by default and a stored
choice kept over a reload; and no horizontal scroll at 360 and 320 px.

## Amendment 2026-10-13: nothing moves the page but the visitor; the tour is a panel beside the terminal

The owner, on the live page of 2026-10-12: visitors still did not like it — "it jumps on its own"; the
step-by-step list could sit beside the terminal on a desktop, floating or sticky; the SIEM's
detection should be a notification; the page should not scroll by itself.

**No automatic scrolling.** Nothing the page does on its own moves the viewport or the focus: not a
tour step completing, not a run ending (the session summary no longer scrolls into view), not a
one-click launch (the console is no longer revealed; the status line says "Watch it play out in the
live run below ↓" with a link), not an incident landing, not a redraw restoring a focus (every such
`focus()` passes `preventScroll`). The page scrolls only for the visitor's own press on something whose
purpose is to go somewhere — a navigation link, "Attack this cluster", "Run it in the terminal ↑",
"Watch the kill timeline", "Show in SIEM", "Open it ↓", the history's Show — and for landing on a
`#hash` when the page opens. Sections no longer open on a step's completion: the step, or the
notice, offers a link, and the visitor follows it or not. A link to an incident card while
`#correlation` is folded opens the section first (its board is not drawn while folded), then the
browser lands on the card. Content that changes above the visitor reserves its room so the page does
not shift under them: the diagram's status line keeps two lines (the lit nodes in words stay for a
screen reader on a phone, where the picture shows them), the launch status moved below the buttons
and keeps its line, the start panel's "a run is in progress" lines keep theirs, the attack stage's
row is never shorter than the panel can get (so a notice landing beside the terminal moves nothing
below it), the phone's tour bar keeps its height.

**The tour beside the terminal.** From 1100 px the attack stage is two columns: the terminal, and a
sticky panel (below the header, which is measured — the mock banner included — into `--header-h`)
with the six steps, the current one expanded with its hint and button, the done ones ticked; a done
step offers its way there ("Watch the kill timeline", "Show the live run", "Show in SIEM"). Below the
steps, the notices: Falco's detection, Talon's response and the SIEM's incident for the visitor's own
runs, each with its time, newest first, derived from the same evidence as the progress (so a reload
lists them again and nothing is listed that did not happen), a polite live list that never takes the
focus. The SIEM's notice dates the attack it caught ("(first seen HH:MM:SS)"), as the API publishes
an incident's first event and not when the SIEM filed it; a listed notice's clock is re-read on each
redraw, so past midnight it gains its date. A redraw under the keyboard (the feed's every view redraws
the panel) puts the focus back on the equivalent control, or on the current step's button when the
one it was on is gone. The notices stay when the tour is hidden. Below 1100 px the tour is a bar of
two fixed rows above the terminal — "Step n of 6" and the toggle; the current step's title, cut with
an ellipsis, and its button ("Tour done" at the end) — so nothing above the terminal ever changes
height; the opened steps and the notices go below the terminal (`#tour-below`), and a fresh notice is
one small toast at the bottom (under the header when the terminal's input is down there, placed again
on scroll, resize and the visual viewport's moves), `role="status"`, dismissable, gone after nine
seconds. "Fresh" is not the notice's own time (the SIEM files minutes after the event it dates) but
whether the page already listed it in its first eight seconds, or with the first incidents the
correlation poll brought (a slow first poll after a reload lists old ones late), which is what a load
re-lists; while
the run's own toast (amendment 2026-10-06) is up with the same news, only that one shows. Colour never
carries a meaning alone (each notice names its source; each step its number or tick), the motion is a
short fade that `prefers-reduced-motion` drops, and everything is a button or a link.

**The defence-map result.** In "Which layer answered which move" each command is one grid row: the
command in the first column, its verdict in the second, "ended the session" under the verdict; the
verdicts share one width (the widest word of the family, in the badge's own font), and a long
command wraps in its own column instead of pushing a badge onto a line of its own.

**Tests.** The unit suite covers the notices (named, timed with the date when not today, own runs
only, stable ids), the side panel (no toggle, polite list, nothing scrolled or focused on an update,
no toast, the notices kept when hidden), the focus put back after a redraw, and the bar (fixed, the
current step's button in it, the steps below the terminal, what a load lists raising no toast whatever
its age or however late the first incidents come, a later notice as a toast that auto-hides and can
be dismissed). The end-to-end suite (mock
build, desktop and phone, the SIEM filing 9 s after the command) asserts that the terminal's place in
the document does not change when a step completes, the SIEM's incident lands or the session ends,
nor `scrollY` on the desktop (on the phone the browser's scroll anchoring moves it to keep the pressed
chips still as the output above them grows), that the panel sits beside the terminal at 1440x900 and
stays below the header through the session, that a launch leaves the page and the launcher where they
were and its link reaches the console, and that the layer map's badges share one column at 360 px
with nothing past the edge. The height budgets stand.

## Amendment 2026-10-13 (2): the wide screen, every step's button goes somewhere, ambient traffic on the diagram

The owner, on a 1920-px-wide screen of the live page: the attack section squeezed into the narrow
column with empty margins, three cramped columns, the tour panel cut at its top, a tall empty
terminal, the commands under the terminal only; "See what the answer is worth (done)" showing
nothing; and a wish for a small, non-distracting animation of the traffic on the diagram.

**The wide attack section.** From 1400 px the attack section's column widens to 100 rem and the stage
is one grid: the terminal with "This run" beside it on the left, the tour's rail (20 rem) on the right,
the command palette and the session summary across both columns (the terminal's wrappers give up
their boxes, `display: contents`, so their parts are the grid's items; the header's wrap widens with
it, so the brand and the section's left edge line up). The output sets the row's height — a 17 rem
floor for the first lines, then as tall as the output up to 64 vh, no empty box — and "This run" and
the tour panel are capped at the row and the screen under the header, scrolling inside only past
that, with a fade at the foot while there is more. A panel the visitor has scrolled down stays where
they left it when a notice lands above (`overflow-anchor: none`, nothing moves by itself): a
"New notice ↑" chip at its top edge offers the way up, and goes once they are there. Below 1400 px the
layout of the first amendment stands.

**Every step's button has a target that is there.** A step's "Do this step" takes the visitor to the
terminal with the command picked (their own press, so the page scrolls). A done step offers its way
back only where there is one: "Watch the kill timeline" while the terminal still shows the session it
caught (a new session or a reload has its own, and the button goes); "Show the live run" puts the
side-by-side run in the live-run console and goes there (the console never shows a terminal run, and
after a newer terminal session it showed the visitor an empty box at `#console`: that is what the
owner pressed); "Show in SIEM" opens the correlation on the card.

**Ambient traffic.** Each flow and response edge of the page's diagram carries one more path
(`pathLength="100"`, the docs file has none): a faint dot that runs the request path hop by hop every
9 s (Visitor, Cloudflare, cloudflared, the Gateway, the page, the API server) and the detect-and-respond
loop once in three rounds, in the text's faint colour. It is CSS only, still under
`prefers-reduced-motion`, paused off screen and in a hidden tab (`data-ambient`, an
IntersectionObserver and `visibilitychange`), and not drawn while a run is playing out on the diagram.

**The header's mark** is the shell's prompt, `>_`, in the brand's green, in place of the three-colour square.

**Tests.** Unit: the progress names the caught session and the side-by-side run; a done step's button
only with its target; the page's layout has an ambient path per flow and response edge, the docs file
none (`overview.svg` unchanged). End to end: every step's button, in order, reaches something visible
(the terminal in view with the command picked, the kill timeline focused, the console with that run,
the SIEM's card), and the kill-timeline button goes once the session is left; at 1920x1080 and
2560x1440 the section is 1300-1600 px wide, the terminal and "This run" left of the rail, the palette
as wide as the stage, the output no taller than "This run", the panel whole (top under the header or
with its row, nothing scrolled away inside); the ambient dots run on screen, pause off screen, are not
drawn under reduced motion; the mark reads `>_` in `--respond` in both themes. The height budgets stand.

## Amendment 2026-10-13 (b): a calmer diagram, a terminal that keeps its height, and a short default view

The owner looked at the live site and found the diagram's lines ugly, its motion unnoticeable, the
tour's panel scrolling inside, "This run" floating on its own, the terminal growing down the page and
"Do this step" leaving nothing to see where it led. He chose the radical cut: the default view shows
the story, Technical Mode the rest.

**The diagram.** Every edge stops 7 units short of the boxes it joins, with one 8-unit arrowhead per
direction (the tunnel one at each end) in its line's colour (`context-stroke`). A lit edge is
recoloured whole and a little heavier: the short "packet" overlay, which stayed at rest as a thick
stub beside each node, is gone. Labels sit above their line on a knock-out of the page's background;
a node's label is centred in its box (with its sub label, as one block, in Technical Mode and on the
phone). Zones have one 10-unit radius, nodes 8, lines 1.5 px in a muted colour. `overview.svg` is
redrawn from the same layout.

**The ambient traffic** is now a small glowing dot (radius 3, the accent colour, a soft
`drop-shadow`) that runs the request path, the visitor to the page, every 6 s, and the detect-and-
respond loop every 18 s; the edge under it brightens as it passes. It moves by `offset-path`, a
transform: the route and the timing are drawn by `src/diagram/layout.ts` into a stylesheet the build
bundles with `styles.css` (`@import "diagram-traffic.css"`; the CSP allows no style attribute). It
passes behind each box and out the other side, is not drawn under reduced motion or while a run
lights the path, and pauses off screen and in a hidden tab as before.

**The terminal** has one fixed height (the output `min(50vh, 28rem)`, 45vh on a phone) and scrolls
its output inside, following new lines only while the visitor is at its bottom; the page never grows
with it and never scrolls for it. Each command's explanation is one "why?" line, opened on a press.
**"This run"** goes with the page: no longer sticky or capped, so only the tour's rail stays put.

**The tour's rail never scrolls inside.** Compact rows; only the current step open; a done step is one
line with its way there as a small link ("Timeline", "Live run", "SIEM", each with its full name for a
screen reader); "Skip the tour" a small link on the head's line; the newest two notices, the rest
behind "Earlier notices (n)", opened in place. Where the panel would still be taller than the screen
under the header it lets go of sticky and goes with the page rather than be cut; the "New notice ↑"
chip and the fade at its foot are gone with the inner scroll.

**A step's press is marked until it is done.** What "Do this step" (now the step's command as a chip)
picked - the input it filled and the command's chip, or the one-click card - wears an accent ring, a
soft glow and a "Step n" tag (the words carry it, not the colour) until the command has run, the step
is done or another step's button is pressed; three slow pulses where motion is welcome, the static
ring otherwise.

**The default view** (Technical Mode off): the hero is the name, one sentence, "Attack this cluster",
the one-line numbers and the diagram; the attack section is the terminal and the tour's rail (on a
phone the bar above and the steps below), each step offering its one command as a chip and step 5 its
side-by-side button. "This run", the command palette, the objectives, "Just show me", the live-run
console, the run history, the limits and the raw fields are in Technical Mode, as are the buttons that
lead to them ("Watch the kill timeline", the tour's "Timeline" and "Live run"); the notices stay in
the rail. Below the attack: the SIEM, How it works and About; Evidence, Posture and Verify are one
folded card, "Evidence for the curious", each still its own fold inside it, and a link or a `#hash`
to any of them opens the card and the section. The navigation is Attack it, SIEM, How it works and
About, with Evidence in Technical Mode, whose switch says what it reveals ("Show the raw run data, the
command palette, posture and verification"). Skills and Projects are part of "About me" in the
default view (shown and folded with it, a link to either opens it); in Technical Mode they fold on
their own. Before a session the attack stage is as tall as what it holds. The default view is hidden only where scripts run
(`theme.ts` adds `.js` before the first paint): without JavaScript everything shows. Height budgets
for a first visit in the default view: desktop 1440 at most 3200 px (measured 2796), phone 390 at
most 5200 px (measured 3433).

**Step 5 speaks in the rail.** In the default view the one-click cards and the console are hidden,
so step 5's button says there what the launcher would: it is off with the reason while a run is in
progress, a request is in flight or a cooldown runs (the countdown beside it, out of the live words);
the launcher's words show under it (polite); and the side-by-side run's two pods follow as two lines
(guarded: Falco detected it, Talon answered in N ms; unguarded: nothing answered, held for N s). In
Technical Mode the cards and the console say it where it happens and the rail stays short.

**No About bar.** The bar between the attack and the SIEM is gone: About is one folded section like
the others, its first paragraph now ending with "I love automating things: if I have done something
twice, the third time a script does it."

**Tests.** Unit: the layout's edges stop short of the boxes with one head per direction; the page
carries two dots and a glow per lane edge, the docs file none, and the generated stylesheet an
offset-path per dot; the rail's notices fold past two. End to end: the dot moves, pauses off screen,
is not drawn under reduced motion; the rail never scrolls inside at 1440x900 and 1920x1080 with all
six steps in view and with four notices; "This run" keeps its place in the document while the page
scrolls; the terminal's box keeps its height through six commands and the page does not move; the
step's mark is there after 5 s and goes when the step is done; the default view hides what it should
and Technical Mode shows it; `#posture` opens the card and the section. Most tests run in Technical
Mode (stored before load); the default view's own tests are tagged `@default`.

## Amendment 2026-10-13 (c): "This run" capped at the terminal, evidence as ordinary sections, a scannable SIEM card, step 5's real refusal

The owner, on the live site after (b).

**"This run" is never taller than the terminal.** In Technical Mode on a wide screen the panel grew
far below the terminal (the run's timeline and the shop). It still goes with the page (never sticky),
but its cell adds nothing to the row's height: the panel is as tall as its content up to the
terminal pane beside it, and scrolls inside past that, its scrollbar shown, `overscroll-behavior:
contain`, nothing scrolling it for the visitor. The shop stays a fold inside it (folded first when the
panel would scroll, unless the visitor chose). On a phone the opened details are capped the same way
(`min(55vh, 30rem)`), so the input stays within reach under them. A stale rule of the mock's stylesheet
for the old sticky panel is gone.

**No "Evidence for the curious" card.** The card of (b) read as random and made the numbering jump
(its three sections were counted only while it was open). Evidence ("What the cluster recorded"),
Posture ("Live security posture") and Verify ("Verify it yourself") are ordinary folded sections again,
in the default view too, exactly like the SIEM's and How it works; a link or a `#hash` to any of them
opens that section. The sections are numbered the same in both views, 01 Attack it to 07 About, About
last: the attack section's eyebrow shows in the default view too, and Skills and Projects, About's
sub-sections, carry no number in either view. The navigation is Attack it, SIEM, How it works, Evidence
and About in both views; the Technical Mode switch says "Show the raw run data, the command palette, the one-click attacks and the run history". The card's markup, styles, script and tests are gone. Height budgets stand
(measured with the mock banner: desktop 1440 2562 px, phone 390 3230 px).
