# ADR 0036: Correlation on the page: the API as a read-only SIEM client, incident model and publication

Date: 2026-10-04 · Status: accepted

## Context
ADR 0034 put a SIEM on its own VM (`siem01`): Fluent Bit ships k3s01's evidence into append-only data
streams, Security Analytics (SA) turns single events into findings with Sigma rules from git, Alerting
monitors count and notice absence. What the page still lacks is the part ADR 0034 gave to the portfolio
API: assembling those findings, documents and alerts into incidents a visitor can read - "this run's
secret left in a DNS query 31 s after the command, Falco saw nothing" - with the evidence ids behind
every claim, and the SOC numbers that follow from them (time to detect, time to isolate, the twin's
dwell time).

The constraints are the project's:
- The API reads the SIEM and never writes to it (0034 "Who may talk to 9200"). Its certificate maps to
  `sdp_api_read`, which reads SA findings, alerts and correlations, Alerting alerts, and the named
  streams `sdp-falco`, `sdp-talon`, `sdp-hubble`, `sdp-k8s-audit`, `sdp-api`, `sdp-host` and the sync
  record `siem-sync` - never `sdp-*` as a pattern, never `sdp-siem01` (ADR 0034 amendment P1).
- Everything the API publishes from the SIEM follows ADR 0021: node names, host/pod/service addresses,
  `*.svc`/`*.cluster.local` names, tokens, ServiceAccount names, user pseudonyms, DNS labels and the flag
  are never published; pod names and `<ns>/<pod>` refs only for `sandbox` and `sandbox-unguarded`;
  host-derived findings as counts only. SA findings carry their full source document, so output is
  built field by field, never forwarded.
- The demo never depends on the SIEM (0034 "Degradation"); the page never starts anything (ADR 0017);
  incidents are not persisted by the API - the SIEM is the persistence (ADR 0030 unchanged).
- Facts from the S0 spike (siem contract S0-#1, S0-#13): the join key `k8s.pod.ref` is stored as
  `<ns>_<pod>`, because a `/` silently breaks SA's correlation query; SA rule correlations are not
  guaranteed (13 of 14 pairs correlated in S0), and the correlations list carries no id of its own and
  truncates hyphenated log-type names.

## Decision

### 1. The SIEM client (`internal/siem`)
- **Off unless configured.** `SIEM_URL` (https only) plus `tls.crt`, `tls.key` and `ca.crt` in
  `SIEM_CERT_DIR` (default `/etc/portfolio-api/siem`, the optional KSOPS Secret). Anything missing or
  unreadable: the SIEM part is off, the API logs it once and starts as before; `/api/correlation`
  answers `available:false`.
- **TLS 1.2+**, the Secret's CA as the only root, the client certificate, no proxy, the server name from
  the URL (siem01's node certificate carries the IP SAN). Every request has a 5 s timeout; a response
  over 16 MiB or with a status other than 200 is an error.
- **Method/path allow-list in code**, checked before any byte leaves the process:
  `GET /_plugins/_security_analytics/findings/_search`, `GET /_plugins/_security_analytics/correlations`,
  `GET /_plugins/_alerting/monitors/alerts`, and
  `POST /<index>[,<index>...]/_search` where every index is one of the seven named above. Anything else -
  another method, `_bulk`, `_doc`, a pattern, `sdp-siem01` - is refused as a programming error, and the
  unit test proves no such request reaches the server. Search bodies are built in code from a typed query:
  `size` 0-500, a mandatory time range of at most 31 days, an explicit `_source` list. Security
  Analytics' own alerts (`GET .../alerts`, allowed by the siem contract) are not read: the incidents
  need findings, correlations and Alerting alerts only, so the path is not on the list.

### 2. Polling, independent of visitors
- One goroutine, single-flight, polls every **15 s** whether anyone is looking. On start (and after a
  failure that outlasted the window) it backfills the **last 24 h once, at most 500 items per type**;
  afterwards each poll reads the window **[last successful poll - 2 min, now]** - findings by detection
  time, documents by `event.ingested` (so a document that arrives late is still read) - and
  de-duplicates by finding id, document id and correlation pair.
- Per poll: findings per detector type (`sdp_falco`, `sdp_talon`, `sdp_hubble`, `sdp_k8s_audit`,
  `sdp_api`, `sdp_host`); SA correlations; Alerting alerts (newest 500 of every state, and the ACTIVE
  ones on their own for the health line, so an ops alarm older than a burst of incident alerts still
  shows); three bounded document searches (`sdp-api` run/command lines; `sdp-k8s-audit` pod
  patches/deletes by Talon and pod creates/deletes in the twin namespace; `sdp-hubble` drops); the newest
  `siem-sync` records and the sync's heartbeat (section 7); one count of `event.overwrite: true`
  documents ingested in the last 24 h over the six streams. Fifteen requests.
- A detector log type that answers 404 (no detector of that type yet) is "no findings", not an outage,
  logged once per type; any other failure of the findings, alerts and document reads fails the poll. The
  correlations, `siem-sync` (records and heartbeat) and `event.overwrite` reads are soft: their failure keeps what was read
  before and does not hide the section (an SA correlation is cited evidence, never a condition). A page
  that comes back full (500) is logged once until it no longer is.
- The evidence is kept in memory for 24 h, at most 2 000 records per source; Hubble DNS findings and
  drops are capped apart, and a drop older than 10 minutes that no check reads (the first drop after a
  Talon patch, a dropped lookup after a dns-exfil command) and no finding names is not kept, so a
  quarantined pod's drop flood never pushes a DNS finding out. Correlations age out with the retention;
  host finding ids are capped too. Incidents are rebuilt after every poll by one pure function, so the
  same evidence always gives the same incidents and ids; the view is marshalled once per poll and every
  request is served those bytes.
- One document is one event: several findings on one document (two rules matched it, or a finding on a
  document a search also read) make one step citing every finding (up to five).

### 3. Pod refs and publication
- A ref is read as `<ns>_<pod>`, split at the **first** `_` (no namespace or pod name contains one), and
  kept only when the namespace is the guarded sandbox or the twin namespace and the pod is a DNS-1123
  label; it is published as `<ns>/<pod>`. Anything else is dropped together with the record it came on:
  evidence outside the sandboxes is not the visitors' business.
- Published strings are built from allow-listed fields per source (below), passed through
  `webhook.Scrub`, then through a second redaction of what Scrub does not know (`k3s01`, `siem01`,
  `serviceaccount` in any form, `hm1:` pseudonyms, `SDP{...}`, `sdp-<16 hex>` labels, any remaining
  `.svc`/`cluster.local`), and truncated (`detail` <= 200 characters, `title` <= 160).
  - falco: the Falco rule name, the pod, the process name.
  - talon: action, actionner, status, the pod.
  - hubble: verdict, drop reason, direction, L4 protocol and destination port, the pod - never the DNS
    query.
  - k8s-audit: verb, resource/subresource, response code, the pod, and "by Talon" / "by the API" /
    "not by the API" - never the user.
  - api: command id, technique, objective, state, exit code, the pod.
  - Alerting alerts: the monitor name without its `sdp-git: ` prefix; a bucket key only when it is a
    publishable pod ref (policy probing's key is a principal and is never published).
- Test data never becomes an incident: the rules acceptance test (P3) writes synthetic canary documents
  into the real streams, with pod refs `sandbox_p3c-<tag>-*` and principals `system:p3c-<tag>`. A
  finding or document whose pod ref matches `^(sandbox|sandbox-unguarded)_p3c-[0-9a-z]+-` or whose
  principal (`user.name`) matches `^system:p3c-[0-9a-z]+$`, and an Alerting alert with a bucket key of
  either form, is dropped before the incidents are built. Both are matched whole, never as a substring:
  a ServiceAccount named `p3c-y` (`system:serviceaccount:x:p3c-y`) or a pod whose name merely contains
  `p3c-` must not be able to hide an exec or a probe from the page. An exact `system:p3c-<tag>` user is
  a client certificate only a cluster admin can issue.
- Host findings (`sdp_host`) are counted, nothing else. `sdp-siem01` is not read at all (the API's role
  has no access to it), so `host_findings` counts k3s01's own findings only.

### 4. Incident kinds and their checks
Every kind is built from SIEM evidence only (never from the API's own in-memory run state), cites its
evidence, and has a canary (siem/canaries.yaml, P3). Joins are made by the API on the pod ref (S0-#13);
an SA correlation, when one pairs two of the incident's findings, is cited as evidence, never required.

| kind | built from | severity |
|---|---|---|
| `contained-intrusion` | a Falco finding and a Talon finding on the same ref | high |
| `dns-exfil` | an SA finding on a Hubble DNS query, joined with the run's `dns-exfil` command on the ref | critical with a flag match, else high |
| `dns-exfil` (quarantined, F7) | the run's `dns-exfil` command and a Hubble drop to port 53 from the same ref within 10 s, no DNS finding | medium |
| `staged-attack` | one run's command lines: a recon step, then a credentials step, then an exfiltration attempt, in `@timestamp` order | high |
| `exec-outside-api` | SA findings on `sdp-k8s-audit` exec/attach/portforward sessions into a sandbox pod by anyone but the API; one step per session (its ResponseStarted and ResponseComplete records, one audit id, are one step) | high |
| `policy-probing` | an alert of the `sdp-git: policy-probing` monitor | medium |
| `prevented-not-detected` | an alert of the `sdp-git: prevented-not-detected` monitor | low |
| `detection-missing` | an alert of the `sdp-git: detection-missing` monitor | medium |
| `twin-dwell` | a compare run: the twin pod's audited create and delete, next to the guarded arm's TTI | medium |

- **Monitor kinds** are chosen by the monitor name after the `sdp-git: ` prefix (lower-cased, words
  joined by `-`, matched as a prefix); other monitors make no incident. Alerts in state `ERROR` or
  `DELETED` are ignored.
- **One incident per** ref (contained-intrusion, dns-exfil, exec-outside-api), run (staged-attack,
  twin-dwell) or alert (monitor kinds); its id is the first 16 hex of SHA-256 over kind and key,
  stable across polls and restarts.
- **Steps** are the incident's evidence in time order (at most 50): the commands that anchor it, the
  findings, the audit and Hubble documents that measure it. `command_seq` is the run's command sequence
  number in effect at the step (the latest command started at or before it), null outside terminal runs.
  `falco_events` counts the Falco findings on the incident's ref (for `dns-exfil`: within 60 s of the
  command, which is the claim "Falco: no event").

### 5. SOC metrics
- **Time to detect (TTD)** = the first Falco finding's `@timestamp` - the anchoring command's `started`
  (the latest `siem.command started` on the ref at or before it), or, for a one-click run, the run's
  `pod_ready` on that ref (the scripted attack is executed as soon as the pod is ready).
- **Time to isolate (TTI)** (M11) = Talon's audited response on that pod - the first successful
  (code < 300) `patch` (quarantine label) or `delete` (terminate) of the pod by
  `system:serviceaccount:falco-response:falco-talon` in `sdp-k8s-audit` at or after the Falco finding -
  minus the Falco finding's `@timestamp`. Anchored on the API server's record of the action, not on
  Talon's own log line or the runner's observation. The first Hubble drop on the ref within 30 s after a
  quarantine patch is a separate step, "policy enforced +N ms", not part of TTI.
- **Twin dwell** = the twin pod's audited `delete` - its audited `create` (both in the twin namespace,
  from `sdp-k8s-audit`): how long an attacker kept the pod nobody answered. The `twin-dwell` incident
  carries the guarded arm's TTD and TTI from the same run, for the contrast.
- `metrics`: over the last 24 h (`since` = now - 24 h); medians (the mean of the two middle values for an
  even count, whole ms) of TTD and TTI over `contained-intrusion` incidents and of dwell over
  `twin-dwell` incidents; null when there is none.
- **Ingest lag** (`metrics.ingest_lag_ms`, an object keyed `falco`, `talon`, `hubble`, `k8s-audit`,
  `api`, `host`) = per source, the median of `event.ingested` (set by the `sdp-final` pipeline, siem01's
  clock) - `@timestamp` over the documents the API read that were ingested in the last 15 minutes; null
  for a source with none. Only documents the polls read anyway count - no extra request. 15 minutes, not
  one poll window: a sandbox source writes only when someone attacks, so one 2-minute window is almost
  always empty. Negative values (clock skew between the hosts) are published as they are.

### 6. Flag match (dns-exfil)
- At terminal start the runner computes `HMAC-SHA256(procKey, "sdp-" + <16 hex of the flag>)` and hands
  only that MAC, with the run id and the pod ref, to the incident tracker; `procKey` is 32 random bytes per
  process (`internal/flagmac`). The flag never enters the incidents package and nothing is logged.
- The runner also reports the run's end. A query matches a run's MAC only if it happened **while the run
  lasted or at most 15 minutes after it ended** - judged by the query's own `@timestamp`, not by when the
  finding is read, so a finding that arrives late (the visitor pressed Leave right after the command, a
  slow detector run, an outage) matches exactly as it would have on time. The registrations (run id, pod
  ref, MAC; at most 64) are kept for the 24 h evidence retention.
- When a DNS finding is first read, its query's first label must match `^sdp-[0-9a-f]{16}$`; it is
  HMAC'd and compared in constant time with the registrations **for the same ref**. The result is
  stored with the finding and the label is discarded: `true` (this run's secret), `false` (the ref has a
  registration and none matches - another run's flag, or a query more than 15 minutes after the run; or
  the query happened while this process was running and the ref has no registration - the same pod name
  in the twin namespace), `null` when the query predates this process and the ref has no registration:
  an API restart lost `procKey` ("flag match unavailable").

### 7. Health on the page (D1)
- `rules`: from the newest `siem-sync` records of the last 31 days: the newest one gives `status`
  (`applied|refused|failed`, else `unknown`; `stale` from the heartbeat below), the newest with status
  `applied` gives `commit` (40 hex)
  and `applied_at`. The sync writes a record only when it has something to do, so a quiet repository
  leaves the last record old: when no record is found, or no applied one, the last known value stands
  (`unknown` only until a record has been read once). Records are read by `applied_at` and never
  include the heartbeat below; a record's `reason`, `changed` and `lint_sha256` are not read.
- **Sync liveness.** Every sync run overwrites one document in `siem-sync`, `_id` `heartbeat`
  (`{kind: heartbeat, checked_at, commit, outcome: applied|unchanged|refused|failed, lint_sha256}`); a
  run with nothing to do writes only that. The API reads it with a term query on `kind: heartbeat` through
  the existing `_search` path (no new path on the allow-list). A `checked_at` that is not an RFC 3339
  time, or a `commit` that is neither empty nor 40 hex, makes the heartbeat count as missing; an unknown
  `outcome` is ignored. Then:
  - `status` = `stale` when `checked_at` is more than 30 minutes old (the sync runs every 5), or when
    the heartbeat is missing while records exist;
  - otherwise a heartbeat `outcome` of `refused` or `failed` newer than the newest record replaces the
    records' status: it is the latest run's verdict (a run that refuses the same commit again writes no
    new record, and a run that fails before writing one still says so). `applied` and `unchanged` change
    nothing - the records already say what is in effect;
  - `commit` and `applied_at` stay the last applied ones in every case.
  The heartbeat read is soft like the record read: a failure keeps the last value read.
- `health.ingest` = `silent` when an ACTIVE Alerting alert belongs to a monitor named
  `ingest silent <source>`, else `ok`; `health.disk` = `high` likewise for `disk watermark`. Both read
  the ACTIVE alerts on their own. When the alerts cannot be read the poll fails, and after 45 s the whole
  answer is `available:false` (section 8), where both are `unknown`. `health.evidence_rewritten` = any
  `event.overwrite: true` document ingested in the last 24 h in the six streams (F1); a failed count
  keeps the previous value.

### 8. Degradation
`available` is true while the last fully successful poll ended at most 45 s ago (so a stopped OpenSearch
turns it false within 60 s, L11, and one slow poll does not hide the section). `available:false` empties
everything else (`rules.commit` "", `applied_at` null, `status`/`ingest`/`disk` `unknown`,
`evidence_rewritten` false, metrics zero/null, no incidents). The page hides the section; the demo is
untouched. An unconfigured SIEM looks the same, with `checked_at` null.

### 9. Endpoints
GET only, under the public middleware and request budget, both in the 405 list.

`GET /api/correlation` (incidents newest first by `first_at`; every array marshals `[]`). The example is
the API's own output for the unit-test fixtures (a terminal run whose dns-exfil carried its flag; its
staged-attack incident omitted); `rule_id` is empty there because the embedded rule index
is not generated yet:

```json
{
  "available": true,
  "checked_at": "2026-10-04T10:02:00Z",
  "rules": {
    "commit": "0123456789abcdef0123456789abcdef01234567",
    "applied_at": "2026-10-04T09:55:00Z",
    "status": "applied"
  },
  "health": {
    "ingest": "ok",
    "evidence_rewritten": false,
    "disk": "ok"
  },
  "metrics": {
    "since": "2026-10-03T10:02:00Z",
    "incidents": 2,
    "median_ttd_ms": null,
    "median_tti_ms": null,
    "median_twin_dwell_ms": null,
    "host_findings": 2,
    "ingest_lag_ms": {
      "api": 3000,
      "falco": null,
      "host": 2000,
      "hubble": 2000,
      "k8s-audit": null,
      "talon": null
    }
  },
  "incidents": [
    {
      "id": "ff3f6fb10a324849",
      "kind": "dns-exfil",
      "severity": "critical",
      "title": "Exfiltration over DNS: this run's secret left sandbox/terminal-3755e65530 in a DNS query; Falco: no event",
      "run_id": "3755e65530aa11bb",
      "arm": "",
      "first_at": "2026-10-04T10:00:09Z",
      "last_at": "2026-10-04T10:00:20.101Z",
      "attack": [
        "T1552.001",
        "T1048.003",
        "T1071.004"
      ],
      "falco_events": 0,
      "flag_match": true,
      "ttd_ms": null,
      "tti_ms": null,
      "steps": [
        {
          "at": "2026-10-04T10:00:09Z",
          "source": "api",
          "rule": "",
          "rule_id": "",
          "command_seq": 2,
          "detail": "command read-flag (T1552.001, credentials) started on sandbox/terminal-3755e65530"
        },
        {
          "at": "2026-10-04T10:00:19Z",
          "source": "api",
          "rule": "Terminal exfiltration command",
          "rule_id": "",
          "command_seq": 3,
          "detail": "command dns-exfil (T1048.003, exfiltration) started on sandbox/terminal-3755e65530"
        },
        {
          "at": "2026-10-04T10:00:20.101Z",
          "source": "hubble",
          "rule": "Hubble - flag-shaped DNS lookup",
          "rule_id": "fa0bd074-18fc-4827-834c-705c707a94f9",
          "command_seq": 3,
          "detail": "DNS query under the exfil zone from sandbox/terminal-3755e65530, FORWARDED egress udp/53"
        }
      ],
      "evidence": [
        {
          "type": "document",
          "id": "c2"
        },
        {
          "type": "finding",
          "id": "8f0e6c1e-0d6b-4f7e-9a51-2b7f3c4d5e6f"
        },
        {
          "type": "finding",
          "id": "f-dns-1"
        }
      ]
    }
  ]
}
```

- `kind`: one of the eight names of section 4. `severity`: `low|medium|high|critical`.
  `arm`: `guarded|unguarded` for a compare run's incident, else "". `run_id`: the run's public id from the
  `sdp-api` lines on the ref, else "". `attack`: ATT&CK ids from the findings' `attack.tNNNN[.NNN]` tags
  and the commands' catalogue techniques, upper-case, de-duplicated, in first-seen order.
- `steps[].source`: `falco|talon|hubble|k8s-audit|api` (monitor steps: `k8s-audit` for policy probing,
  `api` for the two sdp-api/sdp-falco monitors). `rule`: the Sigma rule's title from the finding (or the
  monitor name, or an audit document's name - amendment 2026-10-06), "" for another document without a
  finding. `rule_id`: the rule's Sigma id, looked up by title in the embedded rule index, "" when not
  found. `count`: the records the step stands for, omitted for one (amendment 2026-10-06).
- `evidence[]`: correlations first (so the cap of 50 never cuts them), then each step's finding(s) or
  document. `evidence[].type`: `finding` (SA finding id), `alert` (Alerting alert id), `correlation` (the SA
  correlation rule id that paired two of the incident's findings - the correlations list has no id of its
  own) and `document` (the `_id` of a stream document an incident is measured on: Talon's audited
  response, the twin's create/delete, a Hubble drop, the anchoring command line). `document` is a
  sharpening of the siem contract's three types: TTI and dwell are measured on documents, and an incident
  must cite what it is built from (ADR 0034 "Who detects what").

`GET /api/correlation/rules` serves the embedded `internal/siemindex/index.json`, generated from `siem/`
by `scripts/gen-siem-index.sh` (the pattern of gen-rule-index.sh; `--check` in validate; written when
P3's `siem/` tree and this area are integrated - until then the committed index is empty), served whether
or not the SIEM is reachable:

```json
{"rules": [{"id": "<sigma uuid>", "title": "...", "level": "high", "status": "stable", "source": "hubble",
            "attack": ["T1048.003", "T1071.004"], "file": "siem/rules/dns-exfil-label.yml", "line": 1,
            "canary": "api:dns-exfil"}],
 "monitors": [{"name": "sdp-git: policy-probing", "file": "siem/monitors/policy-probing.json", "canary": "exec:tests/admission/run.sh"}],
 "correlations": [{"name": "contained-intrusion", "file": "siem/correlations/contained-intrusion.yaml", "canary": "api:shell-in-container"}]}
```

## Alternatives considered
- **SA correlations only.** Rejected: 1 of 14 pairs never correlated in S0, the list carries no id and
  mangles log-type names, and order (staged attack), intervals (TTD, TTI, dwell) and the flag match are
  not something a correlation rule expresses. SA correlations stay as cited evidence.
- **Persisting incidents in the API** (a ConfigMap or a SIEM index of its own). Rejected: the SIEM is the
  persistence; a write path from the API would break "the API never writes to the SIEM", and a ConfigMap
  would carry evidence into the cluster (ADR 0030 keeps aggregates only). The 24 h backfill on start
  rebuilds the same incidents after a restart; only the flag match of earlier runs is lost (null).
- **Server-sent push of incidents.** Rejected for now: findings arrive a minute or more after the event
  anyway; a 60 s page poll of a cached snapshot costs nothing, and the SSE stream stays the run's own feed.
- **Querying the SIEM per visitor request.** Rejected: visitor traffic would become SIEM load and a
  slow SIEM would slow the page; the snapshot is built by one poller and served from memory.

## Consequences
- The section shows incidents 1-3 minutes after the event (detector interval 1 min, Fluent Bit flush,
  refresh, the 15 s poll); the page says so.
- Fifteen bounded read requests every 15 s from one client certificate; at most 24 h of evidence
  in memory (capped per source), at most 200 incidents of at most 50 steps.
- Incidents are detection code in the API: versioned, unit- and mutation-tested (`internal/incidents`,
  `internal/siem`), each kind with a canary; a leak test runs the JSON through ADR 0021's never-publish
  list.
- An API restart loses the flag-match key: dns-exfil incidents from before it show "flag match
  unavailable".
- The client certificate is read once, at start: a rotation restarts the API after the new Secret is
  synced and before the old generation is unmapped (docs/bootstrap.md 9.8).
- The rule index is generated from `siem/` and embedded; until it is regenerated, a rule's `rule_id` is
  empty and `/api/correlation/rules` lists nothing new.

## Amendment 2026-10-06: the same evidence is one step, with a count

**Context.** Live, a dns-exfil incident listed about twelve identical steps "Hubble - flag-shaped DNS
lookup": every Hubble flow of the lookup is a record - the request and the response, as a trace event
(type 4) and as an L7 event (type 129), in both directions - and every record was a step. The board
read as a flood, and repeated sessions or Falco findings did the same to the other kinds.

**Decision.** For every kind, records that are the same evidence are one step: the same source, rule
title, pod, `command_seq` and kind, where the kind is the published detail without the traffic
direction (section 3's allow-list otherwise). The step is at the earliest record's time, keeps the
place of that record in the time order (ties keep their order), and carries `count`, the number of
records it stands for: an integer >= 1, omitted when it is 1. Its detail lists the directions seen,
sorted and joined by `+` ("FORWARDED egress+ingress udp/53"). It cites the ids of its records, earliest
first, at most five (the cap of one document's findings in section 2); every record still counts for
`falco_events`, for the ATT&CK ids and for pairing findings with an SA correlation. `last_at` is the
latest record of the steps kept, not the latest step's time. Steps that are not records (monitor alerts,
"policy enforced", the twin's dwell) are not merged. An `exec-outside-api` incident's sessions that
publish the same evidence are one step with a count (the principal is never published); the title still
counts the sessions.

**Consequences.** Fewer steps, so the cap of 50 cuts later; the evidence list of a flood is five ids
instead of one per record. A client that ignores `count` reads the step as before.

## Amendment 2026-10-06: a DNS lookup is an L7 DNS event of the DNS rule; dns-exfil anchored on its command

**Context.** The live acceptance check found the real cause of the repeated steps: Cilium's static flow
exporter, with its field mask, leaves a stale `l7.dns.query` on ordinary flows (trace events, type 4:
tcp/8080 replies, tcp/9200 drops), so about 1 600 `sdp-hubble` documents carried a flag-shaped
`dns.query` that was no lookup. The API took any Hubble finding on a document with a query for a DNS
query, whatever rule fired: four false dns-exfil incidents (test pods whose only steps were policy drops,
read as "DNS query under the exfil zone ... DROPPED egress tcp/9200"), and a real one whose 50 earlier
records filled the step cap before the run's command. The shipper and the Sigma rule are fixed apart;
the API does not trust the field either.

**Decision.**
- A Hubble record is a DNS lookup only when it is a finding of the flag-shaped DNS rule
  (`siem/rules/hubble-dns-exfil.yml`, Sigma id `fa0bd074-18fc-4827-834c-705c707a94f9`, looked up by the
  finding's rule title in the embedded index) on an L7 DNS event (`hubble.event_type` 129 with an
  `hubble.l7.type`). A document read by a search is never a lookup (no rule fired on it). Everything else
  is a flow, described and used as one - a stale-query drop is a drop (the "policy enforced" step, the
  quarantined lookup's drop).
- A dns-exfil incident with lookups is anchored on the run's `dns-exfil` command that a lookup follows
  within the join window: the command before the first lookup matching the run's flag, else before the
  first lookup that follows any command. Its steps are that command (with the run's `read-flag` before
  it) and the lookups at or after it; a lookup before that command is not this incident's, and the flag
  match and the Falco window are taken over the lookups kept. Without any command, the lookups alone
  make the incident, as before. dns-exfil still carries no TTD or TTI (section 5 defines them for
  contained intrusions only).
- An audit document no rule fired on is named in `rule`: "Kubernetes audit - pod labelled by the response
  engine" (Talon's quarantine patch), "... pod deleted by the response engine" (Talon's delete), "... pod
  created by the API" / "... pod deleted by the API" (the twin's create and delete). `rule_id` stays "".

**Consequences.** The false dns-exfil incidents go; a real one shows the command first. Documents already
in the SIEM keep their stale query, and the API ignores it. A rename of the DNS rule's title is followed
through the regenerated index (the id is what the API knows).
