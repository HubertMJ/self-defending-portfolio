# siem: detection content applied to siem01 from git

ADR 0034 "Rules from git" and its amendments. `fields/` (the per-source allow-lists, see
`fields/README.md`) belongs to the host and ingest areas; everything else here is the rules area's:

| path | what | becomes in OpenSearch |
|---|---|---|
| `log-types/<source>.yaml` | `name`, `source`, `description` | a custom Security Analytics (SA) log type |
| `rules/<slug>.yml` | one Sigma rule | an SA custom rule of the source's log type |
| `detectors/<source>.yaml` | `name`, `source`, `interval_minutes`, `rules` (Sigma ids) | an SA detector on the data stream `sdp-<source>` |
| `correlations/<name>.yaml` | `name`, `time_window_ms`, `field`, `correlate` (`source`, `query`) | an SA correlation rule |
| `monitors/<name>.json` | an Alerting monitor body | an Alerting monitor named `sdp-git: ...` |
| `canaries.yaml` | the canary of every rule, correlation and monitor | (nothing; `tests/siem/canaries.sh` runs them) |

`make validate` runs `scripts/check-siem.sh`, which lints this tree with
`ansible/roles/siem_sync/files/siem_lint.py` - the same program the sync on siem01 runs before it
applies anything. The sync (role `siem_sync`) fetches `main` every five minutes, treats this tree as
data only and applies fast-forwards (`ansible/roles/siem_sync/files/sdp_siem_sync.py`).

## How Security Analytics matches (differs from the Sigma specification)

Proven in the S0 spike (siem contract S0-b, S0-k); the lint enforces what it can:

- **Values are case-sensitive.** Fields are keywords and SA builds term queries: `rule: Terminal`
  does not match `terminal`. Write the value exactly as the shipper stores it (`siem/fields`).
- **A value containing a space never matches.** SA rewrites spaces to `_ws_` and Alerting never
  undoes it. Match the space-free slug field the shipper writes next to every multi-word value
  (`falco.rule_slug`, `talon.action_slug`, ...). The lint refuses a detection value with a space.
- **`|re` is a Lucene regular expression over the whole value**: implicitly anchored, `^` and `$`
  are not operators and backslashes are doubled by SA, so `\.` never means a dot - use `[.]`. The lint
  refuses `^`, `$` and `\` inside a `|re` value.
- YAML is read without explicit tags and, outside `fields/`, without aliases.
- Modifiers in use: `startswith`, `endswith`, `contains`, `re`, `all`. No aggregation (`| count()`,
  `near`): counting is an Alerting monitor's job.
- Every field a rule names must be in its source's allow-list; a field outside it is never indexed
  (`dynamic: false`), so such a rule could never fire.

## Names

- Log types are `sdp_<source>` with `_` (SA's correlation list truncates hyphenated names, S0-#2);
  data streams keep `sdp-<source>`.
- Monitors this tree owns are named `sdp-git: <name>`. The sync manages every monitor with that
  prefix and nothing else: SA's own detector monitors, the host role's ops monitors and anything
  made in Dashboards are never touched (contract MJ5, B6). Detector names must not carry the prefix
  (SA names a detector's workflow after it).
- Sigma `id`s are UUIDs, unique across the tree (SA accepts duplicates, S0-#12).
- Tags are `attack.tNNNN[.NNN]` and ATT&CK tactic names; every rule above `informational` names at
  least one technique.

## What the sync owns, and what it records

- An object is the sync's when it carries its marker: a rule whose SA id is in a sync record, a
  detector whose description starts `sdp-git `, a log type or correlation named in the last applied
  tree (or a failed attempt since), a monitor named `sdp-git: ...`. A live object with a git name but
  without the marker is never adopted: the run is refused and says which object to remove.
- Another SA rule carrying a git rule's Sigma id (made by hand, or left over) is a duplicate and is
  deleted by design: the Sigma id belongs to git.
- More than five deletions, or more than five rule/monitor/correlation updates, in one run or in
  24 hours of runs (those an allow flag permitted do not count) are refused until the operator creates `/etc/sdp-siem/allow-mass-delete` or `/etc/sdp-siem/allow-mass-change` (removed
  after the next successful run). Every monitor is enabled in git: switching one off is a deletion.
- `siem-sync` holds one record per applied, refused or failed run (`commit`, `applied_at`, `status`,
  `reason` - at most 512 characters, a lint refusal names files and checks only - `counts`,
  `changed`, `rules`, `monitors`, `lint_sha256`) and one document `heartbeat` that every run
  overwrites (`kind: heartbeat`, `checked_at`, `commit`, `outcome`: applied | unchanged | refused |
  failed). The role creates the index and adds missing fields with the admin certificate, so the
  heartbeat's `kind` is searchable also in an index an older version made. A run with nothing to do
  writes only the heartbeat, so an old `applied_at` with a fresh
  `checked_at` is an idle sync and a stale `checked_at` a dead one.
- Monitors may read only the six k3s01 streams (the API reads their alerts); sources are the seven of
  ADR 0034 - both pinned in `siem_lint.py`. A monitor's search may use only term, terms (no lookup),
  range, exists, match_all and bool, and the aggregations composite (terms sources), terms, filter
  and min/max/avg/sum/value_count/cardinality; no script, query_string or top_hits. Every field it
  names must be in the allow-list of one of its streams. Those allow-lists come from `siem/fields` in
  the same fetched tree (the ingest area's files), so a commit could list a new field there - but a
  field the stream's template does not map is never indexed (`dynamic: false`), the templates are
  written only by the admin's `opensearch_config` from the operator's checkout, and the sync never
  touches them, so such a field matches nothing. Schedules are a plain period of 1-60 minutes;
  trigger conditions only compare counts (`params.a > 0 && params.b == 0`).

## Canaries

`canaries.yaml` names, per object, the run that must produce its finding or alert (kind `api`: the
public API; `exec`: an operator step; `synthetic`: documents written with the temporary
shipper-test identity, for a check whose trigger is a failure of the demo itself). A canary that
stops producing its finding is the detection-drift signal.
