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

## Canaries

`canaries.yaml` names, per object, the run that must produce its finding or alert (kind `api`: the
public API; `exec`: an operator step; `synthetic`: documents written with the temporary
shipper-test identity, for a check whose trigger is a failure of the demo itself). A canary that
stops producing its finding is the detection-drift signal.
