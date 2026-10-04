# siem/fields: per-source field allow-lists

One file per data stream (ADR 0034 "Every source has a field allow-list"). Each file is the single
definition of what a source may ship and how it is mapped:

- the shipper (Fluent Bit's `sdp.lua`, P2) projects every record onto exactly these fields and drops
  everything else;
- `ansible/roles/opensearch_config` renders the data stream's index template from the `type`s
  (`dynamic: false`, so a field outside the list is never indexed);
- the rules lint (P3) rejects a Sigma rule that uses a field not listed for its source;
- live check L4 compares every stored document's keys with the list.

Ownership (siem contract "File ownership"): the area named in `owner` edits the file. A field change
is a contract change. Adding a field is rolled out by the role (template + `PUT <stream>/_mapping`);
removing or retyping one needs a rollover and an amendment note.

## Schema

```yaml
owner: host | ingest | api-events   # area that edits this file
source: falco                  # source name
stream: sdp-falco              # data stream (hyphen)
log_type: sdp_falco            # Security Analytics log type (no hyphen, S0-#2)
input: ...                     # where the records come from (prose)
fixture: tests/siem/fixtures/<file>
fields:
  <dotted.name>:
    type: keyword | date | long | integer | boolean
    from: <key> | [<key>, <key>, ...]   # path into the raw record; list entries are literal keys
    value: <constant>                   # instead of from
    transform: slug | pod_ref | hmac | hmac_unless_system | ...  # see below
    note: ...
```

Every stream additionally maps `@timestamp`, `event.kind`, `event.dataset`, `event.ingested` and
`event.overwrite`; the last two are set only by the `sdp-final` pipeline (F1) and stripped from
anything a client sends.

How `sdp.lua` (ansible/roles/fluent_bit/files/sdp.lua) builds a record, for every source:
- a new record is built from the listed fields only; nothing of the input is passed on, so a key
  outside the list (and any client-sent `event.overwrite` / `event.ingested`, F1) never leaves the host;
- `from` is a path into the input record (a string is one key, a list is a nested path, a number in
  it a 0-based list index); a list of lists gives a transform several values;
- the value is converted to the field's `type` (`keyword` to a string, or a list of strings for an
  array; `integer`/`long` to a whole number; `boolean`); a null, an empty string or a value that does
  not convert is left out - so is a `k8s.pod.ref` that is not `<ns>_<pod>`;
- `@timestamp` is not stored as a field: it becomes the record's time, which Fluent Bit's opensearch
  output writes as `@timestamp` (the read time when the event carries none);
- `sdp.lua` also decides which input records are shipped at all (F2 for the audit log, `.flow` only
  for Hubble, `siem.run`/`siem.command` only for the API, keyed records only for auditd).

Transforms (an unknown name stops Fluent Bit at start-up):
- `slug`: lower-case, every run of characters outside `[a-z0-9]` becomes one `-`. Security Analytics
  never matches a value containing a space and matches case-sensitively (S0-b), so every multi-word
  value a rule matches on has a slug next to it.
- `lower`: lower-case.
- `pod_ref`: `<namespace>_<pod>` from the two `from` paths. `/` breaks SA's correlation query (S0-e);
  `_` occurs in no namespace or pod name, so the split is unambiguous. The API maps it back to
  `<ns>/<pod>` for publication.
- `sandbox_ns`, `sandbox_pod`, `sandbox_pod_ref` (Hubble): from source namespace, source pod,
  destination namespace, destination pod - the source side when its namespace starts with `sandbox`,
  else the destination side.
- `hmac`: `hm1:` + the first 16 hex of HMAC-SHA256(host key, value). Pseudonyms do not correlate
  across hosts (each host has its own key, F4). auditd's `unset` (no login user) is kept as it is.
- `hmac_unless_system`: values starting with `system:` (ServiceAccounts, nodes, components, the k3s
  admin) are kept verbatim, everything else is `hmac` (F3).
- `epoch_us`, `epoch_ns`: a number of micro-/nanoseconds since the epoch into `@timestamp`.
- `int`, `bool`: type conversion (the `type` already converts; kept for readability).
- `audit_dry_run`: true when the request URI carries `dryRun=All`.
- `l4_protocol`, `l4_destination_port` (Hubble): the `l4` object's one key, lower-cased, and its
  destination port.
- Parsed host transforms (`ssh_event`, `ssh_method`, `sudo_result`, `nft_proto`, `nft_dpt`,
  `audit_type`, `audit_key`, `audit_syscall`, `audit_success`, `audit_exe`, `audit_comm`): the value
  `sdp.lua` parsed from the message line; the pattern is in the field's `note`.

None of these fields is ever published as-is: the API builds its output field by field from its own
allow-list (ADR 0021, ADR 0036).
