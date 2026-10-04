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
owner: host | ingest           # area that edits this file
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

Transforms (implemented by `sdp.lua` in P2):
- `slug`: lower-case, every run of characters outside `[a-z0-9]` becomes one `-`. Security Analytics
  never matches a value containing a space and matches case-sensitively (S0-b), so every multi-word
  value a rule matches on has a slug next to it.
- `pod_ref`: `<namespace>_<pod>` from the two `from` paths. `/` breaks SA's correlation query (S0-e);
  `_` occurs in no namespace or pod name, so the split is unambiguous. The API maps it back to
  `<ns>/<pod>` for publication.
- `hmac`: `hm1:` + the first 16 hex of HMAC-SHA256(host key, value). Pseudonyms do not correlate
  across hosts (each host has its own key, F4).
- `hmac_unless_system`: values starting with `system:` (ServiceAccounts, nodes, components, the k3s
  admin) are kept verbatim, everything else is `hmac` (F3).
- `epoch_us`, `epoch_ns`, `audit_msg_time`: event time conversions into `@timestamp`.
- `int`, `bool`: type conversion.
- Parsed transforms (`ssh_*`, `nft_*`, `audit_*`, `sudo_*`) extract one value from a message line;
  their exact pattern is in the field's `note`.

None of these fields is ever published as-is: the API builds its output field by field from its own
allow-list (ADR 0021, ADR 0036).
