# ADR 0034: A ready-made SIEM: OpenSearch with Security Analytics on its own VM, Sigma rules from git, incidents assembled by the API

Date: 2026-10-03 · Status: accepted

## Context
The site shows single-event detection (Falco) and single-action response (Talon). The next section,
"04 · Correlation", is meant to show what a SOC does with those signals: rules over several sources,
correlated incidents with an evidence timeline, ATT&CK coverage and SOC metrics (time to detect, time to
isolate, dwell time in the unguarded twin) - and nothing trivial like counting failed logins.

The sources already exist on k3s01: Falco, Falco Talon, Hubble flows, the k3s audit log (which also
records Kyverno's admission denials), the portfolio API's run and command events, and the host's
auditd, sshd and nftables logs. The candidate detections are: a staged attack in order (recon, then the
flag read, then an exfiltration attempt) per run; beaconing periodicity; the contained-intrusion chain
(Falco alert, Talon patch, first Hubble drop on the same pod) with the measured time to isolate;
"prevented, not detected" (preventive evidence with no detection); policy probing (repeated admission
denials, then a success); dwell time in the twin; an exec in `sandbox*` not made by the API; detection
drift (a rule silent although its scenario ran); and one the eBPF layer cannot see at all (below: the flag
leaving over DNS).

A first plan built an own Go engine (`app/siem`); the owner rejected building a SIEM from scratch and
allowed more resources instead. Three ready-made candidates were evaluated against primary sources
(docs, plugin source, release data, as of 2026-10-03):

- **OpenSearch 3.9.0 + Security Analytics (SA)**, Apache-2.0. Sigma rules uploaded raw over REST
  (`POST _plugins/_security_analytics/rules?category=<log type>`), custom log types, findings / alerts /
  correlations REST APIs, Dashboards; the Alerting plugin alongside (query- and bucket-level monitors).
  Detectors are Alerting monitors on a schedule, **at least every minute**. Correlation rules link
  findings of two log types inside a time window, optionally on **equal values of one field** per side
  (`correlate[].field`, since 2.12) - but with **no order and no count**. Sigma correlation meta-rules
  are not supported (security-analytics#1275). Aggregation rules fail on a log type without field
  mappings (#1750, fix not in 3.9). The "rules past the tenth never fire" report (#1656) is fixed in
  3.9 (alerting#2064).
- **Wazuh 4.14.8** (stable). Real-time XML rule chains (`if_matched_sid` + `same_field` + `timeframe`)
  express an ordered sequence per run id natively; a host agent covers auditd/sshd/FIM. Rules are XML,
  not Sigma; the 4.x ruleset does not carry over to 5.x (rewrite).
- **Wazuh 5.0.0-beta5.** Its detection **is a fork of OpenSearch Security Analytics** (Wazuh's own
  docs), so it has SA's schedule and correlation limits, and 5.0 drops 4.x rule chaining. On top: no
  HTTP or syslog input (agents only), custom content only through a REST content manager with
  draft/test/custom promotion (no file or git loading; wazuh#39656 open), a closed schema (WCS),
  ≥16 GB, an open report of events dropped under load (wazuh#38807), no GA date and no stated
  beta-to-GA upgrade path.

None of the three expresses every candidate detection in its rule language: order, periodicity and
measured intervals need more than SA's rules; ordered per-run sequences fit only Wazuh 4.x, at the
price of leaving Sigma. Graylog (Sigma in the paid tier) and Elastic (licence) were weaker fits.

Placement was a separate question: inside k3s01 (grow the VM to ~16 GB, deploy with Argo CD) or on a
VM of its own.

## Decision

**OpenSearch 3.9.0 with Security Analytics and Alerting, single node, on a new VM `siem01`.** Detection
rules are Sigma files in this repo, count and absence checks are Alerting monitors in this repo, both
synced from git. The portfolio API assembles incidents from their output and adds the order,
periodicity and interval logic. Wazuh is not used.

### Placement: its own VM, not the cluster it watches
- **Why not in the cluster:** whoever takes the k3s node would also hold the SIEM's data and could
  rewrite the history that is supposed to convict them. On `siem01` the node can add documents and can
  stop shipping; it cannot delete anything or rewrite rolled indices, and at most it can rewrite the
  current day's write index (below). It also keeps a JVM search engine
  off the node whose memory the demo needs, and out of the `restricted` / signed-image admission story,
  which a third-party database would only dilute.
- **The VM:** `scripts/pve-create-vm.sh` with `VMID=121 VM_NAME=siem01 VM_VLAN=42 VM_IP=10.4.2.10/24
  VM_GW=10.4.2.1 VM_DISK_GB=80 VM_MAC=<new>` (the script's MAC default is k3s01's: it must be
  overridden, and the hard-coded VM description is made a parameter), 4 vCPU, 8 GB, plus a second
  20 GB disk for snapshots. Debian 13 cloud image, configured by Ansible (ADR 0007) as a new inventory
  group `siem_nodes` with its own group_vars and playbook: base (with time sync - correlation depends
  on both clocks), sysctl (`vm.max_map_count=262144`), ssh_hardening, auditd, unattended upgrades,
  nftables default-deny (ADR 0009). The firewall role gains per-service source lists and its k3s rules
  (6443, pod-to-host ports) become conditional on the group; the auditd role's k3s watches likewise.
- **Network: its own VLAN and firewall zone, not the DMZ.** Created on the UniFi gateway on 2026-10-03:
  network `SIEM`, VLAN 42, 10.4.2.0/24 (gateway 10.4.2.1, no DHCP, no IPv6, no mDNS), in a custom
  zone `Siem` whose defaults block traffic from every other zone. Zone policies on top:
  - allow `Dmz` 10.4.1.20 → 10.4.2.10:9200/tcp (k3s01 to OpenSearch), return traffic only;
  - allow the admin networks (10.1.1.0/24, 10.2.1.0/24) → 10.4.2.10:22/tcp, return traffic only;
  - block `Siem` → gateway on TCP/UDP (ICMP stays), so the SIEM host cannot reach the router's
    management;
  - egress to the internet only on TCP 53/80/443 and UDP 53/123 (apt, GitHub, DNS, NTP).
  The Proxmox uplink port on the switch carries VLAN 42 tagged (its exclusion was lifted; the previous
  port configuration is kept outside the repo for rollback). So k3s01 and `siem01` share no layer-2
  segment: a root attacker on the node cannot ARP-spoof towards the SIEM, and the gateway, not a host
  the attacker might hold, decides that only 9200 is reachable. The host firewall on `siem01` repeats
  the same allow-list (defence in depth: a gateway misconfiguration does not open it).
- **Dashboards listens on localhost only** and is reached through an SSH tunnel; there is no
  password-based admin path over the network (SSH host keys, key-only logins, TLS with client
  certificates on 9200 and for Dashboards' own connection).
- Nothing is exposed through the Cloudflare tunnel; browsers never reach `siem01`.

### Who may talk to 9200, and how
- 10.4.1.20 is the node **and every pod's SNAT address** (`bpf.masquerade`), so the source IP is not
  the control. The control is **TLS client-certificate authentication** on 9200, with password logins
  refused on the HTTP layer: Fluent Bit on the host and `portfolio-api` each hold their own certificate,
  mapped to their own role.
- In the cluster, a CiliumClusterwideNetworkPolicy denies egress to 10.4.2.10/32 (`egressDeny`, with
  `enableDefaultDeny.egress: false` so it adds the deny without switching anything to default-deny)
  for every endpoint **outside the `portfolio-api` namespace** - the exception is in the selector
  (`io.kubernetes.pod.namespace NotIn [portfolio-api]`), because a deny beats every allow in Cilium and an
  allow rule could not punch through it. The API's CNP and NetworkPolicy allow 10.4.2.10:9200.
  hostNetwork pods are outside any CNP; they run as the node, which the design already treats as
  potentially hostile. The cluster holds exactly one SIEM credential: `portfolio-api`'s read-only client
  certificate and key, generated on the operator's machine, encrypted into git as a KSOPS Secret
  (ADR 0006) and never stored elsewhere.
- **Certificates.** The CA is generated on `siem01` by the Ansible role and its key stays there; the CA
  certificate is distributed to the clients that verify the server (Fluent Bit, the API). Its key on
  `siem01` adds nothing for an attacker who already holds `siem01`. Fluent Bit's key is generated on
  k3s01 (only the CSR travels); the admin certificate (`plugins.security.authcz.admin_dn`, used by
  Ansible for templates, ISM and the security configuration), the `rules-sync` certificate and the
  Dashboards certificate are generated on `siem01` and never leave it. Certificates live one year and
  are renewed by the role, except `portfolio-api`'s: its CSR is signed on `siem01` and renewed yearly by
  the operator; revocation on suspicion is removing the DN from `roles_mapping`.

### OpenSearch on `siem01`
- OpenSearch and OpenSearch Dashboards 3.9.0 from the official Debian repository (apt signature
  checked), version pinned (ADR 0008), run by systemd as their package users. Security Analytics,
  Alerting, Notifications and Index Management ship in the distribution; Performance Analyzer is
  disabled. Heap 3 GB; `discovery.type: single-node`; 0 replicas everywhere (`.opensearch-sap-*`
  checked for yellow health). Security plugin on, no demo configuration (no demo certificates or
  users); resource sharing for SA objects stays disabled, so access follows roles only.
- **Data streams, not fixed indices:** one data stream per source - `sdp-falco`, `sdp-talon`,
  `sdp-hubble`, `sdp-k8s-audit`, `sdp-api`, `sdp-host`, `sdp-siem01` (the SIEM host's own sshd and
  auditd) - created with their index templates (explicit mappings, `"dynamic": false`, so ingest never
  needs a mapping update) and ISM policies by the admin through Ansible. ISM rolls over daily, sets the
  rolled backing index **read-only** (`index.blocks.write`) within one ISM job interval, and deletes backing indices after
  30 days. SA's findings and alerts, Alerting's alert history and SA's correlation history are kept for
  the same 30 days, so nothing outlives the documents it points at. Disk watermarks are alarmed before
  the flood stage (which would make every index read-only, findings included).
- **Identities** (all certificate-based):
  - `shipper` (Fluent Bit): `indices:data/write/index` and `indices:data/write/bulk*` on `sdp-*`, nothing
    else - no `indices:admin/*` (no index creation, mapping or settings changes), no delete, no update.
    Writes through a data stream name are create-only, so a document cannot be replaced through the
    stream. But the security plugin evaluates a `.ds-sdp-*` backing index against its data stream's
    privileges, and OpenSearch accepts an `op_type=index` overwrite on a backing index when it carries
    `if_seq_no`/`if_primary_term` - so the role alone does not make the record append-only. Three
    controls bound what is left: rolled backing indices are write-blocked by ISM and the shipper cannot
    lift the block (no `indices:admin/settings/*`); a `final_pipeline` (which a request cannot bypass)
    stamps `event.ingested` on every write, and an Alerting monitor raises "evidence rewritten" when a
    document's `event.ingested` trails its `@timestamp` by more than the shipping backlog allows; and an
    hourly incremental snapshot (the `shipper` has no snapshot rights) keeps the pre-rewrite copy.
    **The node can add documents and stop shipping; it can rewrite only documents in the current day's
    write index. A rewrite made more than the backlog threshold after the event is alarmed, and one made
    before the next hourly snapshot has no earlier copy; the need to know id and sequence number is not
    relied on, since the node can obtain a read credential. Rolled indices are out of its reach.** The tests below
    attack exactly this.
  - `portfolio-api`: read on the SA findings / alerts / correlations APIs, on Alerting alerts, and on
    `sdp-*`.
  - `rules-sync` (on `siem01`): SA and Alerting full access, plus read, `indices:admin/mappings/get` and
    `indices:admin/mapping/put` on `sdp-*` - SA requires a detector's owner to read its indices, and the
    monitors it creates run with that owner's roles.
  - Dashboards runs **without** the security-dashboards plugin (removed at install; the Debian package
    ships it), connects with its own client
    certificate (`opensearch.ssl.alwaysPresentCertificate: true`) mapped to a read-only analyst role,
    and listens on localhost: the SSH key that opens the tunnel is its access control.
  - The admin: the super-admin certificate above, on `siem01` only.
- **Heartbeats, not silence of detections:** Falco, Talon and the filtered Hubble stream are quiet by
  design when nobody attacks, so the absence of detections proves nothing. Fluent Bit adds a `dummy`
  input per stream (one `event.kind: heartbeat` record a minute, proving the shipper still ships), and
  Falco emits its metrics every 5 minutes as an output rule (proving the real Falco → pod log → Fluent
  Bit path). The "ingest silent" monitor fires on 10 minutes without heartbeats.
- Snapshots: hourly, incremental, to a filesystem repository on a second 20 GB disk (a new
  `VM_DATA_DISK_GB` parameter of `pve-create-vm.sh`); an off-host copy (Proxmox backup of the VM) is the
  owner's backup scheme's, recorded as an open item.

### Ingest from k3s01: files only, no push input
- **Fluent Bit on the k3s01 host** (official package, pinned, systemd, Ansible role in the k3s group;
  Debian 13 availability confirmed before the role is written). It reads files, so there is no HTTP
  input, no new pod-to-host port and nothing a pod could use to forge events:
  - Falco: its JSON alerts on stdout (already how alerts are read, ADR 0013), from `/var/log/pods/falco_*`
    with the CRI parser; Talon: its JSON log, likewise.
  - The API: its slog JSON lines on stdout, with the run and command events the contract defines.
  - The k3s audit log file (Kyverno's admission denials are in it as refused `create`s).
  - Hubble: Cilium's static flow exporter (`hubble.export.static`, file
    `/var/run/cilium/hubble/events.log`), with allow-lists for flows whose source **or** destination pod
    is in `sandbox/` or `sandbox-unguarded/` (the twin's drops and the ingress drops to a quarantined
    victim both matter), and a `fieldMask` that drops addresses and node names but keeps verdicts,
    drop reasons, pod/namespace and `l7.dns.query` (Hubble writes names with a trailing dot; rules allow
    it). This changes the Cilium values in both `cluster/apps/cilium.yaml` and the cilium role
    (`scripts/check-cilium-values.sh`), rolls the agent, and is followed by re-measuring ADR 0032's
    quarantine latency.
  - Host: journald (sshd, sudo), auditd, nftables drop logs.
- **Every source has a field allow-list** applied by Fluent Bit before shipping; anything not listed
  is dropped. Event time is parsed into `@timestamp`. For the audit log, the `authentication.k8s.io`
  group is lowered to `Metadata` in the audit policy (TokenReviews carry bearer tokens in
  `requestObject`), and Fluent Bit additionally drops `requestObject`/`responseObject` for that group.
- Rules are written against the ingested field names; if SA's mapping step does not accept identical
  names without aliases, aliases are generated from the same allow-lists (tested before rules are
  written).
- Output: `Write_Operation create`, no `Generate_ID` (server-generated ids), `tls.verify On` against the
  `siem01` CA, the shipper's client certificate. Every record carries `k8s.pod.ref` =
  `<namespace>/<pod>` where a pod is involved, the join key the correlation rules use (a compare run
  gives the guarded pod and the twin the same pod name; the namespace keeps them apart).
- The exact wiring (parsers, buffering, per-source caps) is the phase contract's.

### Privacy
- Visitors are run ids (ADR 0017); the API ships no client IPs, and the Hubble field mask strips
  addresses (including any L7 forwarded-for header).
- The owner appears in the host logs and in the audit log (`sourceIPs` from the admin networks,
  `userAgent`). Before shipping, Fluent Bit **replaces user names and source IPs with HMAC-SHA256
  pseudonyms** - a Lua implementation with a test vector in CI; Fluent Bit's built-in `hash` is plain
  SHA-256 and is not used, because IPv4 addresses and a handful of user names are trivially reversed
  from unkeyed hashes. The key is generated on k3s01 by Ansible, root-only, and never leaves the host
  (not in git, not on `siem01`); losing or rotating it (yearly, or on suspicion) only breaks pseudonym
  continuity. Rules see a stable pseudonym, so "the same actor" still correlates.
- **Anything the API publishes passes ADR 0021's per-field allow-list and scrubber** (no node names,
  host or pod IPs, `*.svc` names, ServiceAccount names); raw documents are never forwarded verbatim.
  Host-derived findings appear on the site only as counts and rule names.

### Rules from git
- `siem/` in the repo: `log-types/` (custom SA log types), `rules/` (Sigma, one file per rule, `id`
  UUID, `level`, `status`, `logsource`, ATT&CK tags as `attack.tXXXX`, no aggregation conditions),
  `detectors/` (which rules run on which data stream, interval 1 minute), `correlations/` (SA
  correlation rules) and `monitors/` (Alerting monitors: counts, absence, heartbeats).
- `make validate` lints all of it (Sigma schema, required fields, tag form, field names within the
  source's allow-list, each rule in exactly one detector, no aggregation rules).
- **Pull-based sync on `siem01`:** a systemd timer fetches `main` of the GitHub repository over HTTPS -
  the same trust Argo CD gives it - and treats the tree **as data only**: the validator and the sync
  program are installed and pinned by Ansible, nothing from the repo is executed. It applies only
  fast-forwards from the last applied commit, refuses to delete more than five rules or monitors in one
  run (an operator override is a flag on the host), and records the applied commit in an index the API
  shows. SA assigns its own rule ids, so the sync keeps a map from Sigma `id` to SA id and updates or
  deletes with `forced=true` (SA re-attaches changed rules to their detectors). Data streams exist
  before detectors are created. Verifying signed commits (`git verify-commit` against an allowed-signers
  file provisioned by Ansible) is added when the threat model's signed-commits item is done.
- Every rule and monitor has a canary - a scenario or test that must produce its finding or alert -
  which is also the detection-drift signal.

### Who detects what
- **Security Analytics:** every single-event rule (a finding with its source documents and ATT&CK tags),
  including "exec in `sandbox*` not by the API"; and correlation rules where "two log types, same field
  value, inside a window" is the whole claim - the contained-intrusion chain on the same `k8s.pod.ref`
  (Falco finding ↔ Talon finding ↔ Hubble drop) is one.
- **Alerting monitors:** counts and absence - policy probing (admission denials per principal in a
  window, then a success), "prevented, not detected" (preventive evidence with no Falco event in the
  window), a rule silent although its scenario ran, ingest silence (heartbeats), evidence rewritten.
- **The portfolio API** (read-only towards the SIEM): polls new findings, correlations and alerts,
  groups them into incidents by run id and pod, checks order (the staged attack), computes periodicity
  (beaconing, from bounded `_search` queries on `sdp-hubble`) and intervals (time to isolate, dwell time
  in the twin), and serves the result to the page. That part is detection code: it is versioned, unit-
  and mutation-tested like the rest of the API, and every check has a canary. It never ingests events
  and never writes to the SIEM; every incident cites the findings and documents it was built from.
- **Latency is stated, not hidden:** a finding arrives about a minute or a little over after the event
  (detector interval, Fluent Bit flush, refresh, asynchronous correlation). The terminal's risk meter
  moves on the API's own command events at once and marks each step "confirmed by the SIEM" when the
  finding lands; a 300 s session leaves room for that. Automatic correlation by shared ATT&CK tags stays
  off (wazuh#38807 reports correlation backpressure write-blocking ingest in the Wazuh fork; ingest is
  load-tested with correlation on before acceptance).

### A scenario only correlation catches: the flag leaves over DNS
The section needs one attack where the eBPF layer is honestly blind and the SIEM is not - otherwise
correlation only restates what Falco already said. The terminal gets one new command, `dns-exfil`
(objective "Phone home"). It is built from what is already true of the cluster, with one deliberate,
amended exception to the safety model (ADR 0017 and ADR 0032 amendments of 2026-10-03: one command
resolves a name, only under the reserved `.test` TLD, in a zone that CoreDNS answers itself).

- **What it runs.** A fixed argv like every command (no free text, no visitor input): `sh -c` without a
  TTY that reads the run's flag file itself (`/srv/shop/.flag`, not the environment - no command reads
  the environment), turns it into one DNS-safe label (`SDP{16 hex}` → `sdp-<16 hex>`, under 63
  characters), runs busybox `nslookup` - already in the image - for `<label>.x.exfil.sdp.test.` (the
  trailing dot stops `ndots:5` search expansion into `*.svc.cluster.local` names) and ends `; true`,
  because `nslookup` exits non-zero on NXDOMAIN and the command's outcome is "allowed".
  `tests/scenarios/offline.sh` proves the argv and the label form under the pod's security context
  (there is no cluster DNS offline); `tests/scenarios/run.sh` proves the lookup live.
- **Falco sees nothing, by design of its rules, not by switching them off.** `nslookup` is not in the
  "SDP network tool" list (`wget, nc, curl`); no stock rule watches name lookups; a non-interactive `sh`
  is not "Terminal shell in container" (`deface` already runs that way). The live test asserts **zero
  Falco events** for the command, so a future rule that catches it turns the test red and the page's
  claim is re-examined.
- **Prevention lets it through, and nothing leaves the homelab.** `sandbox`'s DNS egress already goes
  through Cilium's DNS proxy (`matchPattern: "*"`), so Hubble records the query name. CoreDNS (own
  template, ADR 0026, its `import` of custom server blocks) answers `exfil.sdp.test` itself as a
  sinkhole (NXDOMAIN, never forwarded). The live test also proves no `exfil.sdp.test` query leaves
  CoreDNS for an upstream resolver. In the twin, which has no DNS egress, the attempt is a plain policy
  drop; in a pod already quarantined (after `beacon`), it is a drop under quarantine - the incident then
  says "attempted, contained".
- **What the SIEM concludes.** An SA finding on the Hubble DNS query with a long label under the exfil
  zone (T1071.004) is suspicious on its own but proves nothing about data. SA correlates it with the
  same `k8s.pod.ref`'s terminal activity from `sdp-api` within the session length (300 s). The API adds
  the decisive check: the DNS label **is this run's flag**. When a terminal run ends, the API keeps
  only `HMAC(run key, label)` per run id for 15 minutes - long enough for findings that arrive a minute
  or more after the run - and compares it with the HMAC of the queried label; the flag itself is never
  logged or shipped by the API. A match makes the incident high: "Exfiltration over an alternative
  protocol (T1048.003): this run's secret left in a DNS query at t+31 s; Falco: no event". If
  `read-flag` (T1552.001, as in `scenarios.yaml`) ran earlier in the run, the timeline shows both steps;
  otherwise the read is `dns-exfil`'s own. The page shows the Falco column empty next to the incident.

### Acceptance tests (live, before the section ships)
- `shipper` cannot overwrite or delete: `PUT sdp-falco/_doc/<id>` is refused by the data stream;
  `PUT .ds-sdp-falco-<rolled>/_doc/<existing id>?if_seq_no=<real>&if_primary_term=<real>` (values read by
  the admin) is refused by the write block; `DELETE .ds-…/_doc/<id>`, `POST .ds-…/_update/<id>`,
  `_delete_by_query`, `PUT sdp-falco/_mapping` and `PUT .ds-…/_settings` are refused by the role. The
  same compare-and-set overwrite against the **current** write index succeeds - the accepted residual -
  and, when made more than the backlog threshold after the event, raises "evidence rewritten" within one
  monitor interval.
- A pod outside `portfolio-api` cannot open 10.4.2.10:9200; a request without a client certificate is
  refused.
- No bearer token appears in `sdp-k8s-audit`; no field outside a source's allow-list appears in any
  `sdp-*` stream; host user names and IPs appear only as pseudonyms.
- SA detectors accept a data stream as input (if not: per-source write aliases over rolled indices,
  with the same write-block, role and rewrite-alarm controls proven by the same tests).
- Every rule's canary produces its finding, also after a forced `_rollover` of every stream (SA's
  mappings survive rollover); stopping Fluent Bit raises "ingest silent", stopping Falco raises it for
  `sdp-falco`.
- `dns-exfil`: zero Falco events; CoreDNS forwards no `exfil.sdp.test` query upstream; the incident
  appears with the flag match, also when the visitor leaves right after the command.
- 9200 refuses a request without a client certificate; a write attempted through Dashboards is refused
  by the read-only analyst role; Dashboards is not reachable from any network, only through the tunnel.

### Degradation
If `siem01` is down or unreachable, the API reports the SIEM as unavailable and the page hides the
Correlation section, as it does for the terminal without its dependencies. The demo itself (attack,
detection, response) does not depend on the SIEM.

## Consequences
- A real SIEM with Sigma rules and monitors versioned in git, findings an employer recognises, and an
  honest split: SA says what it can per event and per window, Alerting counts and notices absence, and
  the API's tested detection code adds order, periodicity and intervals from their evidence.
- The record survives a compromised node: the node can append and can rewrite at most the current day's
  write index (late rewrites alarmed, earlier hours recoverable from the hourly snapshots); rolled days
  are out of its reach, and the SIEM holds no credential back into the cluster.
- One more VM to run: OS patches (unattended upgrades), OpenSearch upgrades (pinned, deliberate),
  certificate renewal, disk and snapshots. ~8 GB of Proxmox RAM and 100 GB of storage.
- OpenSearch is a third-party package outside the image pipeline: apt verifies the repository
  signature, but no cosign signature applies; `trivy rootfs` over the installation is run on each
  version bump, and the version is reviewed on each release like the other third-party pins (ADR 0023).
- The 1-minute detector floor rules out sub-second correlation on the page; the response itself stays
  within ADR 0032's 3 s bound and is measured, not delayed, by the SIEM.
- Enabling Hubble's file exporter closes ADR 0021's "Not done: Hubble flows" for the SIEM path.
- If SA gains ordered or counted correlation (security-analytics#1275), checks can move from the API
  and the monitors into SA rules without changing the page.
- Wazuh 5.0 would become reconsiderable at GA if it adds file or git content loading and an HTTP
  input; its detection core is the same SA, so the rules would carry over.
