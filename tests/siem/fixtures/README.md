# SIEM fixtures (contract step F0)

Captured 2026-10-04 (~08:00-08:20 CEST), read-only, from k3s01 (10.4.1.20) via `ssh ansible@10.4.1.20 sudo -n ...`
(cat/grep/journalctl only; nothing on the host or cluster was changed). One record per line, original bytes except
for the sanitisation listed below (the auditd group separator 0x1d is kept).

## Files and sources

| file | lines | source on k3s01 | what each line is |
|---|---|---|---|
| falco.log | 3 | /var/log/pods/falco_falco-rsfkr_a6531a25-656f-4893-9f14-c19c7d39efe7/falco/0.log (raw CRI lines) | `Terminal shell in container` (sc-shell-in-container-44c7e9), `Read sensitive file untrusted` (sc-sensitive-file-read-dd86c0), `SDP network tool in sandbox` (sc-network-tool-bf192d) |
| talon.log | 2 | /var/log/pods/falco-response_falco-talon-6ccdc875ff-ltr65_5cbcef41-60dd-4187-83d9-09529e2bd60c/falco-talon/0.log (raw CRI lines) | action-result line, `kubernetes:terminate` "Terminate Pod" status success (sc-shell-in-container-44c7e9); action-result line, `kubernetes:label` "Quarantine Pod" status success (sc-network-tool-bf192d) |
| k8s-audit.jsonl | 8 | /var/lib/rancher/k3s/server/logs/audit-2026-10-03T07-28-02.826.log (rotated k3s audit log) | see below |
| host-ssh.json | 1 | `journalctl -u ssh -o json` | `Accepted publickey for ansible ...` (SYSLOG_IDENTIFIER is `sshd-session`, OpenSSH 10 on Debian 13) |
| host-sudo.json | 1 | `journalctl SYSLOG_IDENTIFIER=sudo -o json` | `ansible : ... COMMAND=/usr/local/bin/k3s crictl pull ...` (2026-10-02) |
| host-nft.json | 1 | `journalctl -k -o json \| grep nft-drop` | `nft-drop: IN=eth0 ... SRC=10.4.1.1 DST=255.255.255.255 PROTO=UDP ... DPT=10001` (gateway broadcast) |
| host-auditd.log | 3 | /var/log/audit/audit.log.3 (line 1), /var/log/audit/audit.log (lines 2-3) | key `identity` (CONFIG_CHANGE, see Missing), key `privileged` (SYSCALL execve of /usr/bin/sudo, auid=1000), key `k3s_config` (SYSCALL openat by k3s-server) |

Falco, Talon and audit lines come from the same `make scenario-test` window, 2026-10-03 06:45-06:48 UTC (the
`sc-*` pods), plus the API-created visitor/acceptance pod `terminal-3755e65530` (06:47 UTC).

k8s-audit.jsonl, in order:
1. `create pods` sandbox/terminal-3755e65530 by `system:serviceaccount:portfolio-api:portfolio-api`, 201,
   RequestResponse, carries the `SDP_FLAG` env entry (value replaced, entry kept -> proves F2).
2. `create pods/exec` sandbox/terminal-3755e65530 by `system:serviceaccount:portfolio-api:portfolio-api`, 101.
3. `pods/exec` sandbox/sc-network-tool-bf192d by `system:admin` (kubectl), 101. NOTE: verb is `get` (kubectl
   websocket upgrade), not `create`.
4. `patch pods` sandbox/sc-network-tool-bf192d by `system:serviceaccount:falco-response:falco-talon`, 200 (JSON patch
   setting label `sdp.hubertjablon.ski/quarantine=true`).
5. `delete pods` sandbox/sc-shell-in-container-44c7e9 by `system:serviceaccount:falco-response:falco-talon`, 200.
6. Kyverno admission denial, code 400: `create pods` sandbox/admission-test-deadline-missing by `system:admin`,
   policy `require-sandbox-deadline` (NOTE: request is `dryRun=All`, from the admission test suite).
7. TokenReview `create tokenreviews` by `system:node:k3s01`, 201, RequestResponse (spec.token redacted).
8. Kyverno authorization review: `create subjectaccessreviews` by
   `system:serviceaccount:kyverno:kyverno-admission-controller`, 201 (must be dropped by the shipper).

## Sanitisation (exact, applied by regex to the raw line text; JSON validity re-checked afterwards)

| rule | replacement | hits |
|---|---|---|
| JWT `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*` | `REDACTED-JWT` | 2 (TokenReview requestObject.spec.token and responseObject.spec.token) |
| `Bearer <x>` | `Bearer REDACTED` | 0 |
| `Authorization` / `Cookie` / `Set-Cookie` header values | `REDACTED` | 0 |
| PEM blocks `-----BEGIN ...-----...-----END ...-----`, base64 PEM `LS0tLS1CRUdJTi...` | `REDACTED-PEM` / `REDACTED-PEM-B64` | 0 |
| flag `SDP\{[0-9a-f]{16}\}` (and the bare 16-hex value anywhere) | `SDP{0000000000000000}` (bare: 16 zeros) | 2 (env value in requestObject and responseObject of record 1); bare: 0 |
| client-cert fingerprints `X509SHA256=<64 hex>` (credential-id of system:admin and system:node:k3s01) | `X509SHA256=` + 64 zeros | 3 |
| SSH public-key fingerprint `SHA256:<43 b64>` (operator's key) | `SHA256:` + 43 `A` | 1 |
| admin/workstation IPs `10.1.1.x`, `10.2.1.x` (only a LAB 1 workstation address occurred), `192.168.x.x` | `10.1.1.250` | 3 (2 audit sourceIPs, 1 ssh MESSAGE) |
| operator user name `hubertmj` outside `ghcr.io/hubertmj/` | `operator` | 0 |

Kept on purpose (not secrets, needed for shapes/rules): timestamps, auditIDs, UIDs, `JTI=` credential-ids (token IDs,
not tokens), pod/namespace/rule names, cluster addresses (10.4.1.20 k3s01, 10.4.1.1 gateway, 10.42.x pod IPs,
127.0.0.1), journald `_MACHINE_ID`/`_BOOT_ID`/`__CURSOR`, the `ansible` automation account name (a role account
present in the repo inventory, not a person), the image path `ghcr.io/hubertmj/self-defending-portfolio/*` (public
project registry path, matched by Falco/Kyverno fields) and the label domain `sdp.hubertjablon.ski` /
`tests.hubertjablon.ski` (label keys used by Talon and policies). If the publishing rules require those two public
names to be pseudonymised too, the orchestrator must decide; this capture does not alter them.

## Leak check (run in this directory after writing)

```
$ cat * | grep -c eyJ ; cat * | grep -c 'Bearer ' ; cat * | grep -c 'BEGIN '   (README excluded at run time)
eyJ=0 Bearer=0 BEGIN=0
$ grep -oE 'token\\?"\s*:\s*\\?"[^"\\]*' * | grep -v REDACTED
(no output, exit 1)
$ grep -oE 'SDP\{[0-9a-f]{16}\}' * | sort | uniq -c
      2 k8s-audit.jsonl:SDP{0000000000000000}
$ grep -oE '\b10\.(1\.1|2\.1)\.[0-9]+\b|\b192\.168\.[0-9.]+' * | sort | uniq -c
      1 host-ssh.json:10.1.1.250
      2 k8s-audit.jsonl:10.1.1.250
$ grep -oiE '[a-z./]*hubert[a-z.]*' * | sort | uniq -c
      7 falco.log:ghcr.io/hubertmj
      2 host-sudo.json:ghcr.io/hubertmj
      1 k8s-audit.jsonl:/metadata/labels/sdp.hubertjablon.ski
     28 k8s-audit.jsonl:ghcr.io/hubertmj
     27 k8s-audit.jsonl:sdp.hubertjablon.ski
      2 k8s-audit.jsonl:tests.hubertjablon.ski
      3 talon.log:ghcr.io/hubertmj
$ grep -oE 'X509SHA256=[0-9a-f]{64}|SHA256:[A-Za-z0-9+/]{43}' * | sort | uniq -c
      1 host-ssh.json:SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
      3 k8s-audit.jsonl:X509SHA256=0000000000000000000000000000000000000000000000000000000000000000
```
Result: no JWT, bearer, PEM, unredacted token, real flag or admin IP remains; the only `hubert*` strings are the public
image path and label domain kept on purpose (see above). The real flag hex was also searched literally: 0 hits.

## Missing / substituted (orchestrator to decide; `make scenario-test` was NOT run)

- host-ssh.json: no FAILED ssh login exists. The ssh journal (since 2026-10-01 08:07) has no `Failed`,
  `Invalid user` or auth-failure line, only accepted publickey logins from the workstation. Only the accepted login
  is captured. A failed one needs a deliberate bad-key attempt from the workstation.
- host-auditd.log `identity`: no watch hit (write to /etc/passwd, shadow, group, gshadow, sudoers) exists in any
  audit.log*. The line used is the `CONFIG_CHANGE op=add_rule key="identity"` record from rule loading
  (2026-10-01, older non-enriched format, no `node=` prefix). A real SYSCALL identity record needs e.g. a
  sudoers/passwd write on the host.
- Format note: auditd switched to the enriched format with a `node=k3s01 ` prefix (lines 2-3); line 1 is from before.
- Notes, not gaps: k3s-admin exec is verb `get` (record 3); the Kyverno 400 is a dryRun (record 6); the audit
  rotation keeps 10 x 100 MB (about 2.3 h per file, ~24 h total); the source file is the oldest backup and is deleted
  at the next rotation (audit.log was at 54 of 100 MB at capture, i.e. roughly 1-1.5 h later). Talon/Falco pod logs
  survive until those pods restart.
- The README itself contains the regex patterns (`eyJ`, `Bearer`, `BEGIN`) as text; run leak greps on the data files.

## Added by the orchestrator 2026-10-04
- host-ssh-failed.json: a deliberate failed login (invalid user `sdp-fixture-probe`, publickey, from docker01) captured from `journalctl -u ssh -o json`; a LAB 1 workstation address -> 10.1.1.250.
- Public names kept on purpose: ghcr.io/hubertmj/self-defending-portfolio/* image paths and the sdp./tests.hubertjablon.ski label domains are public in the repo.
- auditd `identity` stays a stand-in (CONFIG_CHANGE); a real watch hit is produced on siem01 during P1.

## siem01 (P1, captured 2026-10-04 ~11:00 CEST after hardening, read-only except the triggers below)

Captured on siem01 (10.4.2.10) with `journalctl ... -o json` and `grep` on /var/log/audit/audit.log,
sanitised with the same rules as above (a LAB 1 workstation address -> 10.1.1.250, key fingerprint -> `A`s).

| file | lines | what each line is |
|---|---|---|
| siem01-ssh.json | 1 | `Accepted publickey for ansible ...` (`SYSLOG_IDENTIFIER` sshd-session, `_SYSTEMD_UNIT` ssh.service) |
| siem01-ssh-failed.json | 2 | a deliberate refused login from docker01: `Invalid user sdp-fixture-probe ...` and `Connection closed by invalid user ... [preauth]` |
| siem01-sudo.json | 1 | `ansible : ... COMMAND=/usr/bin/chmod 0644 /etc/group` (the identity trigger below) |
| siem01-nft.json | 1 | `nft-drop: IN=eth0 ... SRC=10.4.2.1 DST=255.255.255.255 ... PROTO=UDP ... DPT=10001` (gateway broadcast) |
| siem01-auditd.log | 3 | enriched records with the `node=siem01 ` prefix: key `identity` - a REAL watch hit (SYSCALL fchmodat on /etc/group; it replaces the CONFIG_CHANGE stand-in of host-auditd.log), key `privileged` (execve of /usr/bin/sudo), key `siem_config` (the P1 watch on /etc/sdp-siem) |

Triggers (harmless, on siem01 only): `chmod 0644 /etc/group` (mode unchanged) for the identity watch,
`touch /etc/sdp-siem` for the siem_config watch, one `ssh sdp-fixture-probe@10.4.2.10` with every
authentication method off for the refused login.

Note: until auditd restarts after its configuration got `name_format = HOSTNAME`, records carry
`node=(null) ` (a SIGHUP reload does not resolve the name); after the reboot they carry
`node=siem01 `. The parser accepts any `node=<x> ` prefix and drops it.

## api (P2 `api-events`, 2026-10-04)

| file | lines | what each line is |
|---|---|---|
| api.log | 24 | raw CRI lines of the API container's stdout as Fluent Bit tails them from /var/log/pods/portfolio-api_portfolio-api-*/api/*.log: 21 `siem.run`/`siem.command` lines (a terminal run - whoami, read-flag (achieved), touch-bin (refused, exit 1), read-shadow (detected, killed) - and a one-click compare run with its guarded and unguarded arm) and 3 other API lines (`listening`, `terminal command exec ended`, `siem events dropped`) that the shipper must drop |

Not captured live: the lines did not exist before this phase. The JSON bodies of the 21 siem lines are
app/api/internal/siemlog/testdata/lines.golden (written by the package's golden test from real runner
event types through a real hub) with slog's `time` key put back in front; the CRI timestamps are local
time (+02:00) 180 us after it, as on k3s01. The three other lines are synthetic, shaped like the API's own log calls: the
`listening` line carries the live Deployment's attack limits (60 per IP / 600 global from its env, not the code
defaults 3/30) and a made-up commit; `terminal command exec ended` and `siem events dropped` carry made-up values.
The read-flag command's output (the flag) is in no line: output events are never written. Regenerate after
a golden change: same bodies, same order. Field allow-list: siem/fields/api.yaml.
