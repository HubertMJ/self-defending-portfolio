#!/usr/bin/env python3
"""Checks what the pinned Fluent Bit printed after sdp.lua (tests/siem/lua-hmac.sh).

Usage: lua_check.py <records.jsonl> <hmac.key> <root> <expected.jsonl> [--write]

Every expected value that is a digest is computed here with Python's hmac/hashlib, independently of
the Lua implementation (siem contract P2 tests).
"""
import hashlib
import hmac
import json
import re
import sys

import yaml

records_path, key_path, root, expected_path = sys.argv[1:5]
write = len(sys.argv) > 5 and sys.argv[5] == "--write"
key = open(key_path, "rb").read()
failures = []


def check(cond, message):
    if not cond:
        failures.append(message)


def hm1(value):
    return "hm1:" + hmac.new(key, value.encode(), hashlib.sha256).hexdigest()[:16]


def flatten(doc, prefix=""):
    out = {}
    for k, v in doc.items():
        path = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(flatten(v, path + "."))
        else:
            out[path] = v
    return out


lines = [line for line in open(records_path) if line.strip()]
docs = [json.loads(line) for line in lines]
vectors = [d for d in docs if d.get("vector") == "hmac"]
records = [d for d in docs if d.get("vector") != "hmac"]

# --- HMAC-SHA256 vectors -------------------------------------------------------------------------
check(len(vectors) == 1, f"expected one vector record, got {len(vectors)}")
if vectors:
    v = vectors[0]
    big_key = b"\xaa" * 131
    want = {
        # RFC 4231 test case 2, literally from the RFC, and recomputed.
        "rfc4231_2": "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        "rfc4231_6": hmac.new(big_key, b"Test Using Larger Than Block-Size Key - Hash Key First", hashlib.sha256).hexdigest(),
        "rfc4231_7": hmac.new(
            big_key,
            b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to "
            b"be hashed before being used by the HMAC algorithm.",
            hashlib.sha256,
        ).hexdigest(),
        "project_operator": hmac.new(key, b"operator", hashlib.sha256).hexdigest(),
        "project_empty": hmac.new(key, b"", hashlib.sha256).hexdigest(),
    }
    check(want["rfc4231_2"] == hmac.new(b"Jefe", b"what do ya want for nothing?", hashlib.sha256).hexdigest(),
          "python disagrees with RFC 4231 case 2 (test environment broken)")
    for name, value in want.items():
        check(v.get(name) == value, f"HMAC vector {name}: lua {v.get(name)} != python {value}")

# --- every record within its allow-list ------------------------------------------------------------
allow = {}
for source in ["falco", "talon", "api", "k8s-audit", "hubble", "host", "siem01"]:
    spec = yaml.safe_load(open(f"{root}/siem/fields/{source}.yaml"))
    dataset = spec["fields"]["event.dataset"]["value"]
    allow[dataset] = set(spec["fields"]) | {"event.kind", "event.dataset"}

by_dataset = {}
for doc in records:
    flat = flatten(doc)
    dataset = flat.get("event.dataset")
    check(dataset in allow, f"record without a known event.dataset: {doc}")
    if dataset not in allow:
        continue
    by_dataset.setdefault(dataset, []).append(flat)
    extra = set(flat) - allow[dataset]
    check(not extra, f"{dataset}: keys outside the allow-list {sorted(extra)}")
    check("@timestamp" in flat, f"{dataset}: no @timestamp")
    for k, val in flat.items():
        # falco's user.name is the container user of a scenario (siem/fields/falco.yaml), not a person.
        if k in ("user.name", "user.effective", "source.ip") and dataset in ("host", "siem01"):
            check(val == "unset" or re.fullmatch(r"hm1:[0-9a-f]{16}", str(val)), f"{dataset}: {k}={val} not a pseudonym")

# --- nothing that must never leave a host --------------------------------------------------------
text = "\n".join(json.dumps(r) for r in records)
for needle in ["SDP{", "0000000000000000", "requestObject", "responseObject", "token", "Bearer",
               "REDACTED", "10.1.1.250", "6.6.6.6", "203.0.113.", "10.42.", "10.4.1.", "k3s01", '"hostname"', "node_name", "userAgent",
               "operator", "ansible", "sdp-fixture-probe", "overwrite", "ingested", "stacktrace", "SHA256:",
               "lost_events", "agent_event", "IP\"", "terminal command exec ended", "listening"]:
    check(needle not in text, f"output contains {needle!r}")

# --- per source ----------------------------------------------------------------------------------
def only(dataset):
    return by_dataset.get(dataset, [])


falco = only("falco")
alerts = [r for r in falco if r.get("event.kind") == "alert"]
metrics = [r for r in falco if r.get("event.kind") == "metric"]
beats = [r for r in falco if r.get("event.kind") == "heartbeat"]
check(len(alerts) == 5, f"falco alerts: {len(alerts)}")
# Review L2: addresses in fd.name and users outside sandbox* are pseudonymised.
redirect = [r for r in alerts if r.get("falco.rule", "").startswith("Redirect STDOUT")]
check(redirect and redirect[0].get("fd.name") == f"{hm1('10.42.0.12')}:40000->{hm1('203.0.113.7')}:4444"
      and redirect[0].get("user.name") == hm1("root"), f"falco: fd.name / user.name outside sandbox {redirect}")
hostproc = [r for r in alerts if r.get("fd.name", "").startswith(hm1("10.4.1.20"))]
check(hostproc and hostproc[0].get("user.name") == hm1("operator") and "k8s.pod.ref" not in hostproc[0],
      f"falco: a host process's user pseudonymised {hostproc}")
check(all(not re.search(r"\d+\.\d+\.\d+\.\d+", str(r.get("fd.name", ""))) for r in alerts), "falco: a dotted quad in fd.name")
check(len(metrics) == 1, f"falco metric records: {len(metrics)}")
check(len(beats) == 1 and set(beats[0]) == {"@timestamp", "event.kind", "event.dataset"} if beats else False,
      f"falco heartbeat: {beats}")
if metrics:
    check(set(metrics[0]) <= {"@timestamp", "event.kind", "event.dataset", "falco.rule", "falco.rule_slug", "falco.priority",
                              "falco.priority_slug", "falco.source"}, f"falco metric record carries {sorted(metrics[0])}")
    check(metrics[0].get("falco.priority") == "Informational", "falco metric priority (N7)")
shell = [r for r in alerts if r.get("falco.rule") == "Terminal shell in container"]
check(shell and shell[0].get("falco.rule_slug") == "terminal-shell-in-container", "falco rule slug")
check(shell and shell[0].get("k8s.pod.ref") == "sandbox_sc-shell-in-container-44c7e9", "falco pod ref")
check(shell and shell[0].get("@timestamp", "").startswith("2026-10-03T06:45:15.046"), f"falco @timestamp from the event time: {shell}")
check(shell and shell[0].get("falco.tags") == ["T1059", "container", "maturity_stable", "mitre_execution", "shell"], "falco tags array")

talon = only("talon")
check(len(talon) == 2, f"talon records: {len(talon)}")
check(sorted(r.get("talon.action_slug") for r in talon) == ["quarantine-pod", "terminate-pod"], "talon action slugs")
check(all(r.get("k8s.pod.ref", "").startswith("sandbox_sc-") for r in talon), "talon pod refs")

api = only("api")
siem_lines = sum(1 for line in open(f"{root}/tests/siem/fixtures/api.log") if '"msg":"siem.' in line)
check(len(api) == siem_lines + 1, f"api records {len(api)} != siem lines {siem_lines} + 1 extra")
check(all(r.get("event.action") in ("siem.run", "siem.command") for r in api), "api: only siem.run / siem.command")
queued = [r for r in api if r.get("api.state") == "queued"]
check(queued and all("k8s.pod.ref" not in r for r in queued), "api: an empty pod_ref is omitted")
forged = [r for r in api if r.get("api.run_id") == "ffffffffffffffff"]
check(forged and "k8s.pod.ref" not in forged[0], "api: a ref that is not <ns>_<pod> is dropped")
exited = [r for r in api if r.get("api.state") == "exited" and r.get("api.command_id") == "read-flag"]
check(exited and exited[0].get("api.exit_code") == 0 and exited[0].get("api.achieved") is True, f"api types: {exited}")
check(any(r.get("k8s.pod.ref") == "sandbox-unguarded_shell-in-container-a1b2c3d4e5-u" for r in api), "api: twin ref")

audit = only("k8s-audit")
resources = sorted((r.get("audit.verb"), r.get("audit.object.resource"), r.get("audit.object.subresource", "")) for r in audit)
check(resources == sorted([
    ("create", "pods", ""), ("create", "pods", "exec"), ("get", "pods", "exec"), ("patch", "pods", ""),
    ("delete", "pods", ""), ("create", "pods", ""), ("get", "secrets", ""),
]), f"F2 audit selection: {resources}")
create = [r for r in audit if r.get("audit.verb") == "create" and r.get("audit.response.code") == 201]
check(create and create[0].get("k8s.pod.ref") == "sandbox_terminal-3755e65530", "audit: the sandbox pod create is shipped")
check(create and create[0].get("user.name") == "system:serviceaccount:portfolio-api:portfolio-api", "audit: system: user kept")
denied = [r for r in audit if r.get("audit.response.code") == 400]
check(denied and denied[0].get("audit.dry_run") is True, "audit: dryRun of the kyverno denial")
person = [r for r in audit if r.get("audit.object.resource") == "secrets"]
check(person and person[0].get("user.name") == hm1("operator") and person[0].get("source.ip") == hm1("10.1.1.250"),
      f"audit: people and addresses pseudonymised: {person}")
check(person and "k8s.pod.ref" not in person[0] and "k8s.pod.name" not in person[0], "audit: no pod fields for a secret")
check(all(r.get("source.ip", "hm1:").startswith("hm1:") for r in audit), "audit: every source.ip pseudonymised")

hubble = only("hubble")
check(len(hubble) == 4, f"hubble: only flow records ({len(hubble)})")
dns = [r for r in hubble if r.get("dns.query")]
check(dns and all(r["dns.query"] == "sdp-0123456789abcdef.x.exfil.sdp.test.".replace("0123456789abcdef", "0123456789abcdef")
                  for r in dns), "hubble: dns.query lower-cased")
check(any(r.get("dns.rcode") == 3 for r in dns), "hubble: rcode")
drop = [r for r in hubble if r.get("hubble.verdict") == "DROPPED"]
check(drop and drop[0].get("hubble.drop_reason") == "POLICY_DENIED" and drop[0].get("hubble.l4.protocol") == "udp"
      and drop[0].get("hubble.l4.destination_port") == 53 and drop[0].get("k8s.pod.ref") == "sandbox_sc-network-tool-bf192d",
      f"hubble drop: {drop}")
ingress = [r for r in hubble if r.get("hubble.traffic_direction") == "INGRESS"]
check(ingress and ingress[0].get("k8s.pod.ref") == "sandbox-unguarded_shell-in-container-a1b2c3d4e5-u",
      "hubble: the sandbox side is the destination when the source is not in sandbox*")
check(all(r.get("hubble.is_reply") in (True, False) for r in hubble), "hubble: is_reply boolean")

host_all = only("host")
loss = [r for r in host_all if r.get("event.kind") == "metric"]
check(len(loss) == 1 and loss[0].get("host.log") == "fluent-bit" and loss[0].get("fluentbit.throttle_dropped") == 17
      and loss[0].get("fluentbit.output_dropped") == 4 and loss[0].get("fluentbit.output_errors") == 2
      and loss[0].get("fluentbit.filter_errors") == 0, f"host: the shipper's loss report {loss}")
host = [r for r in host_all if r.get("event.kind") != "metric"]
logs = sorted(r.get("host.log") for r in host)
check(logs == ["auditd", "auditd", "auditd", "nft", "ssh", "ssh", "ssh", "ssh", "ssh", "ssh", "sudo"], f"host records {logs}")
# Review L3: a user name carrying " from <ip> port <n>" does not choose the address.
spoof = [r for r in host if r.get("user.name") == hm1("a from 6.6.6.6 port 1")]
check(len(spoof) == 2 and all(r.get("source.ip") == hm1("10.1.1.250") for r in spoof), f"host: ssh address spoofed {spoof}")
ssh_op = [r for r in host if r.get("ssh.event") == "accepted" and r.get("user.name") == hm1("operator")]
check(ssh_op and ssh_op[0].get("source.ip") == hm1("10.1.1.250") and ssh_op[0].get("ssh.method") == "publickey",
      "host: the project pseudonyms equal Python's")
check(sorted(r.get("ssh.event") for r in host if r.get("host.log") == "ssh")
      == ["accepted", "accepted", "accepted", "closed-preauth", "invalid-user", "invalid-user"],
      "host: ssh events")
keys = sorted(r.get("audit.key") for r in host if r.get("host.log") == "auditd")
check(keys == ["identity", "k3s_config", "privileged"], f"host: audit keys {keys}")
nft = [r for r in host if r.get("host.log") == "nft"]
check(nft and nft[0].get("nft.protocol") == "udp" and nft[0].get("nft.destination_port") == 10001, "host: nft")
priv = [r for r in host if r.get("audit.key") == "privileged"]
check(priv and priv[0].get("audit.syscall") == "execve" and priv[0].get("process.exe") == "/usr/bin/sudo"
      and priv[0].get("user.effective") == hm1("root"), f"host: auditd parse {priv}")

siem = only("siem01")
logs = sorted(r.get("host.log") for r in siem)
check(logs == ["auditd", "auditd", "auditd", "nft", "opensearch-audit", "opensearch-audit", "opensearch-audit", "ssh",
               "ssh", "ssh", "sudo"], f"siem01 records {logs}")
cats = sorted(r.get("opensearch.audit.category") for r in siem if r.get("host.log") == "opensearch-audit")
check(cats == ["INDEX_EVENT", "MISSING_PRIVILEGES", "SSL_EXCEPTION"], f"siem01 audit categories {cats}")
missing = [r for r in siem if r.get("opensearch.audit.category") == "MISSING_PRIVILEGES"]
check(missing and missing[0].get("opensearch.audit.user") == "dashboards-g1"
      and missing[0].get("opensearch.audit.indices") == ["sdp-falco"] and missing[0].get("source.ip") == hm1("127.0.0.1"),
      f"siem01 audit fields {missing}")

# --- golden: the whole output, heartbeats aside, order-free ----------------------------------------
def stable(r):
    # The loss report carries no event time of its own (it is stamped when read), so its time is
    # left out of the comparison.
    if flatten(r).get("host.log") == "fluent-bit":
        r = {k: v for k, v in r.items() if k != "@timestamp"}
    return json.dumps(r, sort_keys=True)


canon = sorted(stable(r) for r in records if flatten(r).get("event.kind") != "heartbeat")
if write:
    open(expected_path, "w").write("\n".join(canon) + "\n")
    print(f"lua_check: wrote {expected_path} ({len(canon)} records)")
else:
    expected = [line.rstrip("\n") for line in open(expected_path) if line.strip()]
    missing_lines = sorted(set(expected) - set(canon))
    new_lines = sorted(set(canon) - set(expected))
    check(not missing_lines and not new_lines and len(expected) == len(canon),
          "output differs from the expected file:\n  missing: " + "\n  missing: ".join(missing_lines)
          + "\n  new: " + "\n  new: ".join(new_lines))

if failures:
    print("lua-hmac: FAIL")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print(f"lua-hmac: ok - {len(records)} records from {len(by_dataset)} sources, HMAC vectors equal Python's, "
      "allow-lists, F1/F2/F3/F13 hold")
