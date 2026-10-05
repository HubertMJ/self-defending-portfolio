#!/usr/bin/env python3
"""Checks the documents tests/siem/ingest-it.sh found in the throwaway OpenSearch.

Usage: ingest_check.py <work dir with docs-<source>.json> <repository root>
"""
import json
import re
import sys

import yaml

work, root = sys.argv[1], sys.argv[2]
failures = []


def check(cond, message):
    if not cond:
        failures.append(message)


def flatten(doc, prefix=""):
    out = {}
    for k, v in doc.items():
        if isinstance(v, dict):
            out.update(flatten(v, f"{prefix}{k}."))
        else:
            out[f"{prefix}{k}"] = v
    return out


api_lines = sum(1 for line in open(f"{root}/tests/siem/fixtures/api.log") if '"msg":"siem.' in line)
expected = {"falco": 4, "talon": 2, "api": api_lines, "k8s-audit": 6, "hubble": 4, "host": 6}
forbidden = ["SDP{", "requestObject", "responseObject", "token", "10.1.1.250", "k3s01", "operator", "\"hostname\"",
             "node_name", "lost_events", "\"IP\""]
total = 0
for source, want in expected.items():
    spec = yaml.safe_load(open(f"{root}/siem/fields/{source}.yaml"))
    allow = set(spec["fields"]) | {"event.kind", "event.dataset", "event.ingested", "event.overwrite"}
    hits = json.load(open(f"{work}/docs-{source}.json"))["hits"]["hits"]
    docs = [flatten(h["_source"]) for h in hits]
    events = [d for d in docs if d.get("event.kind") != "heartbeat" and d.get("host.log") != "fluent-bit"]
    beats = [d for d in docs if d.get("event.kind") == "heartbeat"]
    total += len(events)
    check(len(events) == want, f"sdp-{source}: {len(events)} documents, expected {want}")
    check(len(beats) >= 1, f"sdp-{source}: no heartbeat")
    for d in docs:
        extra = set(d) - allow
        check(not extra, f"sdp-{source}: keys outside the allow-list {sorted(extra)}")
        # F1: the pipeline stamped every write, and none carried a client id.
        check(d.get("event.overwrite") is False, f"sdp-{source}: event.overwrite {d.get('event.overwrite')}")
        check(isinstance(d.get("event.ingested"), str), f"sdp-{source}: no event.ingested")
        check(d.get("event.dataset") == spec["fields"]["event.dataset"]["value"], f"sdp-{source}: dataset {d.get('event.dataset')}")
        if source == "host":
            for k in ("user.name", "user.effective", "source.ip"):
                if k in d:
                    check(d[k] == "unset" or re.fullmatch(r"hm1:[0-9a-f]{16}", d[k]), f"sdp-host: {k}={d[k]}")
    text = json.dumps([h["_source"] for h in hits])
    for needle in forbidden:
        check(needle not in text, f"sdp-{source}: contains {needle!r}")

host = [flatten(h["_source"]) for h in json.load(open(f"{work}/docs-host.json"))["hits"]["hits"]]
loss = [d for d in host if d.get("event.kind") == "metric"]
check(loss and all(d.get("host.log") == "fluent-bit" and d.get("fluentbit.throttle_dropped") == 0
                   and d.get("fluentbit.output_dropped") == 0 and d.get("fluentbit.filter_errors") == 0 for d in loss),
      f"sdp-host: the shipper's loss reports {loss}")
host = [d for d in host if d.get("event.kind") != "metric"]
check(sorted(d.get("host.log") for d in host if d.get("event.kind") not in ("heartbeat", "metric"))
      == ["auditd", "auditd", "auditd", "ssh", "ssh", "sudo"], "sdp-host: journald (ssh as sshd-session, sudo) and auditd")
audit = [flatten(h["_source"]) for h in json.load(open(f"{work}/docs-k8s-audit.json"))["hits"]["hits"]]
check(not any(d.get("audit.object.resource") in ("tokenreviews", "subjectaccessreviews") for d in audit),
      "sdp-k8s-audit: a review was shipped (F2)")

if failures:
    print("ingest_check: FAIL")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print(f"ingest_check: ok - {total} documents in six streams plus heartbeats, all within their allow-lists, "
      "event.overwrite false and event.ingested set by sdp-final, nothing that must not leave k3s01")
