#!/usr/bin/env python3
"""Reads (and, for the tests, disturbs) what the rules sync manages, with the admin certificate.
Helper of tests/siem/sync-it.sh (offline) and tests/siem/p3-acceptance.sh (siem01).

Usage: sync_check.py <url> <ca> <admin cert> <admin key> <command> [args]
  snapshot              JSON: custom log types, rules by Sigma id, detectors, correlations, monitors, workflows
  records               JSON: the siem-sync records, newest first
  heartbeat             JSON: the sync's heartbeat document
  guard                 L5 / F11: every sdp-* template keeps its data stream, pattern [<stream>] and no
                        component, and no SA alias-mappings component exists; exit 1 otherwise
  delete-rule <sigma>   delete the SA rule(s) with that Sigma id behind the sync's back (S0-#12 test)
  rule-exists <sa id>   exit 0 when SA has a rule with that id
  findings <since ms>   JSON: per Sigma id the findings since then, per monitor name the alerts started
                        since then, and the number of SA correlations since then (tests/siem/canaries.sh)
  oob-create            objects the sync must never touch (MJ5): an unprefixed monitor, and a detector
                        with its own rule on a log type the tree does not define
  oob-check             exit 0 when those are all still there
"""
import json
import ssl
import sys
import urllib.error
import urllib.request

SA = "/_plugins/_security_analytics"
OOB_MONITOR = "ops canary (not managed by the sync)"
OOB_DETECTOR = "oob-detector"
OOB_RULE = """title: Out-of-band rule (not in git)
id: 0b0b0b0b-0000-4000-8000-000000000001
status: experimental
level: low
description: made by hand, must survive every sync
author: test
date: 2026/10/04
logsource:
  product: sdp
  service: siem01
detection:
  selection:
    host.log: sudo
  condition: selection
"""


class Client:
    def __init__(self, url, ca, cert, key):
        self.url = url.rstrip("/")
        self.ctx = ssl.create_default_context(cafile=ca)
        self.ctx.load_cert_chain(cert, key)

    def req(self, method, path, body=None):
        data = None if body is None else (body if isinstance(body, str) else json.dumps(body)).encode()
        r = urllib.request.Request(self.url + path, data=data, method=method, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(r, context=self.ctx, timeout=60) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            text = exc.read().decode(errors="replace")
            try:
                return exc.code, json.loads(text)
            except ValueError:
                return exc.code, {"error": text}

    def hits(self, path, query=None, size=1000):
        code, out = self.req("POST", path, {"size": size, "query": query or {"match_all": {}}})
        return out.get("hits", {}).get("hits", []) if code == 200 else []


def sigma_id(text):
    for line in (text or "").split("\n"):
        if line.startswith("id: "):
            return line[4:].strip()
    return None


def snapshot(c):
    rules, text = {}, {}
    for h in c.hits(f"{SA}/rules/_search?pre_packaged=false"):
        sid = sigma_id(h["_source"].get("rule"))
        rules.setdefault(sid, []).append(h["_id"])
        text[sid] = h["_source"].get("rule")
    detectors = {}
    for h in c.hits(f"{SA}/detectors/_search"):
        s = h["_source"]
        di = s["inputs"][0]["detector_input"]
        detectors[s["name"]] = {"id": h["_id"], "rules": sorted(r["id"] for r in di["custom_rules"]),
                                "description": di.get("description"), "last_update_time": s.get("last_update_time")}
    monitors, workflows = {}, 0
    for h in c.hits("/_plugins/_alerting/monitors/_search"):
        s = h["_source"]
        if s.get("type") == "workflow":
            workflows += 1
        else:
            monitors[s["name"]] = {"id": h["_id"], "last_update_time": s.get("last_update_time"), "enabled": s.get("enabled")}
    return {
        "log_types": sorted(h["_source"]["name"] for h in c.hits(f"{SA}/logtype/_search") if h["_source"].get("source") == "Custom"),
        "rules": rules, "rule_text": text, "detectors": detectors,
        "correlations": sorted(h["_source"]["name"] for h in c.hits(f"{SA}/correlation/rules/_search")),
        "monitors": monitors, "workflows": workflows,
    }


def guard(c):
    code, out = c.req("GET", "/_index_template/sdp-*")
    bad = []
    templates = out.get("index_templates", []) if code == 200 else []
    for t in templates:
        it = t["index_template"]
        if it.get("index_patterns") != [t["name"]] or it.get("composed_of", []) != [] or "data_stream" not in it:
            bad.append(f"template {t['name']}: patterns {it.get('index_patterns')}, composed_of {it.get('composed_of')}")
    code, out = c.req("GET", "/_component_template/.opensearch-sap-alias-mappings-component-*")
    comps = out.get("component_templates", []) if code == 200 else []
    bad += [f"component {x['name']} exists" for x in comps]
    if len(templates) < 7:
        bad.append(f"only {len(templates)} sdp-* templates")
    for b in bad:
        print(f"FAIL {b}")
    print(f"guard: {len(templates)} templates, {len(comps)} SA alias components")
    return 1 if bad else 0


def main():
    url, ca, cert, key, cmd, *args = sys.argv[1:]
    c = Client(url, ca, cert, key)
    if cmd == "snapshot":
        print(json.dumps(snapshot(c), sort_keys=True))
    elif cmd == "records":
        code, out = c.req("POST", "/siem-sync/_search", {"size": 100, "sort": [{"applied_at": {"order": "desc"}}]})
        hits = out.get("hits", {}).get("hits", []) if code == 200 else []
        print(json.dumps([h["_source"] for h in hits if "status" in h["_source"]]))
    elif cmd == "heartbeat":
        code, out = c.req("GET", "/siem-sync/_doc/heartbeat")
        print(json.dumps(out.get("_source", {}), sort_keys=True))
    elif cmd == "guard":
        return guard(c)
    elif cmd == "delete-rule":
        for sa in snapshot(c)["rules"].get(args[0], []):
            code, out = c.req("DELETE", f"{SA}/rules/{sa}?forced=true")
            print(f"deleted {sa}: {code}")
    elif cmd == "rule-exists":
        return 0 if c.hits(f"{SA}/rules/_search?pre_packaged=false", {"ids": {"values": [args[0]]}}) else 1
    elif cmd == "findings":
        since = int(args[0])
        snap = snapshot(c)
        sigma_of = {sa: sid for sid, sas in snap["rules"].items() for sa in sas}
        out = {"rules": {}, "monitors": {}, "correlations": 0}
        types = {h["_source"]["detector_type"] for h in c.hits(f"{SA}/detectors/_search")}
        for lt in sorted(types):
            code, res = c.req("GET", f"{SA}/findings/_search?detectorType={lt}&startTime={since}"
                                     f"&endTime=9999999999999&size=10000")
            for f in res.get("findings", []) if code == 200 else []:
                for q in f.get("queries", []):
                    sid = sigma_of.get(q["id"])
                    if sid:
                        out["rules"][sid] = out["rules"].get(sid, 0) + 1
        for name, m in snap["monitors"].items():
            code, res = c.req("GET", f"/_plugins/_alerting/monitors/alerts?monitorId={m['id']}&size=500")
            n = sum(1 for a in res.get("alerts", []) if (a.get("start_time") or 0) >= since)
            if n:
                out["monitors"][name] = n
        code, res = c.req("GET", f"{SA}/correlations?start_timestamp={since}&end_timestamp=9999999999999")
        out["correlations"] = len(res.get("findings", [])) if code == 200 else 0
        print(json.dumps(out, sort_keys=True))
    elif cmd == "oob-create":
        code, out = c.req("POST", "/_plugins/_alerting/monitors", {
            "type": "monitor", "monitor_type": "query_level_monitor", "name": OOB_MONITOR, "enabled": False,
            "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
            "inputs": [{"search": {"indices": ["sdp-siem01"], "query": {"size": 0, "query": {"match_all": {}}}}}],
            "triggers": []})
        assert code == 201, out
        code, out = c.req("POST", f"{SA}/rules?category=others_application", OOB_RULE)
        assert code == 201, out
        code, out = c.req("POST", f"{SA}/detectors", {
            "type": "detector", "name": OOB_DETECTOR, "detector_type": "others_application", "enabled": True,
            "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
            "inputs": [{"detector_input": {"description": "made by hand", "indices": ["sdp-siem01"],
                                           "custom_rules": [{"id": out["_id"]}], "pre_packaged_rules": []}}],
            "triggers": []})
        assert code == 201, out
        print("out-of-band monitor, rule and detector created")
    elif cmd == "oob-check":
        s = snapshot(c)
        missing = [x for x, ok in ((OOB_MONITOR, OOB_MONITOR in s["monitors"]), (OOB_DETECTOR, OOB_DETECTOR in s["detectors"]),
                                   ("rule 0b0b0b0b", "0b0b0b0b-0000-4000-8000-000000000001" in s["rules"]),
                                   ("the detector's workflow", s["workflows"] >= 1)) if not ok]
        print("out-of-band objects: " + ("all there" if not missing else "MISSING " + ", ".join(missing)))
        return 1 if missing else 0
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
