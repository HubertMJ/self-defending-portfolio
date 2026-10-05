#!/usr/bin/env python3
"""Synthetic canary documents for the siem/ tree, and the check that each one yields its finding or
alert (siem contract P3; canaries.yaml kind "synthetic").

The documents look exactly like what sdp.lua ships (shapes of tests/siem/expected/lua-output.jsonl),
written the way Fluent Bit writes them (bulk create, no id) with a shipper identity. Every document
carries a marker of this pass - a pod ref sandbox_p3c-<tag>-<name> or a host pseudonym hm1:<hex> - so
findings of other passes and of real traffic are never mistaken for these. Negative documents must
NOT produce a finding (an exec by the API, DNS names that only look like the flag label).

Used offline by tests/siem/sync-it.sh against a throwaway OpenSearch, and live on siem01 by
tests/siem/p3-acceptance.sh (copied there; it runs with the node's admin certificate for reads and
the temporary shipper-test identity for writes). Only python3 and the standard library.

Usage: canary_docs.py --url U --ca CA --admin CERT KEY --writer CERT KEY --index index.json
                      [--streams sdp-a,sdp-b] [--timeout 240] [--tag T]
  index.json is `siem_lint.py --index siem`. Without --streams every stream is written; a rule or
  monitor whose documents go to a stream not written is reported as skipped, not passed.
"""
import argparse
import datetime
import hashlib
import json
import ssl
import sys
import time
import urllib.error
import urllib.request

TERMINAL = {  # catalogue command -> (technique, objective, outcome) as in scenarios.yaml
    "whoami": ("T1033", "recon", "allowed"), "hostname": ("T1082", "recon", "allowed"),
    "ps": ("T1057", "recon", "allowed"), "ls-shop": ("T1083", "recon", "allowed"),
    "read-flag": ("T1552.001", "credentials", "allowed"), "read-shadow": ("T1003.008", "credentials", "detected"),
    "beacon": ("T1071.001", "exfiltration", "detected"), "dns-exfil": ("T1048.003", "exfiltration", "allowed"),
    "shell": ("T1059.004", "execution", "detected"), "drop-run": ("T1105", "execution", "detected"),
    "touch-bin": ("T1543", "", "prevented"),
}
FALCO = {  # slug -> (rule name, priority)
    "terminal-shell-in-container": ("Terminal shell in container", "Notice"),
    "read-sensitive-file-untrusted": ("Read sensitive file untrusted", "Warning"),
    "sdp-network-tool-in-sandbox": ("SDP network tool in sandbox", "Warning"),
    "drop-and-execute-new-binary-in-container": ("Drop and execute new binary in container", "Critical"),
    "sdp-execution-from-shop-volume": ("SDP execution from shop volume", "Critical"),
}


def build(tag, now):
    """(documents [(stream, doc)], expectations). Markers are pod refs or host pseudonyms."""
    ts = lambda off=0.0: (now + datetime.timedelta(seconds=off)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"  # noqa: E731
    pod = lambda name: f"p3c-{tag}-{name}"  # noqa: E731
    ref = lambda name: f"sandbox_{pod(name)}"  # noqa: E731
    hm = lambda name: "hm1:" + hashlib.sha256(f"{tag}-{name}".encode()).hexdigest()[:16]  # noqa: E731
    docs = []

    def k8s(name, ns="sandbox"):
        return {"ns": {"name": ns}, "pod": {"name": pod(name), "ref": f"{ns}_{pod(name)}"}}

    def api(name, cmd, off=0.0):
        tech, obj, outcome = TERMINAL[cmd]
        d = {"@timestamp": ts(off), "event": {"kind": "event", "dataset": "api", "action": "siem.command"},
             "api": {"run_id": hashlib.sha256(tag.encode()).hexdigest()[:16], "seq": 1, "command_id": cmd,
                     "state": "started", "achieved": False, "technique": tech, "outcome": outcome},
             "k8s": {"pod": {"ref": ref(name)}}}
        if obj:
            d["api"]["objective"] = obj
        docs.append(("sdp-api", d))

    def falco(name, slug, off=0.0):
        rule, prio = FALCO[slug]
        docs.append(("sdp-falco", {"@timestamp": ts(off), "event": {"kind": "alert", "dataset": "falco"},
                                   "falco": {"rule": rule, "rule_slug": slug, "priority": prio,
                                             "priority_slug": prio.lower(), "source": "syscall"},
                                   "k8s": k8s(name), "container": {"name": "target"}, "user": {"name": "scenario"}}))

    def talon(name, action, actionner, off=0.0):
        docs.append(("sdp-talon", {"@timestamp": ts(off), "event": {"kind": "action", "dataset": "talon"},
                                   "talon": {"action": action, "action_slug": action.lower().replace(" ", "-"),
                                             "actionner": actionner, "status": "success", "rule": "canary",
                                             "rule_slug": "canary"}, "k8s": k8s(name)}))

    def hubble(name, verdict, off=0.0, drop=None, query=None):
        h = {"verdict": verdict, "event_type": 1 if drop else 129, "source": {"namespace": "sandbox", "pod_name": pod(name)},
             "traffic_direction": "EGRESS", "is_reply": False, "l4": {"protocol": "udp", "destination_port": 53}}
        d = {"@timestamp": ts(off), "event": {"kind": "flow", "dataset": "hubble"}, "k8s": k8s(name), "hubble": h}
        if drop:
            h["drop_reason"] = drop
        if query:
            h["l7"] = {"type": "REQUEST"}
            d["dns"] = {"query": query}
        docs.append(("sdp-hubble", d))

    def audit(name, verb, resource, code, user, sub=None, off=0.0, ns="sandbox"):
        d = {"@timestamp": ts(off), "event": {"kind": "event", "dataset": "k8s-audit"},
             "audit": {"verb": verb, "stage": "ResponseComplete", "level": "Metadata", "dry_run": False,
                       "object": {"resource": resource, "name": pod(name)}, "response": {"code": code}},
             "k8s": k8s(name, ns), "user": {"name": user}, "source": {"ip": hm("audit")}}
        if sub:
            d["audit"]["object"]["subresource"] = sub
        if code >= 400:
            d["audit"]["response"]["status"] = "Failure"
        docs.append(("sdp-k8s-audit", d))

    def ssh(stream, name, event):
        d = {"@timestamp": ts(), "event": {"kind": "event", "dataset": stream[len("sdp-"):]}, "host": {"log": "ssh"},
             "ssh": {"event": event}, "user": {"name": hm("user")}, "source": {"ip": hm(name)}}
        if event == "accepted":
            d["ssh"]["method"] = "publickey"
        docs.append((stream, d))

    # The terminal: one pod per command, Falco (and Talon) answering what the catalogue says is detected.
    for cmd in ("whoami", "hostname", "ps", "ls-shop", "read-flag"):
        api(cmd, cmd)
    api("shadow", "read-shadow")
    falco("shadow", "read-sensitive-file-untrusted", 0.3)
    api("shell", "shell")
    falco("shell", "terminal-shell-in-container", 0.3)
    talon("shell", "Terminate Pod", "kubernetes:terminate", 0.5)
    api("beacon", "beacon")
    falco("beacon", "sdp-network-tool-in-sandbox", 0.3)
    talon("beacon", "Quarantine Pod", "kubernetes:label", 0.5)
    hubble("beacon", "DROPPED", 2.0, drop="POLICY_DENY")
    api("droprun", "drop-run")
    falco("droprun", "sdp-execution-from-shop-volume", 0.3)
    falco("dropexec", "drop-and-execute-new-binary-in-container")
    api("dnsexfil", "dns-exfil")
    hubble("dnsexfil", "FORWARDED", 0.5, query="sdp-0123456789abcdef.x.exfil.sdp.test.")
    # Look-alikes the DNS rule must not match (S0-k: full match).
    hubble("dnsneg1", "FORWARDED", query="evil-sdp-0123456789abcdef.x.exfil.sdp.test.")
    hubble("dnsneg2", "FORWARDED", query="sdp-0123456789abcdef.x.exfil.sdp.test.evil.com.")
    # Prevented, and a detected command Falco never answered.
    api("pnd", "touch-bin")
    api("dm", "read-shadow")
    # Kubernetes: exec by the operator (fires) and by the API (must not); three refused pod creates by
    # one principal, then an allowed one (the probing monitor).
    audit("exec", "get", "pods", 101, "system:admin", sub="exec")
    audit("execapi", "create", "pods", 101, "system:serviceaccount:portfolio-api:portfolio-api", sub="exec")
    prober = f"system:p3c-{tag}"
    for i in (1, 2, 3):
        audit(f"deny{i}", "create", "pods", 400, prober, off=-40 + 10 * i)
    audit("allow", "create", "pods", 201, prober)
    # Allowed before the last refusal: not probing that succeeded (the monitor wants success after it).
    early = f"system:p3c-{tag}-early"
    for name, code, off in (("early1", 400, -45), ("early2", 400, -35), ("earlyok", 201, -25), ("early3", 400, -15)):
        audit(name, "create", "pods", code, early, off=off)
    for stream in ("sdp-host", "sdp-siem01"):
        ssh(stream, f"{stream}-accepted", "accepted")
        ssh(stream, f"{stream}-refused", "invalid-user")

    expect = {
        "rules": {
            "api-recon-user": [ref("whoami")], "api-recon-system": [ref("hostname")], "api-recon-process": [ref("ps")],
            "api-recon-files": [ref("ls-shop")], "api-credentials-flag": [ref("read-flag")],
            "api-credentials-shadow": [ref("shadow"), ref("dm")], "api-exfil-web": [ref("beacon")],
            "api-exfil-dns": [ref("dnsexfil")], "api-exec-shell": [ref("shell")], "api-exec-dropped-binary": [ref("droprun")],
            "falco-terminal-shell": [ref("shell")], "falco-sensitive-file": [ref("shadow")],
            "falco-network-tool": [ref("beacon")], "falco-drop-and-execute": [ref("dropexec")],
            "falco-shop-volume-exec": [ref("droprun")], "talon-terminate": [ref("shell")],
            "talon-quarantine": [ref("beacon")], "hubble-sandbox-policy-drop": [ref("beacon")],
            "hubble-dns-exfil": [ref("dnsexfil")], "k8s-exec-outside-api": [ref("exec")],
            "k8s-admission-denied": [ref("deny1"), ref("deny2"), ref("deny3"), ref("early1")],
            "host-ssh-accepted": [hm("sdp-host-accepted")], "host-ssh-failed": [hm("sdp-host-refused")],
            "siem-host-ssh-accepted": [hm("sdp-siem01-accepted")], "siem-host-ssh-failed": [hm("sdp-siem01-refused")],
        },
        "not": {"hubble-dns-exfil": [ref("dnsneg1"), ref("dnsneg2")], "k8s-exec-outside-api": [ref("execapi")]},
        "correlations": {"contained-intrusion": [ref("shell"), ref("beacon")], "dns-exfil": [ref("dnsexfil")]},
        "monitors": {
            "sdp-git: policy-probing": ([prober], [early]),
            "sdp-git: prevented-not-detected": ([ref("pnd")], []),
            "sdp-git: detection-missing": ([ref("dm")], [ref("shadow"), ref("shell"), ref("beacon"), ref("droprun")]),
        },
        "marker_prefix": (f"sandbox_p3c-{tag}-", prober),
    }
    return docs, expect


def marker(doc):
    return ((doc.get("k8s") or {}).get("pod") or {}).get("ref") or (doc.get("source") or {}).get("ip")


class Client:
    def __init__(self, url, ca, cert, key):
        self.url = url.rstrip("/")
        self.ctx = ssl.create_default_context(cafile=ca)
        self.ctx.load_cert_chain(cert, key)

    def req(self, method, path, body=None, ctype="application/json"):
        data = None if body is None else (body if isinstance(body, str) else json.dumps(body)).encode()
        r = urllib.request.Request(self.url + path, data=data, method=method, headers={"Content-Type": ctype})
        try:
            with urllib.request.urlopen(r, context=self.ctx, timeout=60) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            return exc.code, {"error": exc.read().decode(errors="replace")[:300]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--ca", required=True)
    ap.add_argument("--admin", nargs=2, required=True)
    ap.add_argument("--writer", nargs=2, required=True)
    ap.add_argument("--index", required=True)
    ap.add_argument("--streams", default="")
    ap.add_argument("--timeout", type=int, default=240)
    ap.add_argument("--tag", default=datetime.datetime.now(datetime.timezone.utc).strftime("%H%M%S"))
    a = ap.parse_args()
    with open(a.index, encoding="utf-8") as fh:
        idx = json.load(fh)
    rules = {r["file"].rsplit("/", 1)[1][: -len(".yml")]: r for r in idx["rules"]}
    admin, writer = Client(a.url, a.ca, *a.admin), Client(a.url, a.ca, *a.writer)
    start = datetime.datetime.now(datetime.timezone.utc)
    docs, expect = build(a.tag, start)
    streams = set(a.streams.split(",")) if a.streams else {s for s, _ in docs}
    fails, skipped = [], []
    print(f"canaries: tag {a.tag}, {len(docs)} documents, writing to {', '.join(sorted(streams))}")

    # Write like Fluent Bit: one bulk create per stream, no _id (sdp-final refuses a client id).
    for stream in sorted({s for s, _ in docs} & streams):
        lines = "".join('{"create":{}}\n' + json.dumps(d) + "\n" for s, d in docs if s == stream)
        code, out = writer.req("POST", f"/{stream}/_bulk", lines, "application/x-ndjson")
        bad = [i for i in out.get("items", []) if list(i.values())[0].get("status") != 201]
        if code != 200 or bad or out.get("errors"):
            fails.append(f"write {stream}: {code} {json.dumps(bad or out)[:300]}")
    written = {marker(d) for s, d in docs if s in streams}
    if "sdp-k8s-audit" in streams:
        written.add(expect["marker_prefix"][1])  # the probing principal, the policy-probing bucket key

    # Sigma id -> SA id, from SA's stored rules.
    code, out = admin.req("POST", "/_plugins/_security_analytics/rules/_search?pre_packaged=false",
                          {"size": 1000, "query": {"match_all": {}}})
    sa_of = {}
    for h in out.get("hits", {}).get("hits", []):
        for line in (h["_source"].get("rule") or "").split("\n"):
            if line.startswith("id: "):
                sa_of.setdefault(line[4:].strip(), set()).add(h["_id"])

    def findings():
        """{(sa rule id, marker)} and {finding id: marker} for this pass's markers."""
        hits, by_id = set(), {}
        for lt in sorted({r["log_type"] for r in idx["rules"]}):
            since = int((start - datetime.timedelta(minutes=2)).timestamp() * 1000)
            code, out = admin.req("GET", f"/_plugins/_security_analytics/findings/_search?detectorType={lt}"
                                         f"&startTime={since}&endTime={int(time.time() * 1000) + 60000}&size=1000")
            for f in out.get("findings", []) if code == 200 else []:
                for d in f.get("document_list", []):
                    try:
                        m = marker(json.loads(d.get("document") or "{}"))
                    except ValueError:
                        continue
                    if m in written:
                        by_id[f["id"]] = m
                        for q in f.get("queries", []):
                            hits.add((q["id"], m))
        return hits, by_id

    def rule_state(hits):
        missing, unexpected = [], []
        for slug, markers in expect["rules"].items():
            r = rules.get(slug)
            if r is None:
                fails.append(f"rule {slug}: not in the index")
                continue
            for m in markers:
                if m not in written:
                    continue
                if not any((sa, m) in hits for sa in sa_of.get(r["id"], ())):
                    missing.append(f"{slug} <- {m}")
        for slug, markers in expect["not"].items():
            for m in markers:
                if any((sa, m) in hits for sa in sa_of.get(rules[slug]["id"], ())):
                    unexpected.append(f"{slug} <- {m}")
        return missing, unexpected

    def monitor_state():
        out_missing, out_unexpected = [], []
        for name, (want, forbid) in expect["monitors"].items():
            code, out = admin.req("POST", "/_plugins/_alerting/monitors/_search",
                                  {"size": 5, "query": {"term": {"monitor.name.keyword": name}}})
            hits = out.get("hits", {}).get("hits", [])
            if len(hits) != 1:
                out_missing.append(f"{name}: {len(hits)} monitors with that name")
                continue
            code, alerts = admin.req("GET", f"/_plugins/_alerting/monitors/alerts?monitorId={hits[0]['_id']}&size=500")
            keys = {k for al in alerts.get("alerts", []) if al.get("state") in ("ACTIVE", "ACKNOWLEDGED", "COMPLETED")
                    for k in (al.get("agg_alert_content") or {}).get("bucket_keys", [])}
            for k in want:
                if k not in keys and k in written:
                    out_missing.append(f"{name} <- {k}")
            out_unexpected += [f"{name} <- {k}" for k in forbid if k in keys]
        return out_missing, out_unexpected

    def correlation_state(by_id):
        since = int((start - datetime.timedelta(minutes=2)).timestamp() * 1000)
        code, out = admin.req("GET", f"/_plugins/_security_analytics/correlations?start_timestamp={since}"
                                     f"&end_timestamp={int(time.time() * 1000) + 60000}")
        pairs = set()
        for c in out.get("findings", []) if code == 200 else []:
            m1, m2 = by_id.get(c.get("finding1")), by_id.get(c.get("finding2"))
            if m1 and m1 == m2:
                pairs.add(m1)
        return [f"{name} <- {m}" for name, ms in expect["correlations"].items() for m in ms
                if m in written and m not in pairs]

    deadline = time.time() + a.timeout
    while True:
        hits, by_id = findings()
        r_missing, r_unexpected = rule_state(hits)
        m_missing, m_unexpected = monitor_state()
        c_missing = correlation_state(by_id)
        if not (r_missing or m_missing or c_missing) or time.time() > deadline:
            break
        time.sleep(15)
    took = int((datetime.datetime.now(datetime.timezone.utc) - start).total_seconds())
    for slug, markers in expect["rules"].items():
        if not any(m in written for m in markers):
            skipped.append(f"rule {slug} (its stream is not written here)")
    fails += [f"rule finding missing: {x}" for x in r_missing] + [f"finding that must not exist: {x}" for x in r_unexpected]
    fails += [f"monitor alert missing: {x}" for x in m_missing] + [f"monitor alert that must not exist: {x}" for x in m_unexpected]
    # SA correlations are evidence, not guaranteed (S0-e: 13 of 14 pairs; F17): reported, not failed.
    for x in c_missing:
        print(f"note correlation not recorded by SA (S0-e, F17): {x}")
    checked = sum(1 for ms in expect["rules"].values() if any(m in written for m in ms))
    print(f"canaries: {checked} rules, {len(expect['monitors'])} monitors, {len(expect['correlations'])} correlations "
          f"checked in {took} s; {len(fails)} failed, {len(skipped)} skipped")
    for s in skipped:
        print(f"skip {s}")
    for f in fails:
        print(f"FAIL {f}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
