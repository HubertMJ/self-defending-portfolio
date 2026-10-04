#!/usr/bin/env python3
"""The rules sync on siem01 (ADR 0034 "Rules from git", siem contract P3).

Run by sdp-siem-sync.service (timer, every 5 minutes) as the system user sdp-sync with the rules-sync
client certificate. One run:

  1. fetch the branch (main) of the repository into a local bare repository;
  2. fast-forward only: the fetched commit must descend from the last applied one, read from the
     siem-sync index - unless /etc/sdp-siem/accept-commit names it (or an ancestor of it), the
     operator's acceptance of a new base after a force-push (M15); first run: the fetched commit is
     the baseline;
  3. read siem/ of that commit as data (blobs written to a scratch directory, never executed, never
     imported) and lint it with siem_lint.py;
  4. diff against the MANAGED set only (B6): the objects in the tree of the last applied commit (and
     of failed attempts since, so an object a failed run created is not orphaned) plus every Alerting
     monitor named "sdp-git: *". SA's own detector workflows, the host role's ops monitors and
     anything made in Dashboards are never touched (MJ5);
  5. refuse more than DELETE_CAP deletions unless /etc/sdp-siem/allow-mass-delete exists;
  6. apply: log types -> rules -> detectors -> correlations -> monitors, then the deletions in the
     reverse order; record {commit, applied_at, status, reason, counts, rules} in siem-sync.

Security Analytics quirks this program is written around (S0 spike):
  - SA ignores the Sigma id: the Sigma id -> SA id map is rebuilt from SA's stored rule YAML on every
    run, and a rule is updated (PUT rules/<id>) only with an id read back from SA in this very run -
    SA creates a rule when the id is unknown (S0-#12);
  - SA accepts a detector listing rule ids it does not have: every id is read back right before the
    detector is written (S0-#12);
  - every request carries Content-Type: application/json, the raw Sigma YAML too (S0-f);
  - the SA mappings API rewrites our index templates (F11): this client refuses to call it.

Exit status: 0 applied or nothing to do, 1 failed (recorded), 2 refused (recorded, nothing changed).
The record of a refusal or failure is not repeated while the commit and the reason stay the same.
"""
import datetime
import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import siem_lint  # noqa: E402  (installed next to this program by the siem_sync role)

SA = "/_plugins/_security_analytics"
ALERTING = "/_plugins/_alerting"
RECORD_INDEX = "siem-sync"
PREFIX = siem_lint.MONITOR_PREFIX
HEX40 = re.compile(r"^[0-9a-f]{40}$")
MAX_FILE = 1 << 20
MAX_TREE = 8 << 20
TRIGGER_NAME = "any finding"
RECORD_MAPPING = {
    "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
    "mappings": {"dynamic": False, "properties": {
        "commit": {"type": "keyword"}, "applied_at": {"type": "date"}, "status": {"type": "keyword"},
        "reason": {"type": "keyword", "ignore_above": 2048}, "branch": {"type": "keyword"},
        "previous": {"type": "keyword"}, "counts": {"type": "object", "enabled": False},
        "rules": {"type": "object", "enabled": False}, "monitors": {"type": "object", "enabled": False},
    }},
}
KINDS = ("log_types", "rules", "detectors", "correlations", "monitors")


class SyncError(Exception):
    pass


class Refused(Exception):
    pass


def log(msg):
    print(msg, flush=True)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Client:
    """OpenSearch over mTLS with the rules-sync certificate."""

    def __init__(self, url, ca, cert, key, timeout=60):
        self.url = url.rstrip("/")
        self.ctx = ssl.create_default_context(cafile=ca)
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.ctx.load_cert_chain(cert, key)
        self.timeout = timeout

    def req(self, method, path, body=None, ok=(200, 201)):
        if "/_security_analytics/mappings" in path:
            # F11: SA's mappings API appends "<stream>*" and its own component to our templates.
            raise SyncError(f"refusing to call the SA mappings API: {method} {path}")
        data = None
        if body is not None:
            data = (body if isinstance(body, str) else json.dumps(body)).encode()
        # S0-f: application/json for everything, the raw Sigma YAML of a rule upload included.
        request = urllib.request.Request(self.url + path, data=data, method=method,
                                         headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, context=self.ctx, timeout=self.timeout) as resp:
                status, text = resp.status, resp.read().decode()
        except urllib.error.HTTPError as exc:
            status, text = exc.code, exc.read().decode(errors="replace")
        except (urllib.error.URLError, OSError) as exc:
            raise SyncError(f"{method} {path}: {exc}") from exc
        if status not in ok:
            raise SyncError(f"{method} {path} -> {status}: {text[:400]}")
        try:
            return status, json.loads(text) if text else {}
        except ValueError:
            return status, {}

    def search(self, path, query, size=1000):
        status, out = self.req("POST", path, {"size": size, "query": query}, ok=(200, 404))
        return [] if status == 404 else out.get("hits", {}).get("hits", [])


class Git:
    """A bare repository holding what was fetched; only plumbing reads, nothing is checked out."""

    def __init__(self, path, protocols, timeout):
        self.path = path
        self.timeout = timeout
        # Hermetic: no system or user configuration, no prompts, only the allowed transports.
        self.env = {"PATH": "/usr/bin:/bin", "HOME": path, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_ALLOW_PROTOCOL": protocols, "LC_ALL": "C"}

    def run(self, *args, ok=(0,), binary=False):
        p = subprocess.run(["git", "--git-dir", self.path, *args], env=self.env, capture_output=True,
                           timeout=self.timeout, check=False)
        if p.returncode not in ok:
            raise SyncError(f"git {' '.join(args[:2])}: {p.stderr.decode(errors='replace').strip()[:300]}")
        return p if binary else p.stdout.decode().strip()

    def fetch(self, url, branch):
        if not os.path.isdir(os.path.join(self.path, "objects")):
            subprocess.run(["git", "init", "--bare", "-q", self.path], env=self.env, check=True, timeout=self.timeout)
        ref = f"refs/remotes/origin/{branch}"
        self.run("fetch", "--quiet", "--no-tags", "--no-recurse-submodules", url, f"+refs/heads/{branch}:{ref}")
        return self.run("rev-parse", "--verify", f"{ref}^{{commit}}")

    def has_commit(self, commit):
        return self.run("cat-file", "-e", f"{commit}^{{commit}}", ok=(0, 1, 128), binary=True).returncode == 0

    def is_ancestor(self, older, newer):
        if not (self.has_commit(older) and self.has_commit(newer)):
            return False
        return self.run("merge-base", "--is-ancestor", older, newer, ok=(0, 1), binary=True).returncode == 0

    def export(self, commit, dest):
        """Writes the regular files under siem/ of commit into dest (as data: mode 0644, size-capped)."""
        listing = self.run("ls-tree", "-r", "-z", "--full-tree", "-l", commit, "--", "siem/", binary=True).stdout
        total = 0
        for entry in listing.decode().split("\0"):
            if not entry:
                continue
            meta, path = entry.split("\t", 1)
            mode, kind, sha, size = meta.split()
            # Regular files only: symlinks (120000) and submodules (160000) are not data.
            if kind != "blob" or mode not in ("100644", "100755"):
                continue
            parts = path.split("/")
            if parts[0] != "siem" or any(p in ("", ".", "..") for p in parts):
                raise SyncError(f"refusing path {path!r} in {commit}")
            size = int(size)
            total += size
            if size > MAX_FILE or total > MAX_TREE:
                raise SyncError(f"siem/ of {commit} is too large ({path}: {size} bytes, {total} in total)")
            blob = self.run("cat-file", "blob", sha, binary=True).stdout
            target = os.path.join(dest, *parts)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as fh:
                fh.write(blob)
            os.chmod(target, 0o644)
        return os.path.join(dest, "siem")


def identities(tree):
    return {
        "log_types": {d.get("name") for d in tree.log_types.values()},
        "rules": set(tree.rule_ids()),
        "detectors": {d.get("name") for d in tree.detectors.values()},
        "correlations": set(tree.correlation_names()),
        "monitors": set(tree.monitor_names()),
    }


class Sync:
    def __init__(self, cfg, client, git):
        self.cfg = cfg
        self.c = client
        self.git = git
        self.counts = {k: {"created": 0, "updated": 0, "deleted": 0, "unchanged": 0} for k in KINDS}

    # ---- records (siem-sync) ------------------------------------------------------------------
    def records(self, n=50):
        status, out = self.c.req("POST", f"/{RECORD_INDEX}/_search",
                                 {"size": n, "sort": [{"applied_at": {"order": "desc"}}]}, ok=(200, 404))
        self.record_index = status == 200
        return [h["_source"] for h in out["hits"]["hits"]] if self.record_index else []

    def record(self, rec, last):
        if rec["status"] != "applied" and last and all(last.get(k) == rec[k] for k in ("commit", "status", "reason")):
            log(f"{rec['status']} again for the same reason, not recorded twice: {rec['reason']}")
            return
        if not self.record_index:
            # First record: the index with its mapping (rules-sync may create siem-sync and nothing else).
            self.c.req("PUT", f"/{RECORD_INDEX}", RECORD_MAPPING, ok=(200,))
            self.record_index = True
        self.c.req("POST", f"/{RECORD_INDEX}/_doc?refresh=wait_for", rec)

    # ---- live state ----------------------------------------------------------------------------
    def live_log_types(self):
        out = {}
        for h in self.c.search(f"{SA}/logtype/_search", {"match_all": {}}):
            s = h["_source"]
            if s.get("source") == "Custom":
                out.setdefault(s.get("name"), []).append((h["_id"], s))
        return out

    def live_rules(self):
        """Sigma id -> [(SA id, category, parsed rule)], from SA's stored YAML (S0-f: SA ignores the id)."""
        out = {}
        for h in self.c.search(f"{SA}/rules/_search?pre_packaged=false", {"match_all": {}}, size=5000):
            s = h["_source"]
            try:
                parsed = yaml.safe_load(s.get("rule") or "")
            except yaml.YAMLError:
                continue
            if isinstance(parsed, dict) and isinstance(parsed.get("id"), str):
                out.setdefault(parsed["id"], []).append((h["_id"], s.get("category"), parsed))
        return out

    def live_by_name(self, path):
        out = {}
        for h in self.c.search(path, {"match_all": {}}):
            out.setdefault(h["_source"].get("name"), []).append((h["_id"], h["_source"]))
        return out

    def live_monitors(self):
        out = {}
        hits = self.c.search(f"{ALERTING}/monitors/_search", {"prefix": {"monitor.name.keyword": PREFIX}})
        for h in hits:
            s = h["_source"]
            # Only Alerting's own monitors carrying the prefix: never a workflow, never SA's (MJ5).
            if s.get("type") == "monitor" and str(s.get("name", "")).startswith(PREFIX) \
                    and s.get("owner", "alerting") == "alerting":
                out.setdefault(s["name"], []).append((h["_id"], s))
        return out

    def rules_exist(self, sa_ids, category):
        hits = self.c.search(f"{SA}/rules/_search?pre_packaged=false", {"ids": {"values": sorted(sa_ids)}},
                             size=len(sa_ids) + 1)
        found = {h["_id"] for h in hits if h["_source"].get("category") == category}
        return set(sa_ids) - found

    # ---- desired state -------------------------------------------------------------------------
    @staticmethod
    def correlation_body(tree, d):
        return {"name": d["name"], "time_window": d["time_window_ms"], "correlate": [
            {"index": f"sdp-{e['source']}", "category": tree.log_type_of(e["source"]), "query": e["query"],
             "field": d["field"]} for e in d["correlate"]]}

    # ---- one run -------------------------------------------------------------------------------
    def run(self):
        records = self.records()
        last = records[0] if records else None
        applied = next((r for r in records if r.get("status") == "applied"), None)
        commit = self.git.fetch(self.cfg["repo"], self.cfg["branch"])
        base = {"commit": commit, "branch": self.cfg["branch"], "previous": applied["commit"] if applied else ""}
        log(f"fetched {self.cfg['branch']} at {commit}; last applied {base['previous'] or 'none (first run)'}")
        used_accept = False
        try:
            if applied and commit != applied["commit"]:
                accept = self.flag("accept-commit")
                if accept is not None:
                    if not HEX40.match(accept):
                        raise Refused("accept-commit does not hold a 40-hex commit")
                    if accept != commit and not self.git.is_ancestor(accept, commit):
                        raise Refused(f"accept-commit {accept} is neither the fetched commit nor its ancestor")
                    used_accept = True
                    log(f"accept-commit {accept}: new base accepted instead of the ancestry check")
                elif not self.git.is_ancestor(applied["commit"], commit):
                    raise Refused(f"not a fast-forward from {applied['commit']}")
            with tempfile.TemporaryDirectory(prefix="sdp-siem-sync-") as tmp:
                findings, tree = siem_lint.lint(self.git.export(commit, os.path.join(tmp, "new")))
                if findings:
                    raise Refused("lint: " + "; ".join(findings[:5]) + (f" (+{len(findings) - 5} more)" if len(findings) > 5 else ""))
                managed = self.managed(records, applied, tmp)
                plan = self.plan(tree, managed, (applied or {}).get("monitors") or {})
        except Refused as exc:
            log(f"REFUSED: {exc}")
            self.record(dict(base, applied_at=now(), status="refused", reason=str(exc)), last)
            return 2
        except (SyncError, KeyError, TypeError, ValueError) as exc:
            log(f"FAILED: {exc!r}")
            self.record(dict(base, applied_at=now(), status="failed", reason=str(exc)), last)
            return 1
        writes = sum(len(v) for k, v in plan.items() if k not in ("keep", "monitor_state"))
        deletions = sum(len(plan[k]) for k in ("del_monitors", "del_correlations", "del_detectors", "del_rules", "del_log_types"))
        if writes == 0 and applied and commit == applied["commit"]:
            log("nothing to do")
            self.mark_consumed(used_accept)
            return 0
        if deletions > self.cfg["delete_cap"]:
            if self.flag("allow-mass-delete") is None:
                reason = (f"{deletions} managed deletions exceed the cap of {self.cfg['delete_cap']};"
                          " create /etc/sdp-siem/allow-mass-delete to allow them once")
                log(f"REFUSED: {reason}")
                self.record(dict(base, applied_at=now(), status="refused", reason=reason), last)
                return 2
            log(f"allow-mass-delete present: {deletions} deletions allowed")
        try:
            rule_map, monitor_state = self.apply(tree, plan)
        except (SyncError, KeyError, TypeError, ValueError) as exc:
            log(f"FAILED: {exc}")
            self.record(dict(base, applied_at=now(), status="failed", reason=str(exc), counts=self.counts), last)
            return 1
        self.record(dict(base, applied_at=now(), status="applied", reason="" if commit != base["previous"]
                         else "drift repaired", counts=self.counts, rules=rule_map, monitors=monitor_state), last)
        log(f"applied {commit}: {json.dumps(self.counts, sort_keys=True)}")
        self.mark_consumed(used_accept)
        return 0

    def flag(self, name):
        path = os.path.join(self.cfg["flag_dir"], name)
        try:
            with open(path, encoding="ascii", errors="replace") as fh:
                return fh.read().strip()
        except FileNotFoundError:
            return None

    def mark_consumed(self, used_accept):
        """The unit's ExecStartPost (root) removes the flags marked here; this user cannot write /etc."""
        done = os.path.join(self.cfg["state_dir"], "consumed")
        os.makedirs(done, exist_ok=True)
        names = (["accept-commit"] if used_accept else []) + \
            (["allow-mass-delete"] if self.flag("allow-mass-delete") is not None else [])
        for name in names:
            with open(os.path.join(done, name), "w", encoding="ascii") as fh:
                fh.write(now() + "\n")

    def managed(self, records, applied, tmp):
        """Identities in the last applied tree and in the trees of failed attempts since (B6)."""
        out = {k: set() for k in KINDS}
        if not applied:
            return out
        commits = [applied["commit"]]
        for r in records:
            if r is applied:
                break
            if r.get("status") == "failed" and r.get("commit") not in commits:
                commits.append(r["commit"])
        for i, c in enumerate(commits):
            if not self.git.has_commit(c):
                raise SyncError(f"the tree of {c} (last applied or failed since) is not in the local repository")
            tree = siem_lint.Tree(self.git.export(c, os.path.join(tmp, f"old{i}")))
            for k, v in identities(tree).items():
                out[k] |= v
        return out

    def plan(self, tree, managed, recorded):
        p = {k: [] for k in ("log_types", "rules", "correlations", "monitors", "del_monitors", "del_correlations",
                             "del_detectors", "del_rules", "del_log_types")}
        p["keep"] = {}
        self.live = {"log_types": self.live_log_types(), "rules": self.live_rules(),
                     "detectors": self.live_by_name(f"{SA}/detectors/_search"),
                     "correlations": self.live_by_name(f"{SA}/correlation/rules/_search"),
                     "monitors": self.live_monitors()}
        want = identities(tree)
        # Log types.
        for d in tree.log_types.values():
            live = self.live["log_types"].get(d["name"])
            body = {"name": d["name"], "description": d["description"], "source": "Custom", "category": "Other"}
            if not live:
                p["log_types"].append(("create", None, body))
            elif live[0][1].get("description") != d["description"] or live[0][1].get("category") != "Other":
                p["log_types"].append(("update", live[0][0], body))
            else:
                self.counts["log_types"]["unchanged"] += 1
        for name in sorted((managed["log_types"] - want["log_types"]) & set(self.live["log_types"])):
            p["del_log_types"] += [i for i, _ in self.live["log_types"][name]]
        # Rules: identity is the Sigma id inside SA's stored YAML.
        for rel, d in tree.rules.items():
            category = tree.log_type_of(d["logsource"]["service"])
            live = self.live["rules"].get(d["id"], [])
            if not live:
                p["rules"].append(("create", None, rel, category))
                continue
            keep, *dupes = live
            p["keep"][d["id"]] = keep[0]
            p["del_rules"] += [i for i, _, _ in dupes]
            if keep[1] != category or keep[2] != d:
                p["rules"].append(("update", keep[0], rel, category))
            else:
                self.counts["rules"]["unchanged"] += 1
        for rid in sorted((managed["rules"] - want["rules"]) & set(self.live["rules"])):
            p["del_rules"] += [i for i, _, _ in self.live["rules"][rid]]
        # Detectors are planned in apply() (their bodies need the rule ids); deletions here.
        for name in sorted(managed["detectors"] - want["detectors"]):
            p["del_detectors"] += [i for i, _ in self.live["detectors"].get(name, [])]
        for name in want["detectors"]:
            p["del_detectors"] += [i for i, _ in self.live["detectors"].get(name, [])[1:]]
        # Correlation rules.
        for d in tree.correlations.values():
            body = self.correlation_body(tree, d)
            live = self.live["correlations"].get(d["name"], [])
            p["del_correlations"] += [i for i, _ in live[1:]]
            if not live:
                p["correlations"].append(("create", None, body))
            elif {k: live[0][1].get(k) for k in body} != body:
                p["correlations"].append(("update", live[0][0], body))
            else:
                self.counts["correlations"]["unchanged"] += 1
        for name in sorted(managed["correlations"] - want["correlations"]):
            p["del_correlations"] += [i for i, _ in self.live["correlations"].get(name, [])]
        # Monitors: every live monitor with the prefix is managed (B6). Alerting normalises a stored
        # query, so the live body never equals the file: a monitor is unchanged when the last applied
        # record wrote this very body (its hash) and nobody updated it since (its last_update_time, which
        # any edit moves - so an edit in Dashboards is put back, as the host role does for ops monitors).
        p["monitor_state"] = {}
        for d in tree.monitors.values():
            live = self.live["monitors"].get(d["name"], [])
            p["del_monitors"] += [i for i, _ in live[1:]]
            rec = recorded.get(d["name"]) or {}
            if not live:
                p["monitors"].append(("create", None, d))
            elif rec.get("id") != live[0][0] or rec.get("sha256") != digest(d) \
                    or str(rec.get("last_update_time")) != str(live[0][1].get("last_update_time")) \
                    or live[0][1].get("enabled") != d["enabled"]:
                p["monitors"].append(("update", live[0][0], d))
            else:
                p["monitor_state"][d["name"]] = rec
                self.counts["monitors"]["unchanged"] += 1
        for name in sorted(set(self.live["monitors"]) - want["monitors"]):
            p["del_monitors"] += [i for i, _ in self.live["monitors"][name]]
        # Detectors that will change: counted as writes for the "nothing to do" decision.
        p["detectors"] = self.detector_changes(tree, p)
        return p

    def detector_body(self, tree, d, rule_ids):
        lt = tree.log_type_of(d["source"])
        texts = {r: hashlib.sha256(tree.rule_text[rel].encode()).hexdigest()
                 for rel, r in ((rel, x["id"]) for rel, x in tree.rules.items()) if r in d["rules"]}
        body = {"type": "detector", "name": d["name"], "detector_type": lt, "enabled": True,
                "schedule": {"period": {"interval": d["interval_minutes"], "unit": "MINUTES"}},
                "inputs": [{"detector_input": {"description": "", "indices": [f"sdp-{d['source']}"],
                                               "custom_rules": [{"id": i} for i in sorted(rule_ids)],
                                               "pre_packaged_rules": []}}],
                "triggers": [{"name": TRIGGER_NAME, "severity": "1", "types": [lt], "ids": [], "sev_levels": [],
                              "tags": [], "actions": []}]}
        # The hash covers the body and the text of each rule, so a changed rule re-applies its detector.
        body["inputs"][0]["detector_input"]["description"] = "sdp-git " + digest([body, texts])[:32]
        return body

    def detector_changes(self, tree, p):
        """Detectors whose body would change, judged with the rule ids known before apply."""
        changes = []
        changed_rules = {tree.rules[rel]["id"] for _, _, rel, _ in p["rules"]}
        for d in tree.detectors.values():
            live = self.live["detectors"].get(d["name"], [])
            known = [p["keep"].get(r) for r in d["rules"]]
            if not live or None in known or changed_rules & set(d["rules"]):
                changes.append(d["name"])
                continue
            body = self.detector_body(tree, d, known)
            s = live[0][1]
            li = (s.get("inputs") or [{}])[0].get("detector_input", {})
            if li.get("description") != body["inputs"][0]["detector_input"]["description"] or not s.get("enabled") \
                    or {r.get("id") for r in li.get("custom_rules", [])} != set(known):
                changes.append(d["name"])
            else:
                self.counts["detectors"]["unchanged"] += 1
        return changes

    def apply(self, tree, p):
        for op, oid, body in p["log_types"]:
            if op == "create":
                self.c.req("POST", f"{SA}/logtype", body)
            else:
                self.c.req("PUT", f"{SA}/logtype/{oid}", body)
            self.counts["log_types"][op + "d"] += 1
        rule_ids = dict(p["keep"])
        for op, oid, rel, category in p["rules"]:
            text = tree.rule_text[rel]
            if op == "create":
                _, out = self.c.req("POST", f"{SA}/rules?category={category}", text)
                rule_ids[tree.rules[rel]["id"]] = out["_id"]
            else:
                # oid was read back from SA in this run (plan); never an id from a record (S0-#12).
                self.c.req("PUT", f"{SA}/rules/{oid}?category={category}&forced=true", text)
            self.counts["rules"][op + "d"] += 1
        for name in p["detectors"]:
            d = next(x for x in tree.detectors.values() if x["name"] == name)
            ids = [rule_ids[r] for r in d["rules"]]
            missing = self.rules_exist(ids, tree.log_type_of(d["source"]))
            if missing:
                # SA would accept the dangling ids silently (S0-i).
                raise SyncError(f"detector {name}: SA has no rule {', '.join(sorted(missing))} of its log type")
            body = self.detector_body(tree, d, ids)
            live = self.live["detectors"].get(name, [])
            if live:
                self.c.req("PUT", f"{SA}/detectors/{live[0][0]}", body)
                self.counts["detectors"]["updated"] += 1
            else:
                self.c.req("POST", f"{SA}/detectors", body)
                self.counts["detectors"]["created"] += 1
        for op, oid, body in p["correlations"]:
            if op == "create":
                self.c.req("POST", f"{SA}/correlation/rules", body)
            else:
                self.c.req("PUT", f"{SA}/correlation/rules/{oid}", body)
            self.counts["correlations"][op + "d"] += 1
        monitor_state = dict(p["monitor_state"])
        for op, oid, body in p["monitors"]:
            if op == "create":
                _, out = self.c.req("POST", f"{ALERTING}/monitors", body)
            else:
                _, out = self.c.req("PUT", f"{ALERTING}/monitors/{oid}", body)
            monitor_state[body["name"]] = {"id": out["_id"], "sha256": digest(body),
                                           "last_update_time": out["monitor"]["last_update_time"]}
            self.counts["monitors"][op + "d"] += 1
        # Deletions after every write, dependants first: nothing still points at what goes.
        for kind, path in (("monitors", f"{ALERTING}/monitors/{{}}"), ("correlations", f"{SA}/correlation/rules/{{}}"),
                           ("detectors", f"{SA}/detectors/{{}}"), ("rules", f"{SA}/rules/{{}}?forced=true"),
                           ("log_types", f"{SA}/logtype/{{}}")):
            for oid in p["del_" + kind]:
                self.c.req("DELETE", path.format(oid))
                self.counts[kind]["deleted"] += 1
        return {r: rule_ids[r] for r in sorted(rule_ids) if r in tree.rule_ids()}, monitor_state


def config():
    env = os.environ
    creds = env.get("CREDENTIALS_DIRECTORY", "")
    cfg = {
        "url": env.get("SDP_SYNC_URL", "https://127.0.0.1:9200"),
        "repo": env.get("SDP_SYNC_REPO", ""),
        "branch": env.get("SDP_SYNC_BRANCH", "main"),
        "protocols": env.get("SDP_SYNC_GIT_PROTOCOLS", "https"),
        "state_dir": env.get("SDP_SYNC_STATE_DIR", "/var/lib/sdp-siem-sync"),
        "flag_dir": env.get("SDP_SYNC_FLAG_DIR", "/etc/sdp-siem"),
        "delete_cap": int(env.get("SDP_SYNC_DELETE_CAP", "5")),
        "ca": os.path.join(creds, "ca.crt"),
        "cert": os.path.join(creds, "client.crt"),
        "key": os.path.join(creds, "client.key"),
    }
    if not cfg["repo"] or not creds:
        raise SystemExit("SDP_SYNC_REPO and CREDENTIALS_DIRECTORY (the unit's LoadCredential) are required")
    return cfg


def main():
    cfg = config()
    client = Client(cfg["url"], cfg["ca"], cfg["cert"], cfg["key"])
    git = Git(os.path.join(cfg["state_dir"], "repo.git"), cfg["protocols"], timeout=300)
    try:
        return Sync(cfg, client, git).run()
    except SyncError as exc:
        # Before a record could be written (OpenSearch or the fetch unreachable): the journal only.
        log(f"FAILED before recording: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
