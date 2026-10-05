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
  5. refuse to adopt a live object the sync did not make (no git marker) - it would silently become
     managed; refuse more than DELETE_CAP deletions unless /etc/sdp-siem/allow-mass-delete exists, and
     more than CHANGE_CAP rule/monitor updates unless /etc/sdp-siem/allow-mass-change exists;
  6. apply: log types -> rules -> detectors -> correlations -> monitors, then the deletions in the
     reverse order; record {commit, applied_at, status, reason, counts, changed, rules, monitors,
     lint_sha256} in siem-sync.

Records in siem-sync (read by the API, ADR 0036): one document per applied, refused or failed run
(field status, time applied_at). A run that finds nothing to do writes no record; instead every run
that reaches OpenSearch overwrites the single document with id "heartbeat" ({kind: heartbeat,
checked_at, commit, outcome: applied|unchanged|refused|failed, lint_sha256}; no status, no
applied_at, so record queries never see it) - a stale checked_at is a dead sync, a fresh one with an
old applied_at an idle one.

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
Any exception is recorded as failed (its type and at most 300 characters); a reason is capped at 512
characters and a lint refusal names files and checks, never values.
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
DETECTOR_MARK = "sdp-git "
REASON_MAX = 512
HEARTBEAT_ID = "heartbeat"
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "siem_lint.py"), "rb") as _fh:
    LINT_SHA256 = hashlib.sha256(_fh.read()).hexdigest()
RECORD_MAPPING = {
    "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
    "mappings": {"dynamic": False, "properties": {
        "commit": {"type": "keyword"}, "applied_at": {"type": "date"}, "status": {"type": "keyword"},
        "reason": {"type": "keyword", "ignore_above": 2048}, "branch": {"type": "keyword"},
        "previous": {"type": "keyword"}, "counts": {"type": "object", "enabled": False},
        "changed": {"type": "object", "enabled": False}, "lint_sha256": {"type": "keyword"},
        "kind": {"type": "keyword"}, "checked_at": {"type": "date"}, "outcome": {"type": "keyword"},
        "rules": {"type": "object", "enabled": False}, "monitors": {"type": "object", "enabled": False},
    }},
}
KINDS = ("log_types", "rules", "detectors", "correlations", "monitors")


class SyncError(Exception):
    pass


class Refused(Exception):
    pass


def cap(text, limit=REASON_MAX):
    text = str(text)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def exc_reason(exc):
    return f"{type(exc).__name__}: {str(exc)[:300]}"


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

    def __init__(self, path, protocols, timeout, max_bytes=1 << 30):
        self.path = path
        self.timeout = timeout
        self.max_bytes = max_bytes
        # Hermetic: no system or user configuration, no prompts, only the allowed transports.
        self.env = {"PATH": "/usr/bin:/bin", "HOME": path, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_ALLOW_PROTOCOL": protocols, "LC_ALL": "C"}

    def run(self, *args, ok=(0,), binary=False):
        p = subprocess.run(["git", "--git-dir", self.path, *args], env=self.env, capture_output=True,
                           timeout=self.timeout, check=False)
        if p.returncode not in ok:
            verb = next((a for a in args if not a.startswith("-") and "=" not in a), "")
            raise SyncError(f"git {verb}: {p.stderr.decode(errors='replace').strip()[:300]}")
        return p if binary else p.stdout.decode().strip()

    def fetch(self, url, branch):
        if not os.path.isdir(os.path.join(self.path, "objects")):
            subprocess.run(["git", "init", "--bare", "-q", self.path], env=self.env, check=True, timeout=self.timeout)
        ref = f"refs/remotes/origin/{branch}"
        # Every fetched object is checked (malformed trees, odd paths); the repository has a size cap.
        self.run("-c", "transfer.fsckObjects=true", "-c", "fetch.fsckObjects=true", "fetch", "--quiet", "--no-tags",
                 "--no-recurse-submodules", url, f"+refs/heads/{branch}:{ref}")
        size = 0
        for line in self.run("count-objects", "-v").splitlines():
            key, _, value = line.partition(": ")
            if key in ("size", "size-pack"):
                size += int(value) * 1024
        if size > self.max_bytes:
            raise SyncError(f"the fetched repository holds {size >> 20} MiB, more than {self.max_bytes >> 20} MiB")
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
        self.changed = {k: [] for k in KINDS}
        self.record_index = None
        self.rule_ids = {}
        self.prev_rules = {}
        self.marked_rules = set()

    # ---- records (siem-sync) ------------------------------------------------------------------
    def _search_records(self, query, size):
        status, out = self.c.req("POST", f"/{RECORD_INDEX}/_search",
                                 {"size": size, "query": query, "sort": [{"applied_at": {"order": "desc"}}]},
                                 ok=(200, 404))
        self.record_index = status == 200
        return [h["_source"] for h in out["hits"]["hits"]] if self.record_index else []

    def last_applied(self):
        """The newest applied record, by its own query: any number of refusals since cannot hide it."""
        recs = self._search_records({"term": {"status": "applied"}}, 1)
        if recs and not HEX40.match(str(recs[0].get("commit", ""))):
            raise SyncError("the last applied record does not hold a 40-hex commit")
        return recs[0] if recs else None

    def since(self, applied):
        """Records after the last applied one (all records when there is none), newest first."""
        query = ({"range": {"applied_at": {"gt": applied["applied_at"]}}} if applied
                 else {"exists": {"field": "applied_at"}})
        return self._search_records(query, 50)

    def ensure_index(self):
        if self.record_index:
            return
        # First write: the index with its mapping (rules-sync may create siem-sync and nothing else).
        status, out = self.c.req("PUT", f"/{RECORD_INDEX}", RECORD_MAPPING, ok=(200, 400))
        if status == 400 and "resource_already_exists" not in json.dumps(out):
            raise SyncError(f"PUT /{RECORD_INDEX} -> 400: {json.dumps(out)[:300]}")
        self.record_index = True

    def record(self, rec, last):
        rec = dict(rec, reason=cap(rec.get("reason", "")), lint_sha256=LINT_SHA256)
        if rec["status"] != "applied" and last and all(last.get(k) == rec[k] for k in ("commit", "status", "reason")):
            log(f"{rec['status']} again for the same reason, not recorded twice: {rec['reason']}")
            return
        self.ensure_index()
        self.c.req("POST", f"/{RECORD_INDEX}/_doc?refresh=wait_for", rec)

    def heartbeat(self, commit, outcome):
        """Overwrites the one heartbeat document: when the sync last ran to an end, and how it ended."""
        self.ensure_index()
        self.c.req("PUT", f"/{RECORD_INDEX}/_doc/{HEARTBEAT_ID}",
                   {"kind": "heartbeat", "checked_at": now(), "commit": commit, "outcome": outcome,
                    "lint_sha256": LINT_SHA256})

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
                parsed = siem_lint.strict_yaml(s.get("rule") or "")
            except (yaml.YAMLError, RecursionError):
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
        base = {"commit": "", "branch": self.cfg["branch"], "previous": ""}
        last, outcome, code = None, "failed", 1
        used_accept = False
        try:
            applied = self.last_applied()
            since = self.since(applied)
            last = since[0] if since else applied
            base["previous"] = applied["commit"] if applied else ""
            # Rules the sync made: SA ids in the last applied record and in failed attempts since.
            self.prev_rules = (applied or {}).get("rules") or {}
            self.marked_rules = {v for r in [applied or {}] + [x for x in since if x.get("status") == "failed"]
                                 for v in (r.get("rules") or {}).values()}
            base["commit"] = self.git.fetch(self.cfg["repo"], self.cfg["branch"])
            commit = base["commit"]
            log(f"fetched {self.cfg['branch']} at {commit}; last applied {base['previous'] or 'none (first run)'}")
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
                findings, tree = siem_lint.lint_detailed(self.git.export(commit, os.path.join(tmp, "new")))
                if findings:
                    # Files and checks only: a finding's message may quote a value from the commit.
                    names = sorted({f"{path}: {check}" for path, check, _ in findings})
                    raise Refused(f"lint ({len(findings)} findings): " + "; ".join(names))
                managed = self.managed(applied, since, tmp)
                plan = self.plan(tree, managed, (applied or {}).get("monitors") or {})
            writes = sum(len(v) for k, v in plan.items() if k not in ("keep", "monitor_state"))
            if writes == 0 and applied and commit == applied["commit"]:
                log("nothing to do")
                self.mark_consumed(used_accept)
                outcome, code = "unchanged", 0
                return 0
            self.check_caps(plan)
            rule_map, monitor_state = self.apply(tree, plan)
            self.record(dict(base, applied_at=now(), status="applied",
                             reason="" if commit != base["previous"] else "drift repaired", counts=self.counts,
                             changed=self.changed, rules=rule_map, monitors=monitor_state), last)
            log(f"applied {commit}: {json.dumps(self.counts, sort_keys=True)}")
            self.mark_consumed(used_accept)
            outcome, code = "applied", 0
            return 0
        except Refused as exc:
            log(f"REFUSED: {exc}")
            self.record(dict(base, applied_at=now(), status="refused", reason=str(exc)), last)
            outcome, code = "refused", 2
            return 2
        except Exception as exc:  # noqa: BLE001 - every failure is recorded, whatever raised it
            log(f"FAILED: {exc_reason(exc)}")
            self.record(dict(base, applied_at=now(), status="failed", reason=exc_reason(exc), counts=self.counts,
                             changed=self.changed, rules=dict(sorted(self.rule_ids.items()))), last)
            return 1
        finally:
            try:
                self.heartbeat(base["commit"], outcome)
            except Exception as exc:  # noqa: BLE001 - the heartbeat must not change the exit status
                log(f"heartbeat not written: {exc_reason(exc)}")

    def check_caps(self, plan):
        deletions = sum(len(plan[k]) for k in ("del_monitors", "del_correlations", "del_detectors", "del_rules",
                                               "del_log_types"))
        if deletions > self.cfg["delete_cap"]:
            if self.flag("allow-mass-delete") is None:
                raise Refused(f"{deletions} managed deletions exceed the cap of {self.cfg['delete_cap']};"
                              " create /etc/sdp-siem/allow-mass-delete to allow them once")
            log(f"allow-mass-delete present: {deletions} deletions allowed")
        # Rewriting what a detection means is as consequential as removing it (review M3).
        updates = sum(1 for x in plan["rules"] + plan["monitors"] if x[0] == "update")
        if updates > self.cfg["change_cap"]:
            if self.flag("allow-mass-change") is None:
                raise Refused(f"{updates} rule and monitor updates exceed the cap of {self.cfg['change_cap']};"
                              " create /etc/sdp-siem/allow-mass-change to allow them once")
            log(f"allow-mass-change present: {updates} updates allowed")

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
            [f for f in ("allow-mass-delete", "allow-mass-change") if self.flag(f) is not None]
        for name in names:
            with open(os.path.join(done, name), "w", encoding="ascii") as fh:
                fh.write(now() + "\n")

    def managed(self, applied, since, tmp):
        """Identities in the last applied tree and in the trees of failed attempts since (B6) - also
        when nothing was ever applied, so a failed first run does not orphan what it created."""
        out = {k: set() for k in KINDS}
        commits = [applied["commit"]] if applied else []
        for r in since:
            c = str(r.get("commit", ""))
            if r.get("status") == "failed" and HEX40.match(c) and c not in commits:
                commits.append(c)
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
        unmarked = []
        # Log types: the sync's own when their name is in the managed set (L1).
        for d in tree.log_types.values():
            live = self.live["log_types"].get(d["name"])
            body = {"name": d["name"], "description": d["description"], "source": "Custom", "category": "Other"}
            if not live:
                p["log_types"].append(("create", None, d["name"], body))
            elif d["name"] not in managed["log_types"]:
                unmarked.append(f"log type {d['name']}")
            elif live[0][1].get("description") != d["description"] or live[0][1].get("category") != "Other":
                p["log_types"].append(("update", live[0][0], d["name"], body))
            else:
                self.counts["log_types"]["unchanged"] += 1
        for name in sorted((managed["log_types"] - want["log_types"]) & set(self.live["log_types"])):
            p["del_log_types"] += [(i, name) for i, _ in self.live["log_types"][name]]
        # Rules: identity is the Sigma id inside SA's stored YAML; the sync's own are the SA ids it
        # recorded. Other SA rules with a git rule's Sigma id are duplicates and go (by design).
        for rel, d in tree.rules.items():
            category = tree.log_type_of(d["logsource"]["service"])
            live = self.live["rules"].get(d["id"], [])
            if not live:
                p["rules"].append(("create", None, rel, category))
                continue
            mine = [x for x in live if x[0] in self.marked_rules]
            if not mine:
                unmarked.append(f"rule {d['id']} (SA id {live[0][0]})")
                continue
            keep = mine[0]
            p["keep"][d["id"]] = keep[0]
            p["del_rules"] += [(i, d["id"]) for i, _, _ in live if i != keep[0]]
            if keep[1] != category or keep[2] != d:
                p["rules"].append(("update", keep[0], rel, category))
            else:
                self.counts["rules"]["unchanged"] += 1
        for rid in sorted((managed["rules"] - want["rules"]) & set(self.live["rules"])):
            p["del_rules"] += [(i, rid) for i, _, _ in self.live["rules"][rid]]
        # Detectors are planned in apply() (their bodies need the rule ids); the sync's own carry the
        # marker in their description.
        for name in want["detectors"]:
            live = self.live["detectors"].get(name, [])
            if any(not self.detector_marked(s) for _, s in live):
                unmarked.append(f"detector {name}")
            p["del_detectors"] += [(i, name) for i, _ in live[1:]]
        for name in sorted(managed["detectors"] - want["detectors"]):
            p["del_detectors"] += [(i, name) for i, s in self.live["detectors"].get(name, []) if self.detector_marked(s)]
        # Correlation rules: the sync's own when their name is in the managed set.
        for d in tree.correlations.values():
            body = self.correlation_body(tree, d)
            live = self.live["correlations"].get(d["name"], [])
            if live and d["name"] not in managed["correlations"]:
                unmarked.append(f"correlation {d['name']}")
                continue
            p["del_correlations"] += [(i, d["name"]) for i, _ in live[1:]]
            if not live:
                p["correlations"].append(("create", None, d["name"], body))
            elif {k: live[0][1].get(k) for k in body} != body:
                p["correlations"].append(("update", live[0][0], d["name"], body))
            else:
                self.counts["correlations"]["unchanged"] += 1
        for name in sorted(managed["correlations"] - want["correlations"]):
            p["del_correlations"] += [(i, name) for i, _ in self.live["correlations"].get(name, [])]
        if unmarked:
            raise Refused("SA holds objects the sync did not make (no git marker), refusing to adopt them: "
                          + ", ".join(unmarked) + "; remove them or rename the git objects")
        # Monitors: every live monitor with the prefix is managed (B6). Alerting normalises a stored
        # query, so the live body never equals the file: a monitor is unchanged when the last applied
        # record wrote this very body (its hash) and nobody updated it since (its last_update_time, which
        # any edit moves - so an edit in Dashboards is put back, as the host role does for ops monitors).
        p["monitor_state"] = {}
        for d in tree.monitors.values():
            live = self.live["monitors"].get(d["name"], [])
            p["del_monitors"] += [(i, d["name"]) for i, _ in live[1:]]
            rec = recorded.get(d["name"]) or {}
            if not live:
                p["monitors"].append(("create", None, d["name"], d))
            elif rec.get("id") != live[0][0] or rec.get("sha256") != digest(d) \
                    or str(rec.get("last_update_time")) != str(live[0][1].get("last_update_time")) \
                    or live[0][1].get("enabled") != d["enabled"]:
                p["monitors"].append(("update", live[0][0], d["name"], d))
            else:
                p["monitor_state"][d["name"]] = rec
                self.counts["monitors"]["unchanged"] += 1
        for name in sorted(set(self.live["monitors"]) - want["monitors"]):
            p["del_monitors"] += [(i, name) for i, _ in self.live["monitors"][name]]
        # Detectors that will change: counted as writes for the "nothing to do" decision.
        p["detectors"] = self.detector_changes(tree, p)
        return p

    @staticmethod
    def detector_marked(source):
        di = ((source.get("inputs") or [{}])[0] or {}).get("detector_input") or {}
        return str(di.get("description", "")).startswith(DETECTOR_MARK)

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
        # The hash covers the body and the text of each rule, so a changed rule re-applies its detector;
        # its prefix is the marker that the sync made this detector.
        body["inputs"][0]["detector_input"]["description"] = DETECTOR_MARK + digest([body, texts])[:32]
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

    def done(self, kind, op, identity):
        self.counts[kind][op] += 1
        self.changed[kind].append(f"{op} {identity}")

    def apply(self, tree, p):
        for op, oid, name, body in p["log_types"]:
            if op == "create":
                self.c.req("POST", f"{SA}/logtype", body)
            else:
                self.c.req("PUT", f"{SA}/logtype/{oid}", body)
            self.done("log_types", op + "d", name)
        self.rule_ids = dict(p["keep"])
        for op, oid, rel, category in p["rules"]:
            text = tree.rule_text[rel]
            sigma = tree.rules[rel]["id"]
            if op == "create":
                _, out = self.c.req("POST", f"{SA}/rules?category={category}", text)
                self.rule_ids[sigma] = out["_id"]
                if sigma in self.prev_rules:
                    log(f"rule {sigma} re-created as {out['_id']}: its recorded SA id {self.prev_rules[sigma]}"
                        " is gone from SA")
            else:
                # oid was read back from SA in this run (plan); never an id from a record (S0-#12).
                self.c.req("PUT", f"{SA}/rules/{oid}?category={category}&forced=true", text)
            self.done("rules", op + "d", sigma)
        for name in p["detectors"]:
            d = next(x for x in tree.detectors.values() if x["name"] == name)
            ids = [self.rule_ids[r] for r in d["rules"]]
            missing = self.rules_exist(ids, tree.log_type_of(d["source"]))
            if missing:
                # SA would accept the dangling ids silently (S0-i).
                raise SyncError(f"detector {name}: SA has no rule {', '.join(sorted(missing))} of its log type")
            body = self.detector_body(tree, d, ids)
            live = self.live["detectors"].get(name, [])
            if live:
                self.c.req("PUT", f"{SA}/detectors/{live[0][0]}", body)
                self.done("detectors", "updated", name)
            else:
                self.c.req("POST", f"{SA}/detectors", body)
                self.done("detectors", "created", name)
        for op, oid, name, body in p["correlations"]:
            if op == "create":
                self.c.req("POST", f"{SA}/correlation/rules", body)
            else:
                self.c.req("PUT", f"{SA}/correlation/rules/{oid}", body)
            self.done("correlations", op + "d", name)
        monitor_state = dict(p["monitor_state"])
        for op, oid, name, body in p["monitors"]:
            if op == "create":
                _, out = self.c.req("POST", f"{ALERTING}/monitors", body)
            else:
                _, out = self.c.req("PUT", f"{ALERTING}/monitors/{oid}", body)
            monitor_state[name] = {"id": out["_id"], "sha256": digest(body),
                                   "last_update_time": out["monitor"]["last_update_time"]}
            self.done("monitors", op + "d", name)
        # Deletions after every write, dependants first: nothing still points at what goes.
        for kind, path in (("monitors", f"{ALERTING}/monitors/{{}}"), ("correlations", f"{SA}/correlation/rules/{{}}"),
                           ("detectors", f"{SA}/detectors/{{}}"), ("rules", f"{SA}/rules/{{}}?forced=true"),
                           ("log_types", f"{SA}/logtype/{{}}")):
            for oid, name in p["del_" + kind]:
                self.c.req("DELETE", path.format(oid))
                self.done(kind, "deleted", name)
        return {r: self.rule_ids[r] for r in sorted(self.rule_ids) if r in tree.rule_ids()}, monitor_state


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
        "change_cap": int(env.get("SDP_SYNC_CHANGE_CAP", "5")),
        "repo_max_mb": int(env.get("SDP_SYNC_REPO_MAX_MB", "1024")),
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
    git = Git(os.path.join(cfg["state_dir"], "repo.git"), cfg["protocols"], timeout=300,
              max_bytes=cfg["repo_max_mb"] << 20)
    try:
        return Sync(cfg, client, git).run()
    except Exception as exc:  # noqa: BLE001
        # Recording itself failed (OpenSearch unreachable or refusing): the journal only.
        log(f"FAILED, not recorded: {exc_reason(exc)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
