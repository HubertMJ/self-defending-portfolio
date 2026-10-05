#!/usr/bin/env python3
"""Offline tests of the rules sync's guards that tests/siem/sync-it.sh cannot reach from outside
(siem contract P3, S0-#12, F11): the client refuses the SA mappings API; a detector whose rule id SA
does not have is never written; the tree is read as data (no symlink, nothing executable); a refusal
is recorded once per commit and reason. Runs in scripts/check-siem.sh.

Usage: tests/siem/sync_unit_test.py [path to sdp_siem_sync.py]
"""
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROG = sys.argv[1] if len(sys.argv) > 1 else os.path.join(REPO, "ansible/roles/siem_sync/files/sdp_siem_sync.py")
sys.path.insert(0, os.path.join(REPO, "ansible/roles/siem_sync/files"))
spec = importlib.util.spec_from_file_location("sdp_siem_sync", PROG)
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)
import siem_lint  # noqa: E402

fails = []


def case(name, fn):
    try:
        fn()
        print(f"ok   {name}")
    except Exception as exc:  # noqa: BLE001 - any error fails the case
        print(f"FAIL {name}: {type(exc).__name__}: {str(exc)[:400]}")
        fails.append(name)


class Fake:
    """Records requests; SA knows no rule at all."""

    def __init__(self):
        self.calls = []

    def req(self, method, path, body=None, ok=(200, 201)):
        self.calls.append((method, path))
        return 200, {"_id": "new-id", "hits": {"hits": []}}

    def search(self, path, query, size=1000):
        self.calls.append(("POST", path))
        return []


def mappings_refused():
    c = object.__new__(sync.Client)
    for path in ("/_plugins/_security_analytics/mappings", "/_plugins/_security_analytics/mappings?indexName=sdp-falco"):
        try:
            c.req("POST", path, {})
        except sync.SyncError as exc:
            assert "mappings" in str(exc)
        except Exception as exc:  # it went on to send the request
            raise AssertionError(f"{path} was not refused ({exc!r})") from exc
        else:
            raise AssertionError(f"{path} was not refused")


def detector_readback():
    tree = siem_lint.Tree(os.path.join(REPO, "siem"))
    fake = Fake()
    s = sync.Sync({"delete_cap": 5}, fake, None)
    s.live = {"detectors": {}}
    rid = next(iter(tree.detectors.values()))
    plan = {"log_types": [], "rules": [], "keep": {r: f"sa-{r}" for r in tree.rule_ids()},
            "detectors": [rid["name"]], "correlations": [], "monitors": [], "monitor_state": {},
            **{f"del_{k}": [] for k in ("monitors", "correlations", "detectors", "rules", "log_types")}}
    try:
        s.apply(tree, plan)
    except sync.SyncError as exc:
        assert "has no rule" in str(exc), exc
    else:
        raise AssertionError("a detector with rule ids SA does not have was written")
    assert not any(p.endswith("/detectors") or "/detectors/" in p for _, p in fake.calls), fake.calls


def export_as_data():
    tmp = tempfile.mkdtemp()
    try:
        work = os.path.join(tmp, "w")
        os.makedirs(os.path.join(work, "siem"))
        env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
        run = lambda *a: subprocess.run(["git", "-C", work, *a], check=True, capture_output=True, env=env)  # noqa: E731
        run("init", "-q")
        with open(os.path.join(work, "siem", "x.sh"), "w") as fh:
            fh.write("#!/bin/sh\nexit 0\n")
        os.chmod(os.path.join(work, "siem", "x.sh"), 0o755)
        os.symlink("/etc/passwd", os.path.join(work, "siem", "link"))
        run("add", "-A")
        run("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "t")
        g = sync.Git(os.path.join(tmp, "bare.git"), "file", 60)
        commit = g.fetch(f"file://{work}", subprocess.run(["git", "-C", work, "branch", "--show-current"],
                                                          capture_output=True, text=True, env=env).stdout.strip())
        out = g.export(commit, os.path.join(tmp, "out"))
        assert not os.path.lexists(os.path.join(out, "link")), "a symlink came out of the tree"
        mode = os.stat(os.path.join(out, "x.sh")).st_mode & 0o777
        assert mode == 0o644, f"x.sh exported with mode {oct(mode)}"
    finally:
        shutil.rmtree(tmp)


def refusal_once():
    fake = Fake()
    s = sync.Sync({}, fake, None)
    s.record_index = True
    last = {"commit": "a" * 40, "status": "refused", "reason": "not a fast-forward"}
    s.record({"commit": "a" * 40, "status": "refused", "reason": "not a fast-forward", "applied_at": "x"}, last)
    assert fake.calls == [], f"the same refusal was written again: {fake.calls}"
    s.record({"commit": "a" * 40, "status": "refused", "reason": "lint: x", "applied_at": "x"}, last)
    assert fake.calls == [("POST", "/siem-sync/_doc?refresh=wait_for")], fake.calls
    stored = []
    fake.req = lambda m, p, body=None, ok=(200, 201): stored.append(body) or (201, {})
    s.record({"commit": "a" * 40, "status": "failed", "reason": "y" * 5000, "applied_at": "x"}, last)
    assert len(stored[0]["reason"]) <= 512, len(stored[0]["reason"])


# ---- run() against a fake OpenSearch and a fake git ------------------------------------------
A = "a" * 40
B = "b" * 40
SIEM = os.path.join(REPO, "siem")


class FakeOS:
    """siem-sync as a list, SA and Alerting as dicts of live hits; writes are recorded."""

    def __init__(self, records=None, live=None, fail_on=None):
        self.records = list(records or [])
        self.index = records is not None
        self.heartbeat = None
        self.live = live or {}
        self.fail_on = fail_on or {}
        self.writes = []
        self.created = {}

    def req(self, method, path, body=None, ok=(200, 201)):
        for frag, exc in self.fail_on.items():
            if frag in path:
                raise exc
        if path.startswith("/siem-sync/_search"):
            if not self.index:
                return 404, {}
            q, recs = body["query"], [r for r in self.records if "applied_at" in r]
            if "term" in q:
                recs = [r for r in recs if r.get("status") == q["term"]["status"]]
            if "range" in q:
                recs = [r for r in recs if r["applied_at"] > q["range"]["applied_at"]["gt"]]
            recs = sorted(recs, key=lambda r: r["applied_at"], reverse=True)[: body["size"]]
            return 200, {"hits": {"hits": [{"_source": r} for r in recs]}}
        if method == "PUT" and path == "/siem-sync":
            self.index = True
            return 200, {}
        if path.startswith("/siem-sync/_doc/heartbeat"):
            self.heartbeat = body
            return 200, {}
        if path.startswith("/siem-sync/_doc"):
            self.records.append(body)
            return 201, {}
        self.writes.append((method, path))
        if method == "POST" and "/rules?category=" in path:
            sa = f"sa{len(self.writes)}"
            self.created[sa] = path.split("category=")[1]
            return 201, {"_id": sa}
        return 201, {"_id": f"id{len(self.writes)}", "monitor": {"last_update_time": 1}}

    def search(self, path, query, size=1000):
        if "ids" in query:
            return [{"_id": i, "_source": {"category": c}} for i, c in self.created.items()
                    if i in query["ids"]["values"]] + [h for h in self.live.get("rules", []) if h["_id"] in query["ids"]["values"]]
        for key in ("logtype", "rules", "detectors", "correlation", "monitors"):
            if f"/{key}" in path:
                return self.live.get(key, [])
        return []


class FakeGit:
    def __init__(self, trees, head=A, ancestor=True, fetch_error=None):
        self.trees, self.head, self.ancestor, self.fetch_error = trees, head, ancestor, fetch_error
        self.asked = []

    def fetch(self, url, branch):
        if self.fetch_error:
            raise self.fetch_error
        return self.head

    def has_commit(self, c):
        return c in self.trees

    def is_ancestor(self, older, newer):
        self.asked.append((older, newer))
        return self.ancestor

    def export(self, commit, dest):
        shutil.copytree(self.trees[commit], os.path.join(dest, "siem"))
        return os.path.join(dest, "siem")


def empty_tree(tmp):
    t = os.path.join(tmp, "empty")
    shutil.copytree(os.path.join(SIEM, "fields"), os.path.join(t, "fields"))
    with open(os.path.join(t, "canaries.yaml"), "w") as fh:
        fh.write("rules: {}\ncorrelations: {}\nmonitors: {}\n")
    return t


def make_sync(fake, git, flags=None, tmp=None):
    flag_dir = os.path.join(tmp, "flags")
    os.makedirs(flag_dir, exist_ok=True)
    for name in flags or []:
        open(os.path.join(flag_dir, name), "w").close()
    cfg = {"branch": "main", "repo": "x", "delete_cap": 5, "change_cap": 5, "flag_dir": flag_dir,
           "state_dir": os.path.join(tmp, "state")}
    return sync.Sync(cfg, fake, git)


def applied_rec(commit, at, **kw):
    return dict({"commit": commit, "status": "applied", "applied_at": at, "reason": ""}, **kw)


def with_tmp(fn):
    def wrapped():
        tmp = tempfile.mkdtemp()
        try:
            fn(tmp)
        finally:
            shutil.rmtree(tmp)
    return wrapped


@with_tmp
def applied_behind_refusals(tmp):
    recs = [applied_rec(A, "2026-10-05T00:00:00.000Z")]
    recs += [{"commit": B, "status": "refused", "reason": f"r{i}", "applied_at": f"2026-10-05T01:{i:02d}:00.000Z"}
             for i in range(60)]
    fake, git = FakeOS(recs), FakeGit({A: SIEM, B: SIEM}, head=B, ancestor=False)
    rc = make_sync(fake, git, tmp=tmp).run()
    assert git.asked == [(A, B)], f"the ancestry from the last applied commit was not checked: {git.asked}"
    assert rc == 2 and fake.records[-1]["status"] == "refused" and "not a fast-forward from " + A in fake.records[-1]["reason"], \
        fake.records[-1]


@with_tmp
def heartbeat_on_noop(tmp):
    t = empty_tree(tmp)
    fake = FakeOS([applied_rec(A, "2026-10-05T00:00:00.000Z")])
    n = len(fake.records)
    rc = make_sync(fake, FakeGit({A: t}), tmp=tmp).run()
    assert rc == 0 and len(fake.records) == n, "a no-op run wrote a record"
    hb = fake.heartbeat or {}
    assert hb.get("kind") == "heartbeat" and hb.get("outcome") == "unchanged" and hb.get("checked_at"), hb
    assert "status" not in hb and "applied_at" not in hb, "the heartbeat looks like a record"


@with_tmp
def fetch_failure_recorded(tmp):
    fake = FakeOS([applied_rec(A, "2026-10-05T00:00:00.000Z")])
    rc = make_sync(fake, FakeGit({A: SIEM}, fetch_error=sync.SyncError("git fetch: 403")), tmp=tmp).run()
    r = fake.records[-1]
    assert rc == 1 and r["status"] == "failed" and r["commit"] == "" and "git fetch: 403" in r["reason"], r
    assert (fake.heartbeat or {}).get("outcome") == "failed"


@with_tmp
def any_exception_recorded(tmp):
    fake = FakeOS([], live={"logtype": [{"_id": "x"}]})  # a hit without _source: a KeyError in plan()
    rc = make_sync(fake, FakeGit({A: SIEM}), tmp=tmp).run()
    r = fake.records[-1]
    assert rc == 1 and r["status"] == "failed" and r["reason"].startswith("KeyError: "), r


@with_tmp
def lint_reason_without_values(tmp):
    t = os.path.join(tmp, "t")
    shutil.copytree(SIEM, t)
    p = os.path.join(t, "rules", "talon-terminate.yml")
    text = open(p).read().replace("talon.status: success", "talon.status: SECRETVALUE with spaces " + "x" * 600)
    open(p, "w").write(text)
    fake = FakeOS([])
    rc = make_sync(fake, FakeGit({A: t}), tmp=tmp).run()
    r = fake.records[-1]
    assert rc == 2 and "siem/rules/talon-terminate.yml: check_rule_values" in r["reason"], r["reason"]
    assert "SECRETVALUE" not in r["reason"] and len(r["reason"]) <= 512, r["reason"]


@with_tmp
def unmarked_adoption_refused(tmp):
    det = {"_id": "d1", "_source": {"name": "sdp-falco-rules", "inputs": [{"detector_input": {"description": "by hand"}}]}}
    fake = FakeOS([], live={"detectors": [det]})
    rc = make_sync(fake, FakeGit({A: SIEM}), tmp=tmp).run()
    r = fake.records[-1]
    assert rc == 2 and "did not make" in r["reason"] and "detector sdp-falco-rules" in r["reason"], r
    assert not fake.writes, f"wrote before refusing: {fake.writes[:3]}"
    rid = siem_lint.Tree(SIEM).rules["rules/talon-terminate.yml"]["id"]
    rule = {"_id": "hand1", "_source": {"category": "sdp_talon", "rule": open(os.path.join(SIEM, "rules/talon-terminate.yml")).read()}}
    fake = FakeOS([], live={"rules": [rule]})
    rc = make_sync(fake, FakeGit({A: SIEM}), tmp=tmp).run()
    assert rc == 2 and f"rule {rid} (SA id hand1)" in fake.records[-1]["reason"], fake.records[-1]


def changed_rules_live(n):
    tree = siem_lint.Tree(SIEM)
    hits, rmap = [], {}
    for rel, d in sorted(tree.rules.items())[:n]:
        text = tree.rule_text[rel] + "x-changed: 1\n"
        hits.append({"_id": f"sa-{d['id']}", "_source": {"category": tree.log_type_of(d["logsource"]["service"]), "rule": text}})
        rmap[d["id"]] = f"sa-{d['id']}"
    return hits, rmap


@with_tmp
def mass_change_refused(tmp):
    hits, rmap = changed_rules_live(6)
    fake = FakeOS([applied_rec(A, "2026-10-05T00:00:00.000Z", rules=rmap)], live={"rules": hits})
    rc = make_sync(fake, FakeGit({A: SIEM}), tmp=tmp).run()
    assert rc == 2 and "6 rule and monitor updates exceed the cap of 5" in fake.records[-1]["reason"], fake.records[-1]
    assert not fake.writes
    fake = FakeOS([applied_rec(A, "2026-10-05T00:00:00.000Z", rules=rmap)], live={"rules": hits})
    rc = make_sync(fake, FakeGit({A: SIEM}), flags=["allow-mass-change"], tmp=tmp).run()
    r = fake.records[-1]
    assert rc == 0 and r["status"] == "applied", r
    assert sorted(x for x in r["changed"]["rules"] if x.startswith("updated ")) == sorted(f"updated {k}" for k in rmap), r["changed"]
    assert os.path.exists(os.path.join(tmp, "state", "consumed", "allow-mass-change")), "flag not marked for removal"


@with_tmp
def failed_trees_managed_without_applied(tmp):
    t = empty_tree(tmp)
    recs = [{"commit": B, "status": "failed", "reason": "x", "applied_at": "2026-10-05T00:00:00.000Z"}]
    lt = {"_id": "lt1", "_source": {"name": "sdp_falco", "source": "Custom", "description": "d", "category": "Other"}}
    fake = FakeOS(recs, live={"logtype": [lt]})
    rc = make_sync(fake, FakeGit({A: t, B: SIEM}), tmp=tmp).run()
    r = fake.records[-1]
    assert rc == 0 and ("DELETE", "/_plugins/_security_analytics/logtype/lt1") in fake.writes, (r, fake.writes)
    assert r["changed"]["log_types"] == ["deleted sdp_falco"], r["changed"]


@with_tmp
def applied_commit_validated(tmp):
    fake = FakeOS([applied_rec("not-a-commit", "2026-10-05T00:00:00.000Z")])
    rc = make_sync(fake, FakeGit({A: SIEM}), tmp=tmp).run()
    assert rc == 1 and "40-hex" in fake.records[-1]["reason"], fake.records[-1]


def fetch_checks_objects():
    g = sync.Git("/nonexistent", "file", 5)
    seen = []
    g.run = lambda *a, **k: seen.append(a) or ("size: 1\nsize-pack: 2" if a[0] == "count-objects" else "c")
    os.makedirs = os.makedirs
    g.path = tempfile.mkdtemp()
    os.makedirs(os.path.join(g.path, "objects"))
    try:
        g.fetch("file:///x", "main")
        fetch = next(a for a in seen if "fetch" in a)
        assert "transfer.fsckObjects=true" in fetch and "fetch.fsckObjects=true" in fetch, fetch
        g.max_bytes = 1024
        try:
            g.fetch("file:///x", "main")
        except sync.SyncError as exc:
            assert "MiB" in str(exc)
        else:
            raise AssertionError("a repository over the size cap was accepted")
    finally:
        shutil.rmtree(g.path)


case("the client refuses the SA mappings API (F11)", mappings_refused)
case("a detector is not written when SA lacks one of its rule ids (S0-#12)", detector_readback)
case("the tree is exported as data: no symlink, nothing executable", export_as_data)
case("a refusal is recorded once per commit and reason; a reason is capped", refusal_once)
case("the last applied record is found behind 60 refusals (its own query)", applied_behind_refusals)
case("a no-op run writes the heartbeat, not a record", heartbeat_on_noop)
case("a fetch failure is recorded as failed", fetch_failure_recorded)
case("any exception is recorded as failed with its type", any_exception_recorded)
case("a lint refusal names files and checks, no values, capped", lint_reason_without_values)
case("live objects without the git marker are not adopted", unmarked_adoption_refused)
case("more than five updates are refused unless allow-mass-change exists; changes are listed", mass_change_refused)
case("trees of failed attempts are managed even without an applied record", failed_trees_managed_without_applied)
case("a commit read back from siem-sync must be 40-hex", applied_commit_validated)
case("fetch checks objects and caps the repository size", fetch_checks_objects)
total = 14
print(f"sync_unit_test: {total - len(fails)} passed, {len(fails)} failed")
sys.exit(1 if fails else 0)
