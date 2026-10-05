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
    except AssertionError as exc:
        print(f"FAIL {name}: {exc}")
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


case("the client refuses the SA mappings API (F11)", mappings_refused)
case("a detector is not written when SA lacks one of its rule ids (S0-#12)", detector_readback)
case("the tree is exported as data: no symlink, nothing executable", export_as_data)
case("a refusal is recorded once per commit and reason", refusal_once)
print(f"sync_unit_test: {4 - len(fails)} passed, {len(fails)} failed")
sys.exit(1 if fails else 0)
