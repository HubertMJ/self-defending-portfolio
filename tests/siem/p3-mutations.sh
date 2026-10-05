#!/usr/bin/env bash
# Mutation proof of the P3 tests (siem contract "Tests"): each mutation, applied to a scratch copy, must
# make its test fail. A mutation no test notices is a FAIL of this script.
#   lint:  every check of siem_lint.py disabled in turn (an early "return []") -> tests/siem/lint_test.py
#   unit:  the sync's offline guards removed -> tests/siem/sync_unit_test.py
#   sync:  (SYNC=1, about six minutes each) the sync program mutated -> tests/siem/sync-it.sh QUICK=1
set -euo pipefail
cd "$(dirname "$0")/../.."
LINT=ansible/roles/siem_sync/files/siem_lint.py
PROG=ansible/roles/siem_sync/files/sdp_siem_sync.py
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
killed=0 survived=0
verdict() { # <name> <test exit status> <log>
  if [ "$2" != 0 ]; then killed=$((killed + 1)); echo "killed   $1 ($(grep -m1 -E '^FAIL |sync-it: FAIL' "$3" | cut -c1-140))"
  else survived=$((survived + 1)); echo "SURVIVED $1"; fi
}
# mutate <src> <dst> <python expression old> <new>: exact, single replacement, or the mutation is broken
mutate() {
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import sys
src, dst, old, new = sys.argv[1:]
s = open(src).read()
assert s.count(old) == 1, f"mutation anchor found {s.count(old)} times: {old!r}"
open(dst, "w").write(s.replace(old, new))
PY
}

echo "### lint: each check disabled"
grep -oE '^def check_[a-z_]+' "$LINT" | cut -d' ' -f2 > "$work/checks"
while read -r fn; do
  m=$work/lint-$fn.py
  mutate "$LINT" "$m" "def $fn(t):
" "def $fn(t):
    return []
"
  rc=0; python3 tests/siem/lint_test.py "$m" >"$work/log" 2>&1 || rc=$?
  verdict "lint $fn" "$rc" "$work/log"
done < "$work/checks"

echo "### unit: the sync's guards removed"
mkdir -p "$work/unit-control" && cp "$LINT" "$PROG" "$work/unit-control/"
python3 tests/siem/sync_unit_test.py "$work/unit-control/sdp_siem_sync.py" >"$work/log" 2>&1 \
  || { cat "$work/log"; echo "the unmutated copy fails: the harness is broken"; exit 1; }
unit() { # <name> <old> <new>; the copy sits next to the lint, as installed
  local m=$work/unit-$1/sdp_siem_sync.py rc=0
  mkdir -p "$work/unit-$1" && cp "$LINT" "$work/unit-$1/"
  mutate "$PROG" "$m" "$2" "$3"
  python3 tests/siem/sync_unit_test.py "$m" >"$work/log" 2>&1 || rc=$?
  verdict "unit $1" "$rc" "$work/log"
}
unit mappings-allowed 'if "/_security_analytics/mappings" in path:' 'if False:'
unit no-detector-readback 'missing = self.rules_exist(ids, tree.log_type_of(d["source"]))' 'missing = set()'
unit symlink-exported 'if kind != "blob" or mode not in ("100644", "100755"):' 'if kind != "blob":'
unit exec-mode-kept 'os.chmod(target, 0o644)' 'os.chmod(target, int(mode[-3:], 8))'
unit refusal-every-run 'if rec["status"] != "applied" and last and' 'if False and last and'
unit applied-among-recent 'recs = self._search_records({"term": {"status": "applied"}}, 1)' \
  'recs = [r for r in self._search_records({"exists": {"field": "applied_at"}}, 50) if r.get("status") == "applied"][:1]'
unit no-heartbeat 'self.heartbeat(base["commit"], outcome)' 'pass'
unit only-syncerror-recorded 'except Exception as exc:  # noqa: BLE001 - every failure is recorded, whatever raised it' \
  'except SyncError as exc:'
unit fetch-outside-try '        used_accept = False
        try:' '        used_accept = False
        self.git.fetch(self.cfg["repo"], self.cfg["branch"])
        try:'
unit lint-values-recorded 'names = sorted({f"{path}: {check}" for path, check, _ in findings})' \
  'names = sorted({f"{path}: {msg}" for path, _, msg in findings})'
unit reason-uncapped 'rec = dict(rec, reason=cap(rec.get("reason", "")), lint_sha256=LINT_SHA256)' \
  'rec = dict(rec, lint_sha256=LINT_SHA256)'
unit adopts-unmarked 'if unmarked:' 'if False:'
unit no-change-cap 'if updates > self.cfg["change_cap"]:' 'if False:'
unit failed-trees-need-applied 'commits = [applied["commit"]] if applied else []' 'commits = [applied["commit"]] if applied else []
        if not applied:
            return out'
unit applied-commit-unchecked 'if recs and not HEX40.match(str(recs[0].get("commit", ""))):' 'if False:'
unit no-fsck '"-c", "transfer.fsckObjects=true", "-c", "fetch.fsckObjects=true", ' ''
unit no-repo-cap 'if size > self.max_bytes:' 'if False:'

if [ -n "${SYNC:-}" ]; then
  echo "### sync: the program mutated, against sync-it.sh"
  syncm() { # <name> <old> <new>
    local m=$work/sync-$1/sdp_siem_sync.py rc=0
    mkdir -p "$work/sync-$1" && cp "$LINT" "$work/sync-$1/"
    mutate "$PROG" "$m" "$2" "$3"
    SYNC_PY=$m QUICK=1 tests/siem/sync-it.sh >"$work/log-$1" 2>&1 || rc=$?
    verdict "sync $1" "$rc" "$work/log-$1"
  }
  syncm put-recorded-id '_, out = self.c.req("POST", f"{SA}/rules?category={category}", text)' \
    'sid = tree.rules[rel]["id"]; _, out = (self.c.req("PUT", f"{SA}/rules/{self.prev_rules[sid]}?category={category}&forced=true", text) if sid in self.prev_rules else self.c.req("POST", f"{SA}/rules?category={category}", text)); out = {"_id": self.prev_rules.get(sid, out.get("_id"))}'
  syncm no-fast-forward-check 'elif not self.git.is_ancestor(applied["commit"], commit):' 'elif False:'
  syncm accept-commit-ignored 'if accept is not None:' 'if False:'
  syncm no-delete-cap 'if deletions > self.cfg["delete_cap"]:' 'if False:'
  syncm no-lint 'raise Refused(f"lint ({len(findings)} findings): " + "; ".join(names))' 'pass'
  syncm manages-every-monitor '{"prefix": {"monitor.name.keyword": PREFIX}})' '{"match_all": {}})
        hits = [h for h in hits if h["_source"].update(name=PREFIX + h["_source"].get("name", "")) or True]'
  syncm not-idempotent 'elif rec.get("id") != live[0][0] or' 'elif True or'
fi

echo
echo "p3-mutations: $killed killed, $survived survived"
[ "$survived" = 0 ]
