#!/usr/bin/env bash
# Mutation proof of the P3 tests (siem contract "Tests"): each mutation, applied to a scratch copy, must
# make its test fail. A mutation no test notices is a FAIL of this script.
#   lint:  every check of siem_lint.py disabled in turn (an early "return []") -> tests/siem/lint_test.py
#   unit:  the sync's offline guards removed -> tests/siem/sync_unit_test.py
#   slugs: the contained-intrusion slugs or Talon's rules changed -> tests/siem/talon_slugs_test.py
#   sync:  (SYNC=1, about six minutes each) the sync program mutated -> tests/siem/sync-it.sh QUICK=1
set -euo pipefail
cd "$(dirname "$0")/../.."
LINT=ansible/roles/siem_sync/files/siem_lint.py
PROG=ansible/roles/siem_sync/files/sdp_siem_sync.py
INDEX=ansible/roles/siem_sync/files/siem-sync-index.json
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

echo "### lint: single guards weakened"
lintm() { # <name> <old> <new>
  local m=$work/lintm-$1.py rc=0
  mutate "$LINT" "$m" "$2" "$3"
  python3 tests/siem/lint_test.py "$m" >"$work/log" 2>&1 || rc=$?
  verdict "lint $1" "$rc" "$work/log"
}
lintm regex-glob 'if not any(glob_match(token, n) for n in names):' \
  'if not any(re.match("^" + re.escape(token).replace(r"\*", ".*") + "$", n) for n in names):'
lintm no-token-cap 'if len(token) > MAX_TOKEN or any(len(n) > MAX_TOKEN for n in names):' 'if False:'
lintm case-sensitive-publish '"|k3s01|siem01|\.svc\b|cluster\.local", re.IGNORECASE)' '"|k3s01|siem01|\.svc\b|cluster\.local")'
lintm no-ipv6 'r"|(?<![0-9a-z])(?=[0-9a-f:]*[0-9a-f])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-z:])"' 'r"|(?!x)x"'
lintm any-query-type 'self.errs.append(f"query type {kind!r} is not allowed' 'pass  # self.errs.append(f"query type {kind!r} is not allowed'
lintm terms-lookup 'if kind == "terms" and not (isinstance(v, list)' 'if False and not (isinstance(v, list)'
lintm any-agg-type 'self.errs.append(f"aggregation type {kind!r} is not allowed")' 'pass'
lintm any-schedule 'and MONITOR_MINUTES[0] <= period["interval"] <= MONITOR_MINUTES[1]):' 'or True):'
lintm bool-no-should 'for key in ("filter", "must", "must_not", "should"):' 'for key in ("filter", "must", "must_not"):'
lintm metric-extra-keys 'or set(body) - {"field"} - extra:' 'or False:'
lintm unit-any 'period.get("unit") == "MINUTES"' 'True'
lintm bucket-or 'BUCKET_TRIGGER_RE = re.compile(rf"^{_CMP}( && {_CMP}){{0,7}}$")' 'BUCKET_TRIGGER_RE = re.compile(rf"^{_CMP}( (&&|\|\|) .*)?$")'
lintm query-trigger-any 'QUERY_TRIGGER_RE = re.compile(r"^ctx\.results\[0\]\.hits\.total\.value (==|>=|>) \d{1,6}$")' 'QUERY_TRIGGER_RE = re.compile(r"^ctx")'
lintm bucket-below-zero '((==|>=|>) \d{1,6}|' '((==|>=|>|<|<=) -?\d{1,6}|'
lintm exists-extra-keys 'if not isinstance(body, dict) or set(body) != {"field"}:' 'if not isinstance(body, dict) or "field" not in body:'
lintm size-uncapped 'and 0 <= body.get("size", 0) <= 100):' 'or True):'
lintm term-any-value 'set(v) <= {"value", "boost"}' 'True'
lintm range-any-keys 'elif kind == "range" and not (isinstance(v, dict) and set(v) <= RANGE_KEYS):' 'elif kind == "range" and not isinstance(v, dict):'
lintm ipv6-after-colon 'r"|(?<![0-9a-z])(?=[0-9a-f:]*[0-9a-f])' 'r"|(?<![0-9a-z:])(?=[0-9a-f:]*[0-9a-f])'
lintm any-trigger 'or set(script) != {"source", "lang"} or not want.match(source):' 'or False:'

echo "### unit: the sync's guards removed"
mkdir -p "$work/unit-control" && cp "$LINT" "$INDEX" "$PROG" "$work/unit-control/"
python3 tests/siem/sync_unit_test.py "$work/unit-control/sdp_siem_sync.py" >"$work/log" 2>&1 \
  || { cat "$work/log"; echo "the unmutated copy fails: the harness is broken"; exit 1; }
unit() { # <name> <old> <new>; the copy sits next to the lint, as installed
  local m=$work/unit-$1/sdp_siem_sync.py rc=0
  mkdir -p "$work/unit-$1" && cp "$LINT" "$INDEX" "$work/unit-$1/"
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
unit no-change-cap '(updates, past_updated, self.cfg["change_cap"]' '(0, past_updated, self.cfg["change_cap"]'
unit failed-trees-need-applied 'commits = [applied["commit"]] if applied else []' 'commits = [applied["commit"]] if applied else []
        if not applied:
            return out'
unit applied-commit-unchecked 'if recs and not HEX40.match(str(recs[0].get("commit", ""))):' 'if False:'
unit no-fsck '"-c", "transfer.fsckObjects=true", "-c", "fetch.fsckObjects=true", ' ''
unit no-repo-cap 'if size > self.max_bytes:' 'if False:'
unit size-cap-keeps-pack 'shutil.rmtree(self.path, ignore_errors=True)
            raise SyncError(f"the fetched repository holds' 'raise SyncError(f"the fetched repository holds'
unit lint-in-process 'findings = self.lint(root)' 'findings = siem_lint.lint_detailed(root)[0]'
unit no-lint-timeout 'timeout=self.cfg.get("lint_timeout", 60), check=False)' 'check=False)'
unit upd-cap-rules-only 'plan["rules"] + plan["monitors"] + plan["correlations"]' 'plan["rules"]'
unit upd-cap-no-correlations 'plan["rules"] + plan["monitors"] + plan["correlations"]' 'plan["rules"] + plan["monitors"]'
unit del-cap-no-monitors 'sum(len(plan[k]) for k in ("del_monitors", ' 'sum(len(plan[k]) for k in ('
unit no-day-window 'past_deleted, past_updated = self.recent()' 'past_deleted, past_updated = 0, 0'
unit flagged-runs-count 'if "allow-mass-delete" not in allowed:' 'if True:'
unit hb-skip-refused 'self.heartbeat(base["commit"], outcome)' 'self.heartbeat(base["commit"], outcome) if outcome != "refused" else None'
unit sweep-skipped 'self.sweep()
        if not os.path.isdir' 'if not os.path.isdir'
unit failed-fetch-kept '# pack behind; drop the repository, the next run starts from nothing.
            shutil.rmtree(self.path, ignore_errors=True)' '# pack behind.'
unit recent-rules-only-updates 'for k in ("rules", "monitors", "correlations"))' 'for k in ("rules",))'
unit cap-off-by-one 'if count and count + past > cap:' 'if count and count + past >= cap:'
unit cap-zero-count 'if count and count + past > cap:' 'if count + past > cap:'
unit allowed-not-recorded 'changed=self.changed, allowed=self.allowed,' 'changed=self.changed,'
unit recent-applied-only-removed '{"bool": {"filter": [{"term": {"status": "applied"}},' '{"bool": {"filter": ['
unit flag-skips-both-caps 'if "allow-mass-change" not in allowed:' 'if not allowed:'
unit ff-accept-any 'if accept != commit and not self.git.is_ancestor(accept, commit):' 'if False:'

echo "### slugs: contained-intrusion against Talon's rules (tests/siem/talon_slugs_test.py)"
slugm() { # <name> <file> <old> <new>; a copy of the files the test reads
  local t=$work/slug-$1 rc=0
  mkdir -p "$t/cluster/infra/falco-response/talon"
  cp -r siem "$t/siem" && cp cluster/infra/falco-response/talon/rules.yaml "$t/cluster/infra/falco-response/talon/"
  mutate "$2" "$t/$2" "$3" "$4"
  python3 tests/siem/talon_slugs_test.py "$t" >"$work/log" 2>&1 || rc=$?
  verdict "slugs $1" "$rc" "$work/log"
}
slugm misspelt siem/correlations/contained-intrusion.yaml 'sdp-network-tool-in-sandbox OR' 'sdp-network-tool-in-sandbx OR'
slugm dropped siem/correlations/contained-intrusion.yaml ' OR sdp-execution-from-shop-volume)' ')'
slugm talon-rule-added cluster/infra/falco-response/talon/rules.yaml '      - SDP execution from shop volume
' '      - SDP execution from shop volume
      - SDP execution from tmp
'
slugm no-detector-rule siem/detectors/falco.yaml '  - 44a53745-246a-4179-bb42-04ce4b023de8  # falco-shop-volume-exec
' ''

if [ -n "${SYNC:-}" ]; then
  echo "### sync: the program mutated, against sync-it.sh"
  syncm() { # <name> <old> <new>
    local m=$work/sync-$1/sdp_siem_sync.py rc=0
    mkdir -p "$work/sync-$1" && cp "$LINT" "$INDEX" "$work/sync-$1/"
    mutate "$PROG" "$m" "$2" "$3"
    SYNC_PY=$m QUICK=1 tests/siem/sync-it.sh >"$work/log-$1" 2>&1 || rc=$?
    verdict "sync $1" "$rc" "$work/log-$1"
  }
  syncm put-recorded-id '_, out = self.c.req("POST", f"{SA}/rules?category={category}", text)' \
    'sid = tree.rules[rel]["id"]; _, out = (self.c.req("PUT", f"{SA}/rules/{self.prev_rules[sid]}?category={category}&forced=true", text) if sid in self.prev_rules else self.c.req("POST", f"{SA}/rules?category={category}", text)); out = {"_id": self.prev_rules.get(sid, out.get("_id"))}'
  syncm no-fast-forward-check 'elif not self.git.is_ancestor(applied["commit"], commit):' 'elif False:'
  syncm accept-commit-ignored 'if accept is not None:' 'if False:'
  syncm no-delete-cap '(deletions, past_deleted, self.cfg["delete_cap"]' '(0, past_deleted, self.cfg["delete_cap"]'
  syncm no-lint 'raise Refused(f"lint ({len(findings)} findings): " + "; ".join(names))' 'pass'
  syncm manages-every-monitor '{"prefix": {"monitor.name.keyword": PREFIX}})' '{"match_all": {}})
        hits = [h for h in hits if h["_source"].update(name=PREFIX + h["_source"].get("name", "")) or True]'
  syncm not-idempotent 'elif rec.get("id") != live[0][0] or' 'elif True or'
fi

echo
echo "p3-mutations: $killed killed, $survived survived"
[ "$survived" = 0 ]
