#!/usr/bin/env bash
# Generates app/api/internal/siemindex/index.json: the SIEM's detection content as the page lists it
# (ADR 0036, GET /api/correlation/rules) - every Sigma rule, `sdp-git: ` monitor and correlation rule in
# siem/, with its file and line and its canary. The API embeds it (its image is built from app/api
# alone) and turns a finding's rule title into the Sigma id with it; the page links each entry to the
# file at the commit the rules sync last applied.
#
# The index comes from the lint (siem_lint.py --index), so a tree the lint refuses has no index. Canary
# strings: api:terminal:<command id>[,<command id>...], api:scenario:<id>, exec:<command>,
# synthetic:<document set> (siem/canaries.yaml). `--check` regenerates into a temporary file and fails
# if the committed index differs. Needs python3 with PyYAML.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=app/api/internal/siemindex/index.json

generate() {
  python3 ansible/roles/siem_sync/files/siem_lint.py --index siem | python3 -c '
import json, re, sys
ix = json.load(sys.stdin)

def canary(c):
    c = c or {}
    if c.get("kind") == "api":
        return "api:terminal:" + ",".join(c["terminal"]) if c.get("terminal") else "api:scenario:" + c["scenario"]
    if c.get("kind") == "exec":
        return "exec:" + c["run"]
    return "synthetic:" + c.get("docs", "")

# The source is published: the SIEM host is not named by its node name (ADR 0021).
PUBLIC_SOURCE = {"siem01": "siem-host"}
out = {
    "rules": [{k: r[k] for k in ("id", "title", "level", "status", "attack", "file", "line")}
              | {"source": PUBLIC_SOURCE.get(r["source"], r["source"]), "canary": canary(r["canary"])}
              for r in ix["rules"]],
    "monitors": [{"name": m["name"], "file": m["file"], "canary": canary(m["canary"])} for m in ix["monitors"]],
    "correlations": [{"name": c["name"], "file": c["file"], "canary": canary(c["canary"])} for c in ix["correlations"]],
}
text = json.dumps(out, indent=2, ensure_ascii=False)
assert not re.search(r"k3s01|siem01|\\b\\d{1,3}(\\.\\d{1,3}){3}\\b", text), "the index would publish a node name or an address"
print(text)
'
}

if [ ! -d "$(dirname "$OUT")" ]; then
  # The package arrives with the API's incidents (P4); until it is in the tree there is nothing to write.
  echo "gen-siem-index: $(dirname "$OUT") does not exist, nothing to generate"
  exit 0
fi
if [ "${1:-}" = --check ]; then
  tmp=$(mktemp)
  trap 'rm -f "$tmp"' EXIT
  generate > "$tmp"
  if ! diff -u "$OUT" "$tmp" >/dev/null 2>&1; then
    diff -u "$OUT" "$tmp" | head -n 40 >&2 || true
    echo "gen-siem-index: $OUT is stale; run scripts/gen-siem-index.sh and commit it" >&2
    exit 1
  fi
  echo "gen-siem-index: $OUT is current ($(grep -c '"id":' "$tmp") rules)"
else
  generate > "$OUT"
  echo "gen-siem-index: wrote $OUT"
fi
