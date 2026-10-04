#!/usr/bin/env bash
# Mutation proof of the P2 ingest tests (siem contract "Tests"): each mutation is applied to a scratch
# copy of the tree - never to the worktree - and the named test, run against that copy, must FAIL.
# A mutation its test survives is a blocker.
#
# Usage: tests/siem/p2-mutations.sh            the fast set (Lua filter, audit policy, Cilium values)
#        tests/siem/p2-mutations.sh --all      also the end-to-end ones (tests/siem/ingest-it.sh, ~5 min each)
#        tests/siem/p2-mutations.sh <id>...    only these mutations
set -euo pipefail
cd "$(dirname "$0")/../.."
DOCKER=${DOCKER:-docker}
export DOCKER
REPO=$PWD

# id | test | file | python expression on the file text s (must change it) | what it breaks
MUTATIONS=(
  "lua-kat|lua|ansible/roles/fluent_bit/files/sdp.lua|s.replace('0x428a2f98', '0x428a2f99', 1)|a SHA-256 constant (the start-up KAT must stop Fluent Bit)"
  "lua-ipad|lua|ansible/roles/fluent_bit/files/sdp.lua|s.replace('bxor(k, 0x36)', 'bxor(k, 0x37)').replace('if tohex(hmac_sha256(\"Jefe\"', 'if false and tohex(hmac_sha256(\"Jefe\"')|HMAC inner pad, with the KAT switched off (the CI vectors must catch it)"
  "lua-passthrough|lua|ansible/roles/fluent_bit/files/sdp.lua|s.replace('return 1, event_ts or ts, out', 'return 1, event_ts or ts, record')|projection: the input record is forwarded as it came"
  "lua-system|lua|ansible/roles/fluent_bit/files/sdp.lua|s.replace('if v:sub(1, 7) == \"system:\" then return v end', 'do return v end')|F3: every audit user kept verbatim"
  "lua-f2|lua|ansible/roles/fluent_bit/files/sdp.lua|s.replace('local function audit_keep(rec)', 'local function audit_keep(rec) do return true end')|F2: every audit event shipped"
  "lua-f13|lua|ansible/roles/fluent_bit/files/sdp.lua|s.replace('return type(rec.flow) == \"table\"', 'return true')|F13: Hubble's non-flow records shipped"
  "lua-ref|lua|ansible/roles/fluent_bit/files/sdp.lua|s.replace('if f.name == \"k8s.pod.ref\" and v ~= nil and not v:match(REF_PATTERN) then v = nil end', '')|a pod ref that is not <ns>_<pod> shipped"
  "lua-f1|lua|siem/fields/api.yaml|s.replace('fields:\\n', 'fields:\\n  event.overwrite: {type: boolean, from: event.overwrite}\\n', 1)|F1: an allow-list that lets a client-sent event.overwrite through"
  "audit-order|audit|ansible/roles/k3s/templates/audit-policy.yaml.j2|s.replace('  - level: Metadata\\n    resources:\\n      - group: authentication.k8s.io\\n        resources: [\"*\"]\\n', '').replace('  # Everything else: who, what, when.', '  - level: Metadata\\n    resources:\\n      - group: authentication.k8s.io\\n        resources: [\"*\"]\\n\\n  # Everything else: who, what, when.')|the Metadata rule after the RequestResponse rule (TokenReviews keep their bodies)"
  "cilium-ip|cilium|ansible/roles/cilium/defaults/main.yml|s.replace('          - event_type\\n', '          - event_type\\n          - IP\\n')|addresses in the Hubble export (Ansible side)"
  "e2e-sandbox|e2e|ansible/roles/fluent_bit/templates/sdp.conf.j2|s.replace('InaccessiblePaths=', '# InaccessiblePaths=')|no InaccessiblePaths in the role's drop-in (the start check must refuse the start)"
  "e2e-check|e2e|ansible/roles/fluent_bit/files/sandbox-check.sh|s.replace('    exit 1\\n', '    exit 0\\n')|the start check reports but never refuses"
  "e2e-hostname|e2e|ansible/roles/fluent_bit/templates/fluent-bit.conf.j2|s.replace('tls.verify_hostname      On', 'tls.verify_hostname      Off')|host name verification off on the outputs"
  "e2e-id|e2e|ansible/roles/fluent_bit/templates/fluent-bit.conf.j2|s.replace('    Write_Operation          create\\n', '    Write_Operation          create\\n    Generate_ID              On\\n')|an id on every write (sdp-final refuses it, nothing arrives)"
)
# The Cilium mutation needs both sides changed, or the equality check fails for the wrong reason.
EXTRA_cilium_ip="cluster/apps/cilium.yaml|s.replace('                - event_type\\n', '                - event_type\\n                - IP\\n')"

run_test() { # <kind> <tree>
  case $1 in
    lua) LUA_TEST_ROOT=$2 tests/siem/lua-hmac.sh ;;
    audit) AUDIT_TEST_ROOT=$2 tests/golden/audit-policy.sh ;;
    cilium) (cd "$2" && scripts/check-cilium-values.sh) ;;
    e2e) (cd "$2" && tests/siem/ingest-it.sh) ;;
  esac
}

mutate() { # <tree> <file> <expression>
  python3 - "$1/$2" "$3" <<'PY'
import sys
path, expr = sys.argv[1], sys.argv[2]
s = open(path).read()
t = eval(expr, {"s": s})
if t == s:
    sys.exit(f"mutation did not change {path}")
open(path, "w").write(t)
PY
}

want=("$@")
all=0
[ "${1:-}" = "--all" ] && { all=1; want=(); }
fail=0 n=0
for m in "${MUTATIONS[@]}"; do
  IFS='|' read -r id kind file expr what <<<"$m"
  if [ "${#want[@]}" -gt 0 ]; then
    printf '%s\n' "${want[@]}" | grep -qx "$id" || continue
  elif [ "$kind" = e2e ] && [ "$all" = 0 ]; then
    continue
  fi
  n=$((n + 1))
  tree=$(mktemp -d)
  git ls-files -co --exclude-standard | tar -cf - -T - | tar -xf - -C "$tree"
  mutate "$tree" "$file" "$expr"
  if [ "$id" = cilium-ip ]; then IFS='|' read -r f2 e2 <<<"$EXTRA_cilium_ip"; mutate "$tree" "$f2" "$e2"; fi
  if run_test "$kind" "$tree" >"$tree.log" 2>&1; then
    echo "SURVIVED $id ($what): the $kind test passed"; fail=1
  else
    echo "killed   $id ($what): $(grep -m1 -E 'FAIL|refusing|unknown transform|not an allowed|differs|expected|  - ' "$tree.log" | cut -c1-150)"
  fi
  rm -rf "$tree" "$tree.log"
done
cd "$REPO"
[ "$n" -gt 0 ] || { echo "p2-mutations: no mutation selected"; exit 2; }
if [ "$fail" != 0 ]; then echo "p2-mutations: a mutation survived"; exit 1; fi
echo "p2-mutations: all $n mutations killed"
