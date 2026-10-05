#!/usr/bin/env bash
# Live canaries (siem contract P3 tests, MJ6, live acceptance L6): every rule, correlation and monitor in
# siem/canaries.yaml is made to fire the way its canary says, and each must yield its finding or alert
# on siem01 within three minutes.
#   api   through the public API from the operator machine (tests/siem/canary_api.py): the terminal
#         commands in as few sessions as the detected ones allow, one run per one-click scenario.
#         Visible on the site like any visitor's run: run it outside visitor hours, after an announcement.
#   exec  tests/scenarios/run.sh (ONLY=shell-in-container), tests/admission/run.sh (KUBECONFIG needed),
#         and SSH logins to both hosts: one accepted, one refused with a throwaway key.
#   synthetic canaries are documents written with the temporary shipper-test identity:
#         tests/siem/p3-acceptance.sh runs them; they are skipped here.
# ROLLOVER=1 repeats the pass after a forced rollover of every stream (L6). SA correlations are evidence,
# not guaranteed (S0-e, F17): their count is reported, not required.
#
# Usage: tests/siem/canaries.sh [api|exec|all]       (default all)
# Environment: API_BASE (https://hubertjablon.ski), SIEM_HOST (10.4.2.10), K3S_HOST (10.4.1.20),
#              WAIT (180 s per pass for findings).
set -euo pipefail
cd "$(dirname "$0")/../.."
WHAT=${1:-all}
API_BASE=${API_BASE:-https://hubertjablon.ski}
HOST=${SIEM_HOST:-10.4.2.10}
K3S=${K3S_HOST:-10.4.1.20}
WAIT=${WAIT:-180}
work=$(mktemp -d)
cm=$work/cm
remote=""
# shellcheck disable=SC2317  # run by the EXIT trap
cleanup() {
  if [ -n "$remote" ]; then ssh -o ControlPath="$cm" "ansible@$HOST" "sudo rm -rf $remote" || true; fi
  ssh -o ControlPath="$cm" -O exit "ansible@$HOST" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
ssh_siem() { ssh -o ControlPath="$cm" -o BatchMode=yes "ansible@$HOST" "$@"; }
chk() { ssh_siem "sudo python3 $remote/sync_check.py https://127.0.0.1:9200 /etc/opensearch/certs/ca.crt /etc/sdp-siem/pki/admin.crt /etc/sdp-siem/pki/admin.key $*"; }

ssh -o ControlMaster=yes -o ControlPath="$cm" -o ControlPersist=30m -o BatchMode=yes -fN "ansible@$HOST"
remote=$(ssh_siem 'sudo mktemp -d /root/sdp-canaries.XXXXXX')
ssh_siem "sudo tee $remote/sync_check.py >/dev/null" < tests/siem/sync_check.py

# S0-a: a detector does not scan documents indexed before its first run.
wait_detectors() {
  chk snapshot > "$work/snap.json"
  local newest
  newest=$(python3 -c "import json; d=json.load(open('$work/snap.json')); print(max([v['last_update_time'] or 0 for v in d['detectors'].values()] or [0]))")
  local age=$(( $(date +%s) - newest / 1000 ))
  if [ "$age" -lt 70 ]; then echo "waiting $((70 - age)) s for the detectors' first run"; sleep $((70 - age)); fi
}

one_pass() { # <label>
  local start_ms fails=0
  wait_detectors
  start_ms=$(( $(date +%s) * 1000 - 5000 ))
  if [ "$WHAT" = api ] || [ "$WHAT" = all ]; then
    echo "### $1: api canaries through $API_BASE"
    python3 tests/siem/canary_api.py "$API_BASE" siem cluster/infra/sandbox/scenarios/scenarios.yaml | tee "$work/api.json"
  fi
  if [ "$WHAT" = exec ] || [ "$WHAT" = all ]; then
    echo "### $1: exec canaries"
    ONLY=shell-in-container tests/scenarios/run.sh > "$work/run.log" 2>&1 || { tail -20 "$work/run.log"; echo "FAIL tests/scenarios/run.sh"; fails=1; }
    tests/admission/run.sh > "$work/admission.log" 2>&1 || { tail -20 "$work/admission.log"; echo "FAIL tests/admission/run.sh"; fails=1; }
    ssh-keygen -q -t ed25519 -N '' -f "$work/unknown" -C canary
    for h in "$K3S" "$HOST"; do
      ssh -o ControlPath=none -o BatchMode=yes "ansible@$h" true || { echo "FAIL accepted login to $h"; fails=1; }
      ! ssh -o ControlPath=none -o BatchMode=yes -o IdentitiesOnly=yes -i "$work/unknown" "nobody@$h" true 2>/dev/null \
        || { echo "FAIL a login with an unknown key was accepted by $h"; fails=1; }
    done
    rm -f "$work/unknown" "$work/unknown.pub"
  fi
  echo "### $1: waiting up to $WAIT s for every finding and alert"
  local deadline=$(( $(date +%s) + WAIT )) missing
  while :; do
    chk findings "$start_ms" > "$work/found.json"
    missing=$(python3 - "$WHAT" "$work/found.json" <<'PY'
import json, sys, yaml
what, found = sys.argv[1], json.load(open(sys.argv[2]))
can = yaml.safe_load(open("siem/canaries.yaml"))
kinds = {"api": {"api"}, "exec": {"exec"}, "all": {"api", "exec"}}[what]
miss = [f"rule {i}" for i, c in can["rules"].items() if c["kind"] in kinds and not found["rules"].get(i)]
miss += [f"monitor {n}" for n, c in can["monitors"].items() if c["kind"] in kinds and not found["monitors"].get(n)]
print("\n".join(miss))
PY
)
    if [ -z "$missing" ] || [ "$(date +%s)" -gt "$deadline" ]; then break; fi
    sleep 20
  done
  python3 -c "import json; d=json.load(open('$work/found.json')); print(f\"found: {len(d['rules'])} rules, {len(d['monitors'])} monitors, {d['correlations']} SA correlations\")"
  if [ -n "$missing" ]; then
    while read -r m; do echo "FAIL no finding or alert: $m"; done <<<"$missing"
    fails=1
  fi
  return "$fails"
}

rc=0
one_pass "pass 1" || rc=1
if [ -n "${ROLLOVER:-}" ]; then
  echo "### forced rollover of every stream (L6)"
  for s in falco talon hubble k8s-audit api host siem01; do
    ssh_siem "sudo curl -sS -m 30 -o /dev/null -w 'sdp-$s %{http_code}\n' --cacert /etc/opensearch/certs/ca.crt \
      --cert /etc/sdp-siem/pki/admin.crt --key /etc/sdp-siem/pki/admin.key -X POST https://127.0.0.1:9200/sdp-$s/_rollover"
  done
  one_pass "pass 2 (after rollover)" || rc=1
fi
if [ "$rc" = 0 ]; then echo "canaries: PASS"; else echo "canaries: FAIL"; fi
exit "$rc"
