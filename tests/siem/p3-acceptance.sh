#!/usr/bin/env bash
# P3 live acceptance on siem01 (siem contract P3, L5, the synthetic half of L6). Run from the operator
# machine after the rules sync has applied the tree; touches nothing outside siem01 and changes nothing
# there it did not create itself:
#   - L5 / F11: every sdp-* template keeps its data stream, its pattern [<stream>] and no component, and
#     no SA alias-mappings component exists;
#   - the newest siem-sync record is "applied", and SA and Alerting hold exactly the tree's objects;
#   - the sdp-siem01 rules on real data: one accepted SSH login and one refused (a throwaway key);
#   - every other rule, correlation and monitor on synthetic documents (tests/siem/canary_docs.py)
#     written to the six k3s01 streams with a temporary identity shipper-test-g1 - signed through the
#     remote CSR entry point, mapped to the k3s01 shipper role for the run and unmapped at the end (the
#     run FAILS if it still has a role afterwards). The documents carry this pass's markers
#     (sandbox_p3c-<tag>-*, system:p3c-<tag>) and stay in the streams, like every document.
# Every remote step goes through one SSH control master (bursts of new connections into the Siem zone
# have been dropped), except the two SSH canaries, which must be logins of their own.
# Environment: SIEM_HOST (default 10.4.2.10), DOCKER (default docker).
set -euo pipefail
cd "$(dirname "$0")/../.."
DOCKER=${DOCKER:-docker}
HOST=${SIEM_HOST:-10.4.2.10}
work=$(mktemp -d)
cm=$work/cm
remote=""
mapped=0
CA=/etc/opensearch/certs/ca.crt
ADMIN="/etc/sdp-siem/pki/admin.crt /etc/sdp-siem/pki/admin.key"

ssh_siem() { ssh -o ControlPath="$cm" -o BatchMode=yes "ansible@$HOST" "$@"; }
ansible_siem() {
  $DOCKER run --rm -i -v "$PWD":/work -w /work/ansible -v "$HOME/.ssh":/ssh-src:ro -v "$work":/scratch \
    -e ANSIBLE_COLLECTIONS_PATH=/work/.ansible/collections \
    -e ANSIBLE_SSH_ARGS="-o ControlMaster=no -o ControlPath=/scratch/cm" sdp-tooling sh -ec \
    'cp -r /ssh-src /root/.ssh && chmod -R go-rwx /root/.ssh \
     && ansible-galaxy collection install -r requirements.yml -p /work/.ansible/collections >/dev/null \
     && ansible-playbook "$@"' ansible-playbook playbooks/siem.yml --limit siem01 "$@"
}
chk() { ssh_siem "sudo python3 $remote/sync_check.py https://127.0.0.1:9200 $CA $ADMIN $*"; }

cleanup() {
  local rc=$?
  set +e
  if [ "$mapped" = 1 ]; then
    echo "### cleanup: unmapping shipper-test-g1"
    ansible_siem --tags opensearch_config >"$work/unmap.log" 2>&1 || { tail -n 20 "$work/unmap.log"; rc=1; }
    roles=$(ssh_siem "sudo curl -sS -m 20 --cacert $CA --cert $remote/shipper-test.crt --key $remote/shipper-test.key \
      https://127.0.0.1:9200/_plugins/_security/authinfo" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("roles"))')
    if [ "$roles" = "[]" ]; then echo "ok   shipper-test-g1 holds no role any more"; else echo "FAIL shipper-test-g1 still holds $roles"; rc=1; fi
  fi
  [ -n "$remote" ] && ssh_siem "sudo shred -u $remote/*.key 2>/dev/null; sudo rm -rf $remote"
  ssh -o ControlPath="$cm" -O exit "ansible@$HOST" 2>/dev/null
  rm -rf "$work"
  exit "$rc"
}
trap cleanup EXIT

$DOCKER image inspect sdp-tooling >/dev/null 2>&1 || $DOCKER build -q -t sdp-tooling -f scripts/Dockerfile.tooling .
ssh -o ControlMaster=yes -o ControlPath="$cm" -o ControlPersist=30m -o BatchMode=yes -fN "ansible@$HOST"
remote=$(ssh_siem 'sudo mktemp -d /root/sdp-p3-acceptance.XXXXXX')
python3 ansible/roles/siem_sync/files/siem_lint.py --index siem > "$work/index.json"
for f in tests/siem/sync_check.py tests/siem/canary_docs.py "$work/index.json"; do
  name=$(basename "$f")
  ssh_siem "sudo tee $remote/$name >/dev/null" < "$f"
done
fail=0

echo "### L5 / F11: the templates after the sync"
chk guard || fail=1

echo "### the sync's record and what SA and Alerting hold"
chk records > "$work/records.json"
chk snapshot > "$work/snap.json"
python3 - "$work/records.json" "$work/snap.json" "$work/index.json" <<'PY' || fail=1
import json, sys
recs, snap, idx = (json.load(open(p)) for p in sys.argv[1:])
bad = []
applied = next((r for r in recs if r["status"] == "applied"), None)
if not recs or recs[0]["status"] != "applied":
    bad.append(f"newest siem-sync record: {recs[0] if recs else 'none'}")
want = {r["id"] for r in idx["rules"]}
have = {k: v for k, v in snap["rules"].items() if k in want}
if set(have) != want or any(len(v) != 1 for v in have.values()):
    bad.append(f"rules in SA: {len(have)} of {len(want)}, duplicates {[k for k, v in have.items() if len(v) != 1]}")
if applied and applied.get("rules") != {k: v[0] for k, v in have.items()}:
    bad.append("the record's Sigma -> SA map differs from SA")
lts = sorted(x for x in snap["log_types"] if x.startswith("sdp_"))
if len(lts) != 7:
    bad.append(f"log types {lts}")
dets = sorted(k for k in snap["detectors"] if k.endswith("-rules"))
if len(dets) != 7:
    bad.append(f"detectors {dets}")
if sorted(snap["correlations"]) != sorted(c["name"] for c in idx["correlations"]):
    bad.append(f"correlations {snap['correlations']}")
mons = sorted(k for k in snap["monitors"] if k.startswith("sdp-git: "))
if mons != sorted(m["name"] for m in idx["monitors"]):
    bad.append(f"monitors {mons}")
for b in bad:
    print(f"FAIL {b}")
if applied:
    print(f"ok   applied {applied['commit']} at {applied['applied_at']}: {len(have)} rules, {len(lts)} log types, "
          f"{len(dets)} detectors, {len(snap['correlations'])} correlations, {len(mons)} monitors")
sys.exit(1 if bad else 0)
PY

echo "### detectors have run once (S0-a), then the SSH canaries on siem01 itself"
newest=$(python3 -c "import json; d=json.load(open('$work/snap.json')); print(max(v['last_update_time'] or 0 for v in d['detectors'].values()))")
age=$(( $(date +%s) - newest / 1000 ))
[ "$age" -ge 70 ] || sleep $((70 - age))
since_ms=$(( $(date +%s) * 1000 - 5000 ))
if ssh -o ControlPath=none -o BatchMode=yes "ansible@$HOST" true; then echo "ok   an accepted login"; else echo "FAIL the accepted login"; fail=1; fi
ssh-keygen -q -t ed25519 -N '' -f "$work/unknown" -C p3-acceptance
if ssh -o ControlPath=none -o BatchMode=yes -o IdentitiesOnly=yes -i "$work/unknown" "nobody@$HOST" true 2>/dev/null; then
  echo "FAIL a login with an unknown key was accepted"; fail=1
else
  echo "ok   a refused login (unknown key, user nobody)"
fi

echo "### shipper-test-g1 through the remote CSR entry point, mapped for this run"
ssh_siem "sudo openssl req -new -newkey rsa:3072 -nodes -keyout $remote/shipper-test.key \
  -subj /O=sdp/OU=siem/CN=shipper-test-g1 2>/dev/null" >"$work/shipper-test.csr"
ansible_siem --tags client-cert -e siem_client_csr=/scratch/shipper-test.csr -e siem_client_name=shipper-test \
  -e siem_client_generation=1 >"$work/sign.log" 2>&1 || { tail -n 30 "$work/sign.log"; exit 1; }
ssh_siem "sudo tee $remote/shipper-test.crt >/dev/null" <"$work/shipper-test.crt"
mapped=1
ansible_siem --tags opensearch_config -e opensearch_config_test_identity=true >"$work/map.log" 2>&1 \
  || { tail -n 30 "$work/map.log"; exit 1; }
echo "ok   shipper-test-g1 signed and mapped to sdp_shipper_k3s01"

echo "### synthetic canaries in the six k3s01 streams"
ssh_siem "sudo python3 $remote/canary_docs.py --url https://127.0.0.1:9200 --ca $CA --admin $ADMIN \
  --writer $remote/shipper-test.crt $remote/shipper-test.key --index $remote/index.json \
  --streams sdp-falco,sdp-talon,sdp-hubble,sdp-k8s-audit,sdp-api,sdp-host --timeout 240" || fail=1

echo "### the sdp-siem01 rules fired on the two logins"
chk findings "$since_ms" > "$work/found.json"
python3 - "$work/found.json" <<'PY' || fail=1
import json, sys, yaml
found = json.load(open(sys.argv[1]))["rules"]
bad = 0
for slug in ("siem01-ssh-accepted", "siem01-ssh-failed"):
    rid = yaml.safe_load(open(f"siem/rules/{slug}.yml"))["id"]
    n = found.get(rid, 0)
    print(f"{'ok  ' if n else 'FAIL'} {slug}: {n} finding(s) since the logins")
    bad += not n
sys.exit(1 if bad else 0)
PY

if [ "$fail" != 0 ]; then echo "p3-acceptance: FAIL"; exit 1; fi
echo "p3-acceptance: PASS"
