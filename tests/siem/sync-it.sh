#!/usr/bin/env bash
# The rules sync end to end, offline (siem contract P3 tests, (M) sync). Containers on a private network:
#   - a throwaway OpenSearch (the pinned image) with siem01's certificate-only security, the sdp roles
#     (rules-sync as on siem01) and the seven data streams from the opensearch_config role;
#   - a "siem01" systemd container the siem_sync role is applied to, twice (the second run must change
#     nothing), serving the test repository as file:// (on siem01 it is GitHub over HTTPS).
# Each step commits to the test repository, starts sdp-siem-sync.service and checks the siem-sync
# record and what Security Analytics and Alerting hold:
#   first run: baseline recorded, every object created; the template guard (L5, F11); siem/x.sh in the
#     tree is never executed; the synthetic canaries (tests/siem/canary_docs.py) yield every finding
#     and monitor alert; an idempotent second run changes nothing and records nothing;
#   a changed rule keeps its SA id in its detector and the detector fires on the new logic;
#   S0-#12: a rule whose SA id vanished is re-created by POST - the old id never reappears;
#   a lint finding (a detector naming a rule that does not exist) is refused and changes nothing;
#   six managed deletions are refused, applied with allow-mass-delete, and the flag is removed;
#   a force-push is refused (once recorded), accept-commit applies it once and is removed;
#   an empty tree deletes every managed object and nothing else (MJ5: an unprefixed monitor, a
#   detector made by hand with its own rule and workflow survive).
# Needs docker and network access (apt in the container). KEEP=1 leaves the containers.
# SYNC_PY=<file> installs that program instead of the role's (tests/siem/p3-mutations.sh);
# QUICK=1 skips the two finding checks that wait for detectors (about four minutes).
set -euo pipefail
cd "$(dirname "$0")/../.."
DOCKER=${DOCKER:-docker}
NET=sdp-sync-it
OS=sdp-sync-it-os
H=sdp-sync-it-host
OS_IMAGE='opensearchproject/opensearch:3.9.0@sha256:adfa61f85025d06b4aeb562e7e74fde7e31c437039c93c3862c17e9acebd6c7c'
URL=https://172.31.252.10:9200

work=$(mktemp -d)
cleanup() {
  if [ -z "${KEEP:-}" ]; then
    for c in "$OS" "$H"; do $DOCKER rm -f "$c" >/dev/null 2>&1 || true; done
    $DOCKER network rm "$NET" >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT
step() { printf '\n==> %s\n' "$*"; }
fail() { echo "sync-it: FAIL - $*" >&2; $DOCKER exec "$H" journalctl -u sdp-siem-sync --no-pager -n 30 >&2 2>/dev/null || true; exit 1; }
ok() { echo "ok   $*"; }

$DOCKER image inspect sdp-target >/dev/null 2>&1 || $DOCKER build -q -t sdp-target -f tests/Dockerfile.target tests
$DOCKER image inspect sdp-tooling >/dev/null 2>&1 || $DOCKER build -q -t sdp-tooling -f scripts/Dockerfile.tooling .

step "test PKI (shaped like siem01's)"
pki=$work/pki
mkdir -p "$pki"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$pki/ca.key" -out "$pki/ca.crt" -days 30 -subj "/O=sdp/OU=siem/CN=sync-it-ca" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
issue() { # <name> <subject> <extensions>
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$pki/$1.key" 2>/dev/null
  openssl req -new -key "$pki/$1.key" -subj "$2" -out "$pki/$1.csr"
  printf '%b' "$3" > "$pki/$1.ext"
  openssl x509 -req -in "$pki/$1.csr" -CA "$pki/ca.crt" -CAkey "$pki/ca.key" -CAcreateserial -days 30 -sha256 \
    -extfile "$pki/$1.ext" -out "$pki/$1.crt" 2>/dev/null
}
issue node "/O=sdp/OU=node/CN=siem01" "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=IP:172.31.252.10,IP:127.0.0.1,DNS:siem01,DNS:localhost\n"
client_ext="basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n"
issue admin "/O=sdp/OU=siem/CN=admin-g1" "$client_ext"
issue rules-sync "/O=sdp/OU=siem/CN=rules-sync-g1" "$client_ext"
issue shipper-test "/O=sdp/OU=siem/CN=shipper-test-g1" "$client_ext"
chmod 0644 "$pki"/*

step "throwaway OpenSearch with siem01's security shape and roles"
mkdir -p "$work/sec"
cp ansible/roles/opensearch_config/files/security/*.yml "$work/sec/"
cat > "$work/sec/roles_mapping.yml" <<'EOF'
_meta:
  type: "rolesmapping"
  config_version: 2
sdp_rules_sync:
  users: ["rules-sync-g1"]
sdp_shipper_k3s01:
  users: ["shipper-test-g1"]
sdp_shipper_siem01:
  users: ["shipper-test-g1"]
EOF
cat > "$work/opensearch.yml" <<'EOF'
cluster.name: sync-it
node.name: siem01
discovery.type: single-node
network.host: 0.0.0.0
cluster.default_number_of_replicas: 0
plugins.security.ssl.transport.pemcert_filepath: certs/node.crt
plugins.security.ssl.transport.pemkey_filepath: certs/node.key
plugins.security.ssl.transport.pemtrustedcas_filepath: certs/ca.crt
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: certs/node.crt
plugins.security.ssl.http.pemkey_filepath: certs/node.key
plugins.security.ssl.http.pemtrustedcas_filepath: certs/ca.crt
plugins.security.ssl.http.clientauth_mode: REQUIRE
plugins.security.authcz.admin_dn: ["CN=admin-g1,OU=siem,O=sdp"]
plugins.security.nodes_dn: ["CN=siem01,OU=node,O=sdp"]
plugins.security.allow_default_init_securityindex: false
plugins.security.restapi.roles_enabled: []
EOF
chmod -R a+rX "$work/sec" "$work/opensearch.yml"
$DOCKER network rm "$NET" >/dev/null 2>&1 || true
$DOCKER network create --subnet 172.31.252.0/24 "$NET" >/dev/null
$DOCKER run -d --name "$OS" --network "$NET" --ip 172.31.252.10 --memory 2g --ulimit nofile=65536:65536 \
  -e DISABLE_INSTALL_DEMO_CONFIG=true -e DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI=true -e OPENSEARCH_JAVA_OPTS="-Xms768m -Xmx768m" \
  -v "$work/opensearch.yml":/usr/share/opensearch/config/opensearch.yml:ro \
  -v "$pki":/usr/share/opensearch/config/certs:ro \
  -v "$work/sec":/usr/share/opensearch/config/opensearch-security:ro \
  "$OS_IMAGE" >/dev/null

step "siem01 container (systemd) with the rules-sync identity where the opensearch role puts it"
$DOCKER run -d --name "$H" --hostname siem01 --network "$NET" --ip 172.31.252.11 --privileged --cgroupns=private \
  --tmpfs /run --tmpfs /run/lock --tmpfs /tmp -e container=docker sdp-target >/dev/null
for _ in $(seq 1 30); do
  $DOCKER exec "$H" systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break; sleep 1
done
# As in ingest-it.sh: systemd moves a unit's credentials mount out of a helper namespace, which needs a
# shared root mount (a VM's default).
$DOCKER exec "$H" mount --make-rshared /
$DOCKER exec "$H" install -d -m 0700 /etc/sdp-siem/pki
$DOCKER exec "$H" install -d -m 0755 /etc/opensearch/certs
$DOCKER cp "$pki/rules-sync.crt" "$H":/etc/sdp-siem/pki/rules-sync.crt
$DOCKER cp "$pki/rules-sync.key" "$H":/etc/sdp-siem/pki/rules-sync.key
$DOCKER cp "$pki/admin.crt" "$H":/etc/sdp-siem/pki/admin.crt
$DOCKER cp "$pki/admin.key" "$H":/etc/sdp-siem/pki/admin.key
$DOCKER cp "$pki/ca.crt" "$H":/etc/opensearch/certs/ca.crt
$DOCKER exec "$H" sh -ec 'chown root:root /etc/sdp-siem/pki/* /etc/opensearch/certs/ca.crt; chmod 0400 /etc/sdp-siem/pki/rules-sync.key /etc/sdp-siem/pki/admin.key'

tooling() { # <command...> in the tooling container on the test network
  $DOCKER run --rm --network "$NET" -v "$PWD":/work:ro -v "$pki":/pki:ro -v /var/run/docker.sock:/var/run/docker.sock \
    -e ANSIBLE_COLLECTIONS_PATH=/tmp/collections -e ANSIBLE_ROLES_PATH=/work/ansible/roles -e ANSIBLE_HOST_KEY_CHECKING=False \
    -e ANSIBLE_LOCAL_TEMP=/tmp/.ansible-local -w /work/ansible sdp-tooling sh -ec "
      ansible-galaxy collection install -r requirements.yml -p /tmp/collections >/dev/null
      ansible-galaxy collection install community.docker -p /tmp/collections >/dev/null
      $*"
}

step "initialise security, then pipeline, templates and the seven data streams"
for _ in $(seq 1 90); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --cacert "$pki/ca.crt" --cert "$pki/admin.crt" --key "$pki/admin.key" "$URL/" || true)
  [ "$code" != 000 ] && break; sleep 2
done
$DOCKER exec "$OS" bash -c 'cd /usr/share/opensearch && plugins/opensearch-security/tools/securityadmin.sh \
  -cd config/opensearch-security -icl -nhnv -h 127.0.0.1 -cacert config/certs/ca.crt -cert config/certs/admin.crt \
  -key config/certs/admin.key' >"$work/secadmin.log" 2>&1 || { cat "$work/secadmin.log"; fail "securityadmin"; }
tooling "ansible-playbook -i localhost, /work/tests/siem/sync-it.yml -e sync_it_url=$URL" >"$work/prepare.log" 2>&1 \
  || { tail -40 "$work/prepare.log"; fail "preparing OpenSearch"; }

step "siem-sync as an older sync left it (dynamic: false, no heartbeat fields), then the siem_sync role, twice"
curl -sS -o /dev/null --cacert "$pki/ca.crt" --cert "$pki/admin.crt" --key "$pki/admin.key" -X PUT -H 'Content-Type: application/json' \
  "$URL/siem-sync" -d '{"mappings":{"dynamic":false,"properties":{"commit":{"type":"keyword"},"applied_at":{"type":"date"},"status":{"type":"keyword"}}}}'
run_role() {
  tooling "ansible-playbook -i $H, -c community.docker.docker_api -e ansible_python_interpreter=/usr/bin/python3 \
    -e siem_sync_url=$URL -e siem_sync_repo_url=file:///srv/sdp-repo.git -e siem_sync_git_protocols=file \
    -e siem_sync_timer_enabled=false /work/tests/siem/sync-it-host.yml"
}
run_role >"$work/role1.log" 2>&1 || { tail -40 "$work/role1.log"; fail "siem_sync role run 1"; }
tail -3 "$work/role1.log"
run_role >"$work/role2.log" 2>&1 || { tail -40 "$work/role2.log"; fail "siem_sync role run 2"; }
grep -qE "$H +: ok=[0-9]+ +changed=0 +unreachable=0 +failed=0" "$work/role2.log" || { tail -20 "$work/role2.log"; fail "second run is not changed=0"; }
ok "role: second run changed=0"
curl -sS --cacert "$pki/ca.crt" --cert "$pki/admin.crt" --key "$pki/admin.key" "$URL/siem-sync/_mapping" \
  | python3 -c 'import json,sys; p=json.load(sys.stdin)["siem-sync"]["mappings"]["properties"]; sys.exit(0 if all(k in p for k in ("kind","checked_at","outcome","lint_sha256","allowed")) else 1)' \
  || fail "the role did not add the new fields to the existing siem-sync index"
ok "role: the existing siem-sync index gained kind, checked_at, outcome, lint_sha256, allowed"
if [ -n "${SYNC_PY:-}" ]; then
  $DOCKER cp "$SYNC_PY" "$H":/usr/local/lib/sdp-siem-sync/sdp_siem_sync.py
  echo "NOTE: running $SYNC_PY instead of the role's program"
fi
unit=$($DOCKER exec "$H" systemctl show sdp-siem-sync.service -p User -p NoNewPrivileges -p ProtectSystem -p CapabilityBoundingSet | sort | paste -sd' ')
case $unit in *"NoNewPrivileges=yes"*"ProtectSystem=strict"*"User=sdp-sync"*) ok "unit: $unit" ;; *) fail "unit: $unit" ;; esac

step "test repository (file://, owned by the sync's user like its own clone would be)"
# Root writes the test repository; git refuses another user's repository unless told it is safe.
$DOCKER exec "$H" sh -ec 'git config --system safe.directory "*"
  git init -q -b main /srv/work && git -C /srv/work config user.email t@example.test && git -C /srv/work config user.name test
  git init -q --bare -b main /srv/sdp-repo.git'
tar -c siem | $DOCKER exec -i "$H" tar -x -C /srv/work
# A script in the tree: data like everything else, never executed (it would leave the marker).
printf '#!/bin/sh\ntouch /var/lib/sdp-siem-sync/EXECUTED\n' | $DOCKER exec -i "$H" sh -c 'cat > /srv/work/siem/x.sh && chmod 0755 /srv/work/siem/x.sh'
commit() { # <message> -> prints the new commit (pushed to main, force allowed)
  $DOCKER exec "$H" sh -ec "cd /srv/work && git add -A && git commit -q -m '$1' && git push -q --force /srv/sdp-repo.git HEAD:main \
    && chown -R sdp-sync:sdp-sync /srv/sdp-repo.git && git rev-parse HEAD"
}
in_tree() { $DOCKER exec -i "$H" sh -ec "cd /srv/work && $1"; }
sync_run() { # -> prints the program's exit status
  $DOCKER exec "$H" systemctl start sdp-siem-sync.service >/dev/null 2>&1 || true
  $DOCKER exec "$H" systemctl show sdp-siem-sync.service -p ExecMainStatus --value
}
chk() { python3 tests/siem/sync_check.py "$URL" "$pki/ca.crt" "$pki/admin.crt" "$pki/admin.key" "$@"; }
j() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print($2)" "$1"; }
records() { chk records > "$work/rec.json"; j "$work/rec.json" 'len(d)'; }
last() { chk records > "$work/rec.json"; j "$work/rec.json" "d[0]$1"; }
snap() { chk snapshot > "$work/$1.json"; }

step "first run: the baseline"
c1=$(commit "the siem tree")
rc=$(sync_run)
[ "$rc" = 0 ] || fail "first run exit $rc"
{ [ "$(last "['status']")" = applied ] && [ "$(last "['commit']")" = "$c1" ] && [ "$(last "['previous']")" = "" ]; } \
  || fail "first record: $(head -c 400 "$work/rec.json")"
snap s1
[ "$(j "$work/s1.json" 'len([x for x in d["log_types"] if x.startswith("sdp_")])')" = 7 ] || fail "log types: $(j "$work/s1.json" 'd["log_types"]')"
[ "$(j "$work/s1.json" 'sum(1 for v in d["rules"].values() if len(v) == 1)')" = 25 ] || fail "rules: $(j "$work/s1.json" 'd["rules"]')"
[ "$(j "$work/s1.json" 'len(d["detectors"])')" = 7 ] || fail "detectors"
[ "$(j "$work/s1.json" 'd["correlations"]')" = "['contained-intrusion', 'dns-exfil']" ] || fail "correlations"
[ "$(j "$work/s1.json" 'sorted(k for k in d["monitors"] if k.startswith("sdp-git: "))')" = "['sdp-git: detection-missing', 'sdp-git: policy-probing', 'sdp-git: prevented-not-detected']" ] || fail "monitors"
ok "first run applied $c1: 7 log types, 25 rules, 7 detectors, 2 correlations, 3 monitors; record status applied, no previous"
chk guard || fail "template guard after the sync"
$DOCKER exec "$H" test ! -e /var/lib/sdp-siem-sync/EXECUTED || fail "siem/x.sh was executed"
ok "siem/x.sh in the tree was not executed"
chk oob-create
snap s1  # with the out-of-band objects, which every later snapshot holds too

if [ -z "${QUICK:-}" ]; then
  step "the synthetic canaries: every rule's finding and every monitor's alert (detectors run once first, S0-a)"
  sleep 75
  python3 ansible/roles/siem_sync/files/siem_lint.py --index siem > "$work/index.json"
  python3 tests/siem/canary_docs.py --url "$URL" --ca "$pki/ca.crt" --admin "$pki/admin.crt" "$pki/admin.key" \
    --writer "$pki/shipper-test.crt" "$pki/shipper-test.key" --index "$work/index.json" --timeout 240 || fail "synthetic canaries"
fi

step "an idempotent second run"
n=$(records)
rc=$(sync_run)
snap s2
{ [ "$rc" = 0 ] && [ "$(records)" = "$n" ]; } || fail "second run: exit $rc, records $n -> $(records)"
for key in rules detectors monitors; do
  [ "$(j "$work/s1.json" "json.dumps(d['$key'], sort_keys=True)")" = "$(j "$work/s2.json" "json.dumps(d['$key'], sort_keys=True)")" ] \
    || fail "second run changed $key"
done
$DOCKER exec "$H" journalctl -u sdp-siem-sync --no-pager -n 5 | grep -q "nothing to do" || fail "second run did not say nothing to do"
hb=$(chk heartbeat)
case $hb in *'"outcome": "unchanged"'*'"kind": "heartbeat"'*|*'"kind": "heartbeat"'*'"outcome": "unchanged"'*) ;; *) fail "heartbeat after the no-op run: $hb" ;; esac
n_hb=$(curl -sS --cacert "$pki/ca.crt" --cert "$pki/admin.crt" --key "$pki/admin.key" -H 'Content-Type: application/json' \
  "$URL/siem-sync/_search" -d '{"query":{"term":{"kind":"heartbeat"}}}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["hits"]["total"]["value"])')
[ "$n_hb" = 1 ] || fail "a term query on kind:heartbeat finds $n_hb documents (the API reads it that way)"
ok "second run: nothing to do, no record, rules/detectors/monitors untouched; heartbeat outcome unchanged and searchable by kind"

step "a changed rule stays attached to its detector"
talon_id=$(python3 -c "import yaml; print(yaml.safe_load(open('siem/rules/talon-terminate.yml'))['id'])")
sa_before=$(j "$work/s2.json" "d['rules']['$talon_id'][0]")
in_tree "sed -i 's/^    talon.status: success\$/    talon.status: success\n    talon.actionner: kubernetes:terminate/' siem/rules/talon-terminate.yml && grep -q 'talon.actionner' siem/rules/talon-terminate.yml"
c2=$(commit "talon-terminate also checks the actionner")
rc=$(sync_run)
snap s3
{ [ "$rc" = 0 ] && [ "$(last "['status']")" = applied ] && [ "$(last "['commit']")" = "$c2" ]; } || fail "changed rule: exit $rc"
[ "$(j "$work/s3.json" "d['rules']['$talon_id']")" = "['$sa_before']" ] || fail "the rule changed its SA id"
j "$work/s3.json" "d['rule_text']['$talon_id']" | grep -q 'talon.actionner: kubernetes:terminate' || fail "SA holds the old rule text"
j "$work/s3.json" "d['detectors']['sdp-talon-rules']['rules']" | grep -q "$sa_before" || fail "detector lost the rule"
[ "$(j "$work/s3.json" "d['detectors']['sdp-talon-rules']['description']")" != "$(j "$work/s2.json" "d['detectors']['sdp-talon-rules']['description']")" ] \
  || fail "the detector was not re-applied"
ok "changed rule: same SA id $sa_before, new text in SA, still in sdp-talon-rules (re-applied)"
if [ -z "${QUICK:-}" ]; then
  sleep 75
  ref="sandbox_p3c-reattach-$RANDOM"
  for actionner in kubernetes:terminate kubernetes:label; do
    printf '{"create":{}}\n{"@timestamp":"%s","event":{"kind":"action","dataset":"talon"},"talon":{"action":"Terminate Pod","action_slug":"terminate-pod","actionner":"%s","status":"success"},"k8s":{"pod":{"ref":"%s-%s"}}}\n' \
      "$(date -u +%FT%T.%3NZ)" "$actionner" "$ref" "${actionner#kubernetes:}"
  done > "$work/talon.ndjson"
  curl -sS -o /dev/null --cacert "$pki/ca.crt" --cert "$pki/shipper-test.crt" --key "$pki/shipper-test.key" \
    -H 'Content-Type: application/x-ndjson' --data-binary @"$work/talon.ndjson" "$URL/sdp-talon/_bulk"
  found=""
  for _ in $(seq 1 16); do
    found=$(curl -sS --cacert "$pki/ca.crt" --cert "$pki/admin.crt" --key "$pki/admin.key" \
      "$URL/_plugins/_security_analytics/findings/_search?detectorType=sdp_talon&size=500" | python3 -c "
import json,sys
d=json.load(sys.stdin); out=set()
for f in d.get('findings',[]):
    if any(q['id']=='$sa_before' for q in f['queries']):
        for x in f['document_list']:
            r=json.loads(x['document']).get('k8s',{}).get('pod',{}).get('ref','')
            if r.startswith('$ref'): out.add(r[len('$ref')+1:])
print(' '.join(sorted(out)))")
    [ -n "$found" ] && break; sleep 15
  done
  [ "$found" = terminate ] || fail "after the change the detector found '$found' (want terminate only)"
  ok "the detector fires on the changed rule: the terminate action matches, the label action no longer does"
fi

step "S0-#12: a rule whose SA id vanished is re-created by POST"
quar_id=$(python3 -c "import yaml; print(yaml.safe_load(open('siem/rules/talon-quarantine.yml'))['id'])")
old_sa=$(j "$work/s3.json" "d['rules']['$quar_id'][0]")
chk delete-rule "$quar_id" >/dev/null
rc=$(sync_run)
snap s4
{ [ "$rc" = 0 ] && [ "$(last "['status']")" = applied ]; } || fail "re-create: exit $rc $(last "['reason']")"
new_sa=$(j "$work/s4.json" "d['rules'].get('$quar_id', ['none'])[0]")
{ [ "$new_sa" != none ] && [ "$new_sa" != "$old_sa" ]; } || fail "rule not re-created (was $old_sa, now $new_sa)"
! chk rule-exists "$old_sa" || fail "the vanished id $old_sa exists again: the sync wrote to it (PUT creates, S0-#12)"
j "$work/s4.json" "d['detectors']['sdp-talon-rules']['rules']" | grep -q "$new_sa" || fail "detector does not list the new id"
[ "$(last "['rules']['$quar_id']")" = "$new_sa" ] || fail "record maps the old id"
ok "re-created as $new_sa by POST; $old_sa did not reappear; detector and record use the new id"

step "a lint finding is refused and changes nothing"
in_tree "echo '  - 00000000-0000-4000-8000-00000000dead  # no such rule' >> siem/detectors/talon.yaml"
c3=$(commit "a detector names a rule that does not exist")
rc=$(sync_run)
snap s5
{ [ "$rc" = 2 ] && [ "$(last "['status']")" = refused ] && [ "$(last "['commit']")" = "$c3" ]; } || fail "lint: exit $rc"
last "['reason']" | grep -q "lint (1 findings): siem/detectors/talon.yaml: check_detectors" || fail "reason: $(last "['reason']")"
! last "['reason']" | grep -q "00000000dead" || fail "the reason quotes a value from the commit"
[ "$(j "$work/s4.json" "json.dumps(d['detectors'], sort_keys=True)")" = "$(j "$work/s5.json" "json.dumps(d['detectors'], sort_keys=True)")" ] || fail "refused run changed detectors"
ok "refused (exit 2) with the lint finding; detectors untouched"
in_tree "sed -i '/00000000-0000-4000-8000-00000000dead/d' siem/detectors/talon.yaml"
c4=$(commit "fix the detector")
rc=$(sync_run)
{ [ "$rc" = 0 ] && [ "$(last "['commit']")" = "$c4" ] && [ "$(last "['previous']")" = "$c2" ]; } || fail "after the fix: exit $rc"
ok "the fix applies as a fast-forward from the last applied commit"

step "the delete cap: six managed deletions"
in_tree "python3 - <<'EOF'
import os, re, yaml
gone = ['api-recon-user', 'api-recon-system', 'api-recon-process', 'api-recon-files', 'api-credentials-flag', 'api-exec-shell']
ids = [yaml.safe_load(open(f'siem/rules/{s}.yml'))['id'] for s in gone]
for s in gone:
    os.remove(f'siem/rules/{s}.yml')
for path in ('siem/detectors/api.yaml', 'siem/canaries.yaml'):
    lines = open(path).read().split('\n')
    out, skip = [], False
    for line in lines:
        if any(i in line for i in ids):
            skip = path.endswith('canaries.yaml')
            continue
        if skip and line.startswith('    '):
            continue
        skip = False
        out.append(line)
    open(path, 'w').write('\n'.join(out))
EOF"
c5=$(commit "six rules removed")
rc=$(sync_run)
snap s6
{ [ "$rc" = 2 ] && [ "$(last "['status']")" = refused ]; } || fail "cap: exit $rc $(last "['reason']")"
last "['reason']" | grep -q "6 managed deletions (6 in 24 h) exceed the cap of 5" || fail "cap reason: $(last "['reason']")"
[ "$(j "$work/s6.json" 'len(d["rules"])')" = "$(j "$work/s4.json" 'len(d["rules"])')" ] || fail "refused run deleted rules"
ok "refused: 6 managed deletions exceed the cap; nothing deleted"
$DOCKER exec "$H" touch /etc/sdp-siem/allow-mass-delete
rc=$(sync_run)
snap s7
{ [ "$rc" = 0 ] && [ "$(last "['status']")" = applied ] && [ "$(last "['commit']")" = "$c5" ]; } || fail "with the flag: exit $rc $(last "['reason']")"
[ "$(last "['counts']['rules']['deleted']")" = 6 ] || fail "deleted $(last "['counts']")"
shell_id=$(python3 -c "import yaml; print(yaml.safe_load(open('siem/rules/api-exec-shell.yml'))['id'])")
{ [ "$(last "['changed']['rules'].__len__()")" = 6 ] && last "['changed']['rules']" | grep -q "deleted $shell_id"; } \
  || fail "the record does not list the deleted rules: $(last "['changed']")"
[ "$(j "$work/s7.json" 'len(d["rules"])')" = "$(( $(j "$work/s6.json" 'len(d["rules"])') - 6 ))" ] || fail "rules after the flagged run"
$DOCKER exec "$H" test ! -e /etc/sdp-siem/allow-mass-delete || fail "allow-mass-delete was not removed"
ok "with allow-mass-delete: 6 rules deleted, the flag removed by the unit"

step "a force-push is refused, accept-commit applies it once"
c5b=$($DOCKER exec "$H" sh -ec "cd /srv/work && git commit -q --amend -m 'six rules removed (rewritten)' && git push -q --force /srv/sdp-repo.git HEAD:main \
  && chown -R sdp-sync:sdp-sync /srv/sdp-repo.git && git rev-parse HEAD")
rc=$(sync_run)
{ [ "$rc" = 2 ] && [ "$(last "['status']")" = refused ] && last "['reason']" | grep -q "not a fast-forward from $c5"; } || fail "force-push: exit $rc $(last "['reason']")"
n=$(records)
rc=$(sync_run)
{ [ "$rc" = 2 ] && [ "$(records)" = "$n" ]; } || fail "the same refusal was recorded twice"
ok "non-fast-forward refused (exit 2), recorded once"
echo "$c5b" | $DOCKER exec -i "$H" sh -c 'cat > /etc/sdp-siem/accept-commit'
rc=$(sync_run)
{ [ "$rc" = 0 ] && [ "$(last "['status']")" = applied ] && [ "$(last "['commit']")" = "$c5b" ]; } || fail "accept-commit: exit $rc $(last "['reason']")"
$DOCKER exec "$H" test ! -e /etc/sdp-siem/accept-commit || fail "accept-commit was not removed"
rc=$(sync_run)
[ "$rc" = 0 ] || fail "after accept-commit: exit $rc"
ok "accept-commit: applied $c5b once, the flag removed, the next run is a plain fast-forward check"

step "an empty tree removes every managed object and nothing else (MJ5)"
in_tree "rm -rf siem/rules siem/detectors siem/correlations siem/monitors siem/log-types && printf 'rules: {}\ncorrelations: {}\nmonitors: {}\n' > siem/canaries.yaml"
c6=$(commit "empty tree")
$DOCKER exec "$H" touch /etc/sdp-siem/allow-mass-delete
rc=$(sync_run)
snap s8
{ [ "$rc" = 0 ] && [ "$(last "['status']")" = applied ]; } || fail "empty tree: exit $rc $(last "['reason']")"
[ "$(j "$work/s8.json" 'len([x for x in d["log_types"] if x.startswith("sdp_")])')" = 0 ] || fail "log types left: $(j "$work/s8.json" 'd["log_types"]')"
[ "$(j "$work/s8.json" '[k for k in d["rules"] if k != "0b0b0b0b-0000-4000-8000-000000000001"]')" = "[]" ] || fail "managed rules left"
[ "$(j "$work/s8.json" 'sorted(d["detectors"])')" = "['oob-detector']" ] || fail "detectors left: $(j "$work/s8.json" 'sorted(d["detectors"])')"
[ "$(j "$work/s8.json" 'd["correlations"]')" = "[]" ] || fail "correlations left"
[ "$(j "$work/s8.json" '[k for k in d["monitors"] if k.startswith("sdp-git: ")]')" = "[]" ] || fail "prefixed monitors left"
chk oob-check || fail "the sync touched objects it does not manage"
chk guard || fail "template guard after the last sync"
ok "empty tree $c6: every managed object gone; the unprefixed monitor and the hand-made detector, rule and workflow remain"
$DOCKER exec "$H" test ! -e /var/lib/sdp-siem-sync/EXECUTED || fail "siem/x.sh was executed"

echo
echo "sync-it: PASS"
