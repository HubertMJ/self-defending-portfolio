#!/usr/bin/env bash
# P1 live acceptance on siem01 (siem contract P1 tests, L1 siem01 part, L2, L8; ADR 0034
# "Acceptance tests"). Run from the operator machine after `make siem`; changes nothing it did not
# create itself:
#   - a temporary client identity shipper-test-g1: key and CSR made on siem01, signed through the
#     remote entry point (sign_client_csr.yml via siem.yml --tags client-cert), mapped to the k3s01
#     shipper role for the duration of the run and unmapped at the end - the run FAILS if the mapping
#     is still there afterwards;
#   - a few documents in sdp-falco marked event.kind=acceptance, one forced rollover of sdp-falco,
#     one snapshot and one restored copy of a backing index (both deleted again).
# Expected codes are the S0 matrix (S0-d, S0-#8): a _bulk refusal is HTTP 200 with item status 403.
#
# Every remote step goes through ONE ssh connection (a control master): bursts of new SSH
# connections from the operator network to the Siem zone have been observed to be dropped for a
# few minutes.
#
# Environment: SIEM_HOST (default 10.4.2.10), DOCKER (default docker), P1_WAIT_HOURLY=1 waits for the
# next hourly snapshot of the policy instead of taking one (L2 as written; up to 60 minutes).
set -euo pipefail
cd "$(dirname "$0")/../.."
DOCKER=${DOCKER:-docker}
HOST=${SIEM_HOST:-10.4.2.10}
work=$(mktemp -d)
cm=$work/cm
remote_tmp=""
mapped=0

ssh_siem() { ssh -o ControlPath="$cm" -o BatchMode=yes "ansible@$HOST" "$@"; }

# Ansible in the tooling container, multiplexed over the same control master.
ansible_siem() {
  $DOCKER run --rm -i -v "$PWD":/work -w /work/ansible -v "$HOME/.ssh":/ssh-src:ro -v "$work":/scratch \
    -e ANSIBLE_COLLECTIONS_PATH=/work/.ansible/collections \
    -e ANSIBLE_SSH_ARGS="-o ControlMaster=no -o ControlPath=/scratch/cm" sdp-tooling sh -ec \
    'cp -r /ssh-src /root/.ssh && chmod -R go-rwx /root/.ssh \
     && ansible-galaxy collection install -r requirements.yml -p /work/.ansible/collections >/dev/null \
     && ansible-playbook "$@"' ansible-playbook playbooks/siem.yml --limit siem01 "$@"
}

cleanup() {
  local rc=$?
  set +e
  if [ "$mapped" = 1 ]; then
    echo "### cleanup: unmapping shipper-test-g1"
    ansible_siem --tags opensearch_config >"$work/unmap.log" 2>&1 || tail -n 20 "$work/unmap.log"
  fi
  [ -n "$remote_tmp" ] && ssh_siem "sudo shred -u $remote_tmp/*.key 2>/dev/null; sudo rm -rf $remote_tmp"
  ssh -o ControlPath="$cm" -O exit "ansible@$HOST" 2>/dev/null
  rm -rf "$work"
  exit "$rc"
}
trap cleanup EXIT

$DOCKER image inspect sdp-tooling >/dev/null 2>&1 || $DOCKER build -q -t sdp-tooling -f scripts/Dockerfile.tooling .
ssh -o ControlMaster=yes -o ControlPath="$cm" -o ControlPersist=30m -o BatchMode=yes -fN "ansible@$HOST"

echo "### 0: a temporary identity shipper-test-g1 through the remote CSR entry point"
remote_tmp=$(ssh_siem 'sudo mktemp -d /root/sdp-p1-acceptance.XXXXXX')
ssh_siem "sudo openssl req -new -newkey rsa:3072 -nodes -keyout $remote_tmp/shipper-test.key \
  -subj /O=sdp/OU=siem/CN=shipper-test-g1 2>/dev/null" >"$work/shipper-test.csr"
ansible_siem --tags client-cert -e siem_client_csr=/scratch/shipper-test.csr -e siem_client_name=shipper-test \
  -e siem_client_generation=1 >"$work/sign.log" 2>&1 || { tail -n 30 "$work/sign.log"; exit 1; }
ssh_siem "sudo tee $remote_tmp/shipper-test.crt >/dev/null" <"$work/shipper-test.crt"
mapped=1
ansible_siem --tags opensearch_config -e opensearch_config_test_identity=true >"$work/map.log" 2>&1 \
  || { tail -n 30 "$work/map.log"; exit 1; }
echo "ok   0: shipper-test-g1 signed via sign_client_csr.yml and mapped to sdp_shipper_k3s01"

echo "### 1-9 on siem01"
fail=0
ssh_siem "sudo T=$remote_tmp WAIT_HOURLY=${P1_WAIT_HOURLY:-0} bash -s" <<'REMOTE' || fail=1
set -uo pipefail
U=https://127.0.0.1:9200
CA=/etc/opensearch/certs/ca.crt
fail=0
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }
# req <identity> <METHOD> <path> [json body] -> prints the HTTP code, body in $T/body
req() {
  local id=$1 m=$2 p=$3 b=${4-} cert key
  # $(...) strips trailing newlines; a bulk body must end with one.
  [[ $p == *_bulk* ]] && b+=$'\n'
  case $id in
    admin) cert=/etc/sdp-siem/pki/admin.crt key=/etc/sdp-siem/pki/admin.key ;;
    shipper) cert=$T/shipper-test.crt key=$T/shipper-test.key ;;
    dashboards) cert=/etc/opensearch-dashboards/certs/dashboards.crt key=/etc/opensearch-dashboards/certs/dashboards.key ;;
  esac
  if [ -n "$b" ]; then
    curl -sS -m 60 -o "$T/body" -w '%{http_code}' --cacert "$CA" --cert "$cert" --key "$key" -X "$m" \
      -H 'Content-Type: application/json' --data-binary "$b" "$U$p"
  else
    curl -sS -m 60 -o "$T/body" -w '%{http_code}' --cacert "$CA" --cert "$cert" --key "$key" -X "$m" "$U$p"
  fi
}
# j <python expression over d> -> evaluates against the last body
j() { python3 -c "import json,sys; d=json.load(open('$T/body')); print($1)" 2>/dev/null; }
expect() { # <expected code> <description> <identity> <METHOD> <path> [body]
  local want=$1 desc=$2 got; shift 2
  got=$(req "$@")
  if [ "$got" = "$want" ]; then ok "$desc -> $got"; else bad "$desc -> $got, want $want: $(head -c 300 "$T/body")"; fi
}
expect_item() { # <description> <identity> <path> <ndjson>: HTTP 200 with items[0] status 403
  local desc=$1 got item; shift
  got=$(req "$1" POST "$2" "$3")
  item=$(j "list(d['items'][0].values())[0]['status']" 2>/dev/null)
  if [ "$got" = 200 ] && [ "$item" = 403 ]; then ok "$desc -> 200, item 403"
  else bad "$desc -> $got, item $item: $(head -c 300 "$T/body")"; fi
}
refused() { [ "$1" -ge 400 ] 2>/dev/null; }
refusal_reason() { grep -oE 'client-supplied _id refused|cluster_block_exception|security_exception' "$T/body" | head -n 1; }
now=$(date +%s)
mark="p1-acceptance-$now"
doc() { printf '{"@timestamp":"%s","event":{"kind":"acceptance","dataset":"falco"},"falco":{"rule":"%s"}}' "$(date -u +%FT%TZ)" "$1"; }
bulk_create() { # <identity> <stream> <marker> -> sets CREATED_INDEX CREATED_ID (shipper-style create, no id)
  local got
  got=$(req "$1" POST "/$2/_bulk" "$(printf '{"create":{}}\n%s\n' "$(doc "$3")")")
  CREATED_INDEX=$(j "d['items'][0]['create'].get('_index','')") CREATED_ID=$(j "d['items'][0]['create'].get('_id','')")
  [ "$got" = 200 ] && [ "$(j "d['items'][0]['create']['status']")" = 201 ]
}

# --- 5: TLS only with a client certificate; a password header is ignored -----------------------
code=$(curl -sS -m 10 -o /dev/null -w '%{http_code}' --cacert "$CA" "$U/" 2>"$T/tls.err"); rc=$?
if [ "$rc" != 0 ] && [ "$code" = 000 ]; then ok "5 no client certificate -> no TLS session (curl rc $rc: $(grep -oE 'alert [a-z ]+|certificate required' "$T/tls.err" | head -n1))"
else bad "5 no client certificate -> rc $rc code $code"; fi
code=$(curl -sS -m 10 -o /dev/null -w '%{http_code}' --cacert "$CA" -u admin:x "$U/" 2>/dev/null); rc=$?
if [ "$rc" != 0 ] && [ "$code" = 000 ]; then ok "5 -u admin:x without a certificate -> no TLS session (curl rc $rc)"
else bad "5 -u admin:x without a certificate -> rc $rc code $code"; fi
got=$(curl -sS -m 10 -o "$T/body" -w '%{http_code}' --cacert "$CA" --cert "$T/shipper-test.crt" --key "$T/shipper-test.key" \
  -u admin:x "$U/_plugins/_security/authinfo")
user=$(j "d.get('user_name')")
if [ "$got" = 200 ] && [ "$user" = shipper-test-g1 ]; then ok "5 valid certificate + basic header -> authinfo user $user (header ignored)"
else bad "5 valid certificate + basic header -> $got user $user"; fi

# --- 1: a data stream refuses op_type index ------------------------------------------------------
if bulk_create shipper sdp-falco "$mark-1"; then
  ok "1 setup: shipper-style _bulk create into sdp-falco -> 201 ($CREATED_INDEX)"
  expect 400 "1 PUT sdp-falco/_doc/<id>" shipper PUT "/sdp-falco/_doc/$CREATED_ID" "$(doc "$mark-1x")"
else
  bad "1 setup: shipper-style create into sdp-falco failed: $(head -c 300 "$T/body")"; exit 1
fi

# F1: a Fluent-Bit-style create (no id) is stamped event.overwrite=false and the server's
# event.ingested, even when the client sends its own values for both (S0-c).
got=$(req shipper POST /sdp-falco/_bulk "$(printf '{"create":{}}\n{"@timestamp":"%s","event":{"kind":"acceptance","dataset":"falco","overwrite":true,"ingested":"2000-01-01T00:00:00Z"},"event.overwrite":true}\n' "$(date -u +%FT%TZ)")")
fid=$(j "d['items'][0]['create']['_id']") findex=$(j "d['items'][0]['create']['_index']")
req admin GET "/$findex/_doc/$fid" >/dev/null
stamp=$(j "(d['_source']['event']['overwrite'], d['_source']['event']['ingested'][:4], 'event.overwrite' in d['_source'])")
if [ "$stamp" = "(False, '$(date -u +%Y)', False)" ]; then ok "1 F1 create without an id: client-sent event.overwrite/ingested replaced -> overwrite false, ingested now"
else bad "1 F1 create without an id stored $stamp"; fi

# --- 2: CAS on a rolled backing index is write-blocked -------------------------------------------
bulk_create shipper sdp-falco "$mark-2" || { bad "2 setup: create failed"; exit 1; }
rolled=$CREATED_INDEX rolled_id=$CREATED_ID
req admin GET "/$rolled/_doc/$rolled_id" >/dev/null
seq=$(j "d['_seq_no']") term=$(j "d['_primary_term']")
expect 200 "2 setup: admin forces the rollover of sdp-falco" admin POST /sdp-falco/_rollover
t0=$(date +%s) blocked=""
while [ $(( $(date +%s) - t0 )) -lt 240 ]; do
  req admin GET "/$rolled/_settings/index.blocks.write?flat_settings=true" >/dev/null
  blocked=$(j "d['$rolled']['settings'].get('index.blocks.write','')")
  [ "$blocked" = true ] && break
  sleep 5
done
if [ "$blocked" = true ]; then ok "2 ISM write-blocked $rolled $(( $(date +%s) - t0 )) s after the rollover (bound 240 s)"
else bad "2 $rolled not write-blocked within 240 s (B7)"; fi
got=$(req shipper PUT "/$rolled/_doc/$rolled_id?if_seq_no=$seq&if_primary_term=$term" "$(doc "$mark-2-rewrite")")
# Two controls refuse this write now: the ISM write block (proven by the settings read above) and
# sdp-final's refusal of any client-supplied _id, which runs first on the ingest path.
if refused "$got"; then ok "2 CAS on the rolled $rolled -> $got ($(refusal_reason))"
else bad "2 CAS on the rolled index -> $got: $(head -c 300 "$T/body")"; fi
got=$(req shipper POST /_bulk "$(printf '{"index":{"_index":"%s","_id":"%s","if_seq_no":%s,"if_primary_term":%s}}\n%s\n' "$rolled" "$rolled_id" "$seq" "$term" "$(doc "$mark-2-bulk")")")
item=$(j "d['items'][0]['index']['status']")
if [ "$got" = 200 ] && [ -n "$item" ] && [ "$item" -ge 400 ]; then ok "2 the same CAS through _bulk -> 200, item $item ($(refusal_reason))"
else bad "2 the same CAS through _bulk -> $got, item $item: $(head -c 300 "$T/body")"; fi

# --- 3: the role refuses everything but create ---------------------------------------------------
bulk_create shipper sdp-falco "$mark-3" || { bad "3 setup: create failed"; exit 1; }
w=$CREATED_INDEX wid=$CREATED_ID
AUDIT=/var/log/opensearch/sdp-security-audit.log
audit_denied() { grep -F '"audit_category":"MISSING_PRIVILEGES"' "$AUDIT" | grep -F '"audit_request_effective_user":"shipper-test-g1"' \
  | grep -cF '"audit_request_privilege":"indices:data/write/delete"'; }
before=$(audit_denied)
expect 403 "3 DELETE $w/_doc/<id>" shipper DELETE "/$w/_doc/$wid"
sleep 2
after=$(audit_denied)
if [ "$after" -gt "$before" ]; then ok "3 the refused DELETE is in the security audit log (MISSING_PRIVILEGES, shipper-test-g1, indices:data/write/delete)"
else bad "3 no MISSING_PRIVILEGES line for the refused DELETE in $AUDIT"; fi
expect_item "3 _bulk delete" shipper /_bulk "$(printf '{"delete":{"_index":"%s","_id":"%s"}}\n' "$w" "$wid")"
expect 403 "3 POST $w/_update/<id>" shipper POST "/$w/_update/$wid" '{"doc":{"falco":{"rule":"x"}}}'
expect_item "3 _bulk update" shipper /_bulk "$(printf '{"update":{"_index":"%s","_id":"%s"}}\n{"doc":{"falco":{"rule":"x"}}}\n' "$w" "$wid")"
expect 403 "3 _delete_by_query" shipper POST /sdp-falco/_delete_by_query '{"query":{"match_all":{}}}'
expect 403 "3 _update_by_query" shipper POST /sdp-falco/_update_by_query '{"query":{"match_all":{}}}'
expect 403 "3 PUT sdp-falco/_mapping" shipper PUT /sdp-falco/_mapping '{"properties":{"x":{"type":"keyword"}}}'
expect 403 "3 PUT $w/_settings (lift the write block, drop final_pipeline)" shipper PUT "/$w/_settings" \
  '{"index":{"blocks.write":false,"final_pipeline":null}}'
expect 403 "3 POST sdp-falco/_rollover" shipper POST /sdp-falco/_rollover
expect 403 "3 PUT _snapshot/sdp-snapshots/<x>" shipper PUT "/_snapshot/sdp-snapshots/shipper-$now"
expect 403 "3 ISM remove on the write index" shipper POST "/_plugins/_ism/remove/$w"
expect 403 "3 ISM change_policy on the write index" shipper POST "/_plugins/_ism/change_policy/$w" '{"policy_id":"sdp-30d"}'
expect 403 "3 write to sdp-siem01" shipper POST /sdp-siem01/_doc "$(doc "$mark-3-siem01")"
expect_item "3 _bulk create into sdp-siem01" shipper /_bulk "$(printf '{"create":{"_index":"sdp-siem01"}}\n%s\n' "$(doc "$mark-3b")")"

# --- 8 (setup) + 4: snapshot holds the original; no rewrite of the current write index either -------
bulk_create shipper sdp-falco "$mark-4-original" || { bad "4 setup: create failed"; exit 1; }
w=$CREATED_INDEX wid=$CREATED_ID
if [ "$WAIT_HOURLY" = 1 ]; then
  echo "     8: waiting for the next hourly snapshot of sdp-hourly (up to 60 min)"
  snap="" t0=$(date +%s)
  while [ -z "$snap" ] && [ $(( $(date +%s) - t0 )) -lt 3900 ]; do
    sleep 60
    req admin GET "/_snapshot/sdp-snapshots/_all" >/dev/null
    snap=$(j "next((s['snapshot'] for s in d['snapshots'] if s['state']=='SUCCESS' and s['start_time_in_millis']/1000 > $t0 and s['snapshot'].startswith('sdp-hourly')), '')")
  done
  keep_snap=1
else
  snap="p1-acceptance-$now"
  req admin PUT "/_snapshot/sdp-snapshots/$snap?wait_for_completion=true" \
    '{"indices":"sdp-falco","include_global_state":false}' >/dev/null
  keep_snap=0
fi
if [ -n "$snap" ]; then ok "8 setup: snapshot $snap holds $w"; else bad "8 no snapshot to restore from"; fi
req admin GET "/$w/_doc/$wid" >/dev/null
seq=$(j "d['_seq_no']") term=$(j "d['_primary_term']")
# sdp-final refuses every write that carries a client-supplied _id (F1, prevented): a CAS overwrite
# of the current write index, an id-carrying create, and the same through _bulk - for the shipper and
# for the admin alike, since the final pipeline is not a permission.
for who in shipper admin; do
  got=$(req "$who" PUT "/$w/_doc/$wid?if_seq_no=$seq&if_primary_term=$term" "$(doc "$mark-4-rewritten")")
  if refused "$got" && [ "$(refusal_reason)" = "client-supplied _id refused" ]; then ok "4 $who: CAS overwrite on the current write index $w -> $got (client-supplied _id refused)"
  else bad "4 $who: CAS overwrite on the current write index -> $got: $(head -c 300 "$T/body")"; fi
done
got=$(req shipper POST /_bulk "$(printf '{"index":{"_index":"%s","_id":"%s","if_seq_no":%s,"if_primary_term":%s}}\n%s\n' "$w" "$wid" "$seq" "$term" "$(doc "$mark-4-bulk")")")
item=$(j "d['items'][0]['index']['status']")
if [ "$got" = 200 ] && [ -n "$item" ] && [ "$item" -ge 400 ] && [ "$(refusal_reason)" = "client-supplied _id refused" ]; then
  ok "4 the same CAS through _bulk -> 200, item $item (client-supplied _id refused)"
else bad "4 CAS through _bulk -> $got, item $item: $(head -c 300 "$T/body")"; fi
got=$(req shipper PUT "/sdp-falco/_create/$mark-4-own-id" "$(doc "$mark-4-own-id")")
if refused "$got" && [ "$(refusal_reason)" = "client-supplied _id refused" ]; then ok "4 create with a client id (sdp-falco/_create/<id>) -> $got (client-supplied _id refused)"
else bad "4 create with a client id -> $got: $(head -c 300 "$T/body")"; fi
req admin GET "/$w/_doc/$wid" >/dev/null
if [ "$(j "(d['_source']['falco']['rule'], d['_seq_no'])")" = "('$mark-4-original', $seq)" ]; then ok "4 the document is unchanged (same _source, same seq_no)"
else bad "4 the document changed: $(head -c 300 "$T/body")"; fi
req admin POST "/_plugins/_alerting/monitors/_search" '{"query":{"term":{"monitor.name.keyword":"evidence rewritten"}}}' >/dev/null
[ "$(j "d['hits']['hits'][0]['_source']['monitor']['enabled']")" = True ] && ok "4 \"evidence rewritten\" stays enabled as defence in depth" \
  || bad "4 \"evidence rewritten\" is not enabled"

# --- 8: restore the backing index from the snapshot under a new name: the original is there -----
restored="p1-restore-$now"
req admin POST "/_snapshot/sdp-snapshots/$snap/_restore?wait_for_completion=true" \
  "{\"indices\":\"$w\",\"rename_pattern\":\".+\",\"rename_replacement\":\"$restored\",\"include_global_state\":false,\"include_aliases\":false}" >/dev/null
req admin GET "/$restored/_doc/$wid" >/dev/null
orig=$(j "d['_source']['falco']['rule']" 2>/dev/null)
if [ "$orig" = "$mark-4-original" ]; then ok "8 restored $w from $snap as $restored: original _source is back ($orig)"
else bad "8 restored document: $orig"; fi
req admin DELETE "/$restored" >/dev/null
[ "$keep_snap" = 0 ] && req admin DELETE "/_snapshot/sdp-snapshots/$snap" >/dev/null

# --- L8: the Dashboards identity cannot write ----------------------------------------------------
expect 403 "L8 dashboards certificate: PUT sdp-falco/_doc/x" dashboards PUT /sdp-falco/_doc/x "$(doc "$mark-l8")"

# --- 6, 7, 9: health, settings, F11 guard -------------------------------------------------------
req admin GET "/_cluster/health" >/dev/null
[ "$(j "d['status']")" = green ] && ok "6 _cluster/health green" || bad "6 _cluster/health $(j "d['status']")"
req admin GET "/_cluster/settings?include_defaults=true&flat_settings=true" >/dev/null
for kv in cluster.default_number_of_replicas=0 plugins.index_state_management.history.number_of_replicas=0 \
  plugins.security_analytics.alert_history_retention_period=30d plugins.security_analytics.finding_history_retention_period=30d \
  plugins.security_analytics.correlation_history_retention_period=30d plugins.alerting.alert_history_retention_period=30d \
  plugins.security_analytics.auto_correlations_enabled=false; do
  k=${kv%%=*} v=${kv#*=}
  got=$(j "{**d['defaults'], **d['persistent'], **d['transient']}.get('$k')")
  [ "$got" = "$v" ] && ok "7 $k = $got" || bad "7 $k = $got, want $v"
done
req admin GET "/_plugins/_performanceanalyzer/config" >/dev/null
[ "$(j "d['performanceAnalyzerEnabled'] or d['rcaEnabled']")" = False ] && ok "7 Performance Analyzer and RCA off" \
  || bad "7 Performance Analyzer: $(head -c 200 "$T/body")"
req admin GET "/_index_template/sdp-*" >/dev/null
bad_tpl=$(j "[t['name'] for t in d['index_templates'] if t['index_template']['index_patterns'] != [t['name']] or t['index_template'].get('composed_of', []) != [] or 'data_stream' not in t['index_template']]")
n_tpl=$(j "len(d['index_templates'])")
[ "$bad_tpl" = "[]" ] && [ "$n_tpl" = 7 ] && ok "9 seven templates: index_patterns [<stream>], composed_of [], data stream" || bad "9 templates: $n_tpl, drifted $bad_tpl"
got=$(req admin GET "/_component_template/.opensearch-sap-alias-mappings-component-*")
if [ "$got" = 404 ] || [ "$(j "len(d.get('component_templates', []))")" = 0 ]; then ok "9 no .opensearch-sap-alias-mappings-component-*"
else bad "9 SA alias components exist: $(head -c 300 "$T/body")"; fi
exit $fail
REMOTE

echo "### L8 from the operator machine"
if curl -sS -m 5 -o /dev/null "http://$HOST:5601" 2>/dev/null; then echo "FAIL L8 http://$HOST:5601 answered"; fail=1
else echo "ok   L8 http://$HOST:5601 is not reachable"; fi
ssh -o ControlPath="$cm" -O forward -L 15601:127.0.0.1:5601 "ansible@$HOST"
status=$(curl -sS -m 30 -o "$work/dash.json" -w '%{http_code}' http://127.0.0.1:15601/api/status || true)
ssh -o ControlPath="$cm" -O cancel -L 15601:127.0.0.1:5601 "ansible@$HOST" 2>/dev/null
if [ "$status" = 200 ] && grep -q '"state":"green"' "$work/dash.json"; then echo "ok   L8 Dashboards loads through the SSH tunnel (api/status 200, green)"
else echo "FAIL L8 Dashboards through the tunnel: $status $(head -c 200 "$work/dash.json")"; fail=1; fi

echo "### unmap shipper-test-g1 and prove it is gone"
ansible_siem --tags opensearch_config >"$work/unmap.log" 2>&1 || { tail -n 30 "$work/unmap.log"; fail=1; }
mapped=0
users=$(ssh_siem "sudo curl -sS -m 30 --cacert /etc/opensearch/certs/ca.crt --cert /etc/sdp-siem/pki/admin.crt \
  --key /etc/sdp-siem/pki/admin.key https://127.0.0.1:9200/_plugins/_security/api/rolesmapping/sdp_shipper_k3s01")
if [ -n "$users" ] && ! grep -q 'shipper-test' <<<"$users"; then echo "ok   cleanup: shipper-test-g1 is no longer mapped ($users)"
else echo "FAIL cleanup: shipper-test-g1 is still mapped: $users"; fail=1; fi

if [ "$fail" != 0 ]; then echo "p1-acceptance: FAIL"; exit 1; fi
echo "p1-acceptance: PASS"
