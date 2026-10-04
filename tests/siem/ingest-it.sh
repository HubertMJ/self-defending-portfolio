#!/usr/bin/env bash
# The fluent_bit role end to end, k3s01 profile, offline (siem contract P2: k3s01 is changed only in a
# maintenance window, so its behaviour is proven here first). Containers on a private network:
#   - a throwaway OpenSearch (the pinned image) with certificate-only security, the P1 roles and the
#     sdp-final pipeline, templates and data streams from the opensearch_config role;
#   - a "signer" systemd container holding a test CA where siem01 holds the real one;
#   - a "k3s01" systemd container with a root-0600 /etc/rancher/k3s/k3s.yaml.
# ingest.yml runs against the k3s01 container twice (the second run must change nothing): the
# client CSR is signed through the real remote entry point on the signer, the unit starts inside its
# sandbox. Then the F0 fixtures are appended to the files at their real k3s01 paths, ssh and sudo
# lines go through journald, and the documents that arrive are checked (tests/siem/ingest_check.py).
# Also proven:
#   N5    tls.verify_hostname On accepts the node certificate's IP SAN (the shipper's own writes) and
#         refuses a name the certificate does not carry (a one-shot Fluent Bit via the container's
#         DNS name gets no document in; the same with verify_hostname Off does);
#   MJ8   the start check: with InaccessiblePaths removed from the drop-in the unit refuses to start
#         with "sandbox broken";
#   unit  active, InaccessiblePaths lists /etc/rancher, nothing listens but 127.0.0.1:2020.
# Needs docker and network access (apt and the Fluent Bit repository). KEEP=1 leaves the containers.
set -euo pipefail
cd "$(dirname "$0")/../.."
DOCKER=${DOCKER:-docker}
NET=sdp-ingest-it
OS=sdp-ingest-os
SIGNER=sdp-ingest-signer
K3S=sdp-ingest-k3s
OS_IMAGE='opensearchproject/opensearch:3.9.0@sha256:adfa61f85025d06b4aeb562e7e74fde7e31c437039c93c3862c17e9acebd6c7c'

work=$(mktemp -d)
cleanup() {
  if [ -z "${KEEP:-}" ]; then
    for c in "$OS" "$SIGNER" "$K3S" sdp-ingest-n5; do $DOCKER rm -f "$c" >/dev/null 2>&1 || true; done
    $DOCKER network rm "$NET" >/dev/null 2>&1 || true
    $DOCKER volume rm sdp-ingest-it-collections >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT
step() { printf '\n==> %s\n' "$*"; }
fail() { echo "ingest-it: FAIL - $*" >&2; exit 1; }

$DOCKER image inspect sdp-target >/dev/null 2>&1 || $DOCKER build -q -t sdp-target -f tests/Dockerfile.target tests
$DOCKER image inspect sdp-tooling >/dev/null 2>&1 || $DOCKER build -q -t sdp-tooling -f scripts/Dockerfile.tooling .
read -r FB_VERSION FB_SHA256 < <(python3 -c '
import sys, yaml
v = yaml.safe_load(open(sys.argv[1]))
print(v["fluent_bit_version"], v["fluent_bit_deb_sha256"])' ansible/inventory/group_vars/all.yml)
$DOCKER build -q -t sdp-fluent-bit-test --build-arg FLUENT_BIT_VERSION="$FB_VERSION" \
  --build-arg FLUENT_BIT_SHA256="$FB_SHA256" -f tests/siem/Dockerfile.fluent-bit tests/siem >/dev/null

step "test PKI (shaped like siem01's: CA pathlen 0, node SAN IP + DNS siem01, client CN=<name>-g<N>)"
pki=$work/pki
mkdir -p "$pki"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$pki/ca.key" -out "$pki/ca.crt" -days 30 -subj "/O=sdp/OU=siem/CN=ingest-it-ca" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
issue() { # <name> <subject> <extfile lines>
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$pki/$1.key" 2>/dev/null
  openssl req -new -key "$pki/$1.key" -subj "$2" -out "$pki/$1.csr"
  printf '%b' "$3" > "$pki/$1.ext"
  openssl x509 -req -in "$pki/$1.csr" -CA "$pki/ca.crt" -CAkey "$pki/ca.key" -CAcreateserial -days 30 -sha256 \
    -extfile "$pki/$1.ext" -out "$pki/$1.crt" 2>/dev/null
}
issue node "/O=sdp/OU=node/CN=siem01" "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=IP:172.31.250.10,IP:127.0.0.1,DNS:siem01,DNS:localhost\n"
client_ext="basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n"
issue admin "/O=sdp/OU=siem/CN=admin-g1" "$client_ext"
# The one-shot N5 shipper's own identity (the role's key never leaves the k3s01 container).
issue n5 "/O=sdp/OU=siem/CN=shipper-k3s01-g1" "$client_ext"
chmod 0644 "$pki"/*

step "throwaway OpenSearch with siem01's security shape"
mkdir -p "$work/sec"
cp ansible/roles/opensearch_config/files/security/*.yml "$work/sec/"
cat > "$work/sec/roles_mapping.yml" <<'EOF'
_meta:
  type: "rolesmapping"
  config_version: 2
sdp_shipper_k3s01:
  users: ["shipper-k3s01-g1"]
EOF
cat > "$work/opensearch.yml" <<'EOF'
cluster.name: ingest-it
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
$DOCKER network create --subnet 172.31.250.0/24 "$NET" >/dev/null
$DOCKER run -d --name "$OS" --network "$NET" --ip 172.31.250.10 --memory 2g --ulimit nofile=65536:65536 \
  -e DISABLE_INSTALL_DEMO_CONFIG=true -e DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI=true -e OPENSEARCH_JAVA_OPTS="-Xms768m -Xmx768m" \
  -v "$work/opensearch.yml":/usr/share/opensearch/config/opensearch.yml:ro \
  -v "$pki":/usr/share/opensearch/config/certs:ro \
  -v "$work/sec":/usr/share/opensearch/config/opensearch-security:ro \
  "$OS_IMAGE" >/dev/null

step "signer and k3s01 containers (systemd)"
for c in "$SIGNER" "$K3S"; do
  ip=172.31.250.11; [ "$c" = "$K3S" ] && ip=172.31.250.12
  $DOCKER run -d --name "$c" --hostname "$c" --network "$NET" --ip "$ip" --privileged --cgroupns=private \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp -e container=docker sdp-target >/dev/null
done
for c in "$SIGNER" "$K3S"; do
  for _ in $(seq 1 30); do
    $DOCKER exec "$c" systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break; sleep 1
  done
  # systemd moves each unit's credentials mount out of a helper namespace; Docker's mounts are private,
  # a VM's / is shared (systemd's default), so the container is made to match.
  $DOCKER exec "$c" mount --make-rshared /
done
$DOCKER exec "$SIGNER" sh -ec 'apt-get update -qq && apt-get install -y -qq openssl python3-cryptography >/dev/null
  install -d -m 0700 /etc/sdp-siem/pki'
$DOCKER cp "$pki/ca.crt" "$SIGNER":/etc/sdp-siem/pki/ca.crt
$DOCKER cp "$pki/ca.key" "$SIGNER":/etc/sdp-siem/pki/ca.key
$DOCKER exec "$SIGNER" sh -ec 'chown root:root /etc/sdp-siem/pki/*; chmod 0400 /etc/sdp-siem/pki/ca.key'
# What k3s01 has: the kubeconfig (root 0600) the sandbox must hide, and the files the shipper tails
# (created empty, so the shipper starts at their end and reads what the test appends).
# shellcheck disable=SC2016  # expanded by the container's shell
$DOCKER exec "$K3S" sh -ec '
  install -d -m 0700 /etc/rancher/k3s && printf "apiVersion: v1\nkind: Config\n" > /etc/rancher/k3s/k3s.yaml && chmod 0600 /etc/rancher/k3s/k3s.yaml
  install -d -m 0755 /var/log/pods/falco_falco-it_0/falco /var/log/pods/falco-response_falco-talon-it_0/falco-talon \
    /var/log/pods/portfolio-api_portfolio-api-it_0/api /var/lib/rancher/k3s/server/logs /var/run/cilium/hubble /var/log/audit
  for f in /var/log/pods/falco_falco-it_0/falco/0.log /var/log/pods/falco-response_falco-talon-it_0/falco-talon/0.log \
           /var/log/pods/portfolio-api_portfolio-api-it_0/api/0.log /var/lib/rancher/k3s/server/logs/audit.log \
           /var/run/cilium/hubble/events.log /var/log/audit/audit.log; do : > "$f"; chmod 0600 "$f"; done'

# The test inventory with the real group_vars/all.yml next to it (the pins); host vars override the
# connection settings.
mkdir -p "$work/inv/group_vars"
cp tests/siem/ingest-it.inventory.yml "$work/inv/hosts.yml"
cp ansible/inventory/group_vars/all.yml "$work/inv/group_vars/all.yml"
chmod -R a+rX "$work/inv"
# Collections are installed once per test into a volume: one Galaxy outage mid-test is one less
# way for it to fail for reasons that are not the role's.
COLLECTIONS=sdp-ingest-it-collections
tooling() { # <command...> in the tooling container on the test network
  $DOCKER run --rm --network "$NET" -v "$PWD":/work:ro -v "$pki":/pki:ro -v "$work/inv":/inv:ro -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$COLLECTIONS":/collections \
    -e ANSIBLE_COLLECTIONS_PATH=/collections -e ANSIBLE_ROLES_PATH=/work/ansible/roles -e ANSIBLE_HOST_KEY_CHECKING=False \
    -e ANSIBLE_LOCAL_TEMP=/tmp/.ansible-local -w /work/ansible sdp-tooling sh -ec "
      if [ ! -e /collections/.installed ]; then
        ansible-galaxy collection install -r requirements.yml -p /collections >/dev/null
        ansible-galaxy collection install community.docker -p /collections >/dev/null
        touch /collections/.installed
      fi
      $*"
}

step "initialise security, then pipeline, templates and data streams from the opensearch_config role"
for _ in $(seq 1 90); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --cacert "$pki/ca.crt" --cert "$pki/admin.crt" --key "$pki/admin.key" \
    https://172.31.250.10:9200/ || true)
  [ "$code" != 000 ] && break; sleep 2
done
$DOCKER exec "$OS" bash -c 'cd /usr/share/opensearch && plugins/opensearch-security/tools/securityadmin.sh \
  -cd config/opensearch-security -icl -nhnv -h 127.0.0.1 -cacert config/certs/ca.crt -cert config/certs/admin.crt \
  -key config/certs/admin.key' >"$work/secadmin.log" 2>&1 || { cat "$work/secadmin.log"; fail "securityadmin"; }
tooling "ansible-playbook -i localhost, /work/tests/siem/ingest-it.yml" >"$work/prepare.log" 2>&1 \
  || { tail -40 "$work/prepare.log"; fail "preparing OpenSearch"; }

step "ingest.yml against the k3s01 container, twice"
run_ingest() {
  tooling "ansible-playbook -i /inv/hosts.yml playbooks/ingest.yml --limit $K3S"
}
run_ingest >"$work/run1.log" 2>&1 || { tail -60 "$work/run1.log"; fail "ingest.yml run 1"; }
tail -4 "$work/run1.log"
run_ingest >"$work/run2.log" 2>&1 || { tail -60 "$work/run2.log"; fail "ingest.yml run 2"; }
tail -4 "$work/run2.log"
grep -qE "$K3S +: ok=[0-9]+ +changed=0 +unreachable=0 +failed=0" "$work/run2.log" || fail "second run is not changed=0"
echo "IDEMPOTENT: second run changed=0"

step "check mode after the keys were deleted does not fail (review code L2), then the keys come back"
$DOCKER exec "$K3S" sh -c 'cp -a /etc/fluent-bit/keys /root/keys-backup && rm -f /etc/fluent-bit/keys/hmac.key /etc/fluent-bit/keys/client.key'
tooling "ansible-playbook -i /inv/hosts.yml playbooks/ingest.yml --limit $K3S --check" >"$work/check.log" 2>&1 \
  || { tail -40 "$work/check.log"; fail "check mode with deleted keys"; }
tail -2 "$work/check.log"
$DOCKER exec "$K3S" sh -c 'cp -a /root/keys-backup/. /etc/fluent-bit/keys/ && rm -rf /root/keys-backup'
run_ingest >"$work/run3.log" 2>&1 || { tail -40 "$work/run3.log"; fail "ingest.yml run 3"; }
grep -qE "$K3S +: ok=[0-9]+ +changed=0 +unreachable=0 +failed=0" "$work/run3.log" || fail "after restoring the keys the run is not changed=0"

step "the unit and its sandbox"
state=$($DOCKER exec "$K3S" systemctl show fluent-bit -p ActiveState -p SubState -p NRestarts -p User | sort | paste -sd' ')
[ "$state" = "ActiveState=active NRestarts=0 SubState=running User=fluent-bit" ] || fail "unit state: $state"
$DOCKER exec "$K3S" systemctl show fluent-bit -p InaccessiblePaths --value | grep -q '/etc/rancher' || fail "InaccessiblePaths lacks /etc/rancher"
listen=$($DOCKER exec "$K3S" sh -c "ss -Hltnp | grep fluent-bit | awk '{print \$4}'" | paste -sd' ')
[ "$listen" = "127.0.0.1:2020" ] || fail "Fluent Bit listens on: $listen"
$DOCKER exec "$K3S" stat -c '%U:%G %a %n' /etc/fluent-bit/keys/hmac.key /etc/fluent-bit/keys/client.key | tee "$work/keys"
[ "$(grep -c '^root:root 400 ' "$work/keys")" = 2 ] || fail "key files are not root 0400"
subject=$($DOCKER exec "$K3S" openssl x509 -in /etc/fluent-bit/tls/client.crt -noout -subject -nameopt RFC2253)
[ "$subject" = "subject=CN=shipper-k3s01-g1,OU=siem,O=sdp" ] || fail "client certificate: $subject"
props=$($DOCKER exec "$K3S" systemctl show fluent-bit -p ProtectProc -p ProcSubset -p RestrictNamespaces \
  -p ProtectKernelLogs -p ProtectControlGroups -p ProtectClock -p ProtectHostname -p LockPersonality -p RestrictSUIDSGID | sort | paste -sd' ')
[ "$props" = "LockPersonality=yes ProcSubset=pid ProtectClock=yes ProtectControlGroups=yes ProtectHostname=yes ProtectKernelLogs=yes ProtectProc=invisible RestrictNamespaces=yes RestrictSUIDSGID=yes" ] \
  || fail "sandbox properties: $props"
# M2: a process in the unit's cgroup reaches OpenSearch but nothing else - the signer's sshd, which
# answers from outside the cgroup, is not reachable from inside it (the unit's IP filter drops the
# packets; the connect times out).
probe='import socket, sys
for host, port in ((sys.argv[1], 9200), (sys.argv[2], 22)):
    s = socket.socket(); s.settimeout(5)
    try:
        s.connect((host, port)); print(host, "open")
    except OSError as e:
        print(host, "refused", type(e).__name__)'
outside=$($DOCKER exec "$K3S" python3 -c "$probe" 172.31.250.10 172.31.250.11 | paste -sd' ')
cg=$($DOCKER exec "$K3S" systemctl show fluent-bit -p ControlGroup --value)
inside=$($DOCKER exec "$K3S" sh -c 'echo $$ > "/sys/fs/cgroup$1/cgroup.procs" && exec python3 -c "$2" 172.31.250.10 172.31.250.11' \
  sh "$cg" "$probe" | paste -sd' ')
echo "outside the unit: $outside; inside: $inside"
[ "$outside" = "172.31.250.10 open 172.31.250.11 open" ] || fail "the probe targets are not reachable from outside the unit"
case $inside in "172.31.250.10 open 172.31.250.11 refused "*) ;; *) fail "IP filter: $inside" ;; esac
# H1: inside the unit's namespace there is no block device to open, though the container's /dev has them.
outside=$($DOCKER exec "$K3S" sh -c 'find /dev -type b | wc -l')
inside=$($DOCKER exec "$K3S" sh -c 'nsenter -t "$(systemctl show fluent-bit -p MainPID --value)" -m find /dev -type b | wc -l')
[ "$outside" -gt 0 ] || fail "the container shows no block device; the test proves nothing"
[ "$inside" = 0 ] || fail "the unit sees $inside block devices"
echo "block devices: $outside outside the unit, $inside inside"
conf=$($DOCKER exec "$K3S" cat /etc/fluent-bit/sdp/fluent-bit.conf)
for want in 'tls.verify +On' 'tls.verify_hostname +On' 'Write_Operation +create' 'Index +sdp-'; do
  [ "$(grep -cE "^ +$want" <<<"$conf")" = 6 ] || fail "fluent-bit.conf: '$want' is not on all six outputs"
done
! grep -qiE '^ +(Generate_ID|Id_Key|HTTP_User|HTTP_Passwd)' <<<"$conf" || fail "fluent-bit.conf sets an id or a password"
# M4: the throttles see the data inputs only; Falco's Warning+ alerts and metrics snapshot are re-tagged
# away from sdp.falco.log before them.
throttles=$(grep -cE '^ +Name +throttle$' <<<"$conf")
data_only=$(grep -A3 -E '^ +Name +throttle$' <<<"$conf" | grep -cF '\.(log|journal|auditd|osaudit)$')
[ "$throttles" = 6 ] && [ "$data_only" = 6 ] || fail "throttles: $throttles, matching the data inputs only: $data_only"
grep -qF 'Rule                  $priority ^(Warning|Error|Critical|Alert|Emergency)$ sdp.falco.urgent false' <<<"$conf" \
  || fail "Falco's Warning+ alerts are not re-tagged before the throttle"
echo "unit: $state; listens on $listen; $subject"

step "feed the fixtures at their k3s01 paths and through journald"
feed() { $DOCKER exec -i "$K3S" sh -c "cat >> $2" < "tests/siem/fixtures/$1"; }
feed falco.log /var/log/pods/falco_falco-it_0/falco/0.log
feed falco-metrics.log /var/log/pods/falco_falco-it_0/falco/0.log
feed talon.log /var/log/pods/falco-response_falco-talon-it_0/falco-talon/0.log
feed api.log /var/log/pods/portfolio-api_portfolio-api-it_0/api/0.log
feed k8s-audit.jsonl /var/lib/rancher/k3s/server/logs/audit.log
feed hubble.log /var/run/cilium/hubble/events.log
feed host-auditd.log /var/log/audit/audit.log
$DOCKER exec "$K3S" sh -ec '
  logger -t sshd-session "Accepted publickey for operator from 10.1.1.250 port 50022 ssh2: ED25519 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  logger -t sshd-session "Invalid user sdp-fixture-probe from 10.1.1.250 port 33766"
  logger -t sudo " operator : PWD=/home/operator ; USER=root ; COMMAND=/usr/bin/true"'

q() { curl -sS --cacert "$pki/ca.crt" --cert "$pki/admin.crt" --key "$pki/admin.key" "$@"; }
OSURL=https://172.31.250.10:9200
# The test host reaches the container network directly (docker bridge).
for _ in $(seq 1 45); do
  sleep 2
  n=$(q "$OSURL/sdp-*/_count?q=NOT%20event.kind:heartbeat" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("count",0))')
  [ "$n" -ge 43 ] && break
done
# Heartbeats come once a minute per stream.
for _ in $(seq 1 45); do
  n=$(q "$OSURL/sdp-*/_search?size=0" -H 'Content-Type: application/json' \
    -d '{"query":{"term":{"event.kind":"heartbeat"}},"aggs":{"s":{"terms":{"field":"event.dataset"}}}}' \
    | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["aggregations"]["s"]["buckets"]))')
  [ "$n" -ge 6 ] && break
  sleep 2
done
# The shipper's loss report comes once a minute too.
for _ in $(seq 1 45); do
  n=$(q "$OSURL/sdp-host/_count?q=host.log:fluent-bit" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("count",0))')
  [ "$n" -ge 1 ] && break
  sleep 2
done
sleep 3
for s in falco talon api k8s-audit hubble host; do
  q "$OSURL/sdp-$s/_search?size=500" -H 'Content-Type: application/json' -d '{"query":{"match_all":{}}}' >"$work/docs-$s.json"
done
python3 tests/siem/ingest_check.py "$work" . || { $DOCKER exec "$K3S" journalctl -u fluent-bit --no-pager | tail -40; fail "documents"; }

step "N5: verify_hostname refuses a name the node certificate does not carry"
n5() { # <verify_hostname On|Off> <marker>
  cat > "$work/n5.conf" <<EOF
[SERVICE]
    Flush 1
    Log_Level warn
[INPUT]
    Name dummy
    Tag n5
    Samples 1
    Dummy {"heartbeat":1}
[FILTER]
    Name modify
    Match n5
    Add event.kind heartbeat
    Add event.dataset $2
    Remove heartbeat
[OUTPUT]
    Name opensearch
    Match n5
    Host $OS
    Port 9200
    Index sdp-falco
    Write_Operation create
    Suppress_Type_Name On
    Retry_Limit 1
    tls On
    tls.verify On
    tls.verify_hostname $1
    tls.ca_file /pki/ca.crt
    tls.crt_file /pki/n5.crt
    tls.key_file /pki/n5.key
EOF
  $DOCKER rm -f sdp-ingest-n5 >/dev/null 2>&1 || true
  $DOCKER run -d --name sdp-ingest-n5 --network "$NET" -v "$work/n5.conf":/n5.conf:ro -v "$pki":/pki:ro \
    sdp-fluent-bit-test /opt/fluent-bit/bin/fluent-bit -c /n5.conf >/dev/null
  sleep 12
  $DOCKER logs sdp-ingest-n5 >"$work/n5-$1.log" 2>&1 || true
  $DOCKER rm -f sdp-ingest-n5 >/dev/null
  q "$OSURL/sdp-falco/_count?q=event.dataset:$2" | python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])'
}
on=$(n5 On n5-hostname-on)
off=$(n5 Off n5-hostname-off)
echo "via the name $OS (not in the SAN): verify_hostname On -> $on documents, Off -> $off documents"
if [ "$on" != 0 ] || [ "$off" != 1 ]; then cat "$work/n5-On.log"; fail "N5: expected 0 with verify_hostname On and 1 with Off"; fi
grep -iE 'hostname|certificate verify failed|x509' "$work/n5-On.log" | head -2 || true

step "MJ8: without InaccessiblePaths the start check refuses to start"
$DOCKER exec "$K3S" sh -ec '
  sed -i "/^InaccessiblePaths=/d" /etc/systemd/system/fluent-bit.service.d/sdp.conf
  systemctl daemon-reload
  systemctl restart fluent-bit || true
  sleep 3'
state=$($DOCKER exec "$K3S" systemctl show fluent-bit -p ActiveState -p SubState | sort | paste -sd' ')
$DOCKER exec "$K3S" journalctl -u fluent-bit --no-pager -n 30 >"$work/mj8.log"
grep -q 'sandbox broken: /etc/rancher/k3s/k3s.yaml readable' "$work/mj8.log" || { cat "$work/mj8.log"; fail "MJ8: no 'sandbox broken'"; }
case $state in "ActiveState=active SubState=running") fail "MJ8: the unit runs without InaccessiblePaths ($state)" ;; esac
echo "without InaccessiblePaths: $state, journal: $(grep -o 'sandbox broken: [^ ]* readable' "$work/mj8.log" | head -1)"

echo
echo "ingest-it: ok"
