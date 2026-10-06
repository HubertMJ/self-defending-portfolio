#!/usr/bin/env bash
# Smoke-test the host playbooks twice against throwaway systemd containers.
# Proves: roles apply on a clean Debian 13, and the second run is idempotent (changed=0) - for the k3s
# host (hardening.yml) and for the SIEM host (siem.yml --tags base,ssh,firewall,patching, where the
# group switches the shared roles to their non-k3s shape). Then the opensearch role's JVM options and
# unit (--tags opensearch_service) on the SIEM container, against a stand-in for the package: a unit
# that sleeps and the package's jvm.options as installed on siem01 (tests/siem/fixtures).
# Kernel-level tags (sysctl, auditd) are skipped here and need a real VM; their output is checked by
# tests/golden/render.sh and on the hosts by verify.yml.
set -euo pipefail
cd "$(dirname "$0")/.."
DOCKER=${DOCKER:-docker}
SKIP_TAGS=${SKIP_TAGS:-sysctl,auditd,kernel,hostname}
SIEM_TAGS=${SIEM_TAGS:-base,ssh,firewall,patching}
NAMES=(sdp-smoke sdp-smoke-siem)

cleanup() { for n in "${NAMES[@]}"; do $DOCKER rm -f "$n" >/dev/null 2>&1 || true; done; }
trap cleanup EXIT
cleanup
$DOCKER image inspect sdp-target >/dev/null 2>&1 || $DOCKER build -q -t sdp-target -f tests/Dockerfile.target tests
$DOCKER image inspect sdp-tooling >/dev/null 2>&1 || $DOCKER build -q -t sdp-tooling -f scripts/Dockerfile.tooling .

# --privileged is the only way to run systemd as PID 1 under Docker >= 25 with cgroup v2.
# The kernel-touching roles (sysctl, auditd) are skipped by tag, everything else stays inside the container.
for n in "${NAMES[@]}"; do
  $DOCKER run -d --name "$n" --privileged --cgroupns=private \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp -e container=docker \
    sdp-target >/dev/null
  for _ in $(seq 1 30); do
    $DOCKER exec "$n" systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break; sleep 1
  done
done

run() { # <ansible-playbook arguments>
  $DOCKER run --rm -v "$PWD":/work -w /work/ansible -v /var/run/docker.sock:/var/run/docker.sock \
    -e ANSIBLE_COLLECTIONS_PATH=/work/.ansible/collections -e ANSIBLE_HOST_KEY_CHECKING=False \
    sdp-tooling sh -ec "
      ansible-galaxy collection install -r requirements.yml -p /work/.ansible/collections >/dev/null
      ansible-galaxy collection install community.docker -p /work/.ansible/collections >/dev/null
      ansible-playbook -i tests/inventory.yml $*"
}
twice() { # <label> <ansible-playbook arguments>
  local label=$1; shift
  echo "### $label run 1 (apply)"; run "$@" | tee "/tmp/sdp-$label-run1.log" | tail -15
  echo "### $label run 2 (must be idempotent)"; run "$@" | tee "/tmp/sdp-$label-run2.log" | tail -15
  if grep -E 'changed=[1-9]|failed=[1-9]|unreachable=[1-9]' "/tmp/sdp-$label-run2.log"; then echo "$label: NOT IDEMPOTENT"; exit 1; fi
  echo "IDEMPOTENT ($label): second run changed=0"
}
twice k3s "playbooks/hardening.yml --limit sdp-smoke --skip-tags '$SKIP_TAGS'"
# hostname: containers own no UTS namespace we can write to (as SKIP_TAGS above).
twice siem "playbooks/siem.yml --limit sdp-smoke-siem --tags '$SIEM_TAGS' --skip-tags hostname"

# The stand-in for the OpenSearch package: its group, its jvm.options and a unit of the same name.
$DOCKER exec -i sdp-smoke-siem sh -ec '
  groupadd -r opensearch
  mkdir -p /etc/opensearch/jvm.options.d
  cat > /etc/opensearch/jvm.options
  printf "[Service]\nExecStart=/bin/sleep infinity\n\n[Install]\nWantedBy=multi-user.target\n" \
    > /usr/lib/systemd/system/opensearch.service
  systemctl daemon-reload' < tests/siem/fixtures/opensearch-jvm.options
twice opensearch "playbooks/siem.yml --limit sdp-smoke-siem --tags opensearch_service"
# What the JVM gets is jvm.options followed by jvm.options.d/*.options, the last occurrence winning.
# shellcheck disable=SC2016  # the quoted block runs inside the container
$DOCKER exec sdp-smoke-siem sh -ec '
  fail() { echo "opensearch: $*"; exit 1; }
  [ "$(systemctl show opensearch -p Restart --value)" = on-failure ] || fail "Restart= is not on-failure"
  [ "$(stat -c "%U:%G %a" /etc/systemd/system/opensearch.service.d/sdp-restart.conf)" = "root:root 644" ] \
    || fail "the drop-in is not root:root 0644"
  opts=$(cat /etc/opensearch/jvm.options /etc/opensearch/jvm.options.d/*.options | grep -E "^-")
  [ "$(printf "%s\n" "$opts" | grep -E "^-Xm[sx]")" = "$(printf -- "-Xms4g\n-Xmx4g")" ] \
    || fail "heap settings are not exactly -Xms4g and -Xmx4g: $(printf "%s\n" "$opts" | grep -E "^-Xm[sx]" | tr "\n" " ")"
  printf "%s\n" "$opts" | grep -qx -- "-XX:+ExitOnOutOfMemoryError" || fail "no -XX:+ExitOnOutOfMemoryError"
  [ "$(printf "%s\n" "$opts" | grep -E "HeapDumpOnOutOfMemoryError")" = "-XX:-HeapDumpOnOutOfMemoryError" ] \
    || fail "heap dumps are not off exactly once"
  echo "opensearch: Restart=on-failure, one heap setting (4g), exit on OOM, no heap dump"'
