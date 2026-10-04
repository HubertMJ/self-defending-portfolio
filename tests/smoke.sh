#!/usr/bin/env bash
# Smoke-test the host playbooks twice against throwaway systemd containers.
# Proves: roles apply on a clean Debian 13, and the second run is idempotent (changed=0) - for the k3s
# host (hardening.yml) and for the SIEM host (siem.yml --tags base,ssh,firewall,patching, where the
# group switches the shared roles to their non-k3s shape).
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
