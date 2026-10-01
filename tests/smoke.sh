#!/usr/bin/env bash
# Smoke-test the hardening playbook twice against a throwaway systemd container.
# Proves: roles apply on a clean Debian 13, and the second run is idempotent (changed=0).
# Kernel-level tags (sysctl, auditd) are skipped here and need a real VM.
set -euo pipefail
cd "$(dirname "$0")/.."
DOCKER=${DOCKER:-docker}
NAME=sdp-smoke
SKIP_TAGS=${SKIP_TAGS:-sysctl,auditd,kernel,hostname}

cleanup() { $DOCKER rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
$DOCKER image inspect sdp-target >/dev/null 2>&1 || $DOCKER build -q -t sdp-target -f tests/Dockerfile.target tests
$DOCKER image inspect sdp-tooling >/dev/null 2>&1 || $DOCKER build -q -t sdp-tooling -f scripts/Dockerfile.tooling .

# --privileged is the only way to run systemd as PID 1 under Docker >= 25 with cgroup v2.
# The kernel-touching roles (sysctl, auditd) are skipped by tag, everything else stays inside the container.
$DOCKER run -d --name "$NAME" --privileged --cgroupns=private \
  --tmpfs /run --tmpfs /run/lock --tmpfs /tmp -e container=docker \
  sdp-target >/dev/null
for _ in $(seq 1 30); do
  $DOCKER exec "$NAME" systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break; sleep 1
done

run() {
  $DOCKER run --rm -v "$PWD":/work -w /work/ansible -v /var/run/docker.sock:/var/run/docker.sock \
    -e ANSIBLE_COLLECTIONS_PATH=/work/.ansible/collections -e ANSIBLE_HOST_KEY_CHECKING=False \
    sdp-tooling sh -ec "
      ansible-galaxy collection install -r requirements.yml -p /work/.ansible/collections >/dev/null
      ansible-galaxy collection install community.docker -p /work/.ansible/collections >/dev/null
      ansible-playbook -i tests/inventory.yml playbooks/hardening.yml --skip-tags '$SKIP_TAGS'"
}
echo '### run 1 (apply)'; run | tee /tmp/sdp-run1.log | tail -15
echo '### run 2 (must be idempotent)'; run | tee /tmp/sdp-run2.log | tail -15
if grep -E 'changed=[1-9]' /tmp/sdp-run2.log; then echo 'NOT IDEMPOTENT'; exit 1; fi
echo 'IDEMPOTENT: second run changed=0'
