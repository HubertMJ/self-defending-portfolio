#!/usr/bin/env bash
# Run the same linters as CI, inside the local tooling container (no host installs needed).
set -euo pipefail
cd "$(dirname "$0")/.."
DOCKER=${DOCKER:-docker}
$DOCKER image inspect sdp-tooling >/dev/null 2>&1 || $DOCKER build -q -t sdp-tooling -f scripts/Dockerfile.tooling .
# shellcheck disable=SC2016  # the quoted block is executed inside the container
$DOCKER run --rm -v "$PWD":/work -w /work -e ANSIBLE_COLLECTIONS_PATH=/work/.ansible/collections sdp-tooling sh -ec '
  ansible-galaxy collection install -r ansible/requirements.yml -p .ansible/collections >/dev/null
  yamllint -c .yamllint.yml .
  ansible-lint --offline ansible
  shellcheck scripts/*.sh cluster/bootstrap/bootstrap.sh tests/*.sh tests/admission/*.sh tests/runtime/*.sh tests/abuse/*.sh tests/scenarios/*.sh cluster/infra/kube-bench/k3s-cis-1.9/*.sh
  for p in ansible/playbooks/*.yml; do (cd ansible && ansible-playbook --syntax-check "playbooks/$(basename "$p")"); done
'
