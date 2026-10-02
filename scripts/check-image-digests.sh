#!/usr/bin/env bash
# No placeholder digest may reach main. Images are built and signed only by CI on main
# (.github/workflows/build-images.yml, ADR 0016), so a manifest for a new image is committed with an
# all-zero placeholder digest first and pinned to the real one once the build has run
# (scripts/bump-image-digest.sh). Argo CD syncs main: a placeholder there is a Deployment that can
# never pull and a scenario a visitor cannot start, so `make validate` and CI refuse it outright,
# with the list of what is left, before kubeconform and Kyverno get to fail on it less legibly.
#
# ansible/ is scanned too: CoreDNS's pin lives in the k3s role (ADR 0026), and a placeholder there is
# a CoreDNS Deployment that can never pull the next time someone runs the role.
#
# ALLOW_PLACEHOLDER_DIGESTS=1 downgrades the failure to a warning, for working on a branch before
# the images exist.
set -euo pipefail
cd "$(dirname "$0")/.."
PLACEHOLDER=sha256:0000000000000000000000000000000000000000000000000000000000000000
if hits=$(git grep -n -F "$PLACEHOLDER" -- cluster/ ansible/); then
  printf 'placeholder image digests under cluster/ or ansible/ (fill them with scripts/bump-image-digest.sh):\n%s\n' "$hits" >&2
  if [ "${ALLOW_PLACEHOLDER_DIGESTS:-}" = 1 ]; then
    echo "WARNING - ALLOW_PLACEHOLDER_DIGESTS=1, continuing" >&2
    exit 0
  fi
  exit 1
fi
echo "ok - no placeholder image digests under cluster/ or ansible/"
