#!/usr/bin/env bash
# Smoke test of the built cilium-operator-generic image (ADR 0028): the rebuilt binary reports the
# upstream release's exact version string and the operator's whole cell graph constructs
# (`cilium-operator-generic hive` builds every component without starting it). It cannot reach an
# API server; that part is the staged rollout in docs/bootstrap.md, section 8.7.
#
#   app/cilium-operator-generic/test/image-smoke.sh <image ref>
#
# build-images.yml runs it after the push and before signing (see app/web/test/image-smoke.sh).
set -euo pipefail
IMAGE=${1:?usage: $0 <image ref>}
DOCKER=${DOCKER:-docker}
BIN=/usr/bin/cilium-operator-generic

failures=0
check() { # description, actual, expected
  if [ "$2" = "$3" ]; then printf '  PASS  %s\n' "$1"; else printf '  FAIL  %s: got %q, want %q\n' "$1" "$2" "$3" >&2; failures=$((failures + 1)); fi
}
run() { $DOCKER run --rm --network=none --user 65532:65532 --read-only --cap-drop ALL "$IMAGE" "$@" 2>&1; }

check "--version" "$(run "$BIN" --version)" \
  "Cilium-Operator 1.19.8 5791d208 2026-09-15T18:23:52+00:00 go version go1.26.8 linux/amd64"
check "--help exits 0" "$(run "$BIN" --help >/dev/null 2>&1; echo $?)" 0
check "hive constructs" "$(run "$BIN" hive >/dev/null 2>&1; echo $?)" 0
check "gops present" "$(run /usr/bin/gops --help >/dev/null 2>&1; echo $?)" 0

if [ "$failures" -ne 0 ]; then
  echo "image-smoke: $failures check(s) failed" >&2
  exit 1
fi
echo "image-smoke: ok"
