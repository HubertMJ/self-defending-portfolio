#!/usr/bin/env bash
# Smoke test of the built cilium-envoy image (ADR 0028): Envoy is upstream's build for Cilium 1.19.8
# and starts with a minimal static configuration, and OpenSSL is the fixed Ubuntu build. Routing real
# traffic is the staged rollout in docs/bootstrap.md, section 8.7.
#
#   app/cilium-envoy/test/image-smoke.sh <image ref>
#
# build-images.yml runs it after the push and before signing (see app/web/test/image-smoke.sh).
set -euo pipefail
IMAGE=${1:?usage: $0 <image ref>}
DOCKER=${DOCKER:-docker}

failures=0
check() { # description, actual, expected
  if [ "$2" = "$3" ]; then printf '  PASS  %s\n' "$1"; else printf '  FAIL  %s: got %q, want %q\n' "$1" "$2" "$3" >&2; failures=$((failures + 1)); fi
}
run() { $DOCKER run --rm --network=none "$IMAGE" "$@" 2>&1; }

check "cilium-envoy --version" "$(run cilium-envoy --version | tr -s ' \n' ' ' | sed 's/^ //; s/ $//')" \
  "cilium-envoy version: cbec91f666af0bf742da986d43832932dbb26b82/1.37.6/Distribution/RELEASE/BoringSSL"
# --mode validate parses and validates a bootstrap configuration with every extension this build has
# registered, then exits; an admin-only bootstrap is the smallest valid one.
check "cilium-envoy validates a config" "$(run cilium-envoy --mode validate --config-yaml \
  '{admin: {address: {socket_address: {address: 127.0.0.1, port_value: 9901}}}}' >/dev/null 2>&1; echo $?)" 0
check "openssl is the fixed build" "$(run dpkg-query -W -f '${Version}' openssl)" "3.0.13-0ubuntu3.16"
check "libssl3t64 is the fixed build" "$(run dpkg-query -W -f '${Version}' libssl3t64)" "3.0.13-0ubuntu3.16"

if [ "$failures" -ne 0 ]; then
  echo "image-smoke: $failures check(s) failed" >&2
  exit 1
fi
echo "image-smoke: ok"
