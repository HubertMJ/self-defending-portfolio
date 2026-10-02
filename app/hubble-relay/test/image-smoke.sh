#!/usr/bin/env bash
# Smoke test of the built hubble-relay image (ADR 0028): the rebuilt binary reports the upstream
# release's exact version string, and `hubble-relay serve` starts the way the chart runs it (uid
# 65532, read-only root, no capabilities) and keeps running, retrying its peer service. It has no
# Cilium agent to relay; that part is the staged rollout in docs/bootstrap.md, section 8.7.
#
#   app/hubble-relay/test/image-smoke.sh <image ref>
#
# build-images.yml runs it after the push and before signing (see app/web/test/image-smoke.sh).
set -euo pipefail
IMAGE=${1:?usage: $0 <image ref>}
DOCKER=${DOCKER:-docker}
name=hubble-relay-smoke-$$

cleanup() { $DOCKER rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

failures=0
check() { # description, actual, expected
  if [ "$2" = "$3" ]; then printf '  PASS  %s\n' "$1"; else printf '  FAIL  %s: got %q, want %q\n' "$1" "$2" "$3" >&2; failures=$((failures + 1)); fi
}

check "version" "$($DOCKER run --rm --network=none "$IMAGE" version 2>&1)" \
  "Hubble-relay: 1.19.8 5791d208 2026-09-15T18:23:52+00:00 go version go1.26.8 linux/amd64"

$DOCKER run -d --name "$name" --network=none --read-only --tmpfs /home/gops:uid=65532 --cap-drop ALL \
  --security-opt no-new-privileges "$IMAGE" serve --peer-service=unix:///var/run/cilium/hubble.sock \
  --listen-address=:4245 --disable-server-tls --disable-client-tls >/dev/null
sleep 5
check "serve keeps running" "$($DOCKER inspect -f '{{.State.Status}}' "$name")" running
check "gRPC server started" "$($DOCKER logs "$name" 2>&1 | grep -c 'Starting gRPC server')" 1

if [ "$failures" -ne 0 ]; then
  $DOCKER logs "$name" >&2 || true
  echo "image-smoke: $failures check(s) failed" >&2
  exit 1
fi
echo "image-smoke: ok"
