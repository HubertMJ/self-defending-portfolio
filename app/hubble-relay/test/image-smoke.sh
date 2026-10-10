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
NAME=hubble-relay
name=hubble-relay-smoke-$$

failures=0
# Every failure is printed for the log and as a GitHub Actions `::error::` annotation, so the reason
# is readable from the run's annotations without the job log. Annotation text is one line; `%` is
# escaped as the workflow-command syntax requires.
ERR=$(mktemp)
cleanup() { $DOCKER rm -f "$name" >/dev/null 2>&1 || true; rm -f "$ERR"; }
trap cleanup EXIT
fail() { # message
  local msg="image-smoke ($NAME): $1"
  printf '  FAIL  %s\n' "$1" >&2
  if [ -s "$ERR" ]; then sed 's/^/          stderr: /' "$ERR" | tail -n 20 >&2; msg="$msg; stderr: $(tail -n 3 "$ERR" | tr '\n' ' ')"; fi
  msg=${msg//%/%25}
  printf '::error title=image smoke test (%s)::%s\n' "$NAME" "$msg"
  failures=$((failures + 1))
}
check() { # description, actual, expected
  if [ "$2" = "$3" ]; then printf '  PASS  %s\n' "$1"; else fail "$(printf '%s: got %q, want %q' "$1" "$2" "$3")"; fi
}

# Pull once, up front, and run every container with --pull=never: a `docker run` that has to pull
# prints "Unable to find image ... locally" and the pull progress on its stderr, which must never end
# up in an output a check compares (stage 1's CI failure). Containers' stderr goes to $ERR, shown
# only when a check fails; what is compared is their stdout.
if ! $DOCKER pull -q "$IMAGE" >/dev/null 2>"$ERR"; then
  fail "cannot pull $IMAGE"
  exit 1
fi
: >"$ERR"

check "version" "$($DOCKER run --rm --pull=never --network=none "$IMAGE" version 2>"$ERR")" \
  "Hubble-relay: 1.19.8 5791d208 2026-09-15T18:23:52+00:00 go version go1.26.9 linux/amd64"

check "gops present" "$($DOCKER run --rm --pull=never --network=none --entrypoint /usr/bin/gops "$IMAGE" --help >/dev/null 2>"$ERR"; echo $?)" 0

$DOCKER run -d --pull=never --name "$name" --network=none --read-only --tmpfs /home/gops:uid=65532 --cap-drop ALL \
  --security-opt no-new-privileges "$IMAGE" serve --peer-service=unix:///var/run/cilium/hubble.sock \
  --listen-address=:4245 --disable-server-tls --disable-client-tls >/dev/null 2>"$ERR" \
  || { fail "docker run (hubble-relay serve) failed"; exit 1; }
sleep 5
# What the checks below look at is the container itself; its log is attached to any failure.
$DOCKER logs "$name" >"$ERR" 2>&1 || true
check "serve keeps running" "$($DOCKER inspect -f '{{.State.Status}}' "$name")" running
check "gRPC server started" "$($DOCKER logs "$name" 2>&1 | grep -c 'Starting gRPC server')" 1

if [ "$failures" -ne 0 ]; then
  echo "image-smoke: $failures check(s) failed" >&2
  exit 1
fi
echo "image-smoke: ok"
