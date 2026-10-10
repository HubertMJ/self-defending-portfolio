#!/usr/bin/env bash
# Smoke test of the built cilium-envoy image (ADR 0028): Envoy is upstream's build for Cilium 1.19.8
# and starts with a minimal static configuration, and OpenSSL and perl-base are the fixed Ubuntu
# builds. Routing real traffic is the staged rollout in docs/bootstrap.md, section 8.7.
#
#   app/cilium-envoy/test/image-smoke.sh <image ref>
#
# build-images.yml runs it after the push and before signing (see app/web/test/image-smoke.sh).
set -euo pipefail
IMAGE=${1:?usage: $0 <image ref>}
DOCKER=${DOCKER:-docker}
NAME=cilium-envoy

failures=0
# Every failure is printed for the log and as a GitHub Actions `::error::` annotation, so the reason
# is readable from the run's annotations without the job log. Annotation text is one line; `%` is
# escaped as the workflow-command syntax requires.
ERR=$(mktemp)
trap 'rm -f "$ERR"' EXIT
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
run() { $DOCKER run --rm --pull=never --network=none "$IMAGE" "$@" 2>"$ERR"; }

check "cilium-envoy --version" "$(run cilium-envoy --version | tr -s ' \n' ' ' | sed 's/^ //; s/ $//')" \
  "cilium-envoy version: cbec91f666af0bf742da986d43832932dbb26b82/1.37.6/Distribution/RELEASE/BoringSSL"
# --mode validate parses and validates a bootstrap configuration with every extension this build has
# registered, then exits; an admin-only bootstrap is the smallest valid one.
check "cilium-envoy validates a config" "$(run cilium-envoy --mode validate --config-yaml \
  '{admin: {address: {socket_address: {address: 127.0.0.1, port_value: 9901}}}}' >/dev/null; echo $?)" 0
check "openssl is the fixed build" "$(run dpkg-query -W -f '${Version}' openssl)" "3.0.13-0ubuntu3.16"
check "libssl3t64 is the fixed build" "$(run dpkg-query -W -f '${Version}' libssl3t64)" "3.0.13-0ubuntu3.16"
check "perl-base is the fixed build" "$(run dpkg-query -W -f '${Version}' perl-base)" "5.38.2-3.2ubuntu0.6"

if [ "$failures" -ne 0 ]; then
  echo "image-smoke: $failures check(s) failed" >&2
  exit 1
fi
echo "image-smoke: ok"
