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
NAME=cilium-operator-generic
BIN=/usr/bin/cilium-operator-generic

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
run() { $DOCKER run --rm --pull=never --network=none --user 65532:65532 --read-only --cap-drop ALL "$IMAGE" "$@" 2>"$ERR"; }

check "--version" "$(run "$BIN" --version)" \
  "Cilium-Operator 1.19.8 5791d208 2026-09-15T18:23:52+00:00 go version go1.26.9 linux/amd64"
check "--help exits 0" "$(run "$BIN" --help >/dev/null; echo $?)" 0
check "hive constructs" "$(run "$BIN" hive >/dev/null; echo $?)" 0
check "gops present" "$(run /usr/bin/gops --help >/dev/null; echo $?)" 0

if [ "$failures" -ne 0 ]; then
  echo "image-smoke: $failures check(s) failed" >&2
  exit 1
fi
echo "image-smoke: ok"
