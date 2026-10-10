#!/usr/bin/env bash
# Smoke test of the built Cilium agent image (ADR 0028): every rebuilt binary runs and reports the
# upstream release's exact version string, the agent's whole cell graph constructs (`cilium-agent
# hive` builds every component without starting it), and the upstream runtime tools the datapath
# needs are present. It cannot attach BPF programs or talk to an API server; that part of the
# verification is the staged rollout in docs/bootstrap.md, section 8.7.
#
#   app/cilium/test/image-smoke.sh <image ref>
#
# build-images.yml runs it after the push and before signing (see app/web/test/image-smoke.sh).
set -euo pipefail
IMAGE=${1:?usage: $0 <image ref>}
DOCKER=${DOCKER:-docker}
NAME=cilium
VERSION='1.19.8 5791d208 2026-09-15T18:23:52+00:00 go version go1.26.9 linux/amd64'

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
run() { $DOCKER run --rm --pull=never --network=none --entrypoint "$1" "$IMAGE" "${@:2}" 2>"$ERR"; }

check "cilium-agent --version" "$(run cilium-agent --version)" "cilium-agent $VERSION"
check "cilium-dbg version (client)" "$(run cilium-dbg version | head -1)" "Client: $VERSION"
# The CNI plugin prints its version on stderr (stdout is reserved for CNI results): merged inside
# the container, never with docker's own output.
check "cilium-cni --version" "$(run sh -c '/opt/cni/bin/cilium-cni --version 2>&1' | head -1)" "Cilium CNI plugin $VERSION"
check "hubble version" "$(run hubble version)" "hubble v1.19.8@HEAD-5791d208 compiled with go1.26.9 on linux/amd64"
for bin in cilium-dbg cilium-health cilium-health-responder cilium-bugtool cilium-mount cilium-sysctlfix; do
  check "$bin --help exits 0" "$(run "$bin" --help >/dev/null; echo $?)" 0
done
check "cilium-agent hive constructs" "$(run cilium-agent hive >/dev/null; echo $?)" 0
check "cilium-envoy (upstream binary)" "$(run cilium-envoy --version | grep -c '/1\.37\.6/Distribution/RELEASE/BoringSSL$')" 1
for tool in clang llc bpftool ip tc iptables ip6tables ipset; do
  check "runtime tool $tool present" "$(run sh -c "command -v $tool >/dev/null; echo \$?")" 0
done
# gops and the CNI loopback plugin: upstream's releases, compiled again with a newer Go (tools stage)
check "CNI loopback plugin" "$(run sh -c '/cni/loopback --version 2>&1' | head -1)" "CNI loopback plugin v1.9.1"
check "gops --help exits 0" "$(run gops --help >/dev/null; echo $?)" 0
check "BPF sources present" "$(run sh -c 'test -f /var/lib/cilium/bpf/bpf_lxc.c; echo $?')" 0
check "openssl is the fixed build" "$(run dpkg-query -W -f '${Version}' openssl)" "3.0.13-0ubuntu3.16"
check "perl-base is the fixed build" "$(run dpkg-query -W -f '${Version}' perl-base)" "5.38.2-3.2ubuntu0.6"

if [ "$failures" -ne 0 ]; then
  echo "image-smoke: $failures check(s) failed" >&2
  exit 1
fi
echo "image-smoke: ok"
