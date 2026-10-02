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
VERSION='1.19.8 5791d208 2026-09-15T18:23:52+00:00 go version go1.26.8 linux/amd64'

failures=0
check() { # description, actual, expected
  if [ "$2" = "$3" ]; then printf '  PASS  %s\n' "$1"; else printf '  FAIL  %s: got %q, want %q\n' "$1" "$2" "$3" >&2; failures=$((failures + 1)); fi
}
run() { $DOCKER run --rm --network=none --entrypoint "$1" "$IMAGE" "${@:2}" 2>&1; }

check "cilium-agent --version" "$(run cilium-agent --version)" "cilium-agent $VERSION"
check "cilium-dbg version (client)" "$(run cilium-dbg version | head -1)" "Client: $VERSION"
check "cilium-cni --version" "$(run /opt/cni/bin/cilium-cni --version | head -1)" "Cilium CNI plugin $VERSION"
check "hubble version" "$(run hubble version)" "hubble v1.19.8@HEAD-5791d208 compiled with go1.26.8 on linux/amd64"
for bin in cilium-dbg cilium-health cilium-health-responder cilium-bugtool cilium-mount cilium-sysctlfix; do
  check "$bin --help exits 0" "$(run "$bin" --help >/dev/null 2>&1; echo $?)" 0
done
check "cilium-agent hive constructs" "$(run cilium-agent hive >/dev/null 2>&1; echo $?)" 0
check "cilium-envoy (upstream binary)" "$(run cilium-envoy --version | grep -c '/1\.37\.6/Distribution/RELEASE/BoringSSL$')" 1
for tool in clang llc bpftool ip tc iptables ip6tables ipset; do
  check "runtime tool $tool present" "$(run sh -c "command -v $tool >/dev/null; echo \$?")" 0
done
check "BPF sources present" "$(run sh -c 'test -f /var/lib/cilium/bpf/bpf_lxc.c; echo $?')" 0
check "openssl is the fixed build" "$(run dpkg-query -W -f '${Version}' openssl)" "3.0.13-0ubuntu3.16"

if [ "$failures" -ne 0 ]; then
  echo "image-smoke: $failures check(s) failed" >&2
  exit 1
fi
echo "image-smoke: ok"
