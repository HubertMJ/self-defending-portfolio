#!/usr/bin/env bash
# Golden render of the host roles that k3s01 and siem01 share (firewall, sysctl, auditd, ssh_hardening).
# Each role is rendered by Ansible itself, in the tooling container, with the host's real inventory
# variables (hosts.yml + group_vars + role defaults), from a scratch copy of ansible/ that gains one
# render task file per role (tests/golden/tasks/<role>.yml) - the worktree is never modified.
#
#   k3s01:  the output must equal tests/golden/k3s01/ byte for byte. Those goldens were rendered the
#           same way from b374c0e, before the roles became group-conditional, so the split for siem01
#           cannot change one byte of what k3s01 receives (siem contract P1, ADR 0009 amendment).
#   siem01: the output must have the siem01 shape: no kube-apiserver, pod/service CIDR or Cilium
#           rules, 9200/tcp only from k3s01, only 22 and 9200 accepted, no rp_filter, forwarding or
#           kubelet keys, vm.max_map_count set, no 50-k3s.rules, the siem watches in 60-extra.rules,
#           and sshd allowing local forwarding to Dashboards only.
#
# Usage: tests/golden/render.sh               compare (exit 1 on any difference; GOLDEN_KEEP=<dir> keeps the output)
#        tests/golden/render.sh --write REV   regenerate tests/golden/k3s01 from git revision REV
set -euo pipefail
cd "$(dirname "$0")/../.."
DOCKER=${DOCKER:-docker}
GOLDEN=tests/golden/k3s01
ROLES=(firewall sysctl auditd ssh_hardening)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
$DOCKER image inspect sdp-tooling >/dev/null 2>&1 || $DOCKER build -q -t sdp-tooling -f scripts/Dockerfile.tooling .

# render <tree dir containing ansible/> <out dir> <host...>
render() {
  local tree=$1 out=$2 role
  shift 2
  for role in "${ROLES[@]}"; do
    cp tests/golden/tasks/"$role".yml "$tree/ansible/roles/$role/tasks/golden-render.yml"
  done
  cp tests/golden/render.yml "$tree/ansible/golden-render.yml"
  mkdir -p "$out"
  # --user keeps the output owned by the caller so the trap can remove it.
  $DOCKER run --rm -i --user "$(id -u):$(id -g)" -e HOME=/tmp -e USER=golden -e ANSIBLE_LOCAL_TEMP=/tmp/.ansible-local \
    -v "$tree/ansible":/tree -v "$out":/out -w /tree sdp-tooling \
    ansible-playbook -i inventory/hosts.yml golden-render.yml --limit "$(IFS=,; echo "$*")" \
    -e golden_out_root=/out -e ansible_python_interpreter=/usr/local/bin/python3 >"$work/render.log" 2>&1 \
    || { cat "$work/render.log"; echo "golden: render failed" >&2; exit 1; }
}

if [ "${1:-}" = "--write" ]; then
  rev=${2:?usage: --write REV}
  mkdir -p "$work/old"
  git archive "$rev" ansible | tar -x -C "$work/old"
  render "$work/old" "$work/out-old" k3s01
  rm -rf "$GOLDEN"
  cp -r "$work/out-old/k3s01" "$GOLDEN"
  echo "golden: wrote $GOLDEN from $rev"
  exit 0
fi

mkdir -p "$work/cur"
cp -r ansible "$work/cur/ansible"
rm -rf "$work/cur/ansible/.ansible"
render "$work/cur" "$work/out" k3s01 siem01

# GOLDEN_KEEP=<dir> keeps a copy of the rendered files for inspection.
[ -n "${GOLDEN_KEEP:-}" ] && { mkdir -p "$GOLDEN_KEEP"; cp -r "$work/out/." "$GOLDEN_KEEP/"; }

fail=0
if diff -r "$GOLDEN" "$work/out/k3s01"; then
  echo "ok   k3s01: rendered files equal the goldens from b374c0e ($(find "$GOLDEN" -type f | wc -l) files)"
else
  echo "FAIL k3s01: rendered files differ from the goldens (diff above)"; fail=1
fi

s=$work/out/siem01
check() { # <description> <command...>
  local d=$1; shift
  if "$@"; then echo "ok   siem01: $d"; else echo "FAIL siem01: $d"; fail=1; fi
}
absent() { ! grep -qiE "$1" "$2"; }
# Rules only: the file's header comment explains the table scoping with Cilium as the example.
grep -vE '^\s*#' "$s/nftables.conf" >"$work/siem-rules.nft"
check "nftables has no kube-apiserver rule" absent '6443|kube-apiserver' "$work/siem-rules.nft"
check "nftables has no pod/service CIDR" absent '10\.42\.|10\.43\.' "$work/siem-rules.nft"
check "nftables has no Cilium rule" absent 'cilium' "$work/siem-rules.nft"
check "nftables accepts 9200/tcp from 10.4.1.20/32 only" \
  test "$(grep -E 'dport 9200 accept' "$s/nftables.conf" | tr -s ' ' | sed 's/^ //')" = \
  'ip saddr { 10.4.1.20/32 } tcp dport 9200 accept comment "opensearch"'
check "nftables accepts only ports 22 and 9200" \
  test "$(grep -oE 'dport [0-9{ ,}]+ accept' "$s/nftables.conf" | grep -oE '[0-9]+' | sort -n | tr '\n' ' ')" = '22 9200 '
check "nftables caps 9200/tcp from 10.4.1.20/32 at 4 mbytes/second, ahead of the established accept" \
  test "$(grep -nE 'dport 9200 limit rate over 4 mbytes/second counter drop|ct state established,related accept' "$s/nftables.conf" | cut -d: -f2 | tr -s ' ' | cut -c1-20 | tr '\n' '|')" = ' ip saddr { 10.4.1.2| ct state establishe|'
check "nftables input and forward chains drop by default" \
  test "$(grep -c 'policy drop;' "$s/nftables.conf")" = 2
check "sysctl has no forwarding or kubelet keys" \
  absent 'forward|overcommit_memory|panic_on_oom|kernel\.panic|root_maxkeys' "$s/90-hardening.conf"
check "sysctl sets strict rp_filter (all and default = 1)" \
  test "$(grep -E 'rp_filter' "$s/90-hardening.conf" | tr '\n' ' ')" = 'net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1 '
check "sysctl sets vm.max_map_count=262144" grep -qx 'vm.max_map_count=262144' "$s/90-hardening.conf"
check "no rp_filter drop-in" test ! -e "$s/99-cilium-rp-filter.conf"
check "no 50-k3s.rules" test ! -e "$s/50-k3s.rules"
check "60-extra.rules watches the SIEM config, plugins and sync" \
  test "$(grep -oE '^-w [^ ]+ -p wa -k [a-z_]+$' "$s/60-extra.rules" | wc -l)" = 5
check "sshd allows local forwarding to 127.0.0.1:5601 only" \
  grep -qx 'AllowTcpForwarding local' "$s/00-hardening.conf"
check "sshd PermitOpen is 127.0.0.1:5601" grep -qx 'PermitOpen 127.0.0.1:5601' "$s/00-hardening.conf"
check "sshd forwards no Unix sockets" grep -qx 'AllowStreamLocalForwarding no' "$s/00-hardening.conf"

if [ "$fail" != 0 ]; then echo "golden: FAIL"; exit 1; fi
echo "golden: PASS"
