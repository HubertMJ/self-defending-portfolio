#!/usr/bin/env bash
# Mutation proof of the P1 tests marked (M) in the siem contract: each mutation is applied to a
# scratch copy of the repository (the worktree is never modified) and the named test must FAIL on
# it. A mutation no test notices is a blocker.
#   golden render (tests/golden/render.sh):    drop the default of each group switch; give siem01
#                                               the k3s sysctl or audit rules; widen 9200's sources;
#                                               break the sysctl key order
#   CSR signer (tests/siem/csr-signer.sh):      drop the subject compare; copy the CSR's extensions;
#                                               drop the SAN refusal
# Usage: tests/siem/p1-mutations.sh [name-filter]
set -euo pipefail
cd "$(dirname "$0")/../.."
DOCKER=${DOCKER:-docker}
filter=${1:-}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# mutate <name> <test script> <file> <python old literal> <python new literal>
results=()
mutate() {
  local name=$1 test=$2 file=$3 old=$4 new=$5 copy
  [ -n "$filter" ] && [[ $name != *"$filter"* ]] && return 0
  copy=$work/$name
  mkdir -p "$copy"
  tar -c --exclude=./.git --exclude=./.ansible . | tar -x -C "$copy"
  python3 - "$copy/$file" "$old" "$new" <<'PY'
import sys
path, old, new = sys.argv[1:]
text = open(path).read()
if text.count(old) != 1:
    sys.exit(f"mutation anchor found {text.count(old)} times in {path}: {old!r}")
open(path, "w").write(text.replace(old, new))
PY
  if (cd "$copy" && DOCKER="$DOCKER" "$test" >"$work/$name.log" 2>&1); then
    results+=("SURVIVED $name ($test still passes)")
  else
    results+=("killed   $name -> $test: $(grep -m1 -E '^FAIL' "$work/$name.log" || tail -n 1 "$work/$name.log")")
  fi
  rm -rf "$copy"
}

mutate golden-firewall-gate tests/golden/render.sh ansible/roles/firewall/defaults/main.yml \
  "firewall_k3s_enabled: \"{{ 'k3s_nodes' in group_names }}\"" "firewall_k3s_enabled: false"
mutate golden-sysctl-gate tests/golden/render.sh ansible/roles/sysctl/defaults/main.yml \
  "sysctl_k3s_enabled: \"{{ 'k3s_nodes' in group_names }}\"" "sysctl_k3s_enabled: false"
mutate golden-auditd-gate tests/golden/render.sh ansible/roles/auditd/defaults/main.yml \
  "auditd_k3s_enabled: \"{{ 'k3s_nodes' in group_names }}\"" "auditd_k3s_enabled: false"
mutate golden-siem-gets-k3s-sysctl tests/golden/render.sh ansible/roles/sysctl/defaults/main.yml \
  "sysctl_k3s_enabled: \"{{ 'k3s_nodes' in group_names }}\"" "sysctl_k3s_enabled: true"
mutate golden-siem-gets-k3s-audit tests/golden/render.sh ansible/roles/auditd/defaults/main.yml \
  "auditd_k3s_enabled: \"{{ 'k3s_nodes' in group_names }}\"" "auditd_k3s_enabled: true"
mutate golden-siem-9200-open tests/golden/render.sh ansible/inventory/group_vars/siem_nodes.yml \
  "sources: [10.4.1.20/32]" "sources: [10.4.1.0/24]"
mutate golden-sysctl-order tests/golden/render.sh ansible/roles/sysctl/defaults/main.yml \
  "  net.ipv4.conf.all.rp_filter: null
  net.ipv4.conf.default.rp_filter: null
" ""
mutate csr-no-subject-compare tests/siem/csr-signer.sh ansible/roles/opensearch/tasks/sign_client_csr.yml \
  "          - opensearch_csr_subject.stdout == 'subject=CN=' ~ opensearch_csr_name ~ '-g' ~ opensearch_csr_generation ~ ',OU=siem,O=sdp'
" ""
mutate csr-copy-extensions tests/siem/csr-signer.sh ansible/roles/opensearch/tasks/sign_client_csr.yml \
  "          - -copy_extensions
          - none" "          - -copy_extensions
          - copy"
mutate csr-no-san-refusal tests/siem/csr-signer.sh ansible/roles/opensearch/tasks/sign_client_csr.yml \
  "          - (opensearch_csr_info.subject_alt_name or []) | length == 0
" ""

printf '%s\n' "${results[@]}"
if printf '%s\n' "${results[@]}" | grep -q '^SURVIVED'; then echo "p1-mutations: FAIL"; exit 1; fi
echo "p1-mutations: PASS (${#results[@]} mutations killed)"
