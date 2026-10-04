#!/usr/bin/env bash
# Mutation proof of the P1 tests marked (M) in the siem contract: each mutation is applied to a
# scratch copy of the repository (the worktree is never modified) and the named test must FAIL on
# it. A mutation no test notices is a blocker.
#   golden render (tests/golden/render.sh):    drop the default of each group switch; give siem01
#                                               the k3s sysctl or audit rules; widen 9200's sources;
#                                               break the sysctl key order; ungate the rp_filter
#                                               copy; force 50-k3s.rules in; empty the removal loop
#   CSR signer (tests/siem/csr-signer.sh):      drop the subject compare; copy the CSR's extensions;
#                                               drop the SAN refusal, the PEM shape check, the key size
# Usage: tests/siem/p1-mutations.sh [name-filter]
set -euo pipefail
cd "$(dirname "$0")/../.."
DOCKER=${DOCKER:-docker}
filter=${1:-}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# mutate <name> <test script> <file> <old literal> <new literal> <expected FAIL line (ERE)>
# A mutation counts as killed only when the test fails WITH the expected line (review L5): a test
# that fails for another reason (a render error, a typo) proves nothing about the check.
results=()
mutate() {
  local name=$1 test=$2 file=$3 old=$4 new=$5 want=$6 copy
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
  elif line=$(grep -m1 -E "^FAIL .*($want)" "$work/$name.log"); then
    results+=("killed   $name -> $test: $line")
  else
    results+=("SURVIVED $name ($test failed, but not with /$want/: $(grep -m1 -E '^FAIL' "$work/$name.log" || tail -n 1 "$work/$name.log"))")
  fi
  rm -rf "$copy"
}

mutate golden-firewall-gate tests/golden/render.sh ansible/roles/firewall/defaults/main.yml \
  "firewall_k3s_enabled: \"{{ 'k3s_nodes' in group_names }}\"" "firewall_k3s_enabled: false" "k3s01: rendered files or plans differ"
mutate golden-sysctl-gate tests/golden/render.sh ansible/roles/sysctl/defaults/main.yml \
  "sysctl_k3s_enabled: \"{{ 'k3s_nodes' in group_names }}\"" "sysctl_k3s_enabled: false" "k3s01: rendered files or plans differ"
mutate golden-auditd-gate tests/golden/render.sh ansible/roles/auditd/defaults/main.yml \
  "auditd_k3s_enabled: \"{{ 'k3s_nodes' in group_names }}\"" "auditd_k3s_enabled: false" "k3s01: rendered files or plans differ"
mutate golden-siem-gets-k3s-sysctl tests/golden/render.sh ansible/roles/sysctl/defaults/main.yml \
  "sysctl_k3s_enabled: \"{{ 'k3s_nodes' in group_names }}\"" "sysctl_k3s_enabled: true" "siem01: sysctl has no forwarding or kubelet keys"
mutate golden-siem-gets-k3s-audit tests/golden/render.sh ansible/roles/auditd/defaults/main.yml \
  "auditd_k3s_enabled: \"{{ 'k3s_nodes' in group_names }}\"" "auditd_k3s_enabled: true" "siem01: no 50-k3s.rules"
mutate golden-siem-9200-open tests/golden/render.sh ansible/inventory/group_vars/siem_nodes.yml \
  "sources: [10.4.1.20/32]" "sources: [10.4.1.0/24]" "siem01: nftables accepts 9200/tcp from 10.4.1.20/32 only"
mutate golden-sysctl-order tests/golden/render.sh ansible/roles/sysctl/defaults/main.yml \
  "  net.ipv4.conf.all.rp_filter: null
  net.ipv4.conf.default.rp_filter: null
" "" "k3s01: rendered files or plans differ"
# The task gates themselves (review code M1): only the plan sees these.
mutate golden-rp-filter-copy-ungated tests/golden/render.sh ansible/roles/sysctl/tasks/main.yml \
  "    mode: \"0644\"
  when: sysctl_k3s_enabled | bool
  notify: Restart systemd-sysctl" "    mode: \"0644\"
  notify: Restart systemd-sysctl" "siem01: no rp_filter drop-in"
mutate golden-50-k3s-always-installed tests/golden/render.sh ansible/roles/auditd/tasks/main.yml \
  "            + (['50-k3s.rules'] if auditd_k3s_enabled | bool else [])" "            + ['50-k3s.rules']" "siem01: no 50-k3s.rules"
mutate golden-audit-removal-emptied tests/golden/render.sh ansible/roles/auditd/tasks/main.yml \
  "  loop: \"{{ ([] if auditd_k3s_enabled | bool else ['50-k3s.rules'])
            + ([] if auditd_extra_watches | length > 0 else ['60-extra.rules']) }}\"" "  loop: []" \
  "siem01: the auditd role removes 50-k3s.rules and never writes it"
mutate csr-no-subject-compare tests/siem/csr-signer.sh ansible/roles/opensearch/tasks/sign_client_csr.yml \
  "          - opensearch_csr_subject.stdout == 'subject=CN=' ~ opensearch_csr_name ~ '-g' ~ opensearch_csr_generation ~ ',OU=siem,O=sdp'
" "" "refused: CSR for CN=admin-g1,OU=siem,O=sdp when shipper-k3s01 is expected - a certificate was issued"
mutate csr-copy-extensions tests/siem/csr-signer.sh ansible/roles/opensearch/tasks/sign_client_csr.yml \
  "          - -copy_extensions
          - none" "          - -copy_extensions
          - copy" "accepted: no extension beyond BC, KU, EKU, SKI, AKI"
mutate csr-no-san-refusal tests/siem/csr-signer.sh ansible/roles/opensearch/tasks/sign_client_csr.yml \
  "          - (opensearch_csr_info.subject_alt_name or []) | length == 0
" "" "refused: CSR with a SAN - a certificate was issued"
mutate csr-no-pem-shape tests/siem/csr-signer.sh ansible/roles/opensearch/tasks/sign_client_csr.yml \
  "      - opensearch_csr_pem is match(" "      - opensearch_csr_pem is string or opensearch_csr_pem is match(" \
  "refused: input with a second PEM block"
mutate csr-weak-keys tests/siem/csr-signer.sh ansible/roles/opensearch/tasks/sign_client_csr.yml \
  "opensearch_csr_info.public_key_data.size | int >= 2048" "opensearch_csr_info.public_key_data.size | int >= 512" \
  "refused: CSR with a 1024-bit RSA key"

printf '%s\n' "${results[@]}"
if printf '%s\n' "${results[@]}" | grep -q '^SURVIVED'; then echo "p1-mutations: FAIL"; exit 1; fi
echo "p1-mutations: PASS (${#results[@]} mutations killed)"
