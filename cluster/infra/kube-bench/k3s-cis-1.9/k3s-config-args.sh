#!/bin/sh
# Stand-in for `journalctl -m -u k3s [-u k3s-agent]` in kube-bench's k3s-cis-1.9 audits (ADR 0014).
#
# The upstream audits read the component flags from the line k3s logs at start-up, e.g.
#   Running kube-apiserver --advertise-address=... --profiling=false ...
# and pipe it through `grep 'Running kube-apiserver' | tail -n1 | grep <flag>`. The kube-bench image
# (Alpine) has no journalctl, and the host's binary is linked against the host's glibc, so instead of
# reading the journal this script prints the same kind of lines built from the k3s configuration file
# that Ansible writes (ansible/roles/k3s/templates/config.yaml.j2). Everything after the `journalctl`
# in each audit is unchanged, so the tests still parse `--flag=value` exactly as upstream wrote them.
#
# What it can and cannot see. It prints only what is *explicitly configured*:
#   * kube-apiserver-arg, kube-controller-manager-arg, kube-scheduler-arg, kubelet-arg,
#     kube-proxy-arg list entries, as `--<entry>`;
#   * `secrets-encryption: true`, which k3s v1.35 translates into
#     --encryption-provider-config=<data-dir>/server/cred/encryption-config.json and
#     --encryption-provider-config-automatic-reload=true (pkg/daemons/control/server.go,
#     pkg/daemons/control/deps/deps.go at v1.35.9+k3s1);
#   * a "Managed etcd cluster" line when `cluster-init: true` (the audits use it to decide whether the
#     etcd client flags apply), and no kube-proxy line with `disable-kube-proxy: true`, as k3s logs.
# Flags k3s sets on its own (--profiling=false, --anonymous-auth=false, the TLS file paths, ...) are
# NOT printed: they appear in the journal but not in the config file. A check that depends on one of
# them reports FAIL here, meaning "not visible in the configuration", and is verified on the node with
#   journalctl -m -u k3s | grep 'Running kube-apiserver' | tail -n1
# Reproducing k3s's built-in defaults in this script was rejected: a table that drifted from k3s would
# turn into false PASS results, which is the one failure mode a benchmark must not have.
#
# Not handled (and not used by this repository): the `+` append suffix of config.yaml.d drop-ins and
# flow-style lists (`key: [a, b]`). Drop-ins are read in name order and their list entries appended.
set -eu

CONFIG=${K3S_CONFIG_FILE:-/etc/rancher/k3s/config.yaml}
DATA_DIR=/var/lib/rancher/k3s

files=$CONFIG
if [ -d "$CONFIG.d" ]; then
  for f in "$CONFIG.d"/*.yaml; do [ -e "$f" ] && files="$files $f"; done
fi

# shellcheck disable=SC2086  # $files is a space-separated list of paths without spaces
cat $files 2>/dev/null | awk -v datadir="$DATA_DIR" '
  function unquote(s) {
    sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s)
    if (s ~ /^".*"$/ || s ~ /^\047.*\047$/) s = substr(s, 2, length(s) - 2)
    return s
  }
  # A top-level key starts in column 0; everything indented under it belongs to it.
  /^[A-Za-z0-9_.+-]+:/ {
    key = $0; sub(/:.*/, "", key)
    value = $0; sub(/^[^:]*:/, "", value); sub(/[ \t]+#.*$/, "", value); value = unquote(value)
    if (key == "secrets-encryption" && value == "true") encrypt = 1
    if (key == "cluster-init" && value == "true") etcd = 1
    if (key == "disable-kube-proxy" && value == "true") noproxy = 1
    next
  }
  /^[ \t]+-[ \t]*/ {
    item = $0; sub(/^[ \t]+-[ \t]*/, "", item); sub(/[ \t]+#.*$/, "", item); item = unquote(item)
    if (key == "kube-apiserver-arg")          api = api " --" item
    if (key == "kube-controller-manager-arg") kcm = kcm " --" item
    if (key == "kube-scheduler-arg")          sched = sched " --" item
    if (key == "kubelet-arg")                 kubelet = kubelet " --" item
    if (key == "kube-proxy-arg")              proxy = proxy " --" item
  }
  END {
    if (encrypt) api = " --encryption-provider-config=" datadir "/server/cred/encryption-config.json" \
                       " --encryption-provider-config-automatic-reload=true" api
    if (etcd) print "Managed etcd cluster (cluster-init: true in the k3s config)"
    print "Running kube-apiserver" api
    print "Running kube-controller-manager" kcm
    print "Running kube-scheduler" sched
    print "Running kubelet" kubelet
    # k3s does not start (or log) kube-proxy at all with disable-kube-proxy (Cilium replaces it).
    if (!noproxy) print "Running kube-proxy" proxy
  }
'
