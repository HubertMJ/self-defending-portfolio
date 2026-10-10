#!/usr/bin/env bash
# ADR 0025, amendment 2026-10-10: a check the kube-bench patch skips as "Not Applicable." must stay
# not applicable. 1.2.26 (--etcd-cafile) is skipped because this k3s keeps its datastore in SQLite
# through kine, with no etcd. If the k3s role ever configures etcd - embedded (cluster-init) or
# external (datastore-endpoint, etcd-* flags) - the reason is false and the skip would hide a real
# check: fail here until the skip is removed from app/kube-bench/k3s-cis-1.9.patch.
#
# What is read: the checks the patch adds `type: "skip"` to (by the `- id:` line above each in the
# hunk), and every non-comment line of the k3s role and its inventory (templates, defaults, tasks,
# group_vars), where a datastore setting would have to be. Comments may mention the words.
set -euo pipefail
cd "$(dirname "$0")/.."
patch=app/kube-bench/k3s-cis-1.9.patch
python3 - "$patch" ansible/roles/k3s ansible/inventory <<'PY'
import os, re, sys

patch, roots = sys.argv[1], sys.argv[2:]
skipped, last_id = [], None
for line in open(patch):
    m = re.match(r'^[ +]\s+- id: "?([0-9.]+)"?\s*$', line)
    if m:
        last_id = m.group(1)
    elif re.match(r'^\+\s+type: "?skip"?\s*$', line):
        skipped.append(last_id)
print(f"check-cis-na: the patch skips {', '.join(map(str, skipped)) or 'nothing'}")

etcd = re.compile(r'cluster[-_]init|datastore[-_]endpoint|\betcd[-_](?!servers)|etcd-arg|k3s_etcd', re.I)
hits = []
for root in roots:
    for dirpath, _, files in os.walk(root):
        for f in files:
            path = os.path.join(dirpath, f)
            try:
                lines = open(path, encoding="utf-8").read().splitlines()
            except UnicodeDecodeError:
                continue
            for n, text in enumerate(lines, 1):
                code = text.split("#", 1)[0] if not f.endswith(".j2") else re.sub(r"^\s*#.*", "", text)
                if etcd.search(code):
                    hits.append(f"{path}:{n}: {text.strip()}")

if "1.2.26" in skipped and hits:
    print("check-cis-na: 1.2.26 is skipped as not applicable (no etcd), but the k3s role configures etcd:", file=sys.stderr)
    for h in hits:
        print(f"  {h}", file=sys.stderr)
    print("  remove the skip from the patch (and its reason) or the etcd setting", file=sys.stderr)
    sys.exit(1)
if None in skipped:
    sys.exit("check-cis-na: a skip in the patch has no check id above it")
print("check-cis-na: ok - no etcd datastore configured in the k3s role")
PY
