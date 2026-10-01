#!/usr/bin/env bash
# Cilium is installed twice in this project's lifetime: once by Ansible so that Argo CD has a pod
# network to run on (ADR 0004), and from then on by Argo CD, which adopts the release. Two
# declarations of the same thing drift. This is the check that they have not.
#
# It asserts that every key in `cilium_values` from the Ansible role appears with the same value in
# `spec.source.helm.valuesObject` of cluster/apps/cilium.yaml, and that the chart version matches.
# Extra keys are allowed on the Argo CD side only under the paths listed in ALLOWED_EXTRA_PATHS
# below -- the Gateway API additions from phase 2, which Ansible deliberately does not set.
#
# Requires: python3 with PyYAML and Jinja2 (both come with ansible-core, see requirements.txt).
set -euo pipefail

cd "$(dirname "$0")/.."

exec python3 - "$PWD" <<'PY'
import sys
from pathlib import Path

import jinja2
import yaml

root = Path(sys.argv[1])
role_defaults = root / "ansible/roles/cilium/defaults/main.yml"
group_vars = root / "ansible/inventory/group_vars/k3s_nodes.yml"
argo_app = root / "cluster/apps/cilium.yaml"

# Paths (dotted) that may exist in the Argo CD values but not in the Ansible role. Anything else
# extra is a drift in the other direction and fails too: a value that only Argo CD sets is a value
# that a re-run of the Ansible role would silently remove.
ALLOWED_EXTRA_PATHS = ("gatewayAPI", "envoy")

def load(path):
    with path.open() as handle:
        return yaml.safe_load(handle) or {}

# --- resolve the Ansible side -------------------------------------------------------------------
# cilium_values is full of Jinja references, some of which point at other templated variables
# (cilium_k8s_service_host -> k3s_node_ip). Render repeatedly until the result stops changing.
# Ansible facts and magic variables that the role's defaults reference but that no file declares.
# Both are pinned by the single-node inventory (ansible/inventory/hosts.yml), so hard-coding them
# here is a restatement of the inventory, not an assumption about it.
context = {
    "inventory_hostname_short": "k3s01",
    "ansible_default_ipv4": {"address": "10.4.1.20"},
}
# Only these two files: the role's own defaults, and the inventory that overrides them. The k3s
# role's defaults are deliberately not loaded -- they reference playbook-time magic variables that
# have no meaning outside a running play, and nothing in cilium_values needs them.
for source in (role_defaults, group_vars):
    context.update(load(source))

env = jinja2.Environment(undefined=jinja2.StrictUndefined, keep_trailing_newline=False)

def render(value, ctx):
    if isinstance(value, str) and "{{" in value:
        out = env.from_string(value).render(**ctx)
        # Ansible's Jinja produces strings; recover the native type the chart expects.
        try:
            return yaml.safe_load(out)
        except yaml.YAMLError:
            return out
    if isinstance(value, dict):
        return {k: render(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, ctx) for v in value]
    return value

for _ in range(10):
    rendered = {k: render(v, context) for k, v in context.items()}
    if rendered == context:
        break
    context = rendered
else:
    sys.exit("check-cilium-values: variable resolution did not converge; is there a Jinja cycle?")

ansible_values = context["cilium_values"]
ansible_chart_version = str(context["cilium_version"])

# --- resolve the Argo CD side -------------------------------------------------------------------
app = load(argo_app)
source = app["spec"]["source"]
argo_values = source["helm"]["valuesObject"]
argo_chart_version = str(source["targetRevision"])

# --- compare ------------------------------------------------------------------------------------
def flatten(tree, prefix=""):
    flat = {}
    for key, value in tree.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(flatten(value, f"{path}."))
        else:
            flat[path] = value
    return flat

flat_ansible = flatten(ansible_values)
flat_argo = flatten(argo_values)
problems = []

if ansible_chart_version != argo_chart_version:
    problems.append(
        f"chart version: ansible cilium_version={ansible_chart_version} but "
        f"cluster/apps/cilium.yaml targetRevision={argo_chart_version}"
    )

for path, expected in sorted(flat_ansible.items()):
    if path not in flat_argo:
        problems.append(f"missing in cluster/apps/cilium.yaml: {path} (ansible sets {expected!r})")
    elif flat_argo[path] != expected:
        problems.append(
            f"value differs at {path}: ansible={expected!r} argo={flat_argo[path]!r}"
        )

for path in sorted(flat_argo):
    if path in flat_ansible:
        continue
    if path.split(".")[0] in ALLOWED_EXTRA_PATHS:
        continue
    problems.append(
        f"only in cluster/apps/cilium.yaml: {path} (add it to the Ansible role, or to "
        f"ALLOWED_EXTRA_PATHS in scripts/check-cilium-values.sh with a reason)"
    )

if problems:
    print("check-cilium-values: Ansible and Argo CD disagree about Cilium", file=sys.stderr)
    for problem in problems:
        print(f"  - {problem}", file=sys.stderr)
    sys.exit(1)

print(
    f"check-cilium-values: ok - {len(flat_ansible)} shared keys match, chart {argo_chart_version}, "
    f"{len(flat_argo) - len(flat_ansible)} phase-2 additions under {'/'.join(ALLOWED_EXTRA_PATHS)}"
)
PY
