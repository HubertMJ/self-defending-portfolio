#!/usr/bin/env bash
# Cilium is installed twice in this project's lifetime: once by Ansible so that Argo CD has a pod
# network to run on (ADR 0004), and from then on by Argo CD, which adopts the release. Two
# declarations of the same thing drift. This is the check that they have not.
#
# It asserts that `cilium_values` from the Ansible role and `spec.source.helm.valuesObject` of
# cluster/apps/cilium.yaml are *identical*, and that the chart version matches. Equality is the
# whole point: the Argo CD takeover has to be a no-op, because any value that only one side sets
# rewrites cilium-config under the running agents and forces a manual restart of the Cilium
# DaemonSet, cilium-envoy and cilium-operator (that is what the Gateway API additions cost before
# they were added to the role).
#
# It also asserts that the three Cilium images built here (app/cilium, app/cilium-operator-generic,
# app/hubble-relay; ADR 0028) carry byte-identical modules/go.mod and go.sum.
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
    problems.append(
        f"only in cluster/apps/cilium.yaml: {path} (add it to cilium_values in the Ansible role; "
        f"there is no allowance for one-sided values any more)"
    )

# --- the Cilium images built here (ADR 0028) are one source tree -----------------------------------
# app/cilium, app/cilium-operator-generic and app/hubble-relay compile the same Cilium commit, each
# with its own copy of the raised go.mod/go.sum (CI builds every app/<name> from its own directory).
# Different dependencies in the agent and the operator would be a combination upstream never shipped.
module_dirs = [root / "app" / name / "modules" for name in ("cilium", "cilium-operator-generic", "hubble-relay")]
for name in ("go.mod", "go.sum"):
    reference = (module_dirs[0] / name).read_bytes()
    for other in module_dirs[1:]:
        if (other / name).read_bytes() != reference:
            problems.append(
                f"{other.relative_to(root)}/{name} differs from {module_dirs[0].relative_to(root)}/{name} "
                f"(the three Cilium images must build with the same dependencies)"
            )

if problems:
    print("check-cilium-values: the declarations of Cilium disagree", file=sys.stderr)
    for problem in problems:
        print(f"  - {problem}", file=sys.stderr)
    sys.exit(1)

print(
    f"check-cilium-values: ok - {len(flat_ansible)} keys match exactly, chart {argo_chart_version}, "
    f"no values on only one side; the Cilium images build from identical modules"
)
PY
