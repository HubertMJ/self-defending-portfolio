"""The `exfil.sdp.test` sinkhole can never forward (ADR 0034, ADR 0017 amendment of 2026-10-03).

Used by scripts/validate-cluster.sh:

    check_coredns_sinkhole.py <repo root>

The terminal's dns-exfil command puts the run's flag into a DNS label under `exfil.sdp.test`. That
name stays inside the cluster only because CoreDNS answers the zone itself: ConfigMap
`coredns-custom`, key `exfil-sinkhole.server`, rendered by the k3s role from
templates/coredns-sdp.yaml.j2 (ADR 0026). A `forward` (or any other directive) added to that block
would send the flag to an upstream resolver; a removed `import` of the custom server blocks, or a
Deployment that no longer mounts the ConfigMap, would let the zone fall through to the `.:53` block,
whose `forward` sends it out the same way. Both are one-line edits that no other check notices -
kubeconform does not see this template, and the live test (tests/scenarios/run.sh) runs only after
the role has been applied.

So the template is rendered here with the role's defaults and the k3s01 inventory (Jinja2, as Ansible
would; facts that only a running play has are stubbed), and the render must hold:
  - ConfigMap kube-system/coredns-custom with exactly one key, `exfil-sinkhole.server`, whose block is
    exactly: zone `exfil.sdp.test:53`, `errors`, `prometheus :9153`, and a `template ANY ANY
    exfil.sdp.test` answering `rcode NXDOMAIN` - nothing else. `forward` and `log` are named in
    the error when present (the leak, and the query name written to a log), but any other directive
    fails too: the block is an allow-list, not a deny-list.
  - the Corefile of ConfigMap kube-system/coredns imports /etc/coredns/custom/*.server at the top level;
  - Deployment kube-system/coredns mounts ConfigMap coredns-custom at /etc/coredns/custom.
Exits non-zero with every problem listed.
"""

import sys
from pathlib import Path

import jinja2
import yaml

SINKHOLE_KEY = "exfil-sinkhole.server"
# The block, one directive per line, whitespace-normalised. Exact: anything added, removed or changed
# is a failure.
SINKHOLE_BLOCK = [
    "exfil.sdp.test:53 {",
    "errors",
    "prometheus :9153",
    "template ANY ANY exfil.sdp.test {",
    "rcode NXDOMAIN",
    "}",
    "}",
]
# Directives named in the error message because of what they would do here.
NAMED = {
    "forward": "forwards the zone (and the flag in its label) to an upstream resolver",
    "log": "writes every query name - the flag - to the CoreDNS log",
    "alternate": "re-sends the query to another resolver on some answers",
    "import": "pulls further directives into the block",
}
IMPORT_LINE = "import /etc/coredns/custom/*.server"
CUSTOM_DIR = "/etc/coredns/custom"


def render(root: Path) -> list:
    role = root / "ansible/roles/k3s"
    context = {}
    for source in (role / "defaults/main.yml", root / "ansible/inventory/group_vars/k3s_nodes.yml"):
        context.update(yaml.safe_load(source.read_text()) or {})
    # What only a running play has; the values restate the single-node inventory.
    context.update({
        "ansible_managed": "Ansible managed",
        "ansible_facts": {"hostname": "k3s01"},
        "ansible_default_ipv4": {"address": context.get("k3s_node_ip", "10.4.1.20")},
    })
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
    text = env.from_string((role / "templates/coredns-sdp.yaml.j2").read_text()).render(context)
    return [d for d in yaml.safe_load_all(text) if d]


def directives(block: str) -> list:
    """The block's lines, comments dropped, whitespace collapsed, blank lines skipped."""
    out = []
    for line in block.splitlines():
        line = line.split("#", 1)[0]
        line = " ".join(line.split())
        if line:
            out.append(line)
    return out


def find(docs: list, kind: str, name: str):
    for d in docs:
        meta = d.get("metadata") or {}
        if d.get("kind") == kind and meta.get("name") == name and meta.get("namespace") == "kube-system":
            return d
    return None


def check(docs: list) -> list:
    problems = []

    custom = find(docs, "ConfigMap", "coredns-custom")
    if custom is None:
        problems.append("no ConfigMap kube-system/coredns-custom in the render: nothing sinkholes exfil.sdp.test")
    else:
        data = custom.get("data") or {}
        extra = sorted(set(data) - {SINKHOLE_KEY})
        if extra:
            problems.append(f"coredns-custom has keys besides {SINKHOLE_KEY}: {extra} (each would be imported into CoreDNS)")
        if SINKHOLE_KEY not in data:
            problems.append(f"coredns-custom has no key {SINKHOLE_KEY}")
        else:
            got = directives(data[SINKHOLE_KEY])
            for line in got:
                word = line.split()[0]
                if word in NAMED:
                    problems.append(f"{SINKHOLE_KEY}: `{line}` {NAMED[word]}")
            if got != SINKHOLE_BLOCK:
                problems.append(f"{SINKHOLE_KEY} is not exactly the sinkhole block; want {SINKHOLE_BLOCK}, got {got}")

    core = find(docs, "ConfigMap", "coredns")
    corefile = ((core or {}).get("data") or {}).get("Corefile", "")
    # Top level: outside every brace. An import inside `.:53 { }` would splice the block into that
    # server instead of adding a server of its own.
    depth, top = 0, []
    for line in directives(corefile):
        if depth == 0:
            top.append(line)
        depth += line.count("{") - line.count("}")
    if IMPORT_LINE not in top:
        problems.append(f"the coredns Corefile does not `{IMPORT_LINE}` at the top level: the sinkhole block would never load")

    deploy = find(docs, "Deployment", "coredns")
    spec = (((deploy or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
    volumes = {v.get("name"): v for v in spec.get("volumes", [])}
    mounted = False
    for c in spec.get("containers", []):
        for m in c.get("volumeMounts", []):
            cm = (volumes.get(m.get("name")) or {}).get("configMap") or {}
            if m.get("mountPath") == CUSTOM_DIR and cm.get("name") == "coredns-custom":
                mounted = True
    if not mounted:
        problems.append(f"Deployment coredns does not mount ConfigMap coredns-custom at {CUSTOM_DIR}")
    return problems


def main() -> int:
    root = Path(sys.argv[1])
    problems = check(render(root))
    for p in problems:
        print(f"  FAIL  {p}", file=sys.stderr)
    if problems:
        return 1
    print("  exfil.sdp.test sinkhole: NXDOMAIN only, no forward, no log; imported and mounted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
