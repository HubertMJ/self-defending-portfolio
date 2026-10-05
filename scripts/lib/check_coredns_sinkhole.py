"""The `exfil.sdp.test` sinkhole can never forward (ADR 0034, ADR 0026 and 0017 amendments).

Used by scripts/validate-cluster.sh:

    check_coredns_sinkhole.py <repo root>

The terminal's dns-exfil command puts the run's flag into a DNS label under `exfil.sdp.test`. That
name stays inside the cluster only because CoreDNS answers the zone itself, from a server block in the
Corefile of ConfigMap `coredns`, rendered by the k3s role from templates/coredns-sdp.yaml.j2
(ADR 0026). What would send the flag to an upstream resolver is a one-line edit anywhere in what
CoreDNS actually loads - a `forward` in the block, another block (or a block in an imported file) that
serves the zone or a name under it, a `bind` that takes the block off the pod's address, a Corefile the
Deployment no longer mounts or reloads, or a role that no longer deploys this template. kubeconform
does not see this template, and the live test (tests/scenarios/run.sh) runs only after the role has
been applied. So the template is rendered here with the role's defaults and the k3s01 inventory
(Jinja2, as Ansible would; facts only a running play has are stubbed) and the effective configuration
is checked:
  - k3s_coredns_own is true (otherwise k3s's own CoreDNS runs, without the sinkhole);
  - exactly one ConfigMap kube-system/coredns and one Deployment kube-system/coredns, at most one
    ConfigMap kube-system/coredns-custom; no binaryData in either ConfigMap;
  - the Corefile's top level is server blocks plus exactly one `import /etc/coredns/custom/*.server`;
    exactly one block is the sinkhole, byte for byte after whitespace (SINKHOLE_BLOCK), and no other
    block - in the Corefile or in any coredns-custom *.server file - serves `exfil.sdp.test` or a
    name under it, on any port or transport (zones compared case-insensitively, trailing dot, scheme
    and port stripped, several zones per header);
  - no `bind` in any block (a sinkhole bound elsewhere leaves the pod's address to `.:53`);
  - the Deployment runs `-conf /etc/coredns/Corefile`, with no command override; it mounts ConfigMap
    coredns at /etc/coredns with the Corefile item, and coredns-custom at /etc/coredns/custom without
    `items`; no `subPath` (a subPath mount is never updated, so a changed Corefile would not load) and
    no other mount under /etc/coredns.
Exits non-zero with every problem listed. scripts/lib/test_check_coredns_sinkhole.py proves that each
of these checks fails on its mutation.
"""

import re
import sys
from pathlib import Path

import jinja2
import yaml

ZONE = "exfil.sdp.test."
# The block, one directive per line, whitespace-normalised. Exact: anything added, removed or changed
# is a failure.
SINKHOLE_BLOCK = [
    "exfil.sdp.test:53 {",
    "errors",
    "prometheus :9153",
    "template IN A exfil.sdp.test {",
    'match "^ok[.]exfil[.]sdp[.]test[.]$"',
    'answer "{{ .Name }} 60 IN A 192.0.2.53"',
    "fallthrough",
    "}",
    "template ANY ANY exfil.sdp.test {",
    "rcode NXDOMAIN",
    "}",
    "}",
]
# Directives named in the error message because of what they would do in the sinkhole block.
NAMED = {
    "forward": "forwards the zone (and the flag in its label) to an upstream resolver",
    "log": "writes every query name - the flag - to the CoreDNS log",
    "alternate": "re-sends the query to another resolver on some answers",
    "import": "pulls further directives into the block",
    "bind": "moves the block off the address pods query",
}
TOP_IMPORTS = ["import /etc/coredns/custom/*.server"]
CONF_ARGS = ["-conf", "/etc/coredns/Corefile"]
CORE_DIR = "/etc/coredns"
CUSTOM_DIR = "/etc/coredns/custom"
SCHEME = re.compile(r"^([a-z0-9+.-]+)://", re.IGNORECASE)


def render(root: Path, template: str = None, overrides: dict = None):
    """(documents, context) of the k3s role's CoreDNS template, rendered as the role would."""
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
    context.update(overrides or {})
    if template is None:
        template = (role / "templates/coredns-sdp.yaml.j2").read_text()
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
    text = env.from_string(template).render(context)
    return [d for d in yaml.safe_load_all(text) if d], context


def directives(text: str) -> list:
    """The lines, comments dropped, whitespace collapsed, blank lines skipped."""
    out = []
    for line in text.splitlines():
        line = " ".join(line.split("#", 1)[0].split())
        if line:
            out.append(line)
    return out


def parse_top(text: str, where: str, problems: list):
    """(blocks, imports) of a Corefile: blocks as (header keys, body lines incl. header and braces)."""
    blocks, imports = [], []
    lines = directives(text)
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("import "):
            imports.append(line)
            i += 1
            continue
        if not line.endswith("{") or line.startswith("("):
            # A header split from its brace, a snippet, a stray directive: not a layout this
            # repository writes, so not one this check can vouch for.
            problems.append(f"{where}: unexpected top-level line `{line}`")
            i += 1
            continue
        depth, body = 0, []
        while i < len(lines):
            body.append(lines[i])
            depth += lines[i].count("{") - lines[i].count("}")
            i += 1
            if depth == 0:
                break
        if depth != 0:
            problems.append(f"{where}: unbalanced braces in the block starting `{line}`")
        keys = [k for k in re.split(r"[\s,]+", line[:-1].strip()) if k]
        blocks.append((keys, body))
    return blocks, imports


def zone_of(key: str) -> str:
    """`dns://EXFIL.sdp.test.:53` -> `exfil.sdp.test.`."""
    key = SCHEME.sub("", key)
    key = re.sub(r":\d+$", "", key)
    key = key.lower()
    return key if key.endswith(".") else key + "."


def serves_zone(keys: list) -> bool:
    return any(zone_of(k) == ZONE or zone_of(k).endswith("." + ZONE) for k in keys)


def check_blocks(blocks: list, where: str, problems: list, allow_sinkhole: bool) -> int:
    """Problems for blocks that serve the zone or bind; returns how many exact sinkhole blocks."""
    exact = 0
    for keys, body in blocks:
        for line in body[1:]:
            if line.split()[0] == "bind":
                problems.append(f"{where}: `{line}` in the block for {' '.join(keys)} ({NAMED['bind']})")
        if not serves_zone(keys):
            continue
        if allow_sinkhole and body == SINKHOLE_BLOCK:
            exact += 1
            continue
        for line in body[1:]:
            word = line.split()[0]
            if word in NAMED and word != "bind":
                problems.append(f"{where}: `{line}` in the block for {' '.join(keys)}: {NAMED[word]}")
        problems.append(f"{where}: a block other than the exact sinkhole serves {ZONE} or a name under it: {body}")
    return exact


def find_all(docs: list, kind: str, name: str) -> list:
    return [d for d in docs if d.get("kind") == kind
            and (d.get("metadata") or {}).get("name") == name
            and (d.get("metadata") or {}).get("namespace") == "kube-system"]


def check(docs: list, context: dict) -> list:
    problems = []
    if context.get("k3s_coredns_own") is not True:
        problems.append(f"k3s_coredns_own is {context.get('k3s_coredns_own')!r}: k3s's own CoreDNS (no sinkhole) would run")

    cores = find_all(docs, "ConfigMap", "coredns")
    customs = find_all(docs, "ConfigMap", "coredns-custom")
    deploys = find_all(docs, "Deployment", "coredns")
    if len(cores) != 1:
        problems.append(f"{len(cores)} ConfigMap kube-system/coredns documents in the render, want exactly 1")
    if len(customs) > 1:
        problems.append(f"{len(customs)} ConfigMap kube-system/coredns-custom documents in the render, want at most 1")
    if len(deploys) != 1:
        problems.append(f"{len(deploys)} Deployment kube-system/coredns documents in the render, want exactly 1")
    for cm in cores + customs:
        if cm.get("binaryData"):
            problems.append(f"ConfigMap {cm['metadata']['name']} has binaryData {sorted(cm['binaryData'])}: not checked here, may shadow a key")

    corefile = ((cores[0] if cores else {}).get("data") or {}).get("Corefile", "")
    blocks, imports = parse_top(corefile, "Corefile", problems)
    if imports != TOP_IMPORTS:
        problems.append(f"Corefile top-level imports are {imports}, want exactly {TOP_IMPORTS}")
    exact = check_blocks(blocks, "Corefile", problems, allow_sinkhole=True)
    if exact != 1:
        problems.append(f"the Corefile has {exact} exact sinkhole blocks for {ZONE}, want 1: {SINKHOLE_BLOCK}")

    for cm in customs:
        for key, value in (cm.get("data") or {}).items():
            if key.endswith(".server"):
                cblocks, cimports = parse_top(value, f"coredns-custom {key}", problems)
                if cimports:
                    problems.append(f"coredns-custom {key} imports {cimports}")
                check_blocks(cblocks, f"coredns-custom {key}", problems, allow_sinkhole=False)
            elif any(line.split()[0] == "bind" for line in directives(value)):
                problems.append(f"coredns-custom {key}: `bind` ({NAMED['bind']})")

    spec = (((deploys[0] if deploys else {}).get("spec") or {}).get("template") or {}).get("spec") or {}
    volumes = {v.get("name"): v for v in spec.get("volumes", [])}
    containers = spec.get("containers", [])
    if len(containers) != 1:
        problems.append(f"Deployment coredns has {len(containers)} containers, want 1")
    for c in containers:
        if "command" in c:
            problems.append(f"Deployment coredns overrides the command: {c['command']}")
        if c.get("args") != CONF_ARGS:
            problems.append(f"Deployment coredns runs with args {c.get('args')}, want {CONF_ARGS}")
        core_ok = custom_ok = False
        for m in c.get("volumeMounts", []):
            path = str(m.get("mountPath", "")).rstrip("/")
            cm = (volumes.get(m.get("name")) or {}).get("configMap") or {}
            if not (path == CORE_DIR or path.startswith(CORE_DIR + "/")):
                continue
            if "subPath" in m or "subPathExpr" in m:
                problems.append(f"mount {path} uses subPath: a subPath mount never sees a ConfigMap update")
            if path == CORE_DIR and cm.get("name") == "coredns":
                items = {i.get("key"): i.get("path") for i in cm.get("items", [])}
                if cm.get("items") is not None and items.get("Corefile") != "Corefile":
                    problems.append(f"ConfigMap coredns is mounted without the Corefile item at Corefile: {cm.get('items')}")
                core_ok = True
            elif path == CUSTOM_DIR and cm.get("name") == "coredns-custom":
                if "items" in cm:
                    problems.append(f"coredns-custom is mounted with items {cm['items']}: the import must see every key or none")
                custom_ok = True
            else:
                problems.append(f"unexpected mount at {path} (volume {m.get('name')}): it would change what CoreDNS reads")
        if not core_ok:
            problems.append(f"Deployment coredns does not mount ConfigMap coredns at {CORE_DIR}")
        if not custom_ok:
            problems.append(f"Deployment coredns does not mount ConfigMap coredns-custom at {CUSTOM_DIR}")
    return problems


def main() -> int:
    problems = check(*render(Path(sys.argv[1])))
    for p in problems:
        print(f"  FAIL  {p}", file=sys.stderr)
    if problems:
        return 1
    print("  exfil.sdp.test sinkhole: one exact block in the Corefile (canary + NXDOMAIN, no forward, no log),"
          " nothing else serves the zone, mounted and loaded as -conf")
    return 0


if __name__ == "__main__":
    sys.exit(main())
