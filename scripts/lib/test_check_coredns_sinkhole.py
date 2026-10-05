"""Mutation proof of check_coredns_sinkhole.py (ADR 0026 amendment of 2026-10-04).

Used by scripts/validate-cluster.sh right after the check itself:

    test_check_coredns_sinkhole.py <repo root>

Each case edits a copy of the k3s role's CoreDNS template (in memory; nothing on disk changes), or the
role variables it is rendered with, in one way that would let `exfil.sdp.test` reach an upstream
resolver or stop the sinkhole from loading - and the check must report at least one problem for it.
The unedited template must pass. A case whose edit no longer applies (the text it replaces is gone)
fails too, so a template change cannot silently retire a mutation.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_coredns_sinkhole import check, render  # noqa: E402

SINKHOLE_HEAD = "    exfil.sdp.test:53 {\n"
TOP_IMPORT = "    import /etc/coredns/custom/*.server\n"
OVERRIDE_IMPORT = "        import /etc/coredns/custom/*.override\n"
CUSTOM_VOLUME = """          configMap:
            name: coredns-custom
            optional: true
"""
CORE_MOUNT = """            - name: config-volume
              mountPath: /etc/coredns
"""
EXTRA_CUSTOM = """---
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns-custom
  namespace: kube-system
data:
  leak.server: |
    %s {
        forward . 1.1.1.1
    }
"""

# (name, text to find, replacement) - or (name, None, role-variable overrides).
CASES = [
    ("forward in the sinkhole", "        prometheus :9153\n        template IN A",
     "        prometheus :9153\n        forward . /etc/resolv.conf\n        template IN A"),
    ("log in the sinkhole", "    exfil.sdp.test:53 {\n        errors\n", "    exfil.sdp.test:53 {\n        log\n        errors\n"),
    ("template replaced by forward", "        template ANY ANY exfil.sdp.test {\n          rcode NXDOMAIN\n        }\n",
     "        forward . /etc/resolv.conf\n"),
    ("rcode changed", "          rcode NXDOMAIN", "          rcode NOERROR"),
    ("canary answer changed", "60 IN A 192.0.2.53", "60 IN A 10.43.0.10"),
    ("sinkhole block removed", SINKHOLE_HEAD, "    removed.invalid:53 {\n"),
    ("child zone block", TOP_IMPORT, "    x.exfil.sdp.test:53 {\n        forward . 1.1.1.1\n    }\n" + TOP_IMPORT),
    ("child zone with dns:// and trailing dot", TOP_IMPORT,
     "    dns://X.Exfil.SDP.test.:53 {\n        forward . 1.1.1.1\n    }\n" + TOP_IMPORT),
    ("uppercase header", SINKHOLE_HEAD, "    EXFIL.sdp.test:53 {\n"),
    ("multi-zone header", SINKHOLE_HEAD, "    exfil.sdp.test:53 other.test:53 {\n"),
    ("second zone block on another port", TOP_IMPORT,
     "    exfil.sdp.test:5353 {\n        forward . 1.1.1.1\n    }\n" + TOP_IMPORT),
    ("bind in .:53", "        loadbalance\n", "        loadbalance\n        bind 127.0.0.1\n"),
    ("bind in the sinkhole", "    exfil.sdp.test:53 {\n        errors\n", "    exfil.sdp.test:53 {\n        bind 127.0.0.1\n        errors\n"),
    ("extra top-level import", TOP_IMPORT, TOP_IMPORT + "    import /etc/coredns/custom/*.zone\n"),
    ("top-level import dropped", TOP_IMPORT, ""),
    ("binaryData on coredns", "  NodeHosts: |\n", "  NodeHosts: |\n    x\nbinaryData:\n  Corefile: eA==\n  NodeHostsX: |\n"),
    ("duplicate coredns ConfigMap", "---\napiVersion: apps/v1\nkind: Deployment\n",
     "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: coredns\n  namespace: kube-system\ndata:\n"
     "  Corefile: |\n    .:53 {\n        forward . 1.1.1.1\n    }\n---\napiVersion: apps/v1\nkind: Deployment\n"),
    ("coredns-custom serving the zone", "---\napiVersion: apps/v1\nkind: Deployment\n",
     (EXTRA_CUSTOM % "exfil.sdp.test:53").lstrip("-\n").join(["---\n", "---\napiVersion: apps/v1\nkind: Deployment\n"])),
    ("coredns-custom serving a child zone", "---\napiVersion: apps/v1\nkind: Deployment\n",
     (EXTRA_CUSTOM % "a.exfil.sdp.test").lstrip("-\n").join(["---\n", "---\napiVersion: apps/v1\nkind: Deployment\n"])),
    # CoreDNS reads braces as tokens: this one line closes `.:53` and opens a block for the flagged
    # name's parent, which gets `.:53`'s forward. Counting braces per line misses it.
    ("one-line } x.exfil.sdp.test:53 { in .:53", OVERRIDE_IMPORT, OVERRIDE_IMPORT + "    } x.exfil.sdp.test:53 {\n"),
    ("header { not the last token", TOP_IMPORT, "    x.exfil.sdp.test:53 { forward . 1.1.1.1\n    }\n" + TOP_IMPORT),
    # Replaced from CoreDNS's environment before the header is read ({% written for Jinja).
    ("{$VAR} placeholder header", TOP_IMPORT, "    {$SDP_ZONE}:53 {\n        forward . 1.1.1.1\n    }\n" + TOP_IMPORT),
    ("{%VAR%} placeholder header", TOP_IMPORT, "    {{ '{%' }}SDP_ZONE%}:53 {\n        forward . 1.1.1.1\n    }\n" + TOP_IMPORT),
    # An import splices its tokens into `.:53`: a `}` in an *.override ends `.:53` there.
    ("coredns-custom override closing .:53", "---\napiVersion: apps/v1\nkind: Deployment\n",
     "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: coredns-custom\n  namespace: kube-system\ndata:\n"
     "  x.override: |\n    }\n    x.exfil.sdp.test:53 {\n---\napiVersion: apps/v1\nkind: Deployment\n"),
    ("items on the custom volume", CUSTOM_VOLUME, CUSTOM_VOLUME + "            items:\n              - key: x.server\n                path: x.server\n"),
    ("subPath on the Corefile mount", CORE_MOUNT, CORE_MOUNT + "              subPath: Corefile\n"),
    ("Corefile item renamed", "              - key: Corefile\n                path: Corefile\n",
     "              - key: Corefile\n                path: Corefile.orig\n"),
    ("-conf args changed", '          args: ["-conf", "/etc/coredns/Corefile"]', '          args: ["-conf", "/etc/coredns/custom/Corefile"]'),
    ("command override", '          args: ["-conf", "/etc/coredns/Corefile"]',
     '          command: ["/coredns", "-conf", "/tmp/Corefile"]\n          args: ["-conf", "/etc/coredns/Corefile"]'),
    ("custom mount moved", "              mountPath: /etc/coredns/custom\n", "              mountPath: /etc/coredns/other\n"),
    ("k3s_coredns_own false", None, {"k3s_coredns_own": False}),
]


def main() -> int:
    root = Path(sys.argv[1])
    template = (root / "ansible/roles/k3s/templates/coredns-sdp.yaml.j2").read_text()
    failures = 0
    base = check(*render(root, template))
    if base:
        print(f"  FAIL  the unedited template does not pass: {base}", file=sys.stderr)
        failures += 1
    for name, find, replace in CASES:
        if find is None:
            problems = check(*render(root, template, replace))
        elif find not in template:
            print(f"  FAIL  mutation '{name}': its text is no longer in the template", file=sys.stderr)
            failures += 1
            continue
        else:
            try:
                problems = check(*render(root, template.replace(find, replace, 1)))
            except Exception as err:  # a render or YAML error also stops the edit from shipping
                problems = [f"render error: {err}"]
        if problems:
            print(f"  killed  {name}: {problems[0][:150]}")
        else:
            print(f"  FAIL  mutation '{name}' passes the check", file=sys.stderr)
            failures += 1
    if failures:
        return 1
    print(f"  sinkhole check: {len(CASES)} mutations, each fails it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
