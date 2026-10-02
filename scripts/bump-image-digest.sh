#!/usr/bin/env bash
# Pins one of this project's images to a new digest everywhere under cluster/ that references it.
#
#   scripts/bump-image-digest.sh <name> <sha256:digest>
#   scripts/bump-image-digest.sh api sha256:3f1c...      # from the build-images run summary
#
# <name> is the app/<name>/ directory the image is built from (web, api, scenario, talon, ksops,
# coredns, argocd, falcosidekick, ...); the image is ghcr.io/hubertmj/self-defending-portfolio/<name>.
# Three reference forms are rewritten, and nothing else:
#   * a kustomize `images:` entry whose `name:` is the image, or whose `newName:` is (an upstream
#     image replaced by ours under its upstream name, e.g. Argo CD's in cluster/bootstrap/argocd) -
#     its `digest:` line;
#   * an inline reference <image>[:tag]@sha256:<hex> (the scenario pod specs, the Ansible var);
#   * Helm chart values that split the image into sibling keys `registry: ghcr.io`,
#     `repository: hubertmj/self-defending-portfolio/<name>` and `tag: "<tag>@sha256:<hex>"` (the
#     Falcosidekick and Trivy Operator charts in cluster/apps, ADR 0025) - the `tag:` line's digest.
#     All three keys must sit in the same mapping, at the same indentation; a `repository:` without
#     the `registry: ghcr.io` sibling is some other registry's image and is left alone.
# Comments, layout and every other image are left as they are, so the diff is one line per reference.
#
# cluster/bootstrap/ is under cluster/, so a pin there (ksops, in cluster/bootstrap/argocd) is
# rewritten like any other - and scripts/check-image-digests.sh refuses a placeholder there too. Argo
# CD does not deploy the bootstrap, though (ADR 0005, amendment): when a bootstrap file changes, the
# script says so, because the new digest reaches the cluster only through a manual `kubectl apply -k`.
#
# ansible/ is searched too, for the one image deployed by Ansible rather than Argo CD: coredns, whose
# pin is k3s_coredns_image in ansible/roles/k3s/defaults/main.yml (ADR 0026). It reaches the cluster
# only when the k3s role runs, and the script says so.
#
# The digest is not checked against the registry here; verify it before committing:
#   scripts/verify-image.sh ghcr.io/hubertmj/self-defending-portfolio/<name>@<digest>
# `make validate` then runs Kyverno's own signature check over the result.
set -euo pipefail
cd "$(dirname "$0")/.."

die() { echo "bump-image-digest: $*" >&2; exit 2; }

if [ $# -ne 2 ]; then
  echo "usage: $0 <name> <sha256:digest>" >&2
  exit 2
fi
name=$1 digest=$2
if ! [[ $name =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || [ ! -f "app/$name/Dockerfile" ]; then
  die "no image '$name' (expected app/$name/Dockerfile)"
fi
if ! [[ $digest =~ ^sha256:[0-9a-f]{64}$ ]]; then
  die "'$digest' is not a sha256:<64 hex> digest"
fi
if [ "$digest" = "sha256:$(printf '0%.0s' {1..64})" ]; then
  die "that is the placeholder digest"
fi

image=ghcr.io/hubertmj/self-defending-portfolio/$name
# The repository path without the registry, so the split Helm form is found too; the Python below
# decides which lines are really this image.
mapfile -t files < <(git grep -l -F "hubertmj/self-defending-portfolio/$name" -- cluster/ ansible/ | sort)
[ "${#files[@]}" -gt 0 ] || { echo "bump-image-digest: nothing under cluster/ or ansible/ references $image" >&2; exit 1; }

python3 - "$image" "$digest" "${files[@]}" <<'PY'
import re, sys

image, digest, files = sys.argv[1], sys.argv[2], sys.argv[3:]
inline = re.compile(re.escape(image) + r"((?::[\w.-]+)?)@sha256:[0-9a-f]{64}")
entry = re.compile(r"^(\s*)-\s+name:\s*(\S+)\s*$")
new_name = re.compile(r"^\s*newName:\s*" + re.escape(image) + r"\s*$")
registry, _, repository = image.partition("/")
key = re.compile(r"^(\s*)(registry|repository|tag):\s*[\"']?([^\"'#\s]*)[\"']?\s*(?:#.*)?$")

def helm_tag_lines(lines):
    """Indexes of `tag:` lines whose mapping also says registry: <registry>, repository: <repository>."""
    found = set()
    for i, line in enumerate(lines):
        m = key.match(line)
        if not (m and m.group(2) == "repository" and m.group(3) == repository):
            continue
        indent = m.group(1)
        siblings = {}
        for step in (-1, 1):  # walk the mapping up and down until the indentation drops below it
            j = i + step
            while 0 <= j < len(lines):
                l = lines[j]
                if l.strip() and len(l) - len(l.lstrip()) < len(indent):
                    break
                k = key.match(l)
                if k and k.group(1) == indent:
                    siblings[k.group(2)] = (j, k.group(3))
                j += step
        if siblings.get("registry", (None, ""))[1] == registry and "tag" in siblings:
            found.add(siblings["tag"][0])
    return found

changed, bootstrap, ansible = 0, set(), False
for path in files:
    lines = open(path).read().split("\n")
    helm_tags = helm_tag_lines(lines)
    out, in_list_entry, in_entry, indent = [], False, False, ""
    for n, line in enumerate(lines):
        m = entry.match(line)
        if m:
            in_list_entry, in_entry, indent = True, m.group(2) == image, m.group(1)
        elif in_list_entry and line.strip() and len(line) - len(line.lstrip()) <= len(indent):
            in_list_entry = in_entry = False  # the next entry or the end of the list
        elif in_list_entry and new_name.match(line):
            in_entry = True  # `name:` is the upstream image, `newName:` ours
        new = line
        if in_entry:
            new = re.sub(r"^(\s*digest:\s*)sha256:[0-9a-f]{64}", lambda d: d.group(1) + digest, new)
        new = inline.sub(lambda r: image + r.group(1) + "@" + digest, new)
        if n in helm_tags:
            new = re.sub(r"@sha256:[0-9a-f]{64}", "@" + digest, new)
        if new != line:
            changed += 1
            if path.startswith("cluster/bootstrap/"):
                bootstrap.add(path.split("/")[2])
            if path.startswith("ansible/"):
                ansible = True
            print(f"  {path}: {line.strip()}\n  {' ' * len(path)}  -> {new.strip()}")
        out.append(new)
    open(path, "w").write("\n".join(out))
if not changed:
    sys.exit(f"bump-image-digest: {image} is already at {digest} everywhere (nothing changed)")
print(f"{changed} reference(s) to {image} now pinned to {digest}")
for d in sorted(bootstrap):
    print(f"note: cluster/bootstrap/{d} changed - Argo CD does not apply it; after the push, review and apply:\n"
          f"  kubectl diff -k cluster/bootstrap/{d} --server-side --force-conflicts\n"
          f"  kubectl apply -k cluster/bootstrap/{d} --server-side --force-conflicts")
if ansible:
    print("note: ansible/ changed - neither Argo CD nor CI applies it; after the push, run the role (docs/bootstrap.md 8.7):\n"
          "  cd ansible && ansible-playbook playbooks/cluster.yml --tags k3s --check --diff\n"
          "  ansible-playbook playbooks/cluster.yml --tags k3s")
PY
