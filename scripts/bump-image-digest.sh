#!/usr/bin/env bash
# Pins one of this project's images to a new digest everywhere under cluster/ that references it.
#
#   scripts/bump-image-digest.sh <name> <sha256:digest>
#   scripts/bump-image-digest.sh api sha256:3f1c...      # from the build-images run summary
#
# <name> is the app/<name>/ directory the image is built from (web, api, scenario, talon, ksops); the
# image is ghcr.io/hubertmj/self-defending-portfolio/<name>. Two reference forms are rewritten, and
# nothing else:
#   * a kustomize `images:` entry whose `name:` is the image - its `digest:` line;
#   * an inline reference <image>[:tag]@sha256:<hex> (the scenario pod specs).
# Comments, layout and every other image are left as they are, so the diff is one line per reference.
#
# cluster/bootstrap/ is under cluster/, so a pin there (ksops, in cluster/bootstrap/argocd) is
# rewritten like any other - and scripts/check-image-digests.sh refuses a placeholder there too. Argo
# CD does not deploy the bootstrap, though (ADR 0005, amendment): when a bootstrap file changes, the
# script says so, because the new digest reaches the cluster only through a manual `kubectl apply -k`.
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
mapfile -t files < <(git grep -l -F "$image" -- cluster/ | sort)
[ "${#files[@]}" -gt 0 ] || { echo "bump-image-digest: nothing under cluster/ references $image" >&2; exit 1; }

python3 - "$image" "$digest" "${files[@]}" <<'PY'
import re, sys

image, digest, files = sys.argv[1], sys.argv[2], sys.argv[3:]
inline = re.compile(re.escape(image) + r"((?::[\w.-]+)?)@sha256:[0-9a-f]{64}")
entry = re.compile(r"^(\s*)-\s+name:\s*" + re.escape(image) + r"\s*$")
changed, bootstrap = 0, set()
for path in files:
    lines = open(path).read().split("\n")
    out, in_entry, indent = [], False, ""
    for line in lines:
        m = entry.match(line)
        if m:
            in_entry, indent = True, m.group(1)
        elif in_entry and line.strip() and len(line) - len(line.lstrip()) <= len(indent):
            in_entry = False  # the next entry or the end of the list
        new = line
        if in_entry:
            new = re.sub(r"^(\s*digest:\s*)sha256:[0-9a-f]{64}", lambda d: d.group(1) + digest, new)
        new = inline.sub(lambda r: image + r.group(1) + "@" + digest, new)
        if new != line:
            changed += 1
            if path.startswith("cluster/bootstrap/"):
                bootstrap.add(path.split("/")[2])
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
PY
