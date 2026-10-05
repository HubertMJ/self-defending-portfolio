"""Exit 0 if every file a KSOPS generator references exists, 1 otherwise.

Used by scripts/validate-cluster.sh (ADR 0006):
  ksops_files_present.py <kustomize-dir>         the files exist on disk (decide whether to decrypt)
  ksops_files_present.py --git <kustomize-dir>   the files are committed; prints the missing ones

Argo CD builds from git, so a generator naming a file that is not committed breaks that
Application's sync. --git turns that into a validation failure in CI, where the age key is absent
and the generator would otherwise just be skipped.
"""

import subprocess
import sys
from pathlib import Path

import yaml


def main(argv: list[str]) -> int:
    in_git = len(argv) == 3 and argv[1] == "--git"
    if len(argv) != 2 and not in_git:
        print("usage: ksops_files_present.py [--git] <kustomize-dir>", file=sys.stderr)
        return 2

    directory = Path(argv[-1])
    generator = directory / "ksops.yaml"
    with generator.open() as handle:
        referenced = yaml.safe_load(handle).get("files", [])

    if in_git:
        tracked = set(subprocess.run(["git", "ls-files", "--", str(directory)], check=True,
                                     capture_output=True, text=True).stdout.splitlines())
        missing = [name for name in referenced if str(directory / name) not in tracked]
        for name in missing:
            print(f"{directory / name}", file=sys.stderr)
        return 1 if missing else 0

    missing = [name for name in referenced if not (directory / name).exists()]
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
