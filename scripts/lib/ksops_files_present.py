"""Exit 0 if every file a KSOPS generator references exists, 1 otherwise.

Used by scripts/validate-cluster.sh to decide whether a directory can be rendered as-is or whether
its secret generator has to be skipped for validation. See ADR 0006.
"""

import sys
from pathlib import Path

import yaml


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: ksops_files_present.py <kustomize-dir>", file=sys.stderr)
        return 2

    directory = Path(argv[1])
    generator = directory / "ksops.yaml"
    with generator.open() as handle:
        referenced = yaml.safe_load(handle).get("files", [])

    missing = [name for name in referenced if not (directory / name).exists()]
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
