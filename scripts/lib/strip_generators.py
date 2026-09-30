"""Remove the `generators` key from a copy of a kustomization.yaml.

Only ever run against a throwaway copy inside a temporary directory, so losing the file's comments
does not matter. See the KSOPS note in scripts/validate-cluster.sh.
"""

import sys
from pathlib import Path

import yaml


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: strip_generators.py <kustomization.yaml>", file=sys.stderr)
        return 2

    path = Path(argv[1])
    with path.open() as handle:
        document = yaml.safe_load(handle)

    document.pop("generators", None)
    with path.open("w") as handle:
        yaml.safe_dump(document, handle, default_flow_style=False, sort_keys=False)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
