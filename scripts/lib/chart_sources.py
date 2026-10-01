"""List the Helm chart sources of every Argo CD Application under a directory.

Used by scripts/render-charts.sh. For each chart source it writes the source's `helm.valuesObject`
to `<values-dir>/<app>-<n>.yaml` and prints one tab-separated line:

    app  repoURL  chart  version  releaseName  namespace  values-file

Both single-source (`spec.source`) and multi-source (`spec.sources[]`) Applications are read; a
source without `chart:` (a git path) is skipped, because scripts/validate-cluster.sh already renders
every kustomization under cluster/. Only `helm.releaseName` and `helm.valuesObject` are understood
(an allowlist): any other helm.* key - `valueFiles`, `parameters`, string `values`, `skipCrds`,
`skipTests`, `version`, ... - and any OCI or git chart repository is an error rather than a silent
partial render, so a later Application cannot slip past the
`kyverno apply` gate by using a values mechanism nobody taught this script.
"""

import sys
from pathlib import Path

import yaml

SUPPORTED_HELM_KEYS = {"releaseName", "valuesObject"}


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: chart_sources.py <apps-dir> <values-dir>", file=sys.stderr)
        return 2

    apps_dir, values_dir = Path(argv[1]), Path(argv[2])
    problems = []

    for path in sorted(apps_dir.glob("*.yaml")):
        with path.open() as handle:
            app = yaml.safe_load(handle) or {}
        if app.get("kind") != "Application":
            continue

        spec = app["spec"]
        name = app["metadata"]["name"]
        namespace = spec["destination"].get("namespace", "default")
        sources = spec.get("sources") or [spec.get("source", {})]

        for index, source in enumerate(sources):
            if "chart" not in source:
                continue
            repo = source["repoURL"]
            if not repo.startswith(("https://", "http://")):
                problems.append(f"{path}: chart repo {repo!r} is not an HTTP(S) Helm repository")
                continue
            helm = source.get("helm", {})
            unsupported = sorted(set(helm) - SUPPORTED_HELM_KEYS)
            if unsupported:
                problems.append(f"{path}: helm.{', helm.'.join(unsupported)} not supported "
                                f"(only {', '.join(sorted(SUPPORTED_HELM_KEYS))})")
                continue

            values_file = f"{name}-{index}.yaml"
            with (values_dir / values_file).open("w") as handle:
                yaml.safe_dump(helm.get("valuesObject", {}), handle, sort_keys=False)

            release = helm.get("releaseName", name)
            print("\t".join([name, repo, source["chart"], str(source["targetRevision"]), release,
                             namespace, values_file]))

    for problem in problems:
        print(f"chart_sources: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
