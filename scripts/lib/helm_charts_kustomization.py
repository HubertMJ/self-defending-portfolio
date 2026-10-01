"""Prepare a kustomization that uses `helmCharts` for an offline render.

Used by scripts/validate-cluster.sh on a throwaway copy of the repository. Argo CD builds such a
kustomization with `kustomize build --enable-helm`, which pulls the chart, runs `helm template` with
the entry's values and then applies the kustomization's patches (ADR 0013, amendment). The validation
containers do not carry kustomize and helm together, so this does the same in two steps:

  1. for every helmCharts entry, write its `valuesInline` to `<dir>/.helm-values-<name>.yaml` and
     print one tab-separated line for the caller to render with the pinned Helm image:

         name  repo  version  releaseName  namespace  values-file  include-crds  kube-version  out-file

  2. rewrite `<dir>/kustomization.yaml` without `helmCharts` and with each `out-file` prepended to
     `resources`, so the pinned kustomize image then applies the patches to exactly that output.

`helm template` is called with the arguments kustomize passes (release name, namespace, values,
--kube-version, --include-crds only when includeCRDs is true). Only the keys below are understood; any
other helmCharts key (skipTests, skipHooks, valuesFile, additionalValuesFiles, apiVersions, ...) or a
helmGlobals block is an error rather than a partial render, the same allowlist rule as
scripts/lib/chart_sources.py.
"""

import sys
from pathlib import Path

import yaml

SUPPORTED_KEYS = {"name", "repo", "version", "releaseName", "namespace", "valuesInline",
                  "includeCRDs", "kubeVersion"}
REQUIRED_KEYS = {"name", "repo", "version"}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: helm_charts_kustomization.py <kustomization-dir>", file=sys.stderr)
        return 2

    directory = Path(argv[1])
    path = directory / "kustomization.yaml"
    with path.open() as handle:
        kustomization = yaml.safe_load(handle) or {}

    charts = kustomization.pop("helmCharts", None) or []
    problems = []
    if "helmGlobals" in kustomization:
        problems.append("helmGlobals is not supported")

    rendered = []
    for chart in charts:
        unsupported = sorted(set(chart) - SUPPORTED_KEYS)
        missing = sorted(REQUIRED_KEYS - set(chart))
        if unsupported or missing:
            problems.append(f"helmCharts entry {chart.get('name')!r}: "
                            f"unsupported {unsupported}, missing {missing}")
            continue
        name = chart["name"]
        repo = chart["repo"]
        if not repo.startswith(("https://", "http://")):
            problems.append(f"helmCharts entry {name!r}: {repo!r} is not an HTTP(S) Helm repository")
            continue
        values_file = f".helm-values-{name}.yaml"
        with (directory / values_file).open("w") as handle:
            yaml.safe_dump(chart.get("valuesInline", {}), handle, sort_keys=False)
        out_file = f".helm-rendered-{name}.yaml"
        rendered.append(out_file)
        print("\t".join([
            name, repo, str(chart["version"]), chart.get("releaseName", name),
            chart.get("namespace", kustomization.get("namespace", "default")), values_file,
            "true" if chart.get("includeCRDs") else "false", str(chart.get("kubeVersion", "")),
            out_file,
        ]))

    for problem in problems:
        print(f"helm_charts_kustomization: {path}: {problem}", file=sys.stderr)
    if problems:
        return 1

    kustomization["resources"] = rendered + (kustomization.get("resources") or [])
    with path.open("w") as handle:
        yaml.safe_dump(kustomization, handle, sort_keys=False)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
