"""Assert that named workloads mount every hostPath volume read-only.

Used by scripts/validate-cluster.sh on the rendered manifests:

    check_hostpath_readonly.py <render-dir> <Kind>/<namespace>/<name> [...]

For each workload it collects the pod template's hostPath volumes and fails if any container or init
container mounts one without `readOnly: true`, or if the workload is not in the render at all (a
renamed object must not turn the check into a silent pass).

Why this is not a Kyverno policy: Pod Security's HostPath Volumes control is all-or-nothing, and the
two workloads that need host paths (Falco, kube-bench) are exempt from it control by control (ADR
0012). Whether those exempt mounts are writable is a property of what git renders, so it is checked
where the render is: here, before Argo CD applies it. It caught chart 9.2.0 mounting the host's
/lib/modules writable into Falco (ADR 0013, amendment).

Only documents that mention one of the requested kinds are parsed; the rendered CRD schemas are
megabytes of YAML that would only slow this down.
"""

import re
import sys
from pathlib import Path

import yaml


def pod_spec(obj: dict) -> dict:
    kind = obj["kind"]
    spec = obj.get("spec", {})
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return spec["jobTemplate"]["spec"]["template"]["spec"]
    return spec["template"]["spec"]


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("usage: check_hostpath_readonly.py <render-dir> <Kind>/<namespace>/<name> ...",
              file=sys.stderr)
        return 2

    wanted = {tuple(target.split("/", 2)) for target in argv[2:]}
    kinds = {kind for kind, _, _ in wanted}
    kind_line = re.compile(r"^kind:\s*(" + "|".join(map(re.escape, kinds)) + r")\s*$", re.M)

    found = {}
    for path in sorted(Path(argv[1]).glob("*.yaml")):
        for document in re.split(r"^---\s*$", path.read_text(), flags=re.M):
            if not kind_line.search(document):
                continue
            obj = yaml.safe_load(document)
            if not isinstance(obj, dict) or "metadata" not in obj:
                continue
            key = (obj["kind"], obj["metadata"].get("namespace", ""), obj["metadata"]["name"])
            if key in wanted:
                found[key] = obj

    failures = 0
    for key in sorted(wanted):
        label = "/".join(key)
        if key not in found:
            print(f"  FAIL  {label}: not found in the render")
            failures += 1
            continue
        spec = pod_spec(found[key])
        host_volumes = {v["name"]: v["hostPath"]["path"]
                        for v in spec.get("volumes") or [] if "hostPath" in v}
        checked = writable = 0
        for container in (spec.get("initContainers") or []) + (spec.get("containers") or []):
            for mount in container.get("volumeMounts") or []:
                if mount["name"] not in host_volumes:
                    continue
                checked += 1
                if not mount.get("readOnly", False):
                    print(f"  FAIL  {label}: container {container['name']} mounts host "
                          f"{host_volumes[mount['name']]} at {mount['mountPath']} writable")
                    writable += 1
        failures += writable
        if not writable:
            print(f"  ok    {label}: {checked} hostPath mount(s), all read-only")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
