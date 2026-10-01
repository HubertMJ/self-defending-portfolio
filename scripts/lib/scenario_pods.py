"""Render the attack scenarios' pod specs as Pods, so the Kyverno gate judges them (ADR 0017).

Used by scripts/validate-cluster.sh:

    scenario_pods.py <rendered-configmap.yaml> <hello-kustomization.yaml> <out.yaml>

The scenario pods are not manifests in git: the portfolio API creates them at run time from the pod
specs inside ConfigMap `scenarios` (cluster/infra/sandbox/scenarios/scenarios.yaml), so neither
kubeconform nor `kyverno apply` would ever see them. This turns each entry into the Pod the API will
create - namespace `sandbox`, the two labels the API adds, activeDeadlineSeconds from timeout_seconds,
the spec unchanged - and writes them next to the other renders, so a scenario that a policy would refuse
fails `make validate` instead of a visitor's click.

It also checks each entry against the phase 5/6 contract (fields, types, the fixed ids, response values,
timeout <= 120 s, images from the scenario repository pinned by digest, exec shape) and exits non-zero
with every problem listed.

The image placeholder. Until the first build of app/scenario on main there is no signed scenario
digest, and the scenarios carry an all-zero placeholder. verify-portfolio-images would (correctly)
reject that, which would make `make validate` red for a reason no commit here can fix. So while - and
only while - the digest is the placeholder, the rendered Pods use the signed image hello runs instead,
and this script says so on stderr. Every other policy judges the spec exactly as written; the signature
check of the scenario image itself starts with the first real digest, at which point this substitution
switches itself off. A placeholder never reaches main: scripts/check-image-digests.sh fails
`make validate` and CI on it first, so the substitution only matters on a branch run with
ALLOW_PLACEHOLDER_DIGESTS=1 (where hello may still carry a placeholder too, and the stand-in then
fails the signature check like any unsigned image).
"""

import re
import sys
from pathlib import Path

import yaml

FIXED_IDS = {"shell-in-container", "network-tool", "sensitive-file-read"}
RESPONSES = {"terminate", "quarantine"}
MAX_TIMEOUT = 120
REQUIRED = {
    "id": str,
    "title": str,
    "summary": str,
    "technique": str,
    "detection": str,
    "response": str,
    "timeout_seconds": int,
    "pod": dict,
}
IMAGE_RE = re.compile(r"^ghcr\.io/hubertmj/self-defending-portfolio/scenario(:[\w.-]+)?@sha256:[0-9a-f]{64}$")
PLACEHOLDER_DIGEST = "sha256:" + "0" * 64
ID_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def load_scenarios(configmap_path: Path) -> list:
    for doc in yaml.safe_load_all(configmap_path.read_text()):
        if doc and doc.get("kind") == "ConfigMap" and doc["metadata"]["name"] == "scenarios":
            return yaml.safe_load(doc["data"]["scenarios.yaml"])
    raise SystemExit(f"scenario_pods: no ConfigMap `scenarios` in {configmap_path}")


def signed_stand_in(hello_kustomization: Path) -> str:
    kust = yaml.safe_load(hello_kustomization.read_text())
    image = kust["images"][0]
    return f"{image['name']}@{image['digest']}"


def check(entry: dict, index: int) -> list:
    where = f"scenario #{index} ({entry.get('id', '?')})"
    problems = []
    for key, kind in REQUIRED.items():
        if not isinstance(entry.get(key), kind) or isinstance(entry.get(key), bool):
            problems.append(f"{where}: `{key}` missing or not a {kind.__name__}")
    if problems:
        return problems
    if not ID_RE.match(entry["id"]):
        problems.append(f"{where}: id must be a short DNS label")
    if not TECHNIQUE_RE.match(entry["technique"]):
        problems.append(f"{where}: technique must be a MITRE ATT&CK id (T1234 or T1234.001)")
    if entry["response"] not in RESPONSES:
        problems.append(f"{where}: response must be one of {sorted(RESPONSES)}")
    if not 0 < entry["timeout_seconds"] <= MAX_TIMEOUT:
        problems.append(f"{where}: timeout_seconds must be 1..{MAX_TIMEOUT}")

    pod = entry["pod"]
    if "activeDeadlineSeconds" in pod:
        problems.append(f"{where}: activeDeadlineSeconds is set by the API from timeout_seconds")
    containers = pod.get("containers") or []
    if not any(c.get("name") == "target" for c in containers):
        problems.append(f"{where}: needs a container named `target` (the exec goes there)")
    for c in containers + (pod.get("initContainers") or []):
        if not IMAGE_RE.match(str(c.get("image", ""))):
            problems.append(f"{where}: image {c.get('image')!r} is not the scenario image pinned by digest")

    exec_ = entry.get("exec", "missing")
    if exec_ == "missing":
        problems.append(f"{where}: `exec` must be present ({{command, tty}} or null)")
    elif exec_ is not None:
        command = exec_.get("command") if isinstance(exec_, dict) else None
        if not (isinstance(command, list) and command and all(isinstance(a, str) for a in command)):
            problems.append(f"{where}: exec.command must be a non-empty list of strings")
        if not isinstance(exec_.get("tty") if isinstance(exec_, dict) else None, bool):
            problems.append(f"{where}: exec.tty must be true or false")
    return problems


def main(argv: list) -> int:
    if len(argv) != 4:
        print("usage: scenario_pods.py <rendered-configmap.yaml> <hello-kustomization.yaml> <out.yaml>",
              file=sys.stderr)
        return 2
    scenarios = load_scenarios(Path(argv[1]))
    if not isinstance(scenarios, list) or not scenarios:
        print("scenario_pods: scenarios.yaml must be a non-empty list", file=sys.stderr)
        return 1

    problems = []
    for i, entry in enumerate(scenarios, 1):
        problems += check(entry, i) if isinstance(entry, dict) else [f"scenario #{i}: not a mapping"]
    ids = [e.get("id") for e in scenarios if isinstance(e, dict)]
    if len(ids) != len(set(ids)):
        problems.append("ids are not unique")
    if missing := FIXED_IDS - set(ids):
        problems.append(f"the contract's fixed ids are missing: {sorted(missing)}")
    if len(ids) != 4:
        problems.append(f"the contract defines 4 scenarios, found {len(ids)}")
    if problems:
        print("scenario_pods: scenarios.yaml does not match the phase 5/6 contract:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    stand_in = None
    pods = []
    for entry in scenarios:
        spec = entry["pod"]
        for c in spec["containers"] + spec.get("initContainers", []):
            if c["image"].endswith(PLACEHOLDER_DIGEST):
                stand_in = stand_in or signed_stand_in(Path(argv[2]))
                c["image"] = stand_in
        spec["activeDeadlineSeconds"] = entry["timeout_seconds"]
        pods.append({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": f"scenario-{entry['id']}",
                "namespace": "sandbox",
                "labels": {
                    "sdp.hubertjablon.ski/run-id": "validate",
                    "sdp.hubertjablon.ski/quarantine": "false",
                },
            },
            "spec": spec,
        })

    Path(argv[3]).write_text(yaml.safe_dump_all(pods, sort_keys=False))
    if stand_in:
        print(f"  NOTE: scenario image digest is still the PLACEHOLDER; the {len(pods)} scenario Pods are "
              f"judged with {stand_in} standing in (see scripts/lib/scenario_pods.py)", file=sys.stderr)
    print(f"  {len(pods)} scenario Pods rendered: {', '.join(ids)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
