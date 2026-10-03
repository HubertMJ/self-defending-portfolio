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
timeout <= 300 s - the bound require-sandbox-deadline enforces, 120 s until the ADR 0017 amendment of
2026-10-03 - an idle time below the timeout, a victim that outlives its deadline, images from the scenario
repository pinned by digest, exec shape) and exits non-zero with every problem listed.

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
# The longest a scenario pod may live: the API's scenarios.MaxTimeout and require-sandbox-deadline's
# activeDeadlineSeconds bound (ADR 0017/0031 amendments: 300 s, so the terminal leaves time to read).
MAX_TIMEOUT = 300
# The victim server (app/scenario/victim) exits on its own after `-lifetime`, 120 s unless the pod's
# command says otherwise. A victim that exits before the pod's deadline ends the run early - the shop
# goes down and the pod completes, which would read as a response that never happened - so a scenario
# whose timeout is longer must pass a lifetime at least as long (ADR 0022 amendment).
VICTIM_BINARY = "/usr/local/bin/victim"
VICTIM_DEFAULT_LIFETIME = 120
LIFETIME_RE = re.compile(r"^(\d+)(s|m)$")
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

# The interactive terminal (ADR 0032), one scenario: id `terminal`, interactive: true, a catalogue of
# commands the API will run by id. The fields and their bounds are the phase 5/6 contract.
TERMINAL_ID = "terminal"
LAYERS = {"edge", "host", "network", "supply-chain", "admission", "pod-security", "runtime"}
OUTCOMES = {"allowed", "prevented", "detected"}
CMD_ID_RE = re.compile(r"^[a-z0-9-]{1,32}$")
MAX_INPUT = 80
MIN_COMMANDS, MAX_COMMANDS = 12, 16
COMMAND_REQUIRED = {
    "id": str,
    "input": str,
    "technique": str,
    "command": list,
    "tty": bool,
    "outcome": str,
    "layer": str,
    "control": str,
    "explain": str,
}


def check_commands(entry: dict, where: str) -> list:
    """The interactive terminal's extra fields: idle_seconds, objectives[], commands[]."""
    problems = []
    if entry.get("interactive") is not True:
        problems.append(f"{where}: terminal must set `interactive: true`")
    idle = entry.get("idle_seconds")
    # Strictly below the timeout, as the API requires: an idle timer at or past the deadline never fires.
    if not isinstance(idle, int) or isinstance(idle, bool) or not 0 < idle < entry.get("timeout_seconds", 0):
        problems.append(f"{where}: idle_seconds must be an int 1..timeout_seconds-1 (below the timeout)")
    if entry.get("detection") != "" or entry.get("response") != "":
        problems.append(f"{where}: detection and response must be empty strings for the terminal")
    if "exec" in entry and entry["exec"] is not None:
        problems.append(f"{where}: the terminal has no exec (commands are run on request)")
    if "pre_exec" in entry:
        problems.append(f"{where}: the terminal has no pre_exec")

    objectives = entry.get("objectives")
    objective_ids = set()
    if not isinstance(objectives, list) or not objectives:
        problems.append(f"{where}: objectives must be a non-empty list of {{id, title}}")
    else:
        for i, o in enumerate(objectives):
            if not (isinstance(o, dict) and isinstance(o.get("id"), str) and isinstance(o.get("title"), str)):
                problems.append(f"{where}: objective #{i} must be {{id: str, title: str}}")
            elif not CMD_ID_RE.match(o["id"]):
                problems.append(f"{where}: objective id {o['id']!r} must be [a-z0-9-]{{1,32}}")
            else:
                objective_ids.add(o["id"])

    commands = entry.get("commands")
    if not isinstance(commands, list):
        problems.append(f"{where}: commands must be a list")
        return problems
    if not MIN_COMMANDS <= len(commands) <= MAX_COMMANDS:
        problems.append(f"{where}: {len(commands)} commands; the contract asks for {MIN_COMMANDS}..{MAX_COMMANDS}")
    seen_ids, seen_inputs = set(), set()
    for i, c in enumerate(commands):
        cw = f"{where} command #{i} ({c.get('id', '?') if isinstance(c, dict) else '?'})"
        if not isinstance(c, dict):
            problems.append(f"{cw}: not a mapping")
            continue
        for key, kind in COMMAND_REQUIRED.items():
            if not isinstance(c.get(key), kind) or isinstance(c.get(key), bool) != (kind is bool):
                problems.append(f"{cw}: `{key}` missing or not a {kind.__name__}")
        if isinstance(c.get("id"), str):
            if not CMD_ID_RE.match(c["id"]):
                problems.append(f"{cw}: id must be [a-z0-9-]{{1,32}}")
            if c["id"] in seen_ids:
                problems.append(f"{cw}: duplicate command id")
            seen_ids.add(c["id"])
        if isinstance(c.get("input"), str):
            inp = c["input"]
            if not inp or len(inp) > MAX_INPUT or not all(32 <= ord(ch) < 127 for ch in inp):
                problems.append(f"{cw}: input must be 1..{MAX_INPUT} printable ASCII")
            if inp in seen_inputs:
                problems.append(f"{cw}: duplicate input {inp!r}")
            seen_inputs.add(inp)
        if "aliases" in c and not (isinstance(c["aliases"], list) and all(isinstance(a, str) for a in c["aliases"])):
            problems.append(f"{cw}: aliases must be a list of strings")
        if isinstance(c.get("technique"), str) and not TECHNIQUE_RE.match(c["technique"]):
            problems.append(f"{cw}: technique must be a MITRE ATT&CK id")
        if isinstance(c.get("command"), list) and not (c["command"] and all(isinstance(a, str) for a in c["command"])):
            problems.append(f"{cw}: command must be a non-empty list of strings")
        if c.get("outcome") not in OUTCOMES:
            problems.append(f"{cw}: outcome must be one of {sorted(OUTCOMES)}")
        if c.get("layer") not in LAYERS:
            problems.append(f"{cw}: layer must be one of {sorted(LAYERS)}")
        obj = c.get("objective")
        if obj is not None and obj not in objective_ids:
            problems.append(f"{cw}: objective {obj!r} is not one of objectives[].id")
        if c.get("outcome") == "detected":
            if not (isinstance(c.get("detection"), str) and c["detection"]):
                problems.append(f"{cw}: a detected command needs a non-empty detection")
            if c.get("response") not in RESPONSES:
                problems.append(f"{cw}: a detected command needs response in {sorted(RESPONSES)}")
        else:
            if c.get("detection"):
                problems.append(f"{cw}: only a detected command carries a detection")
            if c.get("response"):
                problems.append(f"{cw}: only a detected command carries a response")
    return problems


def load_scenarios(configmap_path: Path) -> list:
    for doc in yaml.safe_load_all(configmap_path.read_text()):
        if doc and doc.get("kind") == "ConfigMap" and doc["metadata"]["name"] == "scenarios":
            return yaml.safe_load(doc["data"]["scenarios.yaml"])
    raise SystemExit(f"scenario_pods: no ConfigMap `scenarios` in {configmap_path}")


def signed_stand_in(hello_kustomization: Path) -> str:
    kust = yaml.safe_load(hello_kustomization.read_text())
    image = kust["images"][0]
    return f"{image['name']}@{image['digest']}"


def victim_lifetime(container: dict, where: str) -> tuple:
    """(seconds the victim in this container lives, problem or None); (None, None) if it runs no victim."""
    command = container.get("command")
    if command is None:
        return VICTIM_DEFAULT_LIFETIME, None  # the image's CMD: the victim with its default lifetime
    if not (isinstance(command, list) and command and command[0] == VICTIM_BINARY):
        return None, None
    value = None
    for i, arg in enumerate(command[1:], 1):
        for flag in ("-lifetime", "--lifetime"):
            if arg == flag:
                value = command[i + 1] if i + 1 < len(command) else ""
            elif isinstance(arg, str) and arg.startswith(flag + "="):
                value = arg[len(flag) + 1:]
    if value is None:
        return VICTIM_DEFAULT_LIFETIME, None
    m = LIFETIME_RE.match(str(value))
    if not m:
        return None, f"{where}: victim -lifetime {value!r} must be whole seconds or minutes (e.g. 300s)"
    return int(m.group(1)) * (60 if m.group(2) == "m" else 1), None


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
    if not 0 < entry["timeout_seconds"] <= MAX_TIMEOUT:
        problems.append(f"{where}: timeout_seconds must be 1..{MAX_TIMEOUT}")

    interactive = entry.get("interactive") is True
    if interactive:
        # The terminal (ADR 0032): no exec/response here; the commands catalogue is checked instead.
        problems += check_commands(entry, where)
    else:
        if entry["response"] not in RESPONSES:
            problems.append(f"{where}: response must be one of {sorted(RESPONSES)}")
        exec_ = entry.get("exec", "missing")
        if exec_ == "missing":
            problems.append(f"{where}: `exec` must be present ({{command, tty}} or null)")
        elif exec_ is not None:
            command = exec_.get("command") if isinstance(exec_, dict) else None
            if not (isinstance(command, list) and command and all(isinstance(a, str) for a in command)):
                problems.append(f"{where}: exec.command must be a non-empty list of strings")
            if not isinstance(exec_.get("tty") if isinstance(exec_, dict) else None, bool):
                problems.append(f"{where}: exec.tty must be true or false")

    pod = entry["pod"]
    if "activeDeadlineSeconds" in pod:
        problems.append(f"{where}: activeDeadlineSeconds is set by the API from timeout_seconds")
    containers = pod.get("containers") or []
    if not any(c.get("name") == "target" for c in containers):
        problems.append(f"{where}: needs a container named `target` (the exec goes there)")
    for c in containers + (pod.get("initContainers") or []):
        if not IMAGE_RE.match(str(c.get("image", ""))):
            problems.append(f"{where}: image {c.get('image')!r} is not the scenario image pinned by digest")
    if entry.get("victim") is True:
        for c in containers:
            lifetime, problem = victim_lifetime(c, where)
            if problem:
                problems.append(problem)
            elif lifetime is not None and lifetime < entry["timeout_seconds"]:
                problems.append(f"{where}: the victim exits after {lifetime} s, before the {entry['timeout_seconds']} s "
                                f"timeout; pass `-lifetime {entry['timeout_seconds']}s` in its command")
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
    if TERMINAL_ID not in ids:
        problems.append(f"the interactive `{TERMINAL_ID}` scenario is missing (ADR 0032)")
    # The four one-click scenarios (the three fixed ids plus the drop/execute one) stay, and the
    # terminal is the fifth; a sixth would be a contract change reviewed here.
    if len(ids) != 5:
        problems.append(f"the contract defines 5 scenarios (4 one-click + terminal), found {len(ids)}")
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
