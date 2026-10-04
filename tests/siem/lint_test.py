#!/usr/bin/env python3
"""Tests of the siem/ lint (siem contract P3 tests, (M) lint): the real tree is clean, and each case
breaks one thing in a scratch copy of it and expects the lint to say so. Every check of siem_lint.py
has at least one case here; tests/siem/p3-mutations.sh disables the checks one by one and expects this
file to fail for each.

Usage: tests/siem/lint_test.py [path to siem_lint.py]   (default: the role's copy)
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LINT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(REPO, "ansible/roles/siem_sync/files/siem_lint.py")
SIEM = os.path.join(REPO, "siem")


def run(tree):
    p = subprocess.run([sys.executable, LINT, tree], capture_output=True, text=True, check=False)
    return p.returncode, p.stderr + p.stdout


def edit_yaml(path, fn):
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    fn(data)
    with open(path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, sort_keys=False, allow_unicode=True)


def edit_json(path, fn):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    fn(data)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def rule(tree, slug):
    return os.path.join(tree, "rules", slug + ".yml")


def sel(tree, slug, fn):
    edit_yaml(rule(tree, slug), lambda d: fn(d["detection"]))


def det(name):
    return lambda d: d["detection"][name]


def set_in(d, key, value):
    d[key] = value


# (name, change to the scratch tree, regex the lint output must match)
CASES = [
    # check_parse
    ("rule does not parse", lambda t: open(rule(t, "talon-terminate"), "a").write("detection: [\n"), r"does not parse"),
    ("monitor JSON does not parse", lambda t: open(os.path.join(t, "monitors/policy-probing.json"), "a").write("}"),
     r"monitors/policy-probing.json: does not parse"),
    ("stray file in rules/", lambda t: open(os.path.join(t, "rules/notes.txt"), "w").write("x"), r"rules/notes.txt: unexpected file"),
    ("canaries.yaml missing", lambda t: os.remove(os.path.join(t, "canaries.yaml")), r"canaries.yaml: missing"),
    # check_log_types
    ("log type with a hyphen", lambda t: edit_yaml(os.path.join(t, "log-types/falco.yaml"), lambda d: set_in(d, "name", "sdp-falco")),
     r"log-types/falco.yaml: name 'sdp-falco' must match"),
    ("log type of an unknown source", lambda t: edit_yaml(os.path.join(t, "log-types/falco.yaml"), lambda d: set_in(d, "source", "nope")),
     r"log-types/falco.yaml: .*source 'nope' has no allow-list"),
    ("log type name differs from fields", lambda t: edit_yaml(os.path.join(t, "log-types/talon.yaml"),
                                                              lambda d: set_in(d, "name", "sdp_talon2")),
     r"differs from siem/fields/talon.yaml log_type"),
    # check_rule_form
    ("rule without level", lambda t: edit_yaml(rule(t, "talon-terminate"), lambda d: d.pop("level")),
     r"talon-terminate.yml: missing Sigma fields: level"),
    ("rule with an unknown field", lambda t: edit_yaml(rule(t, "talon-terminate"), lambda d: set_in(d, "severity", "x")),
     r"unknown Sigma fields: severity"),
    ("rule with a bad status", lambda t: edit_yaml(rule(t, "talon-terminate"), lambda d: set_in(d, "status", "beta")),
     r"status 'beta' not one of"),
    ("rule with another product", lambda t: edit_yaml(rule(t, "talon-terminate"), lambda d: d["logsource"].update(product="linux")),
     r"logsource must be exactly"),
    ("rule with a bad date", lambda t: edit_yaml(rule(t, "talon-terminate"), lambda d: set_in(d, "date", "2026-10-04")),
     r"date must be YYYY/MM/DD"),
    # check_rule_ids
    ("rule id not a UUID", lambda t: edit_yaml(rule(t, "talon-terminate"), lambda d: set_in(d, "id", "talon-1")),
     r"id 'talon-1' is not a lower-case UUID"),
    ("duplicate Sigma id", lambda t: edit_yaml(rule(t, "talon-terminate"), lambda d: set_in(
        d, "id", yaml.safe_load(open(rule(t, "talon-quarantine")))["id"])), r"is also the id of rules/"),
    ("duplicate title", lambda t: edit_yaml(rule(t, "talon-terminate"), lambda d: set_in(
        d, "title", yaml.safe_load(open(rule(t, "talon-quarantine")))["title"])), r"is also the title of rules/"),
    # check_rule_tags
    ("bad tag", lambda t: edit_yaml(rule(t, "falco-network-tool"), lambda d: d["tags"].append("attack.T1071")),
     r"tag 'attack.T1071' is neither"),
    ("no technique above informational", lambda t: edit_yaml(rule(t, "falco-network-tool"),
                                                             lambda d: set_in(d, "tags", ["attack.command_and_control"])),
     r"falco-network-tool.yml: a rule above informational names at least one ATT&CK technique"),
    # check_rule_source
    ("rule of an unknown source", lambda t: edit_yaml(rule(t, "talon-terminate"), lambda d: d["logsource"].update(service="talon2")),
     r"logsource.service 'talon2' is not a source"),
    # check_rule_fields
    ("field outside the allow-list", lambda t: sel(t, "talon-terminate", lambda d: d["selection"].update({"talon.actor": "x"})),
     r"field 'talon.actor' is not in siem/fields/talon.yaml"),
    ("unknown modifier", lambda t: sel(t, "talon-terminate", lambda d: d["selection"].update(
        {"talon.status|base64": d["selection"].pop("talon.status")})), r"modifier 'base64' not one of"),
    # check_rule_condition
    ("aggregation", lambda t: sel(t, "talon-terminate", lambda d: set_in(d, "condition", "selection | count() > 3")),
     r"aggregation .* is not allowed"),
    ("near", lambda t: sel(t, "talon-terminate", lambda d: set_in(d, "condition", "selection near selection")),
     r"aggregation .* is not allowed"),
    ("keyword search", lambda t: sel(t, "talon-terminate", lambda d: d.update(kw=["terminate"], condition="selection and kw")),
     r"selection kw: must be a field map"),
    ("condition names no selection", lambda t: sel(t, "talon-terminate", lambda d: set_in(d, "condition", "selection and other")),
     r"condition names 'other'"),
    # check_rule_values
    ("value with a space", lambda t: sel(t, "falco-network-tool", lambda d: d["selection"].update({"falco.rule": "SDP network tool in sandbox"})),
     r"contains a space and can never match"),
    ("null value", lambda t: sel(t, "talon-terminate", lambda d: d["selection"].update({"talon.status": None})),
     r"value None must be a string"),
    # check_rule_regex
    ("regex with ^ and $", lambda t: sel(t, "hubble-dns-exfil", lambda d: d["selection"].update(
        {"dns.query|re": "^sdp-[0-9a-f]{16}$"})), r"\^, \$ and \\ never work in SA's \|re"),
    ("regex with a backslash", lambda t: sel(t, "hubble-dns-exfil", lambda d: d["selection"].update(
        {"dns.query|re": r"sdp-[0-9a-f]{16}\.x"})), r"never work in SA's \|re"),
    # check_detectors
    ("detector with the monitor prefix", lambda t: edit_yaml(os.path.join(t, "detectors/falco.yaml"),
                                                             lambda d: set_in(d, "name", "sdp-git: falco")),
     r"detectors/falco.yaml: name 'sdp-git: falco' must be"),
    ("detector interval", lambda t: edit_yaml(os.path.join(t, "detectors/falco.yaml"), lambda d: set_in(d, "interval_minutes", 5)),
     r"interval_minutes must be 1"),
    ("detector lists an unknown rule", lambda t: edit_yaml(os.path.join(t, "detectors/falco.yaml"),
                                                           lambda d: d["rules"].append("00000000-0000-4000-8000-000000000000")),
     r"rule '00000000-0000-4000-8000-000000000000' is not the id of any rule"),
    ("rule in the detector of another source", lambda t: (
        edit_yaml(os.path.join(t, "detectors/falco.yaml"),
                  lambda d: d["rules"].append(yaml.safe_load(open(rule(t, "talon-terminate")))["id"])),
        edit_yaml(os.path.join(t, "detectors/talon.yaml"),
                  lambda d: d["rules"].remove(yaml.safe_load(open(rule(t, "talon-terminate")))["id"]))),
     r"detectors/falco.yaml: rule .* is of source 'talon', not 'falco'"),
    # check_rule_in_one_detector
    ("rule in no detector", lambda t: edit_yaml(os.path.join(t, "detectors/talon.yaml"),
                                                lambda d: d["rules"].remove(yaml.safe_load(open(rule(t, "talon-terminate")))["id"])),
     r"talon-terminate.yml: rule is in 0 detectors"),
    ("rule in two detectors", lambda t: shutil.copy(os.path.join(t, "detectors/talon.yaml"), os.path.join(t, "detectors/talon2.yaml")),
     r"rule is in 2 detectors"),
    # check_correlations
    ("correlation join field unknown", lambda t: edit_yaml(os.path.join(t, "correlations/dns-exfil.yaml"),
                                                           lambda d: set_in(d, "field", "k8s.pod.uid")),
     r"join field 'k8s.pod.uid' is not in siem/fields/hubble.yaml"),
    ("correlation source unknown", lambda t: edit_yaml(os.path.join(t, "correlations/dns-exfil.yaml"),
                                                       lambda d: d["correlate"][0].update(source="dns")),
     r"source 'dns' has no allow-list"),
    ("correlation query field unknown", lambda t: edit_yaml(os.path.join(t, "correlations/dns-exfil.yaml"),
                                                            lambda d: d["correlate"][1].update(query="api.cmd:dns-exfil")),
     r"query field 'api.cmd' is not in siem/fields/api.yaml"),
    ("correlation _exists_ field unknown", lambda t: edit_yaml(os.path.join(t, "correlations/dns-exfil.yaml"),
                                                               lambda d: d["correlate"][0].update(query="_exists_:dns.label")),
     r"query field 'dns.label' is not in siem/fields/hubble.yaml"),
    ("correlation with one source", lambda t: edit_yaml(os.path.join(t, "correlations/dns-exfil.yaml"),
                                                        lambda d: d["correlate"].pop()),
     r"correlate must list at least two sources"),
    # check_monitors
    ("unprefixed monitor", lambda t: edit_json(os.path.join(t, "monitors/policy-probing.json"),
                                               lambda d: set_in(d, "name", "policy probing")),
     r"name 'policy probing' must start with 'sdp-git: '"),
    ("monitor with an action", lambda t: edit_json(os.path.join(t, "monitors/policy-probing.json"),
                                                   lambda d: d["triggers"][0]["bucket_level_trigger"]["actions"].append(
                                                       {"name": "mail", "destination_id": "x"})),
     r"trigger actions must be empty"),
    ("monitor on .kibana", lambda t: edit_json(os.path.join(t, "monitors/policy-probing.json"),
                                               lambda d: d["inputs"][0]["search"].update(indices=[".kibana"])),
     r"index '.kibana' is not an sdp-<source> data stream"),
    ("monitor names a duplicate", lambda t: edit_json(os.path.join(t, "monitors/detection-missing.json"),
                                                      lambda d: set_in(d, "name", "sdp-git: prevented-not-detected")),
     r"also used by monitors/"),
    ("monitor name differs from its file", lambda t: edit_json(os.path.join(t, "monitors/policy-probing.json"),
                                                               lambda d: set_in(d, "name", "sdp-git: probing")),
     r"must be 'sdp-git: ' \+ the file name"),
    ("monitor carries ui_metadata", lambda t: edit_json(os.path.join(t, "monitors/policy-probing.json"),
                                                        lambda d: set_in(d, "ui_metadata", {})),
     r"keys not allowed in git: ui_metadata"),
    # check_canaries
    ("rule without a canary", lambda t: edit_yaml(os.path.join(t, "canaries.yaml"),
                                                  lambda d: d["rules"].pop(yaml.safe_load(open(rule(t, "talon-terminate")))["id"])),
     r"canaries.yaml: rules: .* has no canary"),
    ("monitor without a canary", lambda t: edit_yaml(os.path.join(t, "canaries.yaml"),
                                                     lambda d: d["monitors"].pop("sdp-git: policy-probing")),
     r"monitors: sdp-git: policy-probing has no canary"),
    ("canary of a missing object", lambda t: edit_yaml(os.path.join(t, "canaries.yaml"),
                                                       lambda d: d["correlations"].update({"gone": {"kind": "exec", "run": "x", "step": "y"}})),
     r"canary for gone, which does not exist"),
    ("canary of an unknown kind", lambda t: edit_yaml(os.path.join(t, "canaries.yaml"),
                                                      lambda d: d["correlations"].update({"dns-exfil": {"kind": "manual"}})),
     r"dns-exfil: kind must be one of"),
    ("canary names an address", lambda t: edit_yaml(os.path.join(t, "canaries.yaml"),
                                                    lambda d: d["monitors"]["sdp-git: policy-probing"].update(run="ssh 10.4.1.20")),
     r"names an address or a node; canaries are published"),
    ("api canary with both forms", lambda t: edit_yaml(os.path.join(t, "canaries.yaml"),
                                                       lambda d: d["correlations"]["dns-exfil"].update(scenario="network-tool")),
     r"an api canary names either"),
]


def main():
    fails = 0
    code, out = run(SIEM)
    if code != 0:
        print(f"FAIL the real tree is not clean:\n{out}")
        fails += 1
    else:
        print(f"ok   the real tree is clean ({out.strip()})")
    for name, change, want in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            tree = os.path.join(tmp, "siem")
            shutil.copytree(SIEM, tree)
            change(tree)
            code, out = run(tree)
        if code == 1 and re.search(want, out):
            print(f"ok   {name}")
        else:
            print(f"FAIL {name}: exit {code}, wanted /{want}/ in:\n{out}")
            fails += 1
    print(f"lint_test: {len(CASES) + 1 - fails} passed, {fails} failed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
