#!/usr/bin/env python3
"""The contained-intrusion correlation's Falco side names exactly the Falco rules Talon answers.

siem/correlations/contained-intrusion.yaml lists falco.rule_slug values; a misspelt or missing slug makes
SA record no correlation, which the canaries only report as a note (S0-e, F17). Here the slugs are
compared with cluster/infra/falco-response/talon/rules.yaml (match.rules, slugged as sdp.lua's slug
transform does) and each must be the slug of a Sigma rule in the Falco detector (siem/detectors/falco.yaml).

Usage: tests/siem/talon_slugs_test.py [repo root]   (default: this checkout; p3-mutations.sh passes a copy)
"""
import glob
import os
import re
import sys

import yaml

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
UPPER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def slug(v):
    # sdp.lua: v:lower():gsub("[^a-z0-9]+", "-"):gsub("^%-+", ""):gsub("%-+$", "") - Lua's lower is ASCII only.
    return re.sub(r"[^a-z0-9]+", "-", v.translate(UPPER)).strip("-")


def load(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return yaml.safe_load(fh)


fails = []
talon = {slug(r) for item in load("cluster/infra/falco-response/talon/rules.yaml") if "rule" in item
         for r in item["match"]["rules"]}
fails += [] if talon else ["no match.rules in the Talon rules"]

falco_side = [e["query"] for e in load("siem/correlations/contained-intrusion.yaml")["correlate"] if e["source"] == "falco"]
m = re.fullmatch(r"event\.kind:alert AND falco\.rule_slug:\(([a-z0-9-]+(?: OR [a-z0-9-]+)*)\)", falco_side[0]) \
    if len(falco_side) == 1 else None
corr = set(m.group(1).split(" OR ")) if m else set()
if not m:
    fails.append(f"the Falco query is not 'event.kind:alert AND falco.rule_slug:(<slug> OR ...)': {falco_side}")
elif corr != talon:
    fails.append(f"correlation slugs differ from Talon's: only in the correlation {sorted(corr - talon)}, "
                 f"only in Talon {sorted(talon - corr)}")

detector = set(load("siem/detectors/falco.yaml")["rules"])
by_slug = {}
for path in glob.glob(os.path.join(ROOT, "siem/rules/*.yml")):
    with open(path, encoding="utf-8") as fh:
        r = yaml.safe_load(fh)
    s = r.get("detection", {}).get("selection", {}).get("falco.rule_slug")
    if r.get("logsource", {}).get("service") == "falco" and isinstance(s, str):
        by_slug.setdefault(s, set()).add(r["id"])
for s in sorted(talon):
    if not by_slug.get(s, set()) & detector:
        fails.append(f"Talon answers {s!r}, but no rule of the Falco detector matches that slug")

for f in fails:
    print(f"FAIL {f}")
print(f"talon_slugs_test: {'FAIL' if fails else 'ok'} - {len(talon)} Talon rules, {len(corr)} correlation slugs")
sys.exit(1 if fails else 0)
