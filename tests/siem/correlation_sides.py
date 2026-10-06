#!/usr/bin/env python3
"""Prints each correlation's sides as JSON for tests/siem/canary_docs.py --correlations, which runs with
the standard library only (on siem01 too): {name: [{"stream": <data stream>, "query": <query>}, ...]}.

Usage: tests/siem/correlation_sides.py [siem dir]   (default: siem)
"""
import glob
import json
import os
import sys

import yaml

siem = sys.argv[1] if len(sys.argv) > 1 else "siem"
out = {}
for path in sorted(glob.glob(os.path.join(siem, "correlations", "*.yaml"))):
    with open(path, encoding="utf-8") as fh:
        corr = yaml.safe_load(fh)
    sides = []
    for e in corr["correlate"]:
        with open(os.path.join(siem, "fields", e["source"] + ".yaml"), encoding="utf-8") as fh:
            sides.append({"stream": yaml.safe_load(fh)["stream"], "query": e["query"]})
    out[corr["name"]] = sides
json.dump(out, sys.stdout, indent=1)
print()
