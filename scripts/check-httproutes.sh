#!/usr/bin/env bash
# The HTTPRoute rules the Gateway API CRDs (v1.4, standard channel) enforce with CEL at admission,
# which kubeconform's schema check in validate-cluster.sh cannot see. A route that breaks one is
# refused whole by the API server: Argo's sync fails and the Gateway keeps serving the old routes,
# so nothing in CI would otherwise notice. Mirrors these x-kubernetes-validations of a rule:
#   - a RequestRedirect filter is not used together with backendRefs;
#   - a URLRewrite or RequestRedirect with path.replacePrefixMatch needs exactly one match, and that
#     match's path is a PathPrefix.
set -euo pipefail
cd "$(dirname "$0")/.."
mapfile -t routes < <(grep -rl --include="*.yaml" "^kind: HTTPRoute" cluster)
python3 - "${routes[@]}" <<'PY'
import sys, yaml

failures = 0
def fail(path, i, msg):
    global failures
    failures += 1
    print(f"check-httproutes: {path} rule {i}: {msg}", file=sys.stderr)

count = 0
for path in sys.argv[1:]:
    for doc in yaml.safe_load_all(open(path)):
        if not doc or doc.get("kind") != "HTTPRoute":
            continue
        count += 1
        for i, rule in enumerate(doc["spec"].get("rules", []), 1):
            filters = rule.get("filters", [])
            if rule.get("backendRefs") and any("requestRedirect" in f for f in filters):
                fail(path, i, "RequestRedirect filter must not be used together with backendRefs")
            for key in ("urlRewrite", "requestRedirect"):
                if any(((f.get(key) or {}).get("path") or {}).get("type") == "ReplacePrefixMatch" for f in filters):
                    matches = rule.get("matches", [])
                    if len(matches) != 1 or (matches[0].get("path") or {}).get("type") != "PathPrefix":
                        fail(path, i, f"{key} with replacePrefixMatch needs exactly one PathPrefix match "
                                      f"(has {len(matches)})")
if failures:
    sys.exit(1)
print(f"ok - {count} HTTPRoutes pass the Gateway API admission rules for rewrites and redirects")
PY
