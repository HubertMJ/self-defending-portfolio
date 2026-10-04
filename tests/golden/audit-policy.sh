#!/usr/bin/env bash
# The k3s API server audit policy as k3s01 gets it (siem contract P2, F2; ADR 0034). The k3s role's
# template is rendered by Ansible in the tooling container with k3s01's real variables (k3s role
# defaults + group_vars/k3s_nodes.yml), from the working tree and from BASE (the commit before P2):
#   - the new render must equal tests/golden/k3s01/audit-policy.yaml byte for byte;
#   - against BASE the ONLY change is the authentication.k8s.io group moving from the
#     RequestResponse rule into its own Metadata rule placed right before it;
#   - evaluated first-match the way the API server does, a TokenReview is now logged at Metadata
#     (no request/response body, so no bearer token) while pod creates in sandbox*, pods/exec, RBAC
#     changes and SubjectAccessReviews keep their levels.
# The live apply is `cluster.yml --tags k3s` in a maintenance window (k3s restarts once).
#
# Usage: tests/golden/audit-policy.sh            compare
#        tests/golden/audit-policy.sh --write    regenerate the golden after a reviewed change
#        BASE=<rev>                              the revision to diff against (default c4e5e91)
#        AUDIT_TEST_ROOT=<dir>                   take ansible/ from <dir> (mutation runs)
set -euo pipefail
cd "$(dirname "$0")/../.."
DOCKER=${DOCKER:-docker}
BASE=${BASE:-c4e5e91}
ROOT=${AUDIT_TEST_ROOT:-$PWD}
GOLDEN=tests/golden/k3s01/audit-policy.yaml

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
$DOCKER image inspect sdp-tooling >/dev/null 2>&1 || $DOCKER build -q -t sdp-tooling -f scripts/Dockerfile.tooling .
mkdir -p "$work/base" "$work/cur" "$work/out"
git archive "$BASE" ansible | tar -x -C "$work/base"
cp -r "$ROOT/ansible" "$work/cur/ansible"
rm -rf "$work/cur/ansible/.ansible"

render() { # <tree> <output name>
  $DOCKER run --rm -i --user "$(id -u):$(id -g)" -e HOME=/tmp -e USER=golden -e ANSIBLE_LOCAL_TEMP=/tmp/.ansible-local -e ANSIBLE_REMOTE_TMP=/tmp/.ansible-remote \
    -v "$1/ansible":/tree:ro -v "$work/out":/out -w /tree sdp-tooling \
    ansible localhost -c local -i localhost, -m ansible.builtin.template \
    -a "src=roles/k3s/templates/audit-policy.yaml.j2 dest=/out/$2 mode=0644" \
    -e @roles/k3s/defaults/main.yml -e @inventory/group_vars/k3s_nodes.yml \
    -e ansible_python_interpreter=/usr/local/bin/python3 >"$work/$2.log" 2>&1 \
    || { cat "$work/$2.log"; echo "audit-policy: render failed" >&2; exit 1; }
}
render "$work/base" base.yaml
render "$work/cur" cur.yaml

if [ "${1:-}" = "--write" ]; then
  cp "$work/out/cur.yaml" "$GOLDEN"
  echo "audit-policy: wrote $GOLDEN"
  exit 0
fi

fail=0
if ! cmp -s "$work/out/cur.yaml" "$GOLDEN"; then
  echo "audit-policy: the render differs from $GOLDEN:"; diff -u "$GOLDEN" "$work/out/cur.yaml" || true; fail=1
fi
python3 - "$work/out/base.yaml" "$work/out/cur.yaml" <<'PY' || fail=1
import copy, sys, yaml
base = yaml.safe_load(open(sys.argv[1]))
cur = yaml.safe_load(open(sys.argv[2]))
problems = []

# The expected policy, built from the base: authentication.k8s.io out of its RequestResponse rule,
# into a Metadata rule of its own right before it.
want = copy.deepcopy(base)
rules = want["rules"]
idx = next(i for i, r in enumerate(rules) if r.get("level") == "RequestResponse"
           and any(g.get("group") == "authentication.k8s.io" for g in r.get("resources", [])))
rules[idx]["resources"] = [g for g in rules[idx]["resources"] if g.get("group") != "authentication.k8s.io"]
rules.insert(idx, {"level": "Metadata", "resources": [{"group": "authentication.k8s.io", "resources": ["*"]}]})
if cur != want:
    problems.append("the policy differs from the base by more (or less) than moving authentication.k8s.io to Metadata")

def level(policy, verb, group, resource, namespace=None, user="someone", groups=()):
    """First-match evaluation as the API server does it, for the fields this policy uses."""
    for r in policy["rules"]:
        if "users" in r and user not in r["users"]:
            continue
        if "userGroups" in r and not set(groups) & set(r["userGroups"]):
            continue
        if "verbs" in r and verb not in r["verbs"]:
            continue
        if "namespaces" in r and namespace not in r["namespaces"]:
            continue
        if "resources" in r:
            hit = False
            for g in r["resources"]:
                if g.get("group", "") != group:
                    continue
                names = g.get("resources", [])
                if "*" in names or resource in names or ("/" not in resource and f"{resource}/*" in names):
                    hit = True
            if not hit:
                continue
        return r["level"]
    return "None"

cases = [
    # (description, request, expected level now)
    ("TokenReview by the node", ("create", "authentication.k8s.io", "tokenreviews", None, "system:node:k3s01", ["system:nodes"]), "Metadata"),
    ("TokenReview by kyverno", ("create", "authentication.k8s.io", "tokenreviews", None, "system:serviceaccount:kyverno:kyverno-admission-controller", []), "Metadata"),
    ("SelfSubjectReview", ("create", "authentication.k8s.io", "selfsubjectreviews", None, "operator", []), "Metadata"),
    ("pod create in sandbox", ("create", "", "pods", "sandbox", "system:serviceaccount:portfolio-api:portfolio-api", []), "RequestResponse"),
    ("pods/exec", ("create", "", "pods/exec", "sandbox", "system:admin", []), "RequestResponse"),
    ("SubjectAccessReview", ("create", "authorization.k8s.io", "subjectaccessreviews", None, "system:serviceaccount:kyverno:kyverno-admission-controller", []), "RequestResponse"),
    ("RoleBinding change", ("create", "rbac.authorization.k8s.io", "rolebindings", "sandbox", "system:admin", []), "RequestResponse"),
    ("Secret read", ("get", "", "secrets", "kube-system", "operator", []), "Metadata"),
]
for desc, (verb, group, resource, ns, user, groups), expected in cases:
    got = level(cur, verb, group, resource, ns, user, groups)
    if got != expected:
        problems.append(f"{desc}: logged at {got}, expected {expected}")
before = level(base, "create", "authentication.k8s.io", "tokenreviews", None, "system:node:k3s01", ["system:nodes"])
if before != "RequestResponse":
    problems.append(f"the base already logged TokenReviews at {before}; the test no longer proves the change")

if problems:
    print("audit-policy: FAIL")
    for p in problems:
        print(f"  - {p}")
    sys.exit(1)
print(f"audit-policy: ok - one change against the base (authentication.k8s.io RequestResponse -> Metadata, "
      f"ahead of the RequestResponse rule); {len(cases)} requests evaluate to their expected levels")
PY
exit "$fail"
