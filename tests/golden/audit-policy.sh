#!/usr/bin/env bash
# The k3s API server audit policy as k3s01 gets it (siem contract P2, F2; ADR 0034; CIS k3s 3.2.2,
# ADR 0025 amendment 2026-10-10). The k3s role's template is rendered by Ansible in the tooling
# container with k3s01's real variables (k3s role defaults + group_vars/k3s_nodes.yml), from the
# working tree and from BASE (main before the CIS change, with P2 live):
#   - the new render must equal tests/golden/audit-policy/k3s01.yaml byte for byte;
#   - against BASE the ONLY changes are: Secrets, serviceaccounts/token and the authentication.k8s.io
#     group move into one Metadata rule at the top, ahead of the exclusions (ConfigMaps keep their
#     Metadata rule where it was), and pods/proxy, services/proxy and nodes/proxy get a Metadata rule
#     of their own after the pods/exec rule;
#   - evaluated first-match the way the API server does, a node's or a controller's read of a Secret
#     is now logged at Metadata (it was dropped), the proxies are logged at Metadata, and TokenReviews
#     (no body, so no bearer token), pod creates in sandbox*, pods/exec, RBAC changes and
#     SubjectAccessReviews keep their levels.
# The live apply is `cluster.yml --tags k3s` in a maintenance window (k3s restarts once).
#
# Retiring / rebasing (review code L5): BASE is the commit before the change under review. A later,
# reviewed change to the policy either rebases this test - set BASE to the merge commit of this one,
# regenerate the golden with --write and replace the expected-diff block below with that change's
# own - or retires it once tests/golden/render.sh renders the k3s role too (then delete this script,
# its golden and its line in `make golden`). Never regenerate the golden alone: the diff against BASE
# is what makes it a review, not a snapshot. History: c4e5e91 -> P2 (TokenReviews to Metadata);
# 2ae8097 -> the CIS 3.2.2 change described above.
#
# Usage: tests/golden/audit-policy.sh            compare
#        tests/golden/audit-policy.sh --write    regenerate the golden after a reviewed change
#        BASE=<rev>                              the revision to diff against (default 2ae8097)
#        AUDIT_TEST_ROOT=<dir>                   take ansible/ from <dir> (mutation runs)
set -euo pipefail
cd "$(dirname "$0")/../.."
DOCKER=${DOCKER:-docker}
BASE=${BASE:-2ae8097}
ROOT=${AUDIT_TEST_ROOT:-$PWD}
GOLDEN=tests/golden/audit-policy/k3s01.yaml

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

# The expected policy, built from the base: Secrets, serviceaccounts/token and authentication.k8s.io
# out of their rules and into one Metadata rule at the top; the proxies' Metadata rule right after
# the pods/exec rule.
want = copy.deepcopy(base)
rules = want["rules"]
sensitive = {"secrets", "serviceaccounts/token"}
for r in rules:
    if r.get("level") == "Metadata" and "resources" in r:
        kept = []
        for g in r["resources"]:
            if g.get("group", "") == "" and set(g.get("resources", [])) & sensitive:
                g = dict(g, resources=[x for x in g["resources"] if x not in sensitive])
            if g.get("group") == "authentication.k8s.io" or not g.get("resources"):
                continue
            kept.append(g)
        r["resources"] = kept
rules[:] = [r for r in rules if not ("resources" in r and r["resources"] == [])]
rules.insert(0, {"level": "Metadata", "resources": [
    {"group": "", "resources": ["secrets", "serviceaccounts/token"]},
    {"group": "authentication.k8s.io", "resources": ["*"]}]})
idx = next(i for i, r in enumerate(rules) if any("pods/exec" in g.get("resources", []) for g in r.get("resources", [])))
rules.insert(idx + 1, {"level": "Metadata", "resources": [{"group": "", "resources": ["pods/proxy", "services/proxy", "nodes/proxy"]}]})
if cur != want:
    problems.append("the policy differs from the base by more (or less) than the CIS 3.2.2 change")

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
    ("Secret read by the node", ("get", "", "secrets", "sandbox", "system:node:k3s01", ["system:nodes"]), "Metadata"),
    ("Secret watch by the controller-manager", ("watch", "", "secrets", None, "system:kube-controller-manager", []), "Metadata"),
    ("TokenRequest", ("create", "", "serviceaccounts/token", "argocd", "system:node:k3s01", ["system:nodes"]), "Metadata"),
    ("ConfigMap write", ("update", "", "configmaps", "argocd", "system:admin", []), "Metadata"),
    ("ConfigMap read by the node", ("get", "", "configmaps", "argocd", "system:node:k3s01", ["system:nodes"]), "None"),
    ("pods/portforward", ("create", "", "pods/portforward", "portfolio-api", "system:admin", []), "RequestResponse"),
    ("pods/proxy", ("get", "", "pods/proxy", "portfolio-api", "system:admin", []), "Metadata"),
    ("services/proxy", ("get", "", "services/proxy", "kube-system", "system:admin", []), "Metadata"),
    ("Deployment change", ("patch", "apps", "deployments", "portfolio-api", "system:serviceaccount:argocd:argocd-application-controller", []), "Metadata"),
    ("pod delete outside sandbox", ("delete", "", "pods", "falco", "system:serviceaccount:falco-response:falco-talon", []), "Metadata"),
]
for desc, (verb, group, resource, ns, user, groups), expected in cases:
    got = level(cur, verb, group, resource, ns, user, groups)
    if got != expected:
        problems.append(f"{desc}: logged at {got}, expected {expected}")
before = level(base, "get", "", "secrets", "sandbox", "system:node:k3s01", ["system:nodes"])
if before != "None":
    problems.append(f"the base already logged a node's Secret read at {before}; the test no longer proves the change")

if problems:
    print("audit-policy: FAIL")
    for p in problems:
        print(f"  - {p}")
    sys.exit(1)
print(f"audit-policy: ok - the CIS 3.2.2 change against the base (Secrets and tokens first, proxies "
      f"at Metadata) and nothing else; {len(cases)} requests evaluate to their expected levels")
PY
exit "$fail"
