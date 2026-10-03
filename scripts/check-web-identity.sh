#!/usr/bin/env bash
# ADR 0035: the `cosign verify` command the page offers must check exactly the identity everything else
# checks. app/web/src/lib/provenance.ts holds the issuer and the identity regexp the page prints; they
# must be character for character the defaults of scripts/verify-image.sh and every
# subjectRegExp/issuer of cluster/infra/kyverno-policies/verify-portfolio-images.yaml (ADR 0016). Copies
# drifting apart would mean the page tells visitors to verify against an identity the cluster does not
# enforce - the page's earlier exact identity already differed. ADR 0016's TRANSITION removal edits all
# of them together.
#
# provenance.ts is the page's only copy: no other file under app/web/src may spell the issuer or the
# workflow path, so a second, unchecked copy cannot creep back in. A tree without provenance.ts fails;
# the check exists because that file does.
set -euo pipefail
cd "$(dirname "$0")/.."
web=app/web/src/lib/provenance.ts
if [ ! -f "$web" ]; then
  echo "check-web-identity: $web is missing" >&2
  exit 1
fi
others=$(grep -rlF -e token.actions.githubusercontent.com -e workflows/build-images app/web/src | grep -vxF "$web" || true)
if [ -n "$others" ]; then
  echo "check-web-identity: the cosign identity must live only in $web; also found in:" >&2
  printf '  %s\n' "$others" >&2
  exit 1
fi
python3 - "$web" scripts/verify-image.sh cluster/infra/kyverno-policies/verify-portfolio-images.yaml <<'PY'
import re, sys, yaml

web, script, policy = sys.argv[1], sys.argv[2], sys.argv[3]
ts, sh = open(web).read(), open(script).read()

def one(pattern, text, what, where):
    found = re.findall(pattern, text, re.M)
    if len(found) != 1:
        sys.exit(f"check-web-identity: expected exactly one {what} in {where}, found {len(found)}")
    return found[0]

def collect(node, key, out):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key and isinstance(v, str):
                out.append(v)
            else:
                collect(v, key, out)
    elif isinstance(node, list):
        for v in node:
            collect(v, key, out)
    return out

docs = list(yaml.safe_load_all(open(policy)))
subjects = collect(docs, "subjectRegExp", [])
issuers = collect(docs, "issuer", [])
if not subjects or not issuers:
    sys.exit(f"check-web-identity: no subjectRegExp/issuer found in {policy}")

checks = [
    ("identity regexp",
     one(r'^export const COSIGN_IDENTITY_REGEXP = String\.raw`([^`]*)`;', ts, "COSIGN_IDENTITY_REGEXP", web),
     [(script, one(r"^IDENTITY_REGEXP=\$\{IDENTITY_REGEXP:-'([^']*)'\}$", sh, "IDENTITY_REGEXP default", script))]
     + [(policy, s) for s in subjects]),
    ("OIDC issuer",
     one(r'^export const COSIGN_ISSUER = "([^"]*)";', ts, "COSIGN_ISSUER", web),
     [(script, one(r"^OIDC_ISSUER=\$\{OIDC_ISSUER:-([^}]*)\}$", sh, "OIDC_ISSUER default", script))]
     + [(policy, i) for i in issuers]),
]
bad = False
for what, page, others in checks:
    for where, value in others:
        if value != page:
            bad = True
            print(f"check-web-identity: the {what} differs", file=sys.stderr)
            print(f"  {web}: {page}", file=sys.stderr)
            print(f"  {where}: {value}", file=sys.stderr)
if bad:
    sys.exit(1)
print(f"ok - {web} cosign identity matches scripts/verify-image.sh and {policy} "
      f"({len(subjects)} subjectRegExp, {len(issuers)} issuer)")
PY
