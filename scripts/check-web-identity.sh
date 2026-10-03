#!/usr/bin/env bash
# ADR 0035: the `cosign verify` command the page offers must check exactly the identity everything else
# checks. app/web/src/lib/provenance.ts holds the issuer and the identity regexp the page prints; they
# must be character for character the defaults of scripts/verify-image.sh (which in turn equal the
# admission policy, ADR 0016). Two copies drifting apart would mean the page tells visitors to verify
# against an identity the cluster does not enforce - the page's earlier exact identity had already
# drifted. ADR 0016's TRANSITION removal edits all of them together.
#
# The constant arrived with the web side of ADR 0035; on a tree without provenance.ts there is nothing
# to compare, and the check says so instead of passing silently.
set -euo pipefail
cd "$(dirname "$0")/.."
web=app/web/src/lib/provenance.ts
if [ ! -f "$web" ]; then
  echo "check-web-identity: skipped - $web does not exist in this tree"
  exit 0
fi
python3 - "$web" scripts/verify-image.sh <<'PY'
import re, sys

web, script = sys.argv[1], sys.argv[2]
ts, sh = open(web).read(), open(script).read()

def one(pattern, text, what, where):
    found = re.findall(pattern, text, re.M)
    if len(found) != 1:
        sys.exit(f"check-web-identity: expected exactly one {what} in {where}, found {len(found)}")
    return found[0]

pairs = [
    ("identity regexp",
     one(r'^export const COSIGN_IDENTITY_REGEXP = String\.raw`([^`]*)`;', ts, "COSIGN_IDENTITY_REGEXP", web),
     one(r"^IDENTITY_REGEXP=\$\{IDENTITY_REGEXP:-'([^']*)'\}$", sh, "IDENTITY_REGEXP default", script)),
    ("OIDC issuer",
     one(r'^export const COSIGN_ISSUER = "([^"]*)";', ts, "COSIGN_ISSUER", web),
     one(r"^OIDC_ISSUER=\$\{OIDC_ISSUER:-([^}]*)\}$", sh, "OIDC_ISSUER default", script)),
]
bad = False
for what, page, verify in pairs:
    if page != verify:
        bad = True
        print(f"check-web-identity: the {what} differs", file=sys.stderr)
        print(f"  {web}: {page}", file=sys.stderr)
        print(f"  {script}: {verify}", file=sys.stderr)
if bad:
    sys.exit(1)
print(f"ok - {web} cosign identity matches scripts/verify-image.sh")
PY
