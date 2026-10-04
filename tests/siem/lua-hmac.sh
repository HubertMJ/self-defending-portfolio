#!/usr/bin/env bash
# The SIEM shipper's filter under the pinned Fluent Bit (siem contract P2 tests, ADR 0034): the F0
# fixtures and a few hostile extra lines go through the real sdp.lua, the role's parsers and the
# allow-lists rendered from siem/fields with the role's own template, and what Fluent Bit prints is
# checked by tests/siem/lua_check.py:
#   - HMAC-SHA256: RFC 4231 cases 2, 6 and 7 and a project vector, each computed independently by
#     Python's hmac; the pseudonyms in the records equal Python's too;
#   - projection: nothing outside the allow-list; system: users kept, people and addresses replaced;
#   - F2: the sandbox pod create carries no flag and no request body; the TokenReview and the kyverno
#     review are dropped; F13: Hubble's non-flow records are dropped; F1: a client-sent
#     event.overwrite / event.ingested is stripped;
#   - the whole output equals tests/siem/expected/lua-output.jsonl (heartbeats aside).
# Runs in CI (lint.yml validate job). Needs docker and python3 with PyYAML and Jinja2.
#
# Usage: tests/siem/lua-hmac.sh            check
#        tests/siem/lua-hmac.sh --write    regenerate the expected output after a reviewed change
#        LUA_TEST_ROOT=<dir>               take the role, fields and fixtures from <dir> (mutation runs)
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT=${LUA_TEST_ROOT:-$PWD}
DOCKER=${DOCKER:-docker}
IMAGE=sdp-fluent-bit-test

read -r FB_VERSION FB_SHA256 < <(python3 -c '
import sys, yaml
v = yaml.safe_load(open(sys.argv[1]))
print(v["fluent_bit_version"], v["fluent_bit_deb_sha256"])' ansible/inventory/group_vars/all.yml)
$DOCKER build -q -t "$IMAGE" --build-arg FLUENT_BIT_VERSION="$FB_VERSION" --build-arg FLUENT_BIT_SHA256="$FB_SHA256" \
  -f tests/siem/Dockerfile.fluent-bit tests/siem >/dev/null

work=$(mktemp -d)
name=sdp-lua-test-$$
cleanup() { $DOCKER rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
mkdir -p "$work/etc" "$work/creds"

# The test's own key: 32 fixed bytes 0x00..0x1f. Never a host key.
python3 -c 'import sys; open(sys.argv[1], "wb").write(bytes(range(32)))' "$work/creds/hmac.key"
cp "$ROOT/ansible/roles/fluent_bit/files/sdp.lua" "$ROOT/ansible/roles/fluent_bit/files/parsers.conf" \
   tests/siem/lua/vectors.lua "$work/etc/"
python3 - "$ROOT" "$work/etc/sdp_fields.lua" <<'PY'
import sys, yaml, jinja2
root, out = sys.argv[1], sys.argv[2]
env = jinja2.Environment(trim_blocks=True, undefined=jinja2.StrictUndefined)
template = env.from_string(open(f"{root}/ansible/roles/fluent_bit/templates/sdp_fields.lua.j2").read())
sources = ["falco", "talon", "api", "k8s-audit", "hubble", "host", "siem01"]
sets = {s: yaml.safe_load(open(f"{root}/siem/fields/{s}.yaml")) for s in sources}
# Review L4: the template writes every string inside [==[ ]==]; one containing "]==" would end it early.
def strings(x):
    if isinstance(x, dict):
        for k, v in x.items():
            yield from strings(k)
            yield from strings(v)
    elif isinstance(x, list):
        for v in x:
            yield from strings(v)
    elif isinstance(x, str):
        yield x
bad = [v for spec in sets.values() for v in strings(spec["fields"]) if "]==" in v]
if bad:
    sys.exit(f"lua-hmac: field strings contain ']==': {bad}")
open(out, "w").write(template.render(fluent_bit_field_sets=sets))
PY

# tail <tag> <path> <cri|json|raw|osaudit>
tail_input() {
  printf '[INPUT]\n    Name tail\n    Tag %s\n    Path %s\n    Read_from_Head On\n    Buffer_Max_Size 2M\n' "$1" "$2"
  case $3 in
    cri) printf '    multiline.parser cri\n' ;;
    json) printf '    Parser sdp_json\n' ;;
    osaudit) printf '    Parser sdp_osaudit\n' ;;
  esac
}
{
  printf '[SERVICE]\n    Flush 1\n    Log_Level warn\n    Parsers_File /etc/fluent-bit/sdp/parsers.conf\n'
  tail_input sdp.falco.log '/fixtures/falco*.log' cri
  tail_input sdp.talon.log /fixtures/talon.log cri
  tail_input sdp.api.log '/fixtures/api.log,/extra/extra-api.log' cri
  tail_input sdp.k8s-audit.log '/fixtures/k8s-audit.jsonl,/extra/extra-audit.jsonl' json
  tail_input sdp.hubble.log /fixtures/hubble.log json
  tail_input sdp.host.journal '/fixtures/host-*.json,/extra/extra-journal.json' json
  tail_input sdp.host.auditd /fixtures/host-auditd.log raw
  tail_input sdp.host.fbmetrics /extra/extra-fbmetrics.json json
  tail_input sdp.siem01.journal '/fixtures/siem01-*.json' json
  tail_input sdp.siem01.auditd /fixtures/siem01-auditd.log raw
  tail_input sdp.siem01.osaudit /fixtures/siem01-osaudit.log osaudit
  printf '[INPUT]\n    Name dummy\n    Tag sdp.falco.hb\n    Samples 1\n'
  printf '[INPUT]\n    Name dummy\n    Tag sdp.nosuchsource.log\n    Samples 1\n'
  printf '[INPUT]\n    Name dummy\n    Tag test.vectors\n    Samples 1\n'
  # As in the role's fluent-bit.conf: decode the JSON body of CRI lines and of the audit line.
  printf '[FILTER]\n    Name parser\n    Match_Regex ^sdp\\.(falco|talon|api)\\.log$\n    Key_Name log\n    Parser sdp_json\n'
  printf '[FILTER]\n    Name parser\n    Match sdp.siem01.osaudit\n    Key_Name payload\n    Parser sdp_json\n'
  printf '[FILTER]\n    Name lua\n    Match sdp.*\n    Script /etc/fluent-bit/sdp/sdp.lua\n    Call sdp_filter\n'
  printf '[FILTER]\n    Name lua\n    Match test.vectors\n    Script /etc/fluent-bit/sdp/vectors.lua\n    Call vectors\n'
  printf '[OUTPUT]\n    Name stdout\n    Match *\n    Format json_lines\n    json_date_key @timestamp\n    json_date_format iso8601\n'
} > "$work/etc/fluent-bit.conf"

$DOCKER run -d --name "$name" --network none -e CREDENTIALS_DIRECTORY=/creds \
  -v "$work/etc":/etc/fluent-bit/sdp:ro -v "$work/creds":/creds:ro \
  -v "$ROOT/tests/siem/fixtures":/fixtures:ro -v "$PWD/tests/siem/lua":/extra:ro \
  "$IMAGE" /opt/fluent-bit/bin/fluent-bit -c /etc/fluent-bit/sdp/fluent-bit.conf >/dev/null

# Wait until the output stops growing (all files read), at most 40 s.
last=-1
for _ in $(seq 1 40); do
  sleep 1
  n=$($DOCKER logs "$name" 2>/dev/null | grep -c '^{' || true)
  [ "$n" -gt 0 ] && [ "$n" = "$last" ] && break
  last=$n
done
$DOCKER logs "$name" >"$work/stdout" 2>"$work/stderr" || true
if ! $DOCKER inspect -f '{{.State.Running}}' "$name" | grep -q true; then
  echo "lua-hmac: Fluent Bit exited:"; cat "$work/stdout" "$work/stderr"; exit 1
fi
grep '^{' "$work/stdout" >"$work/records.jsonl" || true

python3 tests/siem/lua_check.py "$work/records.jsonl" "$work/creds/hmac.key" "$ROOT" tests/siem/expected/lua-output.jsonl "${1:-}"
