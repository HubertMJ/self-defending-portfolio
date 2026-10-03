#!/usr/bin/env bash
# require-sandbox-deadline (ADR 0031), checked without a cluster: every Pod in sandbox-deadline-pods.yaml
# is judged on its own by the Kyverno CLI against that one policy, and must get the verdict its
# annotation names - refused by the policy (tests.hubertjablon.ski/expect-policy) or admitted
# (tests.hubertjablon.ski/expect-admitted). Needs docker; pulls the Kyverno CLI image `make validate`
# uses, at the in-cluster controller's version.
#
#   tests/admission/offline.sh
#   DOCKER="sudo -n docker" tests/admission/offline.sh
#
# What it proves: the policy's pattern refuses a missing and an over-bound deadline in both sandbox
# namespaces and admits the bound itself - an "admitted" Pod must be evaluated and pass, not skipped,
# so a namespace dropped from the policy's match fails here too. What it cannot prove: that nothing else
# in the live admission chain refuses these Pods first (Pod Security, the image policies, the quota);
# that is tests/admission/run.sh, against the cluster.
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT=$(cd ../.. && pwd)

DOCKER=${DOCKER:-docker}
# The same pin as scripts/validate-cluster.sh, read from there, so a Kyverno bump is one edit.
# shellcheck disable=SC2016  # the sed pattern matches a literal ${...} in that file
KYVERNO_CLI_IMAGE=${KYVERNO_CLI_IMAGE:-$(sed -n 's/^KYVERNO_CLI_IMAGE=\${KYVERNO_CLI_IMAGE:-\(.*\)}$/\1/p' "$REPO_ROOT/scripts/validate-cluster.sh")}
[ -n "$KYVERNO_CLI_IMAGE" ] || { echo "offline.sh: no KYVERNO_CLI_IMAGE in scripts/validate-cluster.sh" >&2; exit 1; }
POLICY=require-sandbox-deadline
MANIFEST=sandbox-deadline-pods.yaml
# The scenario image pinned in the catalogue: what the live runner admits too (see the manifest).
SCENARIO_IMAGE=$(sed -n 's/^ *image: &scenario-image //p' "$REPO_ROOT/cluster/infra/sandbox/scenarios/scenarios.yaml")
[ -n "$SCENARIO_IMAGE" ] || { echo "offline.sh: no &scenario-image in scenarios.yaml" >&2; exit 1; }

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

failures=0
step() { printf '\n==> %s\n' "$*"; }
pass() { printf '  PASS  %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*" >&2; failures=$((failures + 1)); }

step "$POLICY over $MANIFEST ($KYVERNO_CLI_IMAGE)"

cp "$REPO_ROOT/cluster/infra/kyverno-policies/$POLICY.yaml" "$WORK_DIR/policy.yaml"
# One file per document, as tests/admission/run.sh splits them, so each Pod is judged on its own.
awk -v out="$WORK_DIR" '/^---[[:space:]]*$/ { n++; next } { print > (out "/doc." n ".yaml") }' n=0 "$MANIFEST"
sed -i "s#SCENARIO_IMAGE#$SCENARIO_IMAGE#" "$WORK_DIR"/doc.*.yaml
# The CLI runs as the invoking user (mktemp's directory is 0700 for it), as in validate-cluster.sh.
denied=0 admitted=0
for doc in "$WORK_DIR"/doc.*.yaml; do
  name=$(sed -n 's/^  name:[[:space:]]*//p' "$doc" | head -1)
  ns=$(sed -n 's/^  namespace:[[:space:]]*//p' "$doc" | head -1)
  expected=$(sed -n 's#^[[:space:]]*tests\.hubertjablon\.ski/expect-policy:[[:space:]]*##p' "$doc")
  admit=$(sed -n 's#^[[:space:]]*tests\.hubertjablon\.ski/expect-admitted:[[:space:]]*##p' "$doc")
  # The fragment before the first `---` holds only the file's header comment.
  [ -n "$name" ] || continue
  out=$($DOCKER run --rm --user "$(id -u):$(id -g)" --tmpfs /home/cli -e HOME=/home/cli \
          -v "$WORK_DIR":/w:ro "$KYVERNO_CLI_IMAGE" \
          apply /w/policy.yaml --resource "/w/${doc##*/}" --remove-color 2>&1) && rc=0 || rc=$?
  if [ -n "$expected" ]; then
    denied=$((denied + 1))
    if [ "$expected" != "$POLICY" ]; then
      fail "$name expects $expected, but this runner loads only $POLICY"
    elif [ "$rc" -ne 0 ] && grep -qF "policy $POLICY -> resource $ns/Pod/$name failed" <<<"$out" \
         && grep -q 'fail: 1, warn: 0, error: 0' <<<"$out"; then
      pass "$name ($ns) refused by $POLICY"
    else
      fail "$name ($ns) was not refused by $POLICY (rc=$rc)"; printf '%s\n' "$out" | grep -v deprecated | tail -8 >&2
    fi
  elif [ "$admit" = '"true"' ] || [ "$admit" = true ]; then
    admitted=$((admitted + 1))
    if [ "$rc" -eq 0 ] && grep -qE 'pass: [1-9][0-9]*, fail: 0, warn: 0, error: 0' <<<"$out"; then
      pass "$name ($ns) admitted: evaluated by $POLICY and passed"
    else
      fail "$name ($ns) was not admitted (or not evaluated) by $POLICY (rc=$rc)"; printf '%s\n' "$out" | grep -v deprecated | tail -8 >&2
    fi
  else
    fail "$name carries neither expect-policy nor expect-admitted"
  fi
done

# A manifest that lost its annotations would otherwise pass with nothing judged.
[ "$denied" -ge 4 ] || fail "expected at least 4 Pods to be refused, found $denied"
[ "$admitted" -ge 2 ] || fail "expected at least 2 Pods to be admitted, found $admitted"

step "result"
if [ "$failures" -ne 0 ]; then
  printf '  %s assertion(s) failed\n' "$failures" >&2
  exit 1
fi
printf '  admission offline checks: ok\n'
