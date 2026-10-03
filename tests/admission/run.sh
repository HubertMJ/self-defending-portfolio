#!/usr/bin/env bash
# Phase 3's Definition of Done, as an executable assertion: an image this project's workflow did not
# sign does not get into the cluster. Since phase 4 (plan commit 9, ADR 0012) also: a privileged Pod
# and a Pod without requests and limits do not get in either (workload-policy-pods.yaml, in `default`).
# Since ADR 0031 also: a Pod in `sandbox` or `sandbox-unguarded` without a deadline of at most 120 s does
# not get in, and one at 120 s does (sandbox-deadline-pods.yaml; its offline twin is ./offline.sh).
#
# Everything here is `kubectl apply --dry-run=server`, which runs the full admission chain -- the
# built-in Pod Security admission plugin and then Kyverno's webhook -- and discards the object. No Pod
# is ever scheduled, no image is ever pulled, and the script is safe to run against the live cluster.
#
# Each test Pod declares which policy is expected to reject it in the annotation
# tests.hubertjablon.ski/expect-policy, so this script needs no table of its own and a new case is a
# new Pod document in one of the manifests. A Pod annotated tests.hubertjablon.ski/expect-admitted: "true"
# must instead be admitted. `image: SCENARIO_IMAGE` in a manifest is replaced by the scenario image
# pinned in cluster/infra/sandbox/scenarios/scenarios.yaml (signed by the build workflow), or by
# $SCENARIO_IMAGE when set.
#
#   KUBECONFIG=... tests/admission/run.sh
#   KUBECONFIG=... SIGNED_IMAGE=ghcr.io/hubertmj/self-defending-portfolio/web@sha256:... tests/admission/run.sh
#
# With SIGNED_IMAGE set, the script also asserts the other half of the claim: a correctly signed
# digest reference is admitted. Without it, that check is skipped and said so -- a signed digest only
# exists once the build workflow has run, so the negative tests have to be runnable on their own.
set -euo pipefail

cd "$(dirname "$0")"

KUBECTL=${KUBECTL:-kubectl}
NAMESPACE=${NAMESPACE:-hello}
MANIFESTS=(unsigned-pod.yaml latest-pod.yaml workload-policy-pods.yaml sandbox-deadline-pods.yaml)
SCENARIO_IMAGE=${SCENARIO_IMAGE:-$(sed -n 's/^ *image: &scenario-image //p' ../../cluster/infra/sandbox/scenarios/scenarios.yaml)}

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

failures=0
step() { printf '\n==> %s\n' "$*"; }
pass() { printf '  PASS  %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*" >&2; failures=$((failures + 1)); }

# ---------------------------------------------------------------------------- preflight
#
# Without these two checks a missing controller or a policy still in Audit looks identical to a policy
# that failed to reject -- the apply simply succeeds -- and the error message would send the reader
# looking for a bug in the policy instead of at the thing that is actually not set up yet.

step "preflight"

$KUBECTL get namespace "$NAMESPACE" >/dev/null 2>&1 \
  || { echo "run.sh: namespace $NAMESPACE does not exist; is the hello Application synced?" >&2; exit 1; }
for ns in sandbox sandbox-unguarded; do
  $KUBECTL get namespace "$ns" >/dev/null 2>&1 \
    || { echo "run.sh: namespace $ns does not exist; are the sandbox Applications synced?" >&2; exit 1; }
done
case "$SCENARIO_IMAGE" in
  *@sha256:*) ;;
  *) echo "run.sh: no scenario image digest for the sandbox Pods (set SCENARIO_IMAGE=name@sha256:...)" >&2; exit 1 ;;
esac

if ! $KUBECTL -n kyverno rollout status deploy/kyverno-admission-controller --timeout=60s >/dev/null 2>&1; then
  echo "run.sh: the Kyverno admission controller is not ready; nothing below would be meaningful" >&2
  exit 1
fi
pass "kyverno admission controller is ready"

# The policy names the test Pods expect to be rejected by, de-duplicated.
mapfile -t EXPECTED_POLICIES < <(
  sed -n 's#^[[:space:]]*tests\.hubertjablon\.ski/expect-policy:[[:space:]]*##p' "${MANIFESTS[@]}" | sort -u
)
[ "${#EXPECTED_POLICIES[@]}" -gt 0 ] || { echo "run.sh: no expect-policy annotations found" >&2; exit 1; }

for policy in "${EXPECTED_POLICIES[@]}"; do
  if ! $KUBECTL get clusterpolicy "$policy" >/dev/null 2>&1; then
    echo "run.sh: ClusterPolicy $policy is not installed; is the kyverno-policies Application synced?" >&2
    exit 1
  fi
  # A rule in Audit records the violation in a PolicyReport and admits the Pod, so it can never make
  # the assertions below pass. Say that plainly rather than letting it look like a policy that does
  # not match. See the "phase N switch" comment at the top of each policy file.
  actions=$(
    $KUBECTL get clusterpolicy "$policy" \
      -o jsonpath='{range .spec.rules[*]}{.validate.failureAction}{" "}{.verifyImages[*].failureAction}{" "}{end}'
  )
  if grep -qw Audit <<<"$actions"; then
    echo "run.sh: ClusterPolicy $policy still has a rule in Audit (actions: $actions)." >&2
    echo "        Flip it to Enforce first -- docs/bootstrap.md, \"Phase 3\" / \"6.4\"." >&2
    exit 1
  fi
  pass "ClusterPolicy $policy is installed and enforcing"
done

# ---------------------------------------------------------------------------- the denials
#
# Split every manifest into single-document files so each Pod is applied, and judged, on its own: a
# multi-document apply reports only the first rejection and would hide a second policy that silently
# stopped working.

step "every unsigned, foreign, mutable-tag or unbounded Pod is rejected; a bounded sandbox Pod is admitted"

doc_count=0
admitted_count=0
for manifest in "${MANIFESTS[@]}"; do
  awk -v out="$WORK_DIR" -v base="${manifest%.yaml}" '
    /^---[[:space:]]*$/ { n++; next }
    { print > (out "/" base "." n ".yaml") }
  ' n=0 "$manifest"
done
sed -i "s#SCENARIO_IMAGE#$SCENARIO_IMAGE#" "$WORK_DIR"/*.yaml

for doc in "$WORK_DIR"/*.yaml; do
  expected=$(sed -n 's#^[[:space:]]*tests\.hubertjablon\.ski/expect-policy:[[:space:]]*##p' "$doc")
  name=$(sed -n 's/^  name:[[:space:]]*//p' "$doc" | head -1)
  if grep -qE '^[[:space:]]*tests\.hubertjablon\.ski/expect-admitted:[[:space:]]*"?true"?$' "$doc"; then
    # The other half of a bound: at the limit, the whole chain admits it. A dry run still counts
    # against the namespace's ResourceQuota, so a full sandbox refuses it with a quota message.
    admitted_count=$((admitted_count + 1))
    if output=$($KUBECTL apply --dry-run=server -f "$doc" 2>&1); then
      pass "$name admitted"
    else
      fail "$name was REJECTED; it should have been admitted"
      printf '        %s\n' "$output"
    fi
    continue
  fi
  # awk emits a file per inter-document gap, so a leading `---` leaves one fragment holding only the
  # file's header comment. No annotation, nothing to assert.
  [ -n "$expected" ] || continue
  doc_count=$((doc_count + 1))

  if output=$($KUBECTL apply --dry-run=server -f "$doc" 2>&1); then
    fail "$name was ADMITTED; $expected should have rejected it"
    printf '        %s\n' "$output"
  elif grep -q "$expected" <<<"$output"; then
    pass "$name rejected by $expected"
  else
    fail "$name was rejected, but the message does not name $expected"
    printf '        %s\n' "$output"
  fi
done

[ "$doc_count" -ge 9 ] || fail "expected at least 9 test Pods, found $doc_count (did a manifest lose its annotation?)"
[ "$admitted_count" -ge 2 ] || fail "expected at least 2 Pods to be admitted, found $admitted_count"

# ---------------------------------------------------------------------------- the admission
#
# A policy that rejects everything is not a working policy, it is an outage. This is the half of the
# claim that proves the gate has a hole exactly where it should.

step "a signed digest reference is admitted"

if [ -z "${SIGNED_IMAGE:-}" ]; then
  printf '  SKIP  SIGNED_IMAGE is not set; run the build workflow first, then:\n'
  printf '          SIGNED_IMAGE=ghcr.io/hubertmj/self-defending-portfolio/web@sha256:... %s\n' "$0"
else
  case "$SIGNED_IMAGE" in
    *@sha256:*) ;;
    *)
      echo "run.sh: SIGNED_IMAGE must be a digest reference (name@sha256:...), not a tag." >&2
      echo "        A tag would be mutated to a digest by the policy, so the test would not be" >&2
      echo "        asserting what it looks like it asserts." >&2
      exit 1
      ;;
  esac

  cat > "$WORK_DIR/signed-pod.yaml" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: admission-test-signed
  namespace: $NAMESPACE
  labels:
    app.kubernetes.io/name: admission-test
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    runAsGroup: 65534
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: probe
      image: $SIGNED_IMAGE
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        requests:
          cpu: 10m
          memory: 16Mi
        limits:
          memory: 32Mi
YAML

  if output=$($KUBECTL apply --dry-run=server -f "$WORK_DIR/signed-pod.yaml" 2>&1); then
    pass "admission-test-signed admitted ($SIGNED_IMAGE)"
  else
    fail "a signed digest reference was REJECTED; the gate has no hole where it needs one"
    printf '        %s\n' "$output"
  fi
fi

step "result"
if [ "$failures" -ne 0 ]; then
  printf '  %s assertion(s) failed\n' "$failures" >&2
  exit 1
fi
printf '  admission tests: ok\n'
