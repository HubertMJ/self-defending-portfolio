#!/usr/bin/env bash
# Phase 4's Definition of Done, as an executable assertion: an interactive shell opened in a pod by
# `kubectl exec -it` produces a Falco alert, and Falco Talon kills the pod (ADR 0013).
#
# Unlike tests/admission/run.sh this creates real Pods: short-lived victims in `sandbox`, the namespace
# Talon is allowed to act in and nowhere else. Each victim is deleted on exit, whatever happens.
#
#   KUBECONFIG=... tests/runtime/run.sh          (or: make runtime-test)
#   KUBECTL="kubectl --kubeconfig ..." tests/runtime/run.sh
#
# Cases:
#   1. DoD:     `kubectl exec -it <victim> -- sh`  -> Falco "Terminal shell in container" -> Falcosidekick
#               -> Talon kubernetes:terminate -> the pod is gone; prints the time to kill.
#   2. Isolate: `kubectl exec <victim> -- wget ...` -> Falco "SDP network tool in sandbox" -> Talon labels
#               the pod sdp.hubertjablon.ski/quarantine=true -> the quarantine CiliumClusterwideNetworkPolicy
#               cuts it off: a DNS lookup that worked before now fails, and the pod is still Running.
#   3. Least privilege: what Talon's ServiceAccount may and may not do, via `kubectl auth can-i`.
#
# Needs `script` (util-linux) on the machine running it: `kubectl exec -it` only allocates a TTY when its
# own stdin is one, and "Terminal shell in container" is exactly the rule that requires a TTY.
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT=$(cd ../.. && pwd)

KUBECTL=${KUBECTL:-kubectl}
NAMESPACE=sandbox
TALON_SA=system:serviceaccount:falco-response:falco-talon
# How long each asynchronous step may take before it counts as a failure (seconds).
KILL_TIMEOUT=${KILL_TIMEOUT:-30}
# Talon labels the pod within seconds of the alert.
LABEL_TIMEOUT=${LABEL_TIMEOUT:-20}
# The label takes effect only once Cilium has moved the pod to a new security identity: it allocates
# the identity (a CiliumIdentity object, CRD mode), waits identity-change-grace-period (5 s by default)
# and regenerates the endpoint's policy. That is seconds to tens of seconds, measured and printed below
# (ADR 0013, correction). 60 s is the bound beyond which it counts as a failure, not a typical value.
ISOLATE_TIMEOUT=${ISOLATE_TIMEOUT:-60}

WORK_DIR=$(mktemp -d)
PODS=()
cleanup() {
  for pod in "${PODS[@]}"; do
    $KUBECTL -n "$NAMESPACE" delete pod "$pod" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  done
  [ -z "${EXEC_PID:-}" ] || kill "$EXEC_PID" 2>/dev/null || true
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

failures=0
step() { printf '\n==> %s\n' "$*"; }
pass() { printf '  PASS  %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*" >&2; failures=$((failures + 1)); }
die() { printf 'run.sh: %s\n' "$*" >&2; exit 1; }

# Polls a command until it succeeds or `timeout` seconds have passed. Returns the command's status.
poll() {
  local timeout=$1; shift
  local deadline=$((SECONDS + timeout))
  until "$@" >/dev/null 2>&1; do
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep 1
  done
}

# Creates a victim from victim-pod.yaml and waits for it to be Ready.
new_victim() {
  local name=$1
  sed -e "s#__NAME__#$name#" -e "s#__IMAGE__#$IMAGE#" victim-pod.yaml > "$WORK_DIR/$name.yaml"
  PODS+=("$name")
  $KUBECTL apply -f "$WORK_DIR/$name.yaml" >/dev/null
  $KUBECTL -n "$NAMESPACE" wait --for=condition=Ready "pod/$name" --timeout=90s >/dev/null \
    || die "victim $name did not become Ready (image pull, admission or scheduling problem?)"
}

suffix() { tr -dc 'a-z0-9' </dev/urandom | head -c 5 || true; }

# ---------------------------------------------------------------------------- preflight
#
# A missing component looks exactly like a rule that did not fire, so each one is checked first and
# named in the error.

step "preflight"

command -v script >/dev/null || die "the 'script' command (util-linux) is required for a real TTY"

$KUBECTL -n falco rollout status ds/falco --timeout=60s >/dev/null || die "Falco DaemonSet is not ready"
pass "Falco DaemonSet is ready"
$KUBECTL -n falco-response rollout status deploy/falcosidekick --timeout=60s >/dev/null \
  || die "Falcosidekick is not ready"
pass "Falcosidekick is ready"
$KUBECTL -n falco-response rollout status deploy/falco-talon --timeout=60s >/dev/null \
  || die "Falco Talon is not ready"
pass "Falco Talon is ready"

# Talon only processes events once a leader holds its Lease (ADR 0013); without that it accepts the
# POSTs and does nothing, which would look like a rule mismatch.
holder=$($KUBECTL -n falco-response get lease falco-talon -o jsonpath='{.spec.holderIdentity}' 2>/dev/null || true)
[ -n "$holder" ] || die "Lease falco-response/falco-talon has no holder; is Talon's lease RBAC in place?"
pass "Talon holds Lease falco-response/falco-talon ($holder)"

$KUBECTL get namespace "$NAMESPACE" >/dev/null 2>&1 || die "namespace $NAMESPACE does not exist; is the sandbox Application synced?"
$KUBECTL get ciliumclusterwidenetworkpolicy quarantine >/dev/null 2>&1 \
  || die "CiliumClusterwideNetworkPolicy quarantine does not exist; is the sandbox Application synced?"
pass "namespace $NAMESPACE and the quarantine policy exist"

# The victim image is the signed digest hello runs, so it passes verify-portfolio-images in `sandbox`.
digest=$(sed -n 's/^[[:space:]]*digest:[[:space:]]*//p' "$REPO_ROOT/cluster/infra/hello/kustomization.yaml" | head -1)
name=$(sed -n 's/^[[:space:]]*- name:[[:space:]]*//p' "$REPO_ROOT/cluster/infra/hello/kustomization.yaml" | head -1)
{ [ -n "$digest" ] && [ -n "$name" ]; } || die "could not read the signed image from cluster/infra/hello/kustomization.yaml"
IMAGE="$name@$digest"
pass "victim image $IMAGE"

# ---------------------------------------------------------------------------- case 1: the DoD

step "case 1: an interactive shell in a sandbox pod gets the pod killed"

shell_pod="rt-shell-$(suffix)"
new_victim "$shell_pod"
uid=$($KUBECTL -n "$NAMESPACE" get pod "$shell_pod" -o jsonpath='{.metadata.uid}')
t0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
start=$SECONDS

# `script` gives kubectl a pseudo-terminal, so `-it` really allocates a TTY in the container and the
# shell runs with proc.tty != 0. The shell would live for a minute; Talon is expected to end it first.
script -qec "$KUBECTL exec -it -n $NAMESPACE $shell_pod -- sh -c 'id; sleep 60'" /dev/null \
  >"$WORK_DIR/exec.log" 2>&1 &
EXEC_PID=$!

if $KUBECTL -n "$NAMESPACE" wait --for=delete "pod/$shell_pod" --timeout="${KILL_TIMEOUT}s" >/dev/null 2>&1; then
  pass "pod $shell_pod (uid $uid) deleted $((SECONDS - start)) s after the exec started"
else
  current=$($KUBECTL -n "$NAMESPACE" get pod "$shell_pod" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)
  fail "pod $shell_pod still exists after ${KILL_TIMEOUT}s (uid now: ${current:-gone})"
fi
kill "$EXEC_PID" 2>/dev/null || true
wait "$EXEC_PID" 2>/dev/null || true
EXEC_PID=

# The evidence chain, each link on its own so a failure names the broken one.
if $KUBECTL -n falco logs ds/falco --since-time="$t0" 2>/dev/null \
   | grep 'Terminal shell in container' | grep -q "$shell_pod"; then
  pass "Falco alerted: Terminal shell in container ($shell_pod)"
else
  fail "no 'Terminal shell in container' alert naming $shell_pod in the Falco log since $t0"
fi

if $KUBECTL -n falco-response logs deploy/falcosidekick --since-time="$t0" 2>/dev/null \
   | grep -Eq 'Talon - POST OK \(2[0-9][0-9]\)'; then
  pass "Falcosidekick forwarded to Talon (POST OK)"
else
  fail "no successful POST to Talon in the Falcosidekick log since $t0"
fi

# Talon's log is the record of its actions (no Kubernetes Events in 0.3.0, ADR 0013 correction): one
# successful kubernetes:terminate line naming the pod. Talon is configured for JSON lines
# ("status":"success"); the text form (status=success) and ANSI colour codes are tolerated too, so the
# assertion does not depend on the log format.
talon_log() {
  $KUBECTL -n falco-response logs deploy/falco-talon --since-time="$t0" 2>/dev/null \
    | sed 's/\x1b\[[0-9;]*m//g'
}
if talon_log | grep 'kubernetes:terminate' | grep -E '"status":"success"|status=success' \
   | grep -q "$shell_pod"; then
  pass "Talon logged a successful kubernetes:terminate for $shell_pod"
else
  fail "no successful kubernetes:terminate line for $shell_pod in the Talon log since $t0"
fi

# ---------------------------------------------------------------------------- case 2: isolation

step "case 2: a network tool in a sandbox pod gets the pod quarantined"

iso_pod="rt-iso-$(suffix)"
new_victim "$iso_pod"

lookup() { $KUBECTL -n "$NAMESPACE" exec "$iso_pod" -- nslookup kubernetes.default.svc.cluster.local.; }

# The sandbox allows DNS and nothing else; proving the lookup works first is what makes "it fails
# later" mean "quarantined" rather than "never had network".
if poll 30 lookup; then
  pass "$iso_pod can resolve names before the trigger"
else
  die "$iso_pod cannot resolve names even before the trigger; check the sandbox-dns-only policy"
fi

# The trigger is the exec of `wget` (Falco sees the process start), not the transfer, which the
# sandbox policy blocks anyway. No TTY here, so the shell rule of case 1 does not fire.
$KUBECTL -n "$NAMESPACE" exec "$iso_pod" -- wget -q -T 2 -O /dev/null http://kubernetes.default.svc.cluster.local/ \
  >/dev/null 2>&1 || true

labelled() {
  [ "$($KUBECTL -n "$NAMESPACE" get pod "$iso_pod" -o jsonpath='{.metadata.labels.sdp\.hubertjablon\.ski/quarantine}')" = true ]
}
if poll "$LABEL_TIMEOUT" labelled; then
  pass "$iso_pod labelled sdp.hubertjablon.ski/quarantine=true"
else
  fail "$iso_pod was not labelled quarantine=true within ${LABEL_TIMEOUT}s"
fi

phase=$($KUBECTL -n "$NAMESPACE" get pod "$iso_pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)
if [ "$phase" = Running ]; then
  pass "$iso_pod is still Running (isolated, not killed)"
else
  fail "$iso_pod is ${phase:-gone}, expected Running"
fi

lookup_fails() { ! lookup; }
label_seen=$SECONDS
if poll "$ISOLATE_TIMEOUT" lookup_fails; then
  pass "$iso_pod can no longer resolve names (quarantine in effect $((SECONDS - label_seen)) s after the label)"
else
  fail "$iso_pod can still resolve names ${ISOLATE_TIMEOUT}s after the label"
fi

# ---------------------------------------------------------------------------- case 3: least privilege

step "case 3: Talon's ServiceAccount can act in sandbox and nowhere else"

can() { [ "$($KUBECTL auth can-i "$@" --as="$TALON_SA" 2>/dev/null || true)" = yes ]; }

expect_yes() { if can "$@"; then pass "can $*"; else fail "cannot $* (needed)"; fi; }
expect_no() { if can "$@"; then fail "CAN $* (must not)"; else pass "cannot $*"; fi; }

expect_yes delete pods -n sandbox
expect_yes patch pods -n sandbox
expect_no delete pods -n hello
expect_no delete pods -n kube-system
expect_no get secrets -n sandbox
expect_no create pods/exec -n sandbox
expect_no get namespaces/hello
expect_no get namespaces/sandbox
expect_no create events -n sandbox

# ---------------------------------------------------------------------------- result

step "result"
if [ "$failures" -ne 0 ]; then
  printf '  %s assertion(s) failed\n' "$failures" >&2
  exit 1
fi
printf '  runtime tests: ok\n'
