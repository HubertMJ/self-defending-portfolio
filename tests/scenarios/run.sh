#!/usr/bin/env bash
# Phase 5's scenario contract, as an executable assertion against the live cluster (ADR 0017, ADR 0018):
# for every attack scenario in ConfigMap `scenarios`, creating the pod the way the portfolio API does
# and running the scenario's exec produces the Falco alert the scenario names, the Falco Talon action it
# promises, and the end state that action implies.
#
#   KUBECONFIG=... tests/scenarios/run.sh                  (or: make scenario-test)
#   KUBECTL="kubectl --kubeconfig ..." tests/scenarios/run.sh
#   ONLY=network-tool tests/scenarios/run.sh               one scenario
#   ISOLATE_TIMEOUT=90 tests/scenarios/run.sh             longer bound for the quarantine to bite
#   SCENARIO_IMAGE=ghcr.io/hubertmj/self-defending-portfolio/scenario@sha256:... tests/scenarios/run.sh
#
# Scenarios come from the live ConfigMap (portfolio-api/scenarios), which is what the API executes; if it
# is not deployed yet, from cluster/infra/sandbox/scenarios/scenarios.yaml, and the script says so.
# SCENARIO_IMAGE replaces the image of every scenario pod (a digest reference, signed by this project's
# workflow, or Kyverno rejects the pod) - useful before the placeholder digest has been bumped.
#
# Per scenario, like the API: a Pod in `sandbox` from the scenario's PodSpec, with labels
# sdp.hubertjablon.ski/run-id and sdp.hubertjablon.ski/quarantine: "false" and activeDeadlineSeconds =
# timeout_seconds; wait for Ready; run `pre_exec.command`, if any, to completion without a TTY, as the
# API does (ADR 0022); run `exec.command` in container `target` (through `script` for a
# real TTY when exec.tty is true); then, within timeout_seconds:
#   terminate  -> the pod is deleted (by Talon, not by its deadline), Falco logged `detection` for it,
#                 Talon logged a successful kubernetes:terminate for it;
#   quarantine -> the pod is labelled quarantine=true and still Running, Falco logged `detection`,
#                 Talon logged a successful kubernetes:label for it, and a DNS lookup that worked
#                 before now fails.
# Talon's log is its record of an action: Talon 0.3.0 writes no Kubernetes Events here (its k8sevents
# notifier is off, ADR 0013 correction), and its JSON log line carries the actionner, the status and
# the pod, as tests/runtime/run.sh asserts.
# Every pod is deleted at the end of its case and on exit, whatever happens.
#
# Needs python3 with PyYAML (to read the scenario list; `make validate` needs it too) and `script`
# (util-linux) for the TTY scenario, as tests/runtime/run.sh does.
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT=$(cd ../.. && pwd)

KUBECTL=${KUBECTL:-kubectl}
NAMESPACE=sandbox
ONLY=${ONLY:-}
SCENARIO_IMAGE=${SCENARIO_IMAGE:-}
PLACEHOLDER_DIGEST=sha256:0000000000000000000000000000000000000000000000000000000000000000
# Label-to-isolation bound (FIX 1, ADR 0032). Since the per-run labels were taken out of the Cilium
# identity and the identity-change grace period was dropped to 500 ms, a quarantine is a label flip on
# an identity Cilium already knows, so the cut lands in well under 3 s instead of the 22-36 s measured
# before. QUARANTINE_BOUND is the pass/fail threshold for that cut, measured the way the API measures
# it: an API-identity pod polling the victim's /state.json on :8080 (see probe_victim below), which is
# exactly what the page shows going "unreachable". DNS egress (the old proof) is still checked as
# corroboration, with its own looser bound.
QUARANTINE_BOUND=${QUARANTINE_BOUND:-3}
ISOLATE_TIMEOUT=${ISOLATE_TIMEOUT:-30}
# The API lives here; its pods are the only ones the sandbox victim policy admits to :8080. The probe
# pod runs in this namespace with the API's app label so Cilium gives it the API's identity and its
# :8080 egress, and the victim policy admits it (cluster/infra/sandbox/ciliumnetworkpolicy-victim.yaml).
API_NAMESPACE=${API_NAMESPACE:-portfolio-api}

WORK_DIR=$(mktemp -d)
PODS=()
PROBE_POD=
EXEC_PID=
cleanup() {
  [ -z "$EXEC_PID" ] || kill "$EXEC_PID" 2>/dev/null || true
  for pod in "${PODS[@]}"; do
    $KUBECTL -n "$NAMESPACE" delete pod "$pod" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  done
  [ -z "$PROBE_POD" ] || $KUBECTL -n "$API_NAMESPACE" delete pod "$PROBE_POD" --ignore-not-found --wait=false >/dev/null 2>&1 || true
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

suffix() { tr -dc 'a-z0-9' </dev/urandom | head -c 5 || true; }

# The API polls the victim by dialling the pod IP on :8080 and reading /state.json (ADR 0021/0022).
# These two helpers do the same from a throwaway pod that carries the API's identity, so the quarantine
# is measured where the visitor sees it (the shop going unreachable), not only on the victim's egress.
ensure_probe_pod() {
  [ -z "$PROBE_POD" ] || return 0
  PROBE_POD="sdp-probe-$(suffix)"
  # A restricted pod in the API namespace with the API's app label: enough identity for the victim
  # policy to admit it on :8080, and it passes pod-security-restricted and require-pod-resources there.
  # The scenario image (busybox wget, signed) is the one image that namespace's Kyverno gate accepts.
  cat <<YAML | $KUBECTL apply -f - >/dev/null || die "probe pod $PROBE_POD was not admitted in $API_NAMESPACE"
apiVersion: v1
kind: Pod
metadata:
  name: $PROBE_POD
  namespace: $API_NAMESPACE
  labels:
    app.kubernetes.io/name: portfolio-api
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  enableServiceLinks: false
  terminationGracePeriodSeconds: 0
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: probe
      image: $SCENARIO_PROBE_IMAGE
      command: ["sleep", "600"]
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
          cpu: 100m
          memory: 32Mi
YAML
  $KUBECTL -n "$API_NAMESPACE" wait --for=condition=Ready "pod/$PROBE_POD" --timeout=60s >/dev/null 2>&1 \
    || die "probe pod $PROBE_POD did not become Ready in $API_NAMESPACE"
}

# probe_victim <victim-pod>: GET the victim's /state.json the way the API does. 0 iff it answers.
probe_victim() {
  local ip
  ip=$($KUBECTL -n "$NAMESPACE" get pod "$1" -o jsonpath='{.status.podIP}' 2>/dev/null) || return 1
  [ -n "$ip" ] || return 1
  $KUBECTL -n "$API_NAMESPACE" exec "$PROBE_POD" -c probe -- \
    wget -q -T 1 -O- "http://$ip:8080/state.json" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------- preflight
#
# A missing component looks exactly like a rule that did not fire, so each one is checked first and
# named in the error (same checks as tests/runtime/run.sh).

step "preflight"

python3 -c 'import yaml' 2>/dev/null || die "python3 with PyYAML is required"

$KUBECTL -n falco rollout status ds/falco --timeout=60s >/dev/null || die "Falco DaemonSet is not ready"
pass "Falco DaemonSet is ready"
$KUBECTL -n falco-response rollout status deploy/falcosidekick --timeout=60s >/dev/null \
  || die "Falcosidekick is not ready"
pass "Falcosidekick is ready"
$KUBECTL -n falco-response rollout status deploy/falco-talon --timeout=60s >/dev/null \
  || die "Falco Talon is not ready"
pass "Falco Talon is ready"
holder=$($KUBECTL -n falco-response get lease falco-talon -o jsonpath='{.spec.holderIdentity}' 2>/dev/null || true)
[ -n "$holder" ] || die "Lease falco-response/falco-talon has no holder; is Talon's lease RBAC in place?"
pass "Talon holds Lease falco-response/falco-talon ($holder)"

$KUBECTL get namespace "$NAMESPACE" >/dev/null 2>&1 || die "namespace $NAMESPACE does not exist; is the sandbox Application synced?"
$KUBECTL get ciliumclusterwidenetworkpolicy quarantine >/dev/null 2>&1 \
  || die "CiliumClusterwideNetworkPolicy quarantine does not exist; is the sandbox Application synced?"
$KUBECTL -n "$NAMESPACE" get resourcequota sandbox >/dev/null 2>&1 \
  || die "ResourceQuota sandbox/sandbox does not exist; is the sandbox Application synced?"
pass "namespace $NAMESPACE, its quota and the quarantine policy exist"

# The scenario list: the live ConfigMap if there is one (what the API runs), else the repository's.
if $KUBECTL -n portfolio-api get configmap scenarios -o jsonpath='{.data.scenarios\.yaml}' \
     > "$WORK_DIR/scenarios.yaml" 2>/dev/null && [ -s "$WORK_DIR/scenarios.yaml" ]; then
  pass "scenarios from ConfigMap portfolio-api/scenarios"
else
  cp "$REPO_ROOT/cluster/infra/sandbox/scenarios/scenarios.yaml" "$WORK_DIR/scenarios.yaml"
  pass "scenarios from cluster/infra/sandbox/scenarios/scenarios.yaml (ConfigMap portfolio-api/scenarios not deployed)"
fi

if [ -n "$SCENARIO_IMAGE" ]; then
  case "$SCENARIO_IMAGE" in *@sha256:*) ;; *) die "SCENARIO_IMAGE must be a digest reference (name@sha256:...)" ;; esac
  pass "scenario image overridden: $SCENARIO_IMAGE"
elif grep -q "$PLACEHOLDER_DIGEST" "$WORK_DIR/scenarios.yaml"; then
  die "the scenario image digest is still the placeholder; bump it in scenarios.yaml after the first build, or set SCENARIO_IMAGE"
fi

# The image the :8080 probe pod runs: the override, or the scenario image from the catalogue (its
# `target` container). The same signed image the scenarios use, so the API namespace's Kyverno gate
# admits the probe.
if [ -n "$SCENARIO_IMAGE" ]; then
  SCENARIO_PROBE_IMAGE=$SCENARIO_IMAGE
else
  SCENARIO_PROBE_IMAGE=$(python3 - "$WORK_DIR/scenarios.yaml" <<'PY'
import sys, yaml
for s in yaml.safe_load(open(sys.argv[1])):
    for c in s["pod"]["containers"]:
        if c.get("name") == "target":
            print(c["image"]); raise SystemExit
PY
)
fi
[ -n "$SCENARIO_PROBE_IMAGE" ] || die "could not determine the scenario image for the :8080 probe pod"

# One TSV line per scenario plus a Pod manifest per scenario, built exactly as the API builds it.
python3 - "$WORK_DIR" "$SCENARIO_IMAGE" "$ONLY" <<'PY' > "$WORK_DIR/plan.tsv"
import json, secrets, shlex, sys, yaml
work, image, only = sys.argv[1], sys.argv[2], sys.argv[3]
for s in yaml.safe_load(open(f"{work}/scenarios.yaml")):
    if only and s["id"] != only:
        continue
    run_id = "test-" + secrets.token_hex(3)
    name = f"sc-{s['id']}-{run_id[5:]}"
    spec = s["pod"]
    if image:
        for c in spec["containers"] + spec.get("initContainers", []):
            c["image"] = image
    spec["activeDeadlineSeconds"] = s["timeout_seconds"]
    pod = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": name, "namespace": "sandbox",
                        "labels": {"sdp.hubertjablon.ski/run-id": run_id,
                                   "sdp.hubertjablon.ski/quarantine": "false"}},
           "spec": spec}
    json.dump(pod, open(f"{work}/{name}.json", "w"))
    exec_ = s.get("exec") or {"command": [], "tty": False}
    print("\t".join([s["id"], name, s["detection"], s["response"], str(s["timeout_seconds"]),
                     str(exec_["tty"]).lower(),
                     shlex.join(s["pre_exec"]["command"]) if s.get("pre_exec") else "-",
                     shlex.join(exec_["command"])]))
PY
[ -s "$WORK_DIR/plan.tsv" ] || die "no scenario matched${ONLY:+ ONLY=$ONLY}"
if grep -q $'\ttrue\t' "$WORK_DIR/plan.tsv"; then
  command -v script >/dev/null || die "the 'script' command (util-linux) is required for a real TTY"
fi

# ---------------------------------------------------------------------------- the scenarios

# Starts the exec in the background, as the API would; a TTY exec goes through `script` so kubectl
# really allocates one (`kubectl exec -it` only does when its own stdin is a terminal).
start_exec() {
  local pod=$1 tty=$2 cmd=$3
  if [ "$tty" = true ]; then
    script -qec "$KUBECTL exec -it -n $NAMESPACE $pod -c target -- $cmd" /dev/null >"$WORK_DIR/$pod.exec.log" 2>&1 &
  else
    eval "$KUBECTL exec -n $NAMESPACE $pod -c target -- $cmd" </dev/null >"$WORK_DIR/$pod.exec.log" 2>&1 &
  fi
  EXEC_PID=$!
}
stop_exec() {
  [ -z "$EXEC_PID" ] || { kill "$EXEC_PID" 2>/dev/null || true; wait "$EXEC_PID" 2>/dev/null || true; }
  EXEC_PID=
}

falco_alerted() { # rule, pod, since
  $KUBECTL -n falco logs ds/falco --since-time="$3" 2>/dev/null | grep -F "\"rule\":\"$1\"" | grep -qF "$2"
}
# Talon logs JSON lines (talon/config.yaml); the text form and ANSI colours are tolerated, as in
# tests/runtime/run.sh, so the assertion does not depend on the log format. A notification line (the
# webhook to the API) carries the actionner and a status but no pod, so it cannot match on its own.
talon_acted() { # actionner, pod, since
  $KUBECTL -n falco-response logs deploy/falco-talon --since-time="$3" 2>/dev/null \
    | sed 's/\x1b\[[0-9;]*m//g' | grep -F "$1" | grep -E '"status":"success"|status=success' | grep -qF "$2"
}

# The plan is read on fd 3: `script` and kubectl must not swallow it from stdin.
while IFS=$'\t' read -r -u 3 id pod detection response timeout tty pre cmd; do
  step "$id: '$detection' -> $response (timeout ${timeout}s)"

  PODS+=("$pod")
  $KUBECTL apply -f "$WORK_DIR/$pod.json" >/dev/null || { fail "$id: pod $pod was not admitted"; continue; }
  if ! $KUBECTL -n "$NAMESPACE" wait --for=condition=Ready "pod/$pod" --timeout=60s >/dev/null 2>&1; then
    fail "$id: pod $pod did not become Ready (image pull, admission or scheduling problem?)"
    continue
  fi
  pass "$id: pod $pod admitted and Ready"

  if [ "$response" = quarantine ]; then
    lookup() { $KUBECTL -n "$NAMESPACE" exec "$pod" -c target -- nslookup kubernetes.default.svc.cluster.local.; }
    # Proving the lookup works first is what makes "it fails later" mean "quarantined".
    if poll 30 lookup; then pass "$id: $pod can resolve names before the attack"
    else fail "$id: $pod cannot resolve names even before the attack; check sandbox-dns-only"; continue; fi
    # The API's view: an API-identity pod polling the victim's shop on :8080. Proving it answers now
    # is what makes "the probe drops within ${QUARANTINE_BOUND}s of the label" mean the cut landed.
    ensure_probe_pod
    probe_ok() { probe_victim "$pod"; }
    if poll 15 probe_ok; then pass "$id: the API-identity probe reads the shop on :8080 before the attack"
    else fail "$id: the probe cannot reach $pod:8080 even before the attack; check sandbox-victim-from-api"; continue; fi
  fi

  t0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  if [ "$pre" != - ]; then
    # Never with a TTY, to completion; its exit status is not judged, as in the API.
    eval "$KUBECTL exec -n $NAMESPACE $pod -c target -- $pre" </dev/null >"$WORK_DIR/$pod.pre.log" 2>&1 || true
  fi
  start=$SECONDS
  start_exec "$pod" "$tty" "$cmd"

  case $response in
    terminate)
      if $KUBECTL -n "$NAMESPACE" wait --for=delete "pod/$pod" --timeout="${timeout}s" >/dev/null 2>&1; then
        pass "$id: pod deleted $((SECONDS - start)) s after the exec started"
      else
        fail "$id: pod $pod still exists after ${timeout}s"
      fi
      ;;
    quarantine)
      labelled() {
        [ "$($KUBECTL -n "$NAMESPACE" get pod "$pod" -o jsonpath='{.metadata.labels.sdp\.hubertjablon\.ski/quarantine}')" = true ]
      }
      if poll "$timeout" labelled; then pass "$id: labelled quarantine=true $((SECONDS - start)) s after the exec started"
      else fail "$id: not labelled quarantine=true within ${timeout}s"; fi
      phase=$($KUBECTL -n "$NAMESPACE" get pod "$pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)
      if [ "$phase" = Running ]; then pass "$id: still Running (isolated, not killed)"
      else fail "$id: pod is ${phase:-gone}, expected Running"; fi
      # The headline of FIX 1: how long from the label landing until the API's :8080 poll drops - the
      # exact moment the shop goes "unreachable" on the page. Measured in tenths with a 1 s probe
      # timeout; asserted against QUARANTINE_BOUND (3 s, ADR 0032). This is the number the old demo
      # could not show (the pod stayed reachable for tens of seconds).
      label_seen=$(date +%s.%N)
      probe_dropped() { ! probe_victim "$pod"; }
      cut=
      while :; do
        if probe_dropped; then cut=$(awk "BEGIN{printf \"%.1f\", $(date +%s.%N) - $label_seen}"); break; fi
        awk "BEGIN{exit !($(date +%s.%N) - $label_seen > $QUARANTINE_BOUND + 2)}" && break
        sleep 0.2
      done
      if [ -n "$cut" ] && awk "BEGIN{exit !($cut <= $QUARANTINE_BOUND)}"; then
        pass "$id: the shop on :8080 went unreachable ${cut}s after the label (<= ${QUARANTINE_BOUND}s)"
      elif [ -n "$cut" ]; then
        fail "$id: the shop on :8080 took ${cut}s to go unreachable, over the ${QUARANTINE_BOUND}s bound"
      else
        fail "$id: the shop on :8080 was still reachable more than $((QUARANTINE_BOUND + 2))s after the label"
      fi
      # Corroboration on the other direction (egress), with its looser bound: the victim can no longer
      # resolve names either.
      lookup_fails() { ! lookup; }
      label_seen_s=$SECONDS
      if poll "$ISOLATE_TIMEOUT" lookup_fails; then
        pass "$id: can no longer resolve names (egress cut $((SECONDS - label_seen_s)) s after the label)"
      else
        fail "$id: can still resolve names ${ISOLATE_TIMEOUT}s after the label"
      fi
      ;;
    *)
      fail "$id: unknown response '$response'"
      ;;
  esac
  stop_exec

  # The evidence chain, each link on its own so a failure names the broken one. Falco's JSON alert
  # carries the rule name and the pod name (k8s.pod.name output field).
  if poll 10 falco_alerted "$detection" "$pod" "$t0"; then pass "$id: Falco alerted '$detection' for $pod"
  else fail "$id: no '$detection' alert naming $pod in the Falco log since $t0"; fi

  actionner=kubernetes:terminate
  [ "$response" = quarantine ] && actionner=kubernetes:label
  if poll 10 talon_acted "$actionner" "$pod" "$t0"; then pass "$id: Talon logged a successful $actionner for $pod"
  else fail "$id: no successful $actionner line for $pod in the Talon log since $t0"; fi

  $KUBECTL -n "$NAMESPACE" delete pod "$pod" --ignore-not-found --wait=false >/dev/null 2>&1 || true
done 3< "$WORK_DIR/plan.tsv"

# ---------------------------------------------------------------------------- result

step "result"
if [ "$failures" -ne 0 ]; then
  printf '  %s assertion(s) failed\n' "$failures" >&2
  exit 1
fi
printf '  scenario tests: ok\n'
