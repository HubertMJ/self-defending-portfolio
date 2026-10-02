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
  #
  # It MUST carry the app.kubernetes.io/name: portfolio-api label (the victim policy and the API's own
  # egress rule select on it) - but that label also makes it a candidate endpoint of the public
  # portfolio-api Service. So it is given a readiness probe that always fails: it never becomes Ready,
  # therefore never a Service endpoint, and never takes a share of production /api traffic. We exec into
  # it regardless, which needs only Running, not Ready.
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
      # Always fails: keeps the pod out of the portfolio-api Service's endpoints (see above).
      readinessProbe:
        exec:
          command: ["false"]
        periodSeconds: 5
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
  # Never Ready by design, so wait for Running (the container is up and exec works), not Ready.
  $KUBECTL -n "$API_NAMESPACE" wait --for=jsonpath='{.status.phase}'=Running "pod/$PROBE_POD" --timeout=60s >/dev/null 2>&1 \
    || die "probe pod $PROBE_POD did not reach Running in $API_NAMESPACE"
}

# probe_victim <victim-pod>: GET the victim's /state.json the way the API does, from the API-identity
# probe pod. Return codes are distinct so a measurement never mistakes a broken probe for isolation:
#   0  the shop answered
#   1  the probe ran and the shop did not answer (connection refused or timed out) - a real drop
#   2  the probe could not run (no pod IP yet, or the exec into the probe pod failed) - inconclusive
# The wget runs inside the probe pod and prints a sentinel, so a failed `kubectl exec` (rc from kubectl)
# is told apart from a wget that ran and failed (sentinel DROP).
probe_victim() {
  local ip out
  ip=$($KUBECTL -n "$NAMESPACE" get pod "$1" -o jsonpath='{.status.podIP}' 2>/dev/null) || return 2
  [ -n "$ip" ] || return 2
  out=$($KUBECTL -n "$API_NAMESPACE" exec "$PROBE_POD" -c probe -- \
    sh -c "wget -q -T 1 -O- http://$ip:8080/state.json >/dev/null 2>&1 && echo OK || echo DROP" 2>/dev/null) || return 2
  case $out in
    OK) return 0 ;;
    DROP) return 1 ;;
    *) return 2 ;;
  esac
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

# genpod.py builds one scenario Pod the way the API's runner.go buildPod does - the same four labels
# (run-id, scenario, quarantine=false, managed-by), the scenario image optionally overridden, and
# activeDeadlineSeconds from timeout_seconds - and prints its name. Used for the one-click plan below and
# for the fresh pods the quarantine and terminal sections need.
cat > "$WORK_DIR/genpod.py" <<'PY'
import json, secrets, sys, yaml
scn, sid, out = yaml.safe_load(open(sys.argv[1])), sys.argv[2], sys.argv[3]
image = sys.argv[4] if len(sys.argv) > 4 else ""
s = next(x for x in scn if x["id"] == sid)
run_id = "test-" + secrets.token_hex(3)
name = f"sc-{sid}-{run_id[5:]}"
spec = s["pod"]
if image:
    for c in spec["containers"] + spec.get("initContainers", []):
        c["image"] = image
# The API injects the per-run capture flag as env SDP_FLAG on container target (ADR 0032); mirror that
# when SDP_FLAG is in the environment, so the terminal's read-flag command has something to read.
import os
flag = os.environ.get("SDP_FLAG")
if flag:
    for c in spec["containers"]:
        if c.get("name") == "target":
            c.setdefault("env", []).append({"name": "SDP_FLAG", "value": flag})
spec["activeDeadlineSeconds"] = s["timeout_seconds"]
pod = {"apiVersion": "v1", "kind": "Pod",
       "metadata": {"name": name, "namespace": "sandbox",
                    "labels": {"sdp.hubertjablon.ski/run-id": run_id,
                               "sdp.hubertjablon.ski/scenario": sid,
                               "sdp.hubertjablon.ski/quarantine": "false",
                               "app.kubernetes.io/managed-by": "portfolio-api"}},
       "spec": spec}
json.dump(pod, open(out, "w"))
print(name)
PY

# genpod <id> [image] -> writes $WORK_DIR/<name>.json, echoes <name>, registers it for cleanup.
genpod() {
  local name
  name=$(python3 "$WORK_DIR/genpod.py" "$WORK_DIR/scenarios.yaml" "$1" "$WORK_DIR/$1.pod.json" "${2:-$SCENARIO_IMAGE}") \
    || die "could not build a pod for scenario $1"
  mv "$WORK_DIR/$1.pod.json" "$WORK_DIR/$name.json"
  PODS+=("$name")
  printf '%s' "$name"
}

# One TSV line per NON-interactive scenario (the terminal has no single exec; it is run in its own
# section). The one-click plan drives the terminate scenarios below; the quarantine scenario is measured
# separately (cold and warm), so it is marked and skipped by the main loop.
python3 - "$WORK_DIR" "$SCENARIO_IMAGE" "$ONLY" <<'PY' > "$WORK_DIR/plan.tsv"
import json, secrets, shlex, sys, yaml
work, image, only = sys.argv[1], sys.argv[2], sys.argv[3]
for s in yaml.safe_load(open(f"{work}/scenarios.yaml")):
    if only and s["id"] != only:
        continue
    if s.get("interactive"):
        continue  # the terminal catalogue is exercised in its own section, not by one exec
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
                                   "sdp.hubertjablon.ski/scenario": s["id"],
                                   "sdp.hubertjablon.ski/quarantine": "false",
                                   "app.kubernetes.io/managed-by": "portfolio-api"}},
           "spec": spec}
    json.dump(pod, open(f"{work}/{name}.json", "w"))
    exec_ = s.get("exec") or {"command": [], "tty": False}
    print("\t".join([s["id"], name, s["detection"], s["response"], str(s["timeout_seconds"]),
                     str(exec_["tty"]).lower(),
                     shlex.join(s["pre_exec"]["command"]) if s.get("pre_exec") else "-",
                     shlex.join(exec_["command"])]))
PY
if ! [ -s "$WORK_DIR/plan.tsv" ] && ! grep -q 'interactive: true' "$WORK_DIR/scenarios.yaml"; then
  die "no scenario matched${ONLY:+ ONLY=$ONLY}"
fi
if grep -q $'\ttrue\t' "$WORK_DIR/plan.tsv" 2>/dev/null; then
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

# Any Falco alert naming a pod since a time (used to assert an allowed command raises none).
falco_any_alert() { $KUBECTL -n falco logs ds/falco --since-time="$2" 2>/dev/null | grep -qF "$1"; }

# Run a scenario's pre_exec (to completion, no TTY) then its exec in the background, as the API does.
run_scenario_exec() { # pod tty pre cmd
  local pod=$1 tty=$2 pre=$3 cmd=$4
  if [ "$pre" != - ]; then
    eval "$KUBECTL exec -n $NAMESPACE $pod -c target -- $pre" </dev/null >"$WORK_DIR/$pod.pre.log" 2>&1 || true
  fi
  start_exec "$pod" "$tty" "$cmd"
}

# Time from the quarantine label landing to the API's :8080 probe dropping. T0 is taken the instant the
# label first reads true (a tight 0.1 s poll standing in for a watch), NOT after a coarse poll. Only a
# probe that ran and the shop did not answer (probe_victim rc 1) counts as the drop; a probe that could
# not run (rc 2) is ignored, so a transient kubectl/exec failure never looks like isolation. Echoes the
# seconds; non-zero (empty) if the label never landed or the bound+grace elapsed.
measure_label_to_cut() { # pod
  local pod=$1 t0 now rc deadline
  deadline=$((SECONDS + 90))
  while :; do
    [ "$($KUBECTL -n "$NAMESPACE" get pod "$pod" -o jsonpath='{.metadata.labels.sdp\.hubertjablon\.ski/quarantine}' 2>/dev/null)" = true ] \
      && { t0=$(date +%s.%N); break; }
    $KUBECTL -n "$NAMESPACE" get pod "$pod" >/dev/null 2>&1 || return 1
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep 0.1
  done
  while :; do
    probe_victim "$pod"; rc=$?
    now=$(date +%s.%N)
    [ "$rc" = 1 ] && { awk "BEGIN{printf \"%.1f\", $now - $t0}"; return 0; }
    awk "BEGIN{exit !($now - $t0 > $QUARANTINE_BOUND + 2)}" && return 1
    sleep 0.1
  done
}

# -------------------------------------------------- the one-click scenarios (terminate; quarantine below)
# The plan is read on fd 3: `script` and kubectl must not swallow it from stdin.
while IFS=$'\t' read -r -u 3 id pod detection response timeout tty pre cmd; do
  [ "$response" = quarantine ] && continue  # measured, cold and warm, in its own step below
  step "$id: '$detection' -> $response (timeout ${timeout}s)"

  PODS+=("$pod")
  $KUBECTL apply -f "$WORK_DIR/$pod.json" >/dev/null || { fail "$id: pod $pod was not admitted"; continue; }
  if ! $KUBECTL -n "$NAMESPACE" wait --for=condition=Ready "pod/$pod" --timeout=60s >/dev/null 2>&1; then
    fail "$id: pod $pod did not become Ready (image pull, admission or scheduling problem?)"
    continue
  fi
  pass "$id: pod $pod admitted and Ready"

  t0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  start=$SECONDS
  run_scenario_exec "$pod" "$tty" "$pre" "$cmd"

  if $KUBECTL -n "$NAMESPACE" wait --for=delete "pod/$pod" --timeout="${timeout}s" >/dev/null 2>&1; then
    pass "$id: pod deleted $((SECONDS - start)) s after the exec started"
  else
    fail "$id: pod $pod still exists after ${timeout}s"
  fi
  stop_exec

  if poll 10 falco_alerted "$detection" "$pod" "$t0"; then pass "$id: Falco alerted '$detection' for $pod"
  else fail "$id: no '$detection' alert naming $pod in the Falco log since $t0"; fi
  if poll 10 talon_acted "kubernetes:terminate" "$pod" "$t0"; then pass "$id: Talon logged a successful kubernetes:terminate for $pod"
  else fail "$id: no successful kubernetes:terminate line for $pod in the Talon log since $t0"; fi

  $KUBECTL -n "$NAMESPACE" delete pod "$pod" --ignore-not-found --wait=false >/dev/null 2>&1 || true
done 3< "$WORK_DIR/plan.tsv"

# -------------------------------------------------- quarantine: cold then warm, each under the bound
# A quarantine moves the pod to the quarantined Cilium identity. The first use of that identity after
# Cilium has garbage-collected it (identityGCInterval 15m / identityHeartbeatTimeout 30m, chart defaults)
# is a cold allocation; a second quarantine right after reuses the warm identity. We run each quarantine
# scenario twice and hold both to QUARANTINE_BOUND, printing the measured seconds. (Which run is truly
# cold depends on earlier activity; the labels are first/second.)
python3 - "$WORK_DIR/scenarios.yaml" "$ONLY" <<'PY' > "$WORK_DIR/quar.tsv"
import shlex, sys, yaml
only = sys.argv[2]
for s in yaml.safe_load(open(sys.argv[1])):
    if s.get("interactive") or s.get("response") != "quarantine":
        continue
    if only and s["id"] != only:
        continue
    e = s.get("exec") or {"command": [], "tty": False}
    print("\t".join([s["id"], s["detection"], str(e["tty"]).lower(),
                     shlex.join(s["pre_exec"]["command"]) if s.get("pre_exec") else "-",
                     shlex.join(e["command"])]))
PY
if [ -s "$WORK_DIR/quar.tsv" ]; then
  ensure_probe_pod
  while IFS=$'\t' read -r qid detection tty pre cmd; do
    for tag in first second; do
      step "$qid ($tag quarantine): isolation under ${QUARANTINE_BOUND}s (ADR 0032)"
      pod=$(genpod "$qid")
      if ! $KUBECTL apply -f "$WORK_DIR/$pod.json" >/dev/null 2>&1; then fail "$qid ($tag): pod not admitted"; continue; fi
      if ! $KUBECTL -n "$NAMESPACE" wait --for=condition=Ready "pod/$pod" --timeout=60s >/dev/null 2>&1; then
        fail "$qid ($tag): pod $pod did not become Ready"; continue; fi
      ok=
      for _ in $(seq 1 30); do if probe_victim "$pod"; then ok=1; break; fi; sleep 0.5; done
      if [ -z "$ok" ]; then fail "$qid ($tag): the probe cannot reach $pod:8080 before the attack"
        $KUBECTL -n "$NAMESPACE" delete pod "$pod" --wait=false >/dev/null 2>&1 || true; continue; fi
      pass "$qid ($tag): the probe reads the shop on :8080 before the attack"
      t0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
      run_scenario_exec "$pod" "$tty" "$pre" "$cmd"
      cut=$(measure_label_to_cut "$pod" || true)
      stop_exec
      if [ -n "$cut" ] && awk "BEGIN{exit !($cut <= $QUARANTINE_BOUND)}"; then
        pass "$qid ($tag): the shop on :8080 dropped ${cut}s after the label (<= ${QUARANTINE_BOUND}s)"
      elif [ -n "$cut" ]; then
        fail "$qid ($tag): the shop dropped after ${cut}s, over the ${QUARANTINE_BOUND}s bound"
      else
        fail "$qid ($tag): the shop stayed reachable past the bound, or the label never landed"
      fi
      phase=$($KUBECTL -n "$NAMESPACE" get pod "$pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)
      if [ "$phase" = Running ]; then pass "$qid ($tag): still Running (isolated, not killed)"
      else fail "$qid ($tag): pod is ${phase:-gone}, expected Running"; fi
      if poll 10 falco_alerted "$detection" "$pod" "$t0"; then pass "$qid ($tag): Falco alerted '$detection'"
      else fail "$qid ($tag): no '$detection' alert for $pod"; fi
      if poll 10 talon_acted "kubernetes:label" "$pod" "$t0"; then pass "$qid ($tag): Talon logged a successful kubernetes:label"
      else fail "$qid ($tag): no successful kubernetes:label for $pod"; fi
      $KUBECTL -n "$NAMESPACE" delete pod "$pod" --ignore-not-found --wait=false >/dev/null 2>&1 || true
      sleep 2
    done
  done < "$WORK_DIR/quar.tsv"
fi

# -------------------------------------------------- the interactive terminal catalogue (ADR 0032)
if grep -q 'interactive: true' "$WORK_DIR/scenarios.yaml" && { [ -z "$ONLY" ] || [ "$ONLY" = terminal ]; }; then
  ensure_probe_pod
  python3 - "$WORK_DIR/scenarios.yaml" <<'PY' > "$WORK_DIR/term.tsv"
import shlex, sys, yaml
t = next((s for s in yaml.safe_load(open(sys.argv[1])) if s.get("interactive")), None)
if t is None:
    raise SystemExit
print("TERM\t" + t["id"])
for c in t["commands"]:
    print("\t".join(["CMD", c["id"], c["outcome"], str(c["tty"]).lower(),
                     c.get("detection") or "-", c.get("response") or "-", shlex.join(c["command"])]))
PY
  termid=$(awk -F'\t' '$1=="TERM"{print $2}' "$WORK_DIR/term.tsv")
  FLAG="SDP{$(tr -dc 'a-f0-9' </dev/urandom | head -c 16)}"

  # The quiet commands (allowed, prevented) all run in one terminal pod: none ends the run, so this is
  # the pod a visitor keeps while poking around. The loud ones (detected) each get a fresh pod below,
  # because each ends the run.
  step "terminal: the flag, and the allowed/prevented commands on one pod (ADR 0032)"
  tpod=$(SDP_FLAG="$FLAG" genpod "$termid")
  if ! $KUBECTL apply -f "$WORK_DIR/$tpod.json" >/dev/null 2>&1; then fail "terminal: pod not admitted"
  elif ! $KUBECTL -n "$NAMESPACE" wait --for=condition=Ready "pod/$tpod" --timeout=60s >/dev/null 2>&1; then
    fail "terminal: pod $tpod did not become Ready"
  else
    pass "terminal: pod $tpod admitted and Ready"
    got=$($KUBECTL -n "$NAMESPACE" exec "$tpod" -c target -- cat /srv/shop/.flag 2>/dev/null | tr -d '\r\n' || true)
    if [ "$got" = "$FLAG" ]; then pass "terminal: the per-run flag is readable at /srv/shop/.flag"
    else fail "terminal: /srv/shop/.flag is '${got:-missing}', expected the injected flag"; fi
    quiet_t0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    while IFS=$'\t' read -r tag cid outcome ttyc det resp argv; do
      [ "$tag" = CMD ] || continue
      case $outcome in
        allowed)
          if out=$(eval "$KUBECTL exec -n $NAMESPACE $tpod -c target -- $argv" </dev/null 2>&1); then
            if [ "$cid" = read-flag ]; then
              if grep -qF "$FLAG" <<<"$out"; then pass "$cid: prints the flag"; else fail "$cid: flag not printed"; fi
            else
              pass "$cid: runs and exits 0"
            fi
          else
            fail "$cid: expected allowed but it failed ('$(head -1 <<<"$out")')"
          fi ;;
        prevented)
          case $cid in
            touch-bin)  want="Read-only file system" ;;
            read-token) want="No such file or directory" ;;
            chown-root) want="Operation not permitted" ;;
            *)          want="" ;;
          esac
          if out=$(eval "$KUBECTL exec -n $NAMESPACE $tpod -c target -- $argv" </dev/null 2>&1); then
            fail "$cid: expected prevented but it succeeded ('$out')"
          elif [ -n "$want" ] && ! grep -qiF "$want" <<<"$out"; then
            fail "$cid: refused, but not with '$want' ('$(head -1 <<<"$out")')"
          else
            pass "$cid: refused by the pod ('$(head -1 <<<"$out")')"
          fi ;;
        *) : ;;  # detected commands are run on fresh pods below
      esac
    done < "$WORK_DIR/term.tsv"
    phase=$($KUBECTL -n "$NAMESPACE" get pod "$tpod" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    if [ "$phase" = Running ]; then pass "terminal: the pod is still Running after the quiet commands"
    else fail "terminal: the pod is ${phase:-gone} after only allowed/prevented commands"; fi
    if falco_any_alert "$tpod" "$quiet_t0"; then fail "terminal: an allowed/prevented command raised a Falco alert"
    else pass "terminal: no Falco alert for the quiet commands"; fi
    $KUBECTL -n "$NAMESPACE" delete pod "$tpod" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  fi

  # Each detected command on its own fresh pod: run it the way the API will (argv, tty, no stdin), then
  # assert the named Falco rule, the Talon action and the end state. drop-run is proven here: only a live
  # run shows Falco's proc.exepath for the dropped binary reads /srv/shop/..., not a host path.
  while IFS=$'\t' read -r tag cid outcome ttyc det resp argv; do
    { [ "$tag" = CMD ] && [ "$outcome" = detected ]; } || continue
    step "terminal/$cid: '$det' -> $resp (ADR 0032)"
    dpod=$(SDP_FLAG="$FLAG" genpod "$termid")
    if ! $KUBECTL apply -f "$WORK_DIR/$dpod.json" >/dev/null 2>&1; then fail "$cid: pod not admitted"; continue; fi
    if ! $KUBECTL -n "$NAMESPACE" wait --for=condition=Ready "pod/$dpod" --timeout=60s >/dev/null 2>&1; then
      fail "$cid: pod $dpod did not become Ready"; continue; fi
    if [ "$resp" = quarantine ]; then
      ok=; for _ in $(seq 1 30); do if probe_victim "$dpod"; then ok=1; break; fi; sleep 0.5; done
      if [ -n "$ok" ]; then pass "$cid: the probe reads the shop on :8080 before the command"
      else fail "$cid: the probe cannot reach $dpod:8080 before the command"; fi
    fi
    t0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    start_exec "$dpod" "$ttyc" "$argv"
    if [ "$resp" = terminate ]; then
      if $KUBECTL -n "$NAMESPACE" wait --for=delete "pod/$dpod" --timeout=60s >/dev/null 2>&1; then
        pass "$cid: pod deleted after the command"
      else
        fail "$cid: pod $dpod still exists 60 s after the command"
      fi
    else
      cut=$(measure_label_to_cut "$dpod" || true)
      if [ -n "$cut" ] && awk "BEGIN{exit !($cut <= $QUARANTINE_BOUND)}"; then
        pass "$cid: the shop on :8080 dropped ${cut}s after the label (<= ${QUARANTINE_BOUND}s)"
      else
        fail "$cid: the shop did not drop within the bound (${cut:-no drop})"
      fi
      phase=$($KUBECTL -n "$NAMESPACE" get pod "$dpod" -o jsonpath='{.status.phase}' 2>/dev/null || true)
      if [ "$phase" = Running ]; then pass "$cid: still Running (isolated, not killed)"; else fail "$cid: pod is ${phase:-gone}, expected Running"; fi
    fi
    stop_exec
    if poll 10 falco_alerted "$det" "$dpod" "$t0"; then pass "$cid: Falco alerted '$det' for $dpod"
    else fail "$cid: no '$det' alert naming $dpod since $t0"; fi
    act=kubernetes:terminate; [ "$resp" = quarantine ] && act=kubernetes:label
    if poll 10 talon_acted "$act" "$dpod" "$t0"; then pass "$cid: Talon logged a successful $act for $dpod"
    else fail "$cid: no successful $act for $dpod since $t0"; fi
    $KUBECTL -n "$NAMESPACE" delete pod "$dpod" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  done < "$WORK_DIR/term.tsv"
fi

# ---------------------------------------------------------------------------- result

step "result"
if [ "$failures" -ne 0 ]; then
  printf '  %s assertion(s) failed\n' "$failures" >&2
  exit 1
fi
printf '  scenario tests: ok\n'
