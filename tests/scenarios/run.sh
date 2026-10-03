#!/usr/bin/env bash
# Phase 5's scenario contract, as an executable assertion against the live cluster (ADR 0017, ADR 0018,
# ADR 0032): for every attack scenario in ConfigMap `scenarios`, creating the pod the way the portfolio
# API does and running the scenario's exec produces the Falco alert the scenario names, the Falco Talon
# action it promises, and the end state that action implies; and every command of the interactive
# terminal ends the way its catalogue entry says.
#
#   KUBECONFIG=... tests/scenarios/run.sh                  (or: make scenario-test)
#   KUBECTL="kubectl --kubeconfig ..." tests/scenarios/run.sh
#   ONLY=network-tool tests/scenarios/run.sh               one scenario, by its id in the catalogue
#   QUARANTINE_BOUND=3 tests/scenarios/run.sh              the label-to-isolation bound, in seconds
#   ISOLATE_TIMEOUT=30 tests/scenarios/run.sh             how long after the label to keep probing
#   QUIET_WAIT=5 tests/scenarios/run.sh                    how long a quiet command gets to raise an alert
#   SCENARIO_IMAGE=ghcr.io/hubertmj/self-defending-portfolio/scenario@sha256:... tests/scenarios/run.sh
#
# Scenarios come from the live ConfigMap (portfolio-api/scenarios), which is what the API executes; if it
# is not deployed yet, from cluster/infra/sandbox/scenarios/scenarios.yaml, and the script says so.
# SCENARIO_IMAGE replaces the image of every scenario pod (a digest reference, signed by this project's
# workflow, or Kyverno rejects the pod) - useful before the placeholder digest has been bumped.
#
# Per one-click scenario, like the API: a Pod in `sandbox` from the scenario's PodSpec, with labels
# sdp.hubertjablon.ski/run-id, sdp.hubertjablon.ski/scenario, sdp.hubertjablon.ski/quarantine: "false"
# and app.kubernetes.io/managed-by: portfolio-api, and activeDeadlineSeconds = timeout_seconds; wait for
# Ready; run `pre_exec.command`, if any, to completion without a TTY, as the API does (ADR 0022); run
# `exec.command` in container `target` (through `script` for a real TTY when exec.tty is true); then:
#   terminate  -> the pod is deleted (by Talon, not by its deadline), Falco logged `detection` for it,
#                 Talon logged a successful kubernetes:terminate for it;
#   quarantine -> the pod is labelled quarantine=true and still Running, Falco logged `detection`, Talon
#                 logged a successful kubernetes:label for it, and the victim's shop on :8080 stopped
#                 answering a probe with the API's identity within QUARANTINE_BOUND seconds of the label.
#                 Run twice in a row; each measurement is printed with its bound, pass or fail, and
#                 labelled cold or warm by what Cilium held just before it (see the quarantine section).
# The interactive terminal: every `allowed` command succeeds and every `prevented` one fails with its
# expected refusal, all on one pod, with no Falco alert after any of them; every `detected` command, on a
# fresh pod each, raises its Falco rule and Talon's action, as the one-click scenarios do.
# Talon's log is its record of an action: Talon 0.3.0 writes no Kubernetes Events here (its k8sevents
# notifier is off, ADR 0013 correction), and its JSON log line carries the actionner, the status and
# the pod, as tests/runtime/run.sh asserts.
#
# Cleanup. Every pod this script creates is registered, by its exact name, before it is applied; it is
# deleted at the end of its case on every path, and again on exit, Ctrl-C and SIGTERM included. Never by
# label selector: the API's own runs share the namespace and the labels. A delete that fails is a FAIL
# naming the pod. What no trap covers - SIGKILL, a lost connection to the cluster - leaves a pod up to
# its activeDeadlineSeconds (<= 300 s), holding one of the 3 pods the sandbox quota allows, so a
# visitor's run can be refused meanwhile: check `kubectl -n sandbox get pods` for sc-* after such an end.
#
# Visible on the site. The test pods are real sandbox pods: their Falco alerts and Talon actions take the
# same path as a visitor's (Falcosidekick -> the portfolio API -> the public live feed), so anyone
# watching the site while this runs may see them. That is accepted; run it when it is fine to be seen.
#
# Needs python3 with PyYAML (to read the scenario list; `make validate` needs it too) and `script`
# (util-linux) for every command that needs a TTY (a scenario's exec, or the terminal's `shell`), as
# tests/runtime/run.sh does.
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT=$(cd ../.. && pwd)

KUBECTL=${KUBECTL:-kubectl}
NAMESPACE=sandbox
ONLY=${ONLY:-}
SCENARIO_IMAGE=${SCENARIO_IMAGE:-}
PLACEHOLDER_DIGEST=sha256:0000000000000000000000000000000000000000000000000000000000000000
# Label-to-isolation bound (ADR 0032), measured the way the visitor sees it: a probe with the API's
# identity polling the victim's /state.json on :8080 (see the isolation measurement below).
QUARANTINE_BOUND=${QUARANTINE_BOUND:-3}
# How long, after the label, the probe keeps polling for the drop before giving up. The measured value
# is printed whenever it is below this; above it, "no drop within ISOLATE_TIMEOUT s" is.
ISOLATE_TIMEOUT=${ISOLATE_TIMEOUT:-30}
# How long Talon may take to set the label after the attack starts (Falco + Falcosidekick + Talon).
LABEL_WAIT=60
# How long an allowed or prevented terminal command gets for a Falco alert to show up in Falco's log
# before it is concluded that none fired. Falco writes an alert within a second of the syscall; the
# margin is for the log path. Eight quiet steps at 5 s stay well inside the pod's 300 s deadline.
QUIET_WAIT=${QUIET_WAIT:-5}
# The API's probe (app/api/internal/runner: VictimTimeout 300 ms, ADR 0021/0022).
PROBE_TIMEOUT=0.3
# The isolation probe stops after this many dropped probes in a row: the drop is sustained, not a blip.
DROP_RUN=5
# The API lives here; its pods are the only ones the sandbox victim policy admits to :8080. The probe
# pod runs in this namespace with the API's app label so Cilium gives it the API's identity and its
# :8080 egress, and the victim policy admits it (cluster/infra/sandbox/ciliumnetworkpolicy-victim.yaml).
API_NAMESPACE=${API_NAMESPACE:-portfolio-api}

WORK_DIR=$(mktemp -d)
PODS=()
PROBE_POD=
EXEC_PID=
WATCH_PID=
PROBE_LOOP_PID=
# Stops what runs in the background, then deletes every pod this script created, by name. Runs on every
# exit: errexit, die, the end of the script, and (through the INT/TERM traps) Ctrl-C and SIGTERM.
cleanup() {
  local rc=$? pod pid
  for pid in "$EXEC_PID" "$WATCH_PID" "$PROBE_LOOP_PID"; do
    [ -z "$pid" ] || kill "$pid" 2>/dev/null || :  # already gone is fine: it is being stopped anyway
  done
  for pod in "${PODS[@]}"; do
    if ! $KUBECTL -n "$NAMESPACE" delete pod "$pod" --ignore-not-found --wait=false >/dev/null 2>"$WORK_DIR/delete.err"; then
      printf 'run.sh: could not delete pod %s/%s, delete it by hand: %s\n' "$NAMESPACE" "$pod" "$(head -c 300 "$WORK_DIR/delete.err")" >&2
      rc=1
    fi
  done
  if [ -n "$PROBE_POD" ] \
     && ! $KUBECTL -n "$API_NAMESPACE" delete pod "$PROBE_POD" --ignore-not-found --wait=false >/dev/null 2>"$WORK_DIR/delete.err"; then
    printf 'run.sh: could not delete pod %s/%s, delete it by hand: %s\n' "$API_NAMESPACE" "$PROBE_POD" "$(head -c 300 "$WORK_DIR/delete.err")" >&2
    rc=1
  fi
  rm -rf "$WORK_DIR"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

failures=0
asserted=0
step() { printf '\n==> %s\n' "$*"; }
pass() { printf '  PASS  %s\n' "$*"; asserted=$((asserted + 1)); }
fail() { printf '  FAIL  %s\n' "$*" >&2; failures=$((failures + 1)); asserted=$((asserted + 1)); }
die() { printf 'run.sh: %s\n' "$*" >&2; exit 1; }

# Polls a command until it succeeds or `timeout` seconds have passed. Returns the command's last status,
# so a caller can tell "not yet" (1) from "could not look" (2).
poll() {
  local timeout=$1 rc; shift
  local deadline=$((SECONDS + timeout))
  while :; do
    "$@" >/dev/null 2>&1 && return 0 || rc=$?
    [ "$SECONDS" -lt "$deadline" ] || return "$rc"
    sleep 1
  done
}

# Random hex. `od -N` reads exactly the bytes it needs, so no producer is cut off mid-write: a
# `tr </dev/urandom | head` pipeline ends with tr killed by SIGPIPE, which pipefail turns into status 141
# and errexit into a silent exit.
randhex() { od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }

# Deletes one pod this script created, by its exact name. A failed delete is a FAIL: the pod would hold
# one of the sandbox quota's 3 pods until its deadline.
delete_pod() { # pod
  $KUBECTL -n "$NAMESPACE" delete pod "$1" --ignore-not-found --wait=false >/dev/null 2>"$WORK_DIR/delete.err" \
    || fail "could not delete pod $1: $(head -c 300 "$WORK_DIR/delete.err")"
}

# The pod's creationTimestamp: the time every log search for it starts from. It is the API server's
# clock, the same node's clock the container logs are stamped with, so --since-time never depends on
# this machine's clock; and nothing can log about a pod before it exists.
pod_created() { $KUBECTL -n "$NAMESPACE" get pod "$1" -o jsonpath='{.metadata.creationTimestamp}'; }

# The API polls the victim by dialling the pod IP on :8080 and reading /state.json (ADR 0021/0022). This
# throwaway pod carries the API's identity, so the quarantine is measured where the visitor sees it (the
# shop going unreachable), not only on the victim's egress.
ensure_probe_pod() {
  [ -z "$PROBE_POD" ] || return 0
  PROBE_POD="sdp-probe-$(randhex 3)"
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

# ONLY must be an id of the catalogue: a typo would otherwise select nothing, assert nothing, and pass.
if [ -n "$ONLY" ]; then
  python3 - "$WORK_DIR/scenarios.yaml" "$ONLY" <<'PY' || exit 1
import sys, yaml
ids = [s["id"] for s in yaml.safe_load(open(sys.argv[1]))]
if sys.argv[2] not in ids:
    sys.exit(f"run.sh: ONLY={sys.argv[2]} matches no scenario id; the ids are: {' '.join(ids)}")
PY
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

# genpod <id> [image]: writes $WORK_DIR/<name>.json, registers <name> for cleanup, sets POD to it.
# Called as a plain command, never inside $(...): a subshell's PODS+= would never reach cleanup.
genpod() {
  POD=$(python3 "$WORK_DIR/genpod.py" "$WORK_DIR/scenarios.yaml" "$1" "$WORK_DIR/$1.pod.json" "${2:-$SCENARIO_IMAGE}") \
    || die "could not build a pod for scenario $1"
  mv "$WORK_DIR/$1.pod.json" "$WORK_DIR/$POD.json"
  PODS+=("$POD")
}

# One TSV line per NON-interactive scenario (the terminal has no single exec; it is run in its own
# section). The one-click plan drives the terminate scenarios below; the quarantine scenario is measured
# separately (twice), so it is marked and skipped by the main loop.
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

# The quarantine scenarios, measured in their own section.
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

# The interactive terminal's catalogue: a TERM line with its id, then one CMD line per command. Empty
# when there is no terminal or ONLY names another scenario.
python3 - "$WORK_DIR/scenarios.yaml" "$ONLY" <<'PY' > "$WORK_DIR/term.tsv"
import shlex, sys, yaml
only = sys.argv[2]
t = next((s for s in yaml.safe_load(open(sys.argv[1])) if s.get("interactive")), None)
if t is None or (only and t["id"] != only):
    raise SystemExit
print("TERM\t" + t["id"])
for c in t["commands"]:
    print("\t".join(["CMD", c["id"], c["outcome"], str(c["tty"]).lower(),
                     c.get("detection") or "-", c.get("response") or "-", shlex.join(c["command"])]))
PY

# `script` makes kubectl allocate a real TTY; needed if anything that will run asks for one: a one-click
# exec (plan column 6, quarantine column 3) or a terminal command (CMD column 4, e.g. `shell`).
if awk -F'\t' 'FILENAME ~ /plan\.tsv$/ && $6 == "true" { f = 1 }
               FILENAME ~ /quar\.tsv$/ && $3 == "true" { f = 1 }
               FILENAME ~ /term\.tsv$/ && $1 == "CMD" && $4 == "true" { f = 1 }
               END { exit !f }' "$WORK_DIR/plan.tsv" "$WORK_DIR/quar.tsv" "$WORK_DIR/term.tsv"; then
  command -v script >/dev/null || die "the 'script' command (util-linux) is required for a real TTY"
fi

# Everything above is preflight; the result below insists that at least one scenario assertion ran.
asserted=0

# ---------------------------------------------------------------------------- the scenarios

# Starts the exec in the background, as the API would; a TTY exec goes through `script` so kubectl
# really allocates one (`kubectl exec -it` only does when its own stdin is a terminal). Both get an empty
# stdin, as the API's exec does: a backgrounded process must never inherit (and read) the caller's.
start_exec() {
  local pod=$1 tty=$2 cmd=$3
  if [ "$tty" = true ]; then
    script -qec "$KUBECTL exec -it -n $NAMESPACE $pod -c target -- $cmd" /dev/null </dev/null >"$WORK_DIR/$pod.exec.log" 2>&1 &
  else
    eval "$KUBECTL exec -n $NAMESPACE $pod -c target -- $cmd" </dev/null >"$WORK_DIR/$pod.exec.log" 2>&1 &
  fi
  EXEC_PID=$!
}
stop_exec() {
  # The exec's own status is not a signal (a killed pod ends it with an error); it is being stopped.
  [ -z "$EXEC_PID" ] || { kill "$EXEC_PID" 2>/dev/null || :; wait "$EXEC_PID" 2>/dev/null || :; }
  EXEC_PID=
}

# exec_in <pod> <tty> <argv>: runs one command in container target to completion, stdin empty, the
# catalogue's tty flag honoured; prints stdout and stderr, returns the command's (or kubectl's) status.
exec_in() {
  local pod=$1 tty=$2 argv=$3
  if [ "$tty" = true ]; then
    script -qec "$KUBECTL exec -it -n $NAMESPACE $pod -c target -- $argv" /dev/null </dev/null 2>&1
  else
    eval "$KUBECTL exec -n $NAMESPACE $pod -c target -- $argv" </dev/null 2>&1
  fi
}

# Logs are read into a file in full, then searched: `kubectl logs | grep -q` exits 141 under pipefail
# when grep stops at the first match while kubectl is still writing. A failed read is status 2 below,
# reported as such, never as "no alert".
read_log() { # namespace workload since file
  $KUBECTL -n "$1" logs "$2" --since-time="$3" >"$4" 2>"$4.err"
}
falco_alerted() { # rule, pod, since
  read_log falco ds/falco "$3" "$WORK_DIR/falco.log" || return 2
  awk -v r="\"rule\":\"$1\"" -v p="$2" 'index($0, r) && index($0, p) { f = 1 } END { exit !f }' "$WORK_DIR/falco.log"
}
# Talon logs JSON lines (talon/config.yaml); the text form and ANSI colours are tolerated, as in
# tests/runtime/run.sh, so the assertion does not depend on the log format. A notification line (the
# webhook to the API) carries the actionner and a status but no pod, so it cannot match on its own.
talon_acted() { # actionner, pod, since
  read_log falco-response deploy/falco-talon "$3" "$WORK_DIR/talon.log" || return 2
  sed 's/\x1b\[[0-9;]*m//g' "$WORK_DIR/talon.log" | awk -v a="$1" -v p="$2" '
    index($0, a) && index($0, p) && (index($0, "\"status\":\"success\"") || index($0, "status=success")) { f = 1 }
    END { exit !f }'
}
check_falco() { # who rule pod since
  local rc=0
  poll 10 falco_alerted "$2" "$3" "$4" || rc=$?
  case $rc in
    0) pass "$1: Falco alerted '$2' for $3" ;;
    2) fail "$1: could not read Falco's log: $(head -c 300 "$WORK_DIR/falco.log.err")" ;;
    *) fail "$1: no '$2' alert naming $3 in the Falco log since $4" ;;
  esac
}
check_talon() { # who actionner pod since
  local rc=0
  poll 10 talon_acted "$2" "$3" "$4" || rc=$?
  case $rc in
    0) pass "$1: Talon logged a successful $2 for $3" ;;
    2) fail "$1: could not read Talon's log: $(head -c 300 "$WORK_DIR/talon.log.err")" ;;
    *) fail "$1: no successful $2 line for $3 in the Talon log since $4" ;;
  esac
}

# Run a scenario's pre_exec (to completion, no TTY) then its exec in the background, as the API does.
run_scenario_exec() { # pod tty pre cmd
  local pod=$1 tty=$2 pre=$3 cmd=$4
  if [ "$pre" != - ]; then
    # Its status is not judged, as in the API: a failed pre_exec shows as a victim that did not change.
    eval "$KUBECTL exec -n $NAMESPACE $pod -c target -- $pre" </dev/null >"$WORK_DIR/$pod.pre.log" 2>&1 || :
  fi
  start_exec "$pod" "$tty" "$cmd"
}

# ------------------------------------------------- the isolation measurement (quarantine, ADR 0032)
#
# What is measured: the time from the quarantine label being set to the first probe with the API's
# identity that the shop no longer answered - the moment the page shows the shop "unreachable".
#
# Both ends are stamped on ONE clock, this machine's (bash's EPOCHREALTIME, microseconds), as the lines
# arrive:
#   T0  - a `kubectl get --watch` on the pod, started before the attack, prints the label on every
#         change; T0 is when the line saying "true" arrived. Not the pod's managedFields time: that is
#         the API server's clock, with whole-second resolution, which against a 3 s bound is too coarse.
#   end - a loop inside the probe pod (one `kubectl exec`, started before the attack) prints a line as
#         each probe STARTS and its result when it ends; end is when the start line of the first dropped
#         probe arrived. A probe is one GET of /state.json with the API's 300 ms timeout, every ~0.1 s
#         plus its own duration. Probing inside the pod keeps exec overhead out of the timing.
# Each end reaches this machine one delivery later than it happened (watch event; exec stream), both
# from the same API server, so the two delays largely cancel. Precision: the first dropped probe starts
# at most one probe interval after the cut (~0.15 s while the shop answers), so the value is late by at
# most that, plus the difference of the two delivery delays (milliseconds to tens of milliseconds).
#
# What counts as a drop: a probe that ran and got no answer - killed by the 300 ms timeout, or the
# connection refused. An HTTP error is an answer (the shop is reachable, just unhappy); a probe that
# could not run (no wget, an exec failure) is neither, and a measurement made only of those is
# inconclusive, not a pass. The drop that counts is the first one after the last answer: a single blip
# followed by answers again is not the cut.
#
# The in-pod loop (busybox sh). Arguments: the victim's IP, how long it may run (s), how many drops in a
# row end it. Output: "S" when a probe starts, then OK | HTTP | DROP | "ERR <message>".
# shellcheck disable=SC2016  # expanded by the probe pod's shell
PROBE_LOOP='ip=$1; end=$(( $(date +%s) + $2 )); n=0
while [ "$(date +%s)" -lt "$end" ]; do
  echo S
  out=$(timeout '"$PROBE_TIMEOUT"' wget -q -O /dev/null "http://$ip:8080/state.json" 2>&1); rc=$?
  case $rc in
    0) r=OK; n=0 ;;
    143) r=DROP; n=$((n + 1)) ;;
    1) case $out in
         *"server returned error"*) r=HTTP; n=0 ;;
         *refused*|*"timed out"*) r=DROP; n=$((n + 1)) ;;
         *) r="ERR $out" ;;
       esac ;;
    *) r="ERR rc=$rc $out" ;;
  esac
  echo "$r"
  [ "$n" -lt "$3" ] || exit 0
  sleep 0.1
done'

# Prefixes every line read with this machine's wall clock, in seconds with microseconds.
stamp() { local line; while IFS= read -r line; do printf '%s %s\n' "${EPOCHREALTIME/,/.}" "$line"; done; }

# Whether Cilium already holds the quarantined identity of a scenario pod, right before a quarantine:
# a CiliumIdentity whose security labels carry quarantine=true, the namespace, and the API's managed-by
# label. Absent means this quarantine allocates it (cold); present means it is reused (warm). Cilium's
# operator garbage-collects an identity no endpoint uses (identityGCInterval 15m, identityHeartbeatTimeout
# 30m, chart defaults), so after a quiet spell the first quarantine is cold - established here, not
# assumed. Prints "cold ..." or "warm ..."; returns 1 if the identities could not be listed.
quarantine_identity() {
  $KUBECTL get ciliumidentities.cilium.io -o json >"$WORK_DIR/identities.json" 2>"$WORK_DIR/identities.err" || return 1
  python3 - "$WORK_DIR/identities.json" "$NAMESPACE" <<'PY'
import json, sys
ns = sys.argv[2]
quarantined = [i for i in json.load(open(sys.argv[1]))["items"]
               if i.get("security-labels", {}).get("k8s:sdp.hubertjablon.ski/quarantine") == "true"
               and i.get("security-labels", {}).get("k8s:io.kubernetes.pod.namespace") == ns]
ours = [i["metadata"]["name"] for i in quarantined
        if i["security-labels"].get("k8s:app.kubernetes.io/managed-by") == "portfolio-api"]
others = [i["metadata"]["name"] for i in quarantined if i["metadata"]["name"] not in ours]
if ours:
    print(f"warm (CiliumIdentity {', '.join(ours)} exists)")
else:
    print(f"cold (no CiliumIdentity with quarantine=true for scenario pods in {ns}"
          + (f"; other quarantined identities there: {', '.join(others)})" if others else ")"))
PY
}

# arm_isolation <who> <pod>: starts the label watch and the probe loop against the victim, and waits
# until both are live - the watch has printed the label as "false" and the shop has answered a probe -
# so nothing about the attack can happen before the measurement can see it. FAILs and returns 1 if not.
arm_isolation() {
  local who=$1 pod=$2 ip deadline
  ensure_probe_pod
  if ! ip=$($KUBECTL -n "$NAMESPACE" get pod "$pod" -o jsonpath='{.status.podIP}' 2>"$WORK_DIR/ip.err") || [ -z "$ip" ]; then
    fail "$who: no pod IP for $pod: $(head -c 300 "$WORK_DIR/ip.err")"; return 1
  fi
  : >"$WORK_DIR/$pod.watch"; : >"$WORK_DIR/$pod.probe"
  $KUBECTL -n "$NAMESPACE" get pod "$pod" --watch -o jsonpath='{.metadata.labels.sdp\.hubertjablon\.ski/quarantine}{"\n"}' \
    </dev/null 2>"$WORK_DIR/$pod.watch.err" > >(stamp >"$WORK_DIR/$pod.watch") &
  WATCH_PID=$!
  $KUBECTL -n "$API_NAMESPACE" exec "$PROBE_POD" -c probe -- sh -c "$PROBE_LOOP" probe "$ip" \
    "$((15 + LABEL_WAIT + ISOLATE_TIMEOUT + 15))" "$DROP_RUN" \
    </dev/null 2>"$WORK_DIR/$pod.probe.err" > >(stamp >"$WORK_DIR/$pod.probe") &
  PROBE_LOOP_PID=$!
  deadline=$((SECONDS + 15))
  until awk 'NR == 1 && $2 == "false" { f = 1 } END { exit !f }' "$WORK_DIR/$pod.watch" \
        && awk '$2 == "OK" { f = 1 } END { exit !f }' "$WORK_DIR/$pod.probe"; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      if ! awk 'NR == 1 && $2 == "false" { f = 1 } END { exit !f }' "$WORK_DIR/$pod.watch"; then
        fail "$who: the label watch on $pod did not start with quarantine=false ($(head -1 "$WORK_DIR/$pod.watch") $(head -c 300 "$WORK_DIR/$pod.watch.err"))"
      elif grep -q ' DROP$' "$WORK_DIR/$pod.probe"; then
        fail "$who: the probe ran but the shop on $pod:8080 did not answer before the attack"
      else
        fail "$who: the probe could not run against $pod:8080 ($(grep -m1 ' ERR' "$WORK_DIR/$pod.probe") $(head -c 300 "$WORK_DIR/$pod.probe.err"))"
      fi
      return 1
    fi
    sleep 0.2
  done
  pass "$who: the probe reads the shop on $pod:8080 before the attack; the label watch is live"
}

disarm_isolation() {
  local pid
  # Their exit status is that of the kill: they are being stopped, not judged.
  for pid in "$WATCH_PID" "$PROBE_LOOP_PID"; do
    [ -z "$pid" ] || { kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; }
  done
  WATCH_PID=
  PROBE_LOOP_PID=
}

# measure_isolation <who> <pod> <identity>: after the attack has started. Waits for the label, then for
# the shop to stop answering, and always prints the measured value and the bound.
measure_isolation() {
  local who=$1 pod=$2 ident=$3 t0 deadline now result
  deadline=$((SECONDS + LABEL_WAIT))
  until t0=$(awk '$2 == "true" { print $1; exit }' "$WORK_DIR/$pod.watch") && [ -n "$t0" ]; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      fail "$who: the quarantine label did not reach $pod within ${LABEL_WAIT}s of the attack (bound ${QUARANTINE_BOUND}s not measurable)"
      return
    fi
    sleep 0.2
  done
  # Wait for the loop to end on a sustained drop (or its own deadline), or for ISOLATE_TIMEOUT past T0.
  while kill -0 "$PROBE_LOOP_PID" 2>/dev/null; do
    now=${EPOCHREALTIME/,/.}
    awk -v n="$now" -v t="$t0" -v w="$ISOLATE_TIMEOUT" 'BEGIN { exit !(n - t > w) }' && break
    sleep 0.2
  done
  # The result, from the stamped probe lines: CUT <s> | EARLY <s> | NODROP <s probed after T0> | NOPROBE.
  result=$(awk -v t0="$t0" '
    $2 == "S" { n++; start[n] = $1; next }
    n && !(n in res) { res[n] = $2 }
    END {
      last = 0; ran = 0; first = 0; seen = 0
      for (i = 1; i <= n; i++) {
        if (res[i] == "OK" || res[i] == "HTTP") last = i
        if (start[i] >= t0 && (res[i] == "OK" || res[i] == "HTTP" || res[i] == "DROP")) { ran++; seen = start[i] - t0 }
      }
      for (i = last + 1; i <= n; i++) if (res[i] == "DROP") { first = i; break }
      if (!first && !ran) { print "NOPROBE"; exit }
      if (!first) { printf "NODROP %.1f\n", seen; exit }
      if (start[first] < t0) { printf "EARLY %.2f\n", t0 - start[first]; exit }
      printf "CUT %.2f\n", start[first] - t0
    }' "$WORK_DIR/$pod.probe")
  case $result in
    CUT\ *)
      if awk -v c="${result#CUT }" -v b="$QUARANTINE_BOUND" 'BEGIN { exit !(c <= b) }'; then
        pass "$who: the shop on :8080 dropped ${result#CUT }s after the label (bound ${QUARANTINE_BOUND}s; $ident)"
      else
        fail "$who: the shop on :8080 dropped ${result#CUT }s after the label, over the ${QUARANTINE_BOUND}s bound ($ident)"
      fi ;;
    EARLY\ *)
      fail "$who: the shop stopped answering ${result#EARLY }s BEFORE the label landed, so the label is not what cut it (bound ${QUARANTINE_BOUND}s; $ident)" ;;
    NODROP\ *)
      # Probing stopped early (the probe pod or its exec died) is not the same as the shop staying up.
      if awk -v s="${result#NODROP }" -v w="$ISOLATE_TIMEOUT" 'BEGIN { exit !(s >= w - 1) }'; then
        fail "$who: the shop on :8080 still answered ${result#NODROP }s after the label: no drop within ${ISOLATE_TIMEOUT}s (bound ${QUARANTINE_BOUND}s; $ident)"
      else
        fail "$who: inconclusive: the probe stopped ${result#NODROP }s after the label without a drop ($(grep -m1 ' ERR' "$WORK_DIR/$pod.probe") $(head -c 300 "$WORK_DIR/$pod.probe.err")) (bound ${QUARANTINE_BOUND}s; $ident)"
      fi ;;
    *)
      fail "$who: inconclusive: no probe ran after the label ($(grep -m1 ' ERR' "$WORK_DIR/$pod.probe") $(head -c 300 "$WORK_DIR/$pod.probe.err")) (bound ${QUARANTINE_BOUND}s; $ident)" ;;
  esac
}

# -------------------------------------------------- the one-click scenarios (terminate; quarantine below)
# The plan is read on fd 3: `script` and kubectl must not swallow it from stdin.
while IFS=$'\t' read -r -u 3 id pod detection response timeout tty pre cmd; do
  [ "$response" = quarantine ] && continue  # measured, twice, in its own step below
  step "$id: '$detection' -> $response (timeout ${timeout}s)"

  PODS+=("$pod")
  if ! $KUBECTL apply -f "$WORK_DIR/$pod.json" >/dev/null; then
    fail "$id: pod $pod was not admitted"; delete_pod "$pod"; continue
  fi
  if ! $KUBECTL -n "$NAMESPACE" wait --for=condition=Ready "pod/$pod" --timeout=60s >/dev/null 2>&1; then
    fail "$id: pod $pod did not become Ready (image pull, admission or scheduling problem?)"
    delete_pod "$pod"; continue
  fi
  pass "$id: pod $pod admitted and Ready"
  if ! since=$(pod_created "$pod"); then fail "$id: could not read $pod's creation time"; delete_pod "$pod"; continue; fi

  start=$SECONDS
  run_scenario_exec "$pod" "$tty" "$pre" "$cmd"

  if $KUBECTL -n "$NAMESPACE" wait --for=delete "pod/$pod" --timeout="${timeout}s" >/dev/null 2>&1; then
    pass "$id: pod deleted $((SECONDS - start)) s after the exec started"
  else
    fail "$id: pod $pod still exists after ${timeout}s"
  fi
  stop_exec

  check_falco "$id" "$detection" "$pod" "$since"
  check_talon "$id" "kubernetes:terminate" "$pod" "$since"

  delete_pod "$pod"
done 3< "$WORK_DIR/plan.tsv"

# -------------------------------------------------- quarantine: twice in a row, each under the bound
# A quarantine moves the pod to the quarantined Cilium identity. Whether that identity has to be
# allocated (cold) or already exists (warm) is checked and printed before each run (quarantine_identity
# above), and each measurement is labelled with it. The second run follows the first within seconds,
# so it is expected warm; the first is cold only if nothing was quarantined in the GC window before.
# The list is read on fd 4 (a TTY exec's `script` must not read it from stdin).
if [ -s "$WORK_DIR/quar.tsv" ]; then
  while IFS=$'\t' read -r -u 4 qid detection tty pre cmd; do
    for run in 1 2; do
      who="$qid (quarantine $run of 2)"
      step "$who: isolation under ${QUARANTINE_BOUND}s (ADR 0032)"
      genpod "$qid"; pod=$POD
      if ! $KUBECTL apply -f "$WORK_DIR/$pod.json" >/dev/null 2>"$WORK_DIR/apply.err"; then
        fail "$who: pod not admitted: $(head -c 300 "$WORK_DIR/apply.err")"; delete_pod "$pod"; continue
      fi
      if ! $KUBECTL -n "$NAMESPACE" wait --for=condition=Ready "pod/$pod" --timeout=60s >/dev/null 2>&1; then
        fail "$who: pod $pod did not become Ready"; delete_pod "$pod"; continue
      fi
      if ! since=$(pod_created "$pod"); then fail "$who: could not read $pod's creation time"; delete_pod "$pod"; continue; fi
      if ident=$(quarantine_identity); then
        pass "$who: quarantined identity before the attack: $ident"
      else
        fail "$who: could not list CiliumIdentities, so cold/warm is unknown: $(head -c 300 "$WORK_DIR/identities.err")"
        ident="cold/warm unknown"
      fi
      if arm_isolation "$who" "$pod"; then
        run_scenario_exec "$pod" "$tty" "$pre" "$cmd"
        measure_isolation "$who" "$pod" "${ident%% (*}"
        stop_exec
        phase=$($KUBECTL -n "$NAMESPACE" get pod "$pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)
        if [ "$phase" = Running ]; then pass "$who: still Running (isolated, not killed)"
        else fail "$who: pod is ${phase:-gone}, expected Running"; fi
        check_falco "$who" "$detection" "$pod" "$since"
        check_talon "$who" "kubernetes:label" "$pod" "$since"
      fi
      disarm_isolation
      delete_pod "$pod"
      sleep 2
    done
  done 4< "$WORK_DIR/quar.tsv"
fi

# -------------------------------------------------- the interactive terminal catalogue (ADR 0032)
if [ -s "$WORK_DIR/term.tsv" ]; then
  termid=$(awk -F'\t' '$1 == "TERM" { print $2 }' "$WORK_DIR/term.tsv")
  # The API's format: SDP{ + 16 hex + }.
  FLAG="SDP{$(randhex 8)}"
  quiet_expected=$(awk -F'\t' '$1 == "CMD" && ($3 == "allowed" || $3 == "prevented")' "$WORK_DIR/term.tsv" | wc -l)
  detected_expected=$(awk -F'\t' '$1 == "CMD" && $3 == "detected"' "$WORK_DIR/term.tsv" | wc -l)
  quiet_run=0
  detected_run=0

  # The quiet commands (allowed, prevented) all run in one terminal pod: none ends the run, so this is
  # the pod a visitor keeps while poking around. The loud ones (detected) each get a fresh pod below,
  # because each ends the run.
  step "terminal: the flag, and the allowed/prevented commands on one pod (ADR 0032)"
  SDP_FLAG="$FLAG" genpod "$termid"; tpod=$POD
  if ! $KUBECTL apply -f "$WORK_DIR/$tpod.json" >/dev/null 2>"$WORK_DIR/apply.err"; then
    fail "terminal: pod not admitted: $(head -c 300 "$WORK_DIR/apply.err")"
  elif ! $KUBECTL -n "$NAMESPACE" wait --for=condition=Ready "pod/$tpod" --timeout=60s >/dev/null 2>&1; then
    fail "terminal: pod $tpod did not become Ready"
  elif ! tsince=$(pod_created "$tpod"); then
    fail "terminal: could not read $tpod's creation time"
  else
    pass "terminal: pod $tpod admitted and Ready"

    # Per step, how many Falco log lines name the pod: a step that adds one raised an alert. Each step
    # gets QUIET_WAIT seconds for its alert to land before it is concluded that none fired; a late alert
    # from the step before would show up on the next one, which the message says.
    falco_count() { # -> number of Falco log lines naming the terminal pod; status 2 if unreadable
      read_log falco ds/falco "$tsince" "$WORK_DIR/falco.log" || return 2
      awk -v p="$tpod" 'index($0, p) { n++ } END { print n + 0 }' "$WORK_DIR/falco.log"
    }
    quiet_check() { # who
      local now waited=0
      while :; do
        if ! now=$(falco_count); then
          fail "$1: could not read Falco's log: $(head -c 300 "$WORK_DIR/falco.log.err")"; return
        fi
        if [ "$now" -gt "$seen" ]; then
          fail "$1: a Falco alert names $tpod after it (or late, from the step before): $(awk -v p="$tpod" 'index($0, p)' "$WORK_DIR/falco.log" | tail -n +"$((seen + 1))" | grep -o '"rule":"[^"]*"' | tr '\n' ' ')"
          seen=$now; return
        fi
        [ "$waited" -lt "$QUIET_WAIT" ] || break
        sleep 1; waited=$((waited + 1))
      done
      pass "$1: no Falco alert within ${QUIET_WAIT}s"
    }
    if ! seen=$(falco_count); then
      fail "terminal: could not read Falco's log: $(head -c 300 "$WORK_DIR/falco.log.err")"; seen=0
    fi

    if got=$(exec_in "$tpod" false "cat /srv/shop/.flag"); then
      got=${got//$'\r'/}
      if [ "$got" = "$FLAG" ]; then pass "terminal: the per-run flag is readable at /srv/shop/.flag"
      else fail "terminal: /srv/shop/.flag is '${got:-empty}', expected the injected flag"; fi
    else
      fail "terminal: could not read /srv/shop/.flag ('$(head -1 <<<"$got")')"
    fi
    quiet_check "terminal: the flag read"

    # The list is read on fd 4: nothing run in the loop may read it from stdin.
    while IFS=$'\t' read -r -u 4 tag cid outcome ttyc det resp argv; do
      [ "$tag" = CMD ] || continue
      case $outcome in
        allowed)
          quiet_run=$((quiet_run + 1))
          if out=$(exec_in "$tpod" "$ttyc" "$argv"); then
            if [ "$cid" = read-flag ]; then
              if grep -qF "$FLAG" <<<"$out"; then pass "$cid: prints the flag"; else fail "$cid: flag not printed"; fi
            else
              pass "$cid: runs and exits 0"
            fi
          else
            fail "$cid: expected allowed but it failed ('$(head -1 <<<"$out")')"
          fi
          quiet_check "$cid" ;;
        prevented)
          # The exact refusal each command must get: a non-zero exit is not enough (a typo, or kubectl's
          # own error, also exits non-zero), so the kernel's message for the control the catalogue
          # claims is required, and a prevented command with no expectation here is a failure.
          case $cid in
            touch-bin)  want="Read-only file system" ;;
            read-token) want="No such file or directory" ;;
            chown-root) want="Operation not permitted" ;;
            *)          want= ;;
          esac
          quiet_run=$((quiet_run + 1))
          if [ -z "$want" ]; then
            fail "$cid: prevented, but run.sh has no expected refusal for it - add one"
          elif out=$(exec_in "$tpod" "$ttyc" "$argv"); then
            fail "$cid: expected prevented but it succeeded ('$out')"
          elif ! grep -qiF "$want" <<<"$out"; then
            fail "$cid: refused, but not with '$want' ('$(head -1 <<<"$out")')"
          else
            pass "$cid: refused by the pod ('$(head -1 <<<"$out")')"
          fi
          quiet_check "$cid" ;;
        detected) : ;;  # run on fresh pods below
        *) fail "$cid: unknown outcome '$outcome'" ;;
      esac
    done 4< "$WORK_DIR/term.tsv"
    phase=$($KUBECTL -n "$NAMESPACE" get pod "$tpod" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    if [ "$phase" = Running ]; then pass "terminal: the pod is still Running after the quiet commands"
    else fail "terminal: the pod is ${phase:-gone} after only allowed/prevented commands"; fi
  fi
  delete_pod "$tpod"
  if [ "$quiet_run" -eq "$quiet_expected" ]; then pass "terminal: all $quiet_expected allowed/prevented commands were run"
  else fail "terminal: only $quiet_run of $quiet_expected allowed/prevented commands were run"; fi

  # Each detected command on its own fresh pod: run it the way the API will (argv, tty, empty stdin),
  # then assert the named Falco rule, the Talon action and the end state. drop-run is proven here: only
  # a live run shows Falco's proc.exepath for the dropped binary reads /srv/shop/..., not a host path.
  # The list is read on fd 4: the `shell` command's backgrounded `script` must not read it from stdin.
  while IFS=$'\t' read -r -u 4 tag cid outcome ttyc det resp argv; do
    { [ "$tag" = CMD ] && [ "$outcome" = detected ]; } || continue
    step "terminal/$cid: '$det' -> $resp (ADR 0032)"
    SDP_FLAG="$FLAG" genpod "$termid"; dpod=$POD
    if ! $KUBECTL apply -f "$WORK_DIR/$dpod.json" >/dev/null 2>"$WORK_DIR/apply.err"; then
      fail "$cid: pod not admitted: $(head -c 300 "$WORK_DIR/apply.err")"; delete_pod "$dpod"; continue
    fi
    if ! $KUBECTL -n "$NAMESPACE" wait --for=condition=Ready "pod/$dpod" --timeout=60s >/dev/null 2>&1; then
      fail "$cid: pod $dpod did not become Ready"; delete_pod "$dpod"; continue
    fi
    if ! since=$(pod_created "$dpod"); then fail "$cid: could not read $dpod's creation time"; delete_pod "$dpod"; continue; fi
    case $resp in
      terminate)
        detected_run=$((detected_run + 1))
        start_exec "$dpod" "$ttyc" "$argv"
        if $KUBECTL -n "$NAMESPACE" wait --for=delete "pod/$dpod" --timeout=60s >/dev/null 2>&1; then
          pass "$cid: pod deleted after the command"
        else
          fail "$cid: pod $dpod still exists 60 s after the command"
        fi
        stop_exec
        check_falco "$cid" "$det" "$dpod" "$since"
        check_talon "$cid" "kubernetes:terminate" "$dpod" "$since" ;;
      quarantine)
        if ident=$(quarantine_identity); then
          pass "$cid: quarantined identity before the command: $ident"
        else
          fail "$cid: could not list CiliumIdentities, so cold/warm is unknown: $(head -c 300 "$WORK_DIR/identities.err")"
          ident="cold/warm unknown"
        fi
        if arm_isolation "$cid" "$dpod"; then
          detected_run=$((detected_run + 1))
          start_exec "$dpod" "$ttyc" "$argv"
          measure_isolation "$cid" "$dpod" "${ident%% (*}"
          stop_exec
          phase=$($KUBECTL -n "$NAMESPACE" get pod "$dpod" -o jsonpath='{.status.phase}' 2>/dev/null || true)
          if [ "$phase" = Running ]; then pass "$cid: still Running (isolated, not killed)"; else fail "$cid: pod is ${phase:-gone}, expected Running"; fi
          check_falco "$cid" "$det" "$dpod" "$since"
          check_talon "$cid" "kubernetes:label" "$dpod" "$since"
        fi
        disarm_isolation ;;
      *)
        fail "$cid: unknown response '$resp'" ;;
    esac
    delete_pod "$dpod"
  done 4< "$WORK_DIR/term.tsv"
  if [ "$detected_run" -eq "$detected_expected" ]; then pass "terminal: all $detected_expected detected commands were run"
  else fail "terminal: only $detected_run of $detected_expected detected commands were run"; fi
fi

# ---------------------------------------------------------------------------- result

step "result"
if [ "$failures" -ne 0 ]; then
  printf '  %s assertion(s) failed\n' "$failures" >&2
  exit 1
fi
# A run that asserted nothing proved nothing (a scenario list that selected nothing, a section skipped).
[ "$asserted" -gt 0 ] || die "no scenario assertion ran${ONLY:+ for ONLY=$ONLY}; nothing was tested"
printf '  scenario tests: ok (%s assertions)\n' "$asserted"
