#!/usr/bin/env bash
# The attack scenarios' detection chain, checked without a cluster (ADR 0018). Needs docker and python3
# with PyYAML; pulls the pinned Falco and Falco Talon images and builds app/scenario locally.
#
#   tests/scenarios/offline.sh                     (or: make scenario-offline)
#   DOCKER="sudo -n docker" tests/scenarios/offline.sh
#
# What it proves, per link:
#   1. Falco loads the rules: the image's falco_rules.yaml plus cluster/infra/falco's customRules
#      validate with the pinned Falco binary (`falco -V`).
#   2. The names line up: every scenario's `detection`, and every rule Talon matches on, is a rule that
#      Falco actually loads, enabled, at a priority Falcosidekick forwards (>= notice). A renamed or
#      disabled upstream rule fails here instead of silently never firing.
#   3. Talon loads its rules (`falco-talon rules check`, pinned binary).
#   4. Each scenario meets its rule's preconditions under the pod's own security context. The scenario
#      image is built from app/scenario and run with the pod spec's uid/gid, supplemental groups,
#      read-only root filesystem, no capabilities, no-new-privileges and no network, and the scenario's
#      exec is run in it. Per rule, the facts the Falco condition depends on are asserted: a TTY for the
#      terminal-shell rule, the process name for the network-tool rule, a *successful* open for the
#      sensitive-file rule (open_read requires fd.num >= 0), and an executable on the overlay root for
#      the drift rule (proc.is_exe_upper_layer). The two design decisions those rules force are checked
#      from the other side as well: without the shadow group the read fails, and with a read-only root
#      the drop fails. Where an exec is a shell that first marks the victim and then `exec`s the
#      detected program (ADR 0022), the checks apply to that program - the process Falco sees.
#   5. The victim (ADR 0022), for scenarios with `victim: true`: the pod's own readiness probe reads a
#      healthy /state.json ("up") under the same security context, and running the scenario's exec
#      changes it (status, banner, and for a defacement the page checksum) - what the visitor watches.
#
# What it cannot prove: that Falco *emits* the alert. That needs the syscalls themselves - a live probe
# (BPF, PERFMON and CAP_SYS_RESOURCE to lock its ring buffers, which a CI or build sandbox container
# usually lacks) or a capture file replayed with `falco -e`. No capture is committed: one would have to
# be recorded with the same probe, and a capture taken outside Kubernetes carries no CRI pod metadata,
# so "SDP network tool in sandbox" (k8s.ns.name = sandbox) could not match it anyway. The end-to-end
# proof is tests/scenarios/run.sh against the live cluster.
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT=$(cd ../.. && pwd)

DOCKER=${DOCKER:-docker}
# Same digests as cluster/infra/falco/kustomization.yaml and cluster/infra/falco-response/talon-deployment.yaml.
FALCO_IMAGE=${FALCO_IMAGE:-docker.io/falcosecurity/falco:0.45.0@sha256:788f1129c542171813083d4afc61b16730a47dde8c23d9c39370acef996349b6}
TALON_IMAGE=${TALON_IMAGE:-docker.io/falcosecurity/falco-talon:0.3.0@sha256:333224a111a0722ff3f418ffe6bc5d8a3be0941f37c67520bc845e62f1234ad3}
SCENARIO_TAG=sdp-scenario:offline-test
SCENARIOS=$REPO_ROOT/cluster/infra/sandbox/scenarios/scenarios.yaml

WORK_DIR=$(mktemp -d)
CONTAINERS=()
cleanup() {
  for c in "${CONTAINERS[@]}"; do $DOCKER rm -f "$c" >/dev/null 2>&1 || true; done
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

failures=0
step() { printf '\n==> %s\n' "$*"; }
pass() { printf '  PASS  %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*" >&2; failures=$((failures + 1)); }

# ---------------------------------------------------------------------------- 1. Falco loads the rules

step "falco -V: stock rules + cluster/infra/falco customRules ($FALCO_IMAGE)"

# The chart's values are the helmCharts entry of the falco kustomization (ADR 0013, amendment).
python3 - "$REPO_ROOT/cluster/infra/falco/kustomization.yaml" "$WORK_DIR" <<'PY'
import sys, yaml
kust = yaml.safe_load(open(sys.argv[1]))
rules = {}
for chart in kust.get("helmCharts", []):
    if chart.get("name") == "falco":
        rules = chart.get("valuesInline", {}).get("customRules", {})
if not rules:
    sys.exit("offline.sh: no customRules in the falco helmCharts entry")
for name, body in rules.items():
    open(f"{sys.argv[2]}/{name}", "w").write(body)
PY
mapfile -t CUSTOM < <(cd "$WORK_DIR" && ls ./*.yaml)
mounts=() ; validate=(-V /etc/falco/falco_rules.yaml)
for f in "${CUSTOM[@]}"; do
  mounts+=(-v "$WORK_DIR/${f#./}:/etc/falco/rules.d/${f#./}:ro")
  validate+=(-V "/etc/falco/rules.d/${f#./}")
done
if out=$($DOCKER run --rm "${mounts[@]}" "$FALCO_IMAGE" falco "${validate[@]}" 2>&1) \
   && ! grep -v ': Ok$' <<<"$out" | grep -qiE 'error|invalid'; then
  pass "$(grep -c ': Ok$' <<<"$out") rules file(s) valid: $(grep ': Ok$' <<<"$out" | cut -d: -f1 | xargs)"
else
  fail "falco -V failed"; printf '%s\n' "$out" | tail -20 >&2
fi

# ---------------------------------------------------------------------------- 2. the names line up

step "every scenario detection and every Talon match is a loaded, enabled rule at >= notice"

# -L with json_output lists every rule Falco loads from its default config (falco_rules.yaml and
# rules.d), with its enabled state and priority after all overrides are applied.
$DOCKER run --rm "${mounts[@]}" "$FALCO_IMAGE" falco -L -o json_output=true 2>/dev/null > "$WORK_DIR/rules.json"
python3 - "$WORK_DIR/rules.json" "$SCENARIOS" "$REPO_ROOT/cluster/infra/falco-response/talon/rules.yaml" <<'PY' \
  > "$WORK_DIR/names.txt"
import json, sys, yaml
loaded = {r["info"]["name"]: r["info"] for r in json.load(open(sys.argv[1]))["rules"]}
order = ["debug", "informational", "notice", "warning", "error", "critical", "alert", "emergency"]
wanted = [(f"scenario {s['id']}", s["detection"]) for s in yaml.safe_load(open(sys.argv[2]))]
wanted += [(f"talon rule '{t['rule']}'", name)
           for t in yaml.safe_load(open(sys.argv[3])) if "rule" in t for name in t["match"]["rules"]]
for who, name in wanted:
    info = loaded.get(name)
    if info is None:
        print(f"FAIL\t{who}: Falco rule '{name}' is not loaded")
    elif not info["enabled"]:
        print(f"FAIL\t{who}: Falco rule '{name}' is disabled")
    elif order.index(info["priority"].lower()) < order.index("notice"):
        print(f"FAIL\t{who}: Falco rule '{name}' is {info['priority']}, below Falcosidekick's notice cut-off")
    else:
        print(f"PASS\t{who} -> '{name}' ({info['priority']}, enabled)")
PY
while IFS=$'\t' read -r verdict msg; do
  if [ "$verdict" = PASS ]; then pass "$msg"; else fail "$msg"; fi
done < "$WORK_DIR/names.txt"

# ---------------------------------------------------------------------------- 3. Talon loads its rules

step "falco-talon rules check ($TALON_IMAGE)"

talon_dir=$REPO_ROOT/cluster/infra/falco-response/talon
if out=$($DOCKER run --rm -v "$talon_dir":/t:ro "$TALON_IMAGE" rules check -c /t/config.yaml -r /t/rules.yaml 2>&1) \
   && grep -q 'rules file valid' <<<"$out"; then
  pass "talon/rules.yaml valid"
else
  fail "falco-talon rules check failed"; printf '%s\n' "$out" | tail -20 >&2
fi

# ---------------------------------------------------------------------------- 4. preconditions

step "scenario preconditions under each pod's security context (image built from app/scenario)"

$DOCKER build -q -t "$SCENARIO_TAG" "$REPO_ROOT/app/scenario" >/dev/null
pass "built $SCENARIO_TAG"

# One line per scenario: id, detection, then shell-quoted docker flags, container command and exec
# command. The flags translate the pod spec's security context, not a hand-written copy of it.
python3 - "$SCENARIOS" <<'PY' > "$WORK_DIR/scenarios.tsv"
import re, shlex, sys, yaml
SHELLS = {"ash", "bash", "csh", "ksh", "sh", "tcsh", "zsh", "dash"}
for s in yaml.safe_load(open(sys.argv[1])):
    pod = s["pod"]; psc = pod.get("securityContext", {})
    target = next(c for c in pod["containers"] if c["name"] == "target")
    csc = target.get("securityContext", {})
    uid = csc.get("runAsUser", psc.get("runAsUser")); gid = csc.get("runAsGroup", psc.get("runAsGroup"))
    flags = ["--user", f"{uid}:{gid}", "--network", "none", "--security-opt", "no-new-privileges",
             "--memory", target["resources"]["limits"]["memory"].replace("Mi", "m")]
    # emptyDir volumes become a tmpfs at the same path: writable, separate from the root filesystem
    # (and so, like an emptyDir, not the overlay upper layer the drift rule looks at).
    empty = {v["name"]: v["emptyDir"] for v in pod.get("volumes", []) if "emptyDir" in v}
    for m in target.get("volumeMounts", []):
        if m["name"] in empty:
            size = str(empty[m["name"]].get("sizeLimit", "1Mi")).replace("Mi", "m").replace("Ki", "k")
            flags += ["--tmpfs", f"{m['mountPath']}:rw,size={size},mode=1777"]
    if csc.get("capabilities", {}).get("drop") == ["ALL"]:
        flags += ["--cap-drop", "ALL"]
    for g in psc.get("supplementalGroups", []):
        flags += ["--group-add", str(g)]
    if csc.get("readOnlyRootFilesystem"):
        flags += ["--read-only"]
    exec_ = s["exec"] or {"command": [], "tty": False}
    # The program the rule sees: argv0, or for `sh -c '...; exec prog ...'` the last program the
    # shell replaces itself with (ADR 0022: the shell marks the victim first).
    command = exec_["command"]
    trigger = command[0] if command else ""
    if len(command) >= 3 and command[0].rsplit("/", 1)[-1] in SHELLS and command[1] == "-c":
        execs = re.findall(r"(?:^|[;&|]\s*)exec\s+(\S+)", command[2])
        trigger = execs[-1] if execs else command[0]
    probe = (target.get("readinessProbe") or {}).get("exec", {}).get("command", [])
    print("\t".join([s["id"], s["detection"], shlex.join(flags), shlex.join(target["command"]),
                     shlex.join(command), str(exec_["tty"]).lower(), trigger.rsplit("/", 1)[-1],
                     str(bool(s.get("victim"))).lower(), shlex.join(probe)]))
PY

# Starts the scenario's pod as a container with the given flags; prints its name.
start() {
  local name="sdp-offline-$1-$RANDOM"; shift
  local flags=$1 cmd=$2
  eval "$DOCKER run -d --name $name $flags $SCENARIO_TAG $cmd" >/dev/null
  CONTAINERS+=("$name")
  printf '%s' "$name"
}

# The status field of a /state.json body (compact JSON, as the victim writes it).
field() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" <<<"$2"; }

while IFS=$'\t' read -r id detection flags cmd exec_cmd tty trigger victim probe; do
  printf '  -- %s (%s)\n' "$id" "$detection"
  c=$(start "$id" "$flags" "$cmd")
  case $detection in
    "Terminal shell in container")
      # proc.name in shell_binaries, proc.tty != 0. `tty` prints the controlling terminal, or "not a tty".
      if [ "$tty" = true ]; then pass "$id: exec asks for a TTY"; else fail "$id: exec must set tty: true for this rule"; fi
      argv0=$(eval "set -- $exec_cmd"; basename "$1")
      case $argv0 in ash|bash|csh|ksh|sh|tcsh|zsh|dash) pass "$id: proc.name '$argv0' is in shell_binaries" ;;
        *) fail "$id: '$argv0' is not in Falco's shell_binaries" ;; esac
      if out=$($DOCKER exec -t "$c" "$argv0" -c tty 2>&1) && grep -q '^/dev/pts/' <<<"$out"; then
        pass "$id: the shell runs with a terminal ($(tr -d '\r' <<<"$out"))"
      else
        fail "$id: no terminal in the exec ($out)"
      fi
      ;;
    "SDP network tool in sandbox")
      # proc.name in (wget, nc, curl): the base name of the path executed, symlink included.
      case $trigger in wget|nc|curl) pass "$id: proc.name '$trigger' is in the rule's list" ;;
        *) fail "$id: '$trigger' is not wget/nc/curl" ;; esac
      start_s=$SECONDS
      out=$(eval "$DOCKER exec $c $exec_cmd" 2>&1 || true)
      if grep -qi 'refused' <<<"$out" && [ $((SECONDS - start_s)) -le 5 ]; then
        pass "$id: the tool starts and fails fast without network (\"$(head -1 <<<"$out")\")"
      else
        fail "$id: unexpected result of the exec: $out"
      fi
      ;;
    "Read sensitive file untrusted")
      # open_read needs fd.num >= 0, i.e. the open must succeed; cat is not a trusted reader. A shell
      # is (shell_binaries is on the rule's exclusion list), so the file must be opened by the
      # exec'd program, not by a shell redirect.
      case $trigger in ash|bash|csh|ksh|sh|tcsh|zsh|dash|"") fail "$id: the file would be opened by '$trigger', which the rule trusts" ;;
        *) pass "$id: proc.name '$trigger' opens the file (not on the rule's trusted lists)" ;; esac
      if out=$(eval "$DOCKER exec $c $exec_cmd" 2>&1) && grep -q '^root:' <<<"$out"; then
        pass "$id: the read succeeds as uid $(eval "$DOCKER exec $c id -u") (open_read matches)"
      else
        fail "$id: the read failed, so the rule would not fire: $out"
      fi
      if grep -q '^root:[*!]:' <<<"$out" && ! grep -qE '^[^:]+:\$' <<<"$out"; then
        pass "$id: no password hash in what the visitor sees (all accounts locked)"
      else
        fail "$id: /etc/shadow in the image contains a password hash"
      fi
      # The other side: without the supplemental group the open fails with EACCES and nothing fires.
      c2=$(start "$id-nogroup" "$(sed -E 's/--group-add [0-9]+//g' <<<"$flags")" "$cmd")
      if out=$(eval "$DOCKER exec $c2 $exec_cmd" 2>&1); then
        fail "$id: readable without the shadow group - the image's /etc/shadow mode is too open"
      else
        pass "$id: without supplementalGroups the read is denied (\"$out\")"
      fi
      ;;
    "Drop and execute new binary in container")
      # proc.is_exe_upper_layer: the executable must live on the overlay root, not on a separate mount.
      eval "$DOCKER exec -d $c $exec_cmd"
      exe=
      for _ in 1 2 3 4 5; do
        # shellcheck disable=SC2016  # expanded by the container's shell
        exe=$($DOCKER exec "$c" sh -c 'for p in /proc/[0-9]*; do readlink "$p/exe"; done' 2>/dev/null \
          | grep '^/tmp/' | head -1 || true)
        [ -n "$exe" ] && break
        sleep 1
      done
      if [ -n "$exe" ]; then pass "$id: a process runs from $exe"; else fail "$id: no process runs from /tmp"; fi
      mounts_out=$($DOCKER exec "$c" cat /proc/self/mountinfo)
      if awk '$5 == "/" && $0 ~ / - overlay /' <<<"$mounts_out" | grep -q . \
         && ! awk '{print $5}' <<<"$mounts_out" | grep -qx '/tmp'; then
        pass "$id: / is overlayfs and /tmp is not a separate mount (the binary is in the upper layer)"
      else
        fail "$id: /tmp is a separate mount or / is not overlayfs; is_exe_upper_layer would be false"
      fi
      # The other side: on a read-only root (what every other scenario runs with) the drop fails.
      c2=$(start "$id-ro" "$flags --read-only" "$cmd")
      if out=$(eval "$DOCKER exec $c2 $exec_cmd" 2>&1); then
        fail "$id: the drop succeeded on a read-only root?"
      else
        pass "$id: with readOnlyRootFilesystem the drop fails (\"$(head -1 <<<"$out")\")"
      fi
      ;;
    *)
      fail "$id: no offline precondition check for rule '$detection' - add one here"
      ;;
  esac

  # 5. The victim: healthy before, visibly changed by the exec (detached: the shell and drift
  # scenarios sleep until a kill that does not come here).
  if [ "$victim" = true ]; then
    if [ -z "$probe" ]; then fail "$id: victim: true but no exec readinessProbe"; continue; fi
    c3=$(start "$id-victim" "$flags" "$cmd")
    before=
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      before=$(eval "$DOCKER exec $c3 $probe" 2>/dev/null) && break
      before=; sleep 0.5
    done
    if [ "$(field status "$before")" = up ]; then
      pass "$id: the readiness probe reads a healthy shop ($before)"
    else
      fail "$id: the victim is not up under the pod's security context: '${before:-no answer}'"
      continue
    fi
    eval "$DOCKER exec -d $c3 $exec_cmd"
    after=
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      after=$(eval "$DOCKER exec $c3 $probe" 2>/dev/null || true)
      [ -n "$after" ] && [ "$(field status "$after")" != up ] && break
      sleep 0.5
    done
    if [ -n "$after" ] && [ "$(field status "$after")" != up ]; then
      changed="checksum unchanged"
      [ "$(field checksum "$after")" != "$(field checksum "$before")" ] && changed="page checksum changed"
      pass "$id: the exec changes the victim: $(field status "$after"), \"$(field banner "$after")\", $changed"
    else
      fail "$id: the exec did not change the victim's state ('${after:-no answer}')"
    fi
  fi
done < "$WORK_DIR/scenarios.tsv"

# ---------------------------------------------------------------------------- result

step "result"
if [ "$failures" -ne 0 ]; then
  printf '  %s assertion(s) failed\n' "$failures" >&2
  exit 1
fi
printf '  scenario offline checks: ok\n'
