#!/usr/bin/env bash
# The abuse limits of the public API (ADR 0015), as an executable assertion: the attack trigger is
# rationed per visitor and globally, only one run happens at a time, and the cheap endpoints have a
# budget too. Everything is asserted from the outside, over HTTP, against a running API.
#
#   tests/abuse/run.sh                                     (or: make abuse-test) - the live site
#   API=http://127.0.0.1:8080 FAKE_IPS=1 tests/abuse/run.sh                       - via port-forward
#
# Through the real site every request carries this machine's address in CF-Connecting-IP (Cloudflare
# overwrites whatever the client sends), so the run spends *your* attack quota for 10 minutes and
# takes as long as up to three scenario runs (a few minutes). With `kubectl -n portfolio-api
# port-forward deploy/portfolio-api 8080` and FAKE_IPS=1 the script sets CF-Connecting-IP itself and
# can act as several visitors; the port-forward bypasses Cloudflare, which is the only reason the
# header is then the script's to choose.
#
# Cases:
#   1. 404 for an unknown scenario, 403 for a cross-origin or cross-site POST (neither spends quota).
#   2. A burst of parallel attack requests: at most one 202, every other answer 409 or 429, no 5xx.
#   3. One visitor triggers until refused: at most 3 accepted per 10 minutes, then 429 with a
#      Retry-After of at most 600 s. Every accepted run is followed on the event stream to its end.
#   4. The event stream: per-visitor cap on concurrent streams (the 5th gets 429).
#   5. The request budget: 130 quick requests to /api/scenarios get at least one 429 (120 / min).
#      Last, because it locks this visitor out of every endpoint for up to a minute.
#
# Needs curl. The global limit (30 / hour) is not exhausted here - that would take 30 runs; it is
# covered by the Go integration test (app/api/internal/server, TestHammer) with smaller numbers.
set -euo pipefail

API=${API:-https://hubertjablon.ski}
API=${API%/}
FAKE_IPS=${FAKE_IPS:-}
# The scenario to trigger; defaults to the first one the API lists.
SCENARIO=${SCENARIO:-}
# How long to follow one run on the event stream before giving up (scenario timeout is <= 120 s).
RUN_TIMEOUT=${RUN_TIMEOUT:-150}

WORK_DIR=$(mktemp -d)
PIDS=()
cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

failures=0
step() { printf '\n==> %s\n' "$*"; }
pass() { printf '  PASS  %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*" >&2; failures=$((failures + 1)); }
die() { printf 'run.sh: %s\n' "$*" >&2; exit 1; }

# The visitor a request claims to be: a documentation address (RFC 5737) per name, only in
# FAKE_IPS mode.
visitor_args() {
  [ -n "$FAKE_IPS" ] || return 0
  case $1 in
    main) printf -- '-H\nCF-Connecting-IP: 192.0.2.10\n' ;;
    burst*) printf -- '-H\nCF-Connecting-IP: 192.0.2.%s\n' "$((20 + ${1#burst}))" ;;
    budget) printf -- '-H\nCF-Connecting-IP: 192.0.2.99\n' ;;
  esac
}

# request <visitor> <method> <path> [curl args...] -> prints "<status> <retry-after>"; the body is
# left in $WORK_DIR/body.<visitor> (one file per visitor, so parallel visitors do not collide).
request() {
  local who=$1 method=$2 path=$3; shift 3
  local -a extra=()
  mapfile -t extra < <(visitor_args "$who")
  local status retry
  # `|| true`: curl exits non-zero when --max-time cuts a stream short, but the status it printed
  # is still the answer.
  status=$(curl -sS -o "$WORK_DIR/body.$who" -D "$WORK_DIR/headers.$who" -w '%{http_code}' \
             -X "$method" --max-time 20 "${extra[@]}" "$@" "$API$path" 2>/dev/null) || true
  retry=$(sed -n 's/^[Rr]etry-[Aa]fter:[[:space:]]*\([0-9]*\).*/\1/p' "$WORK_DIR/headers.$who" 2>/dev/null | head -1)
  printf '%s %s\n' "${status:-000}" "${retry:--}"
}

run_id_of() { grep -o '"run_id":"[0-9a-f]*"' "$WORK_DIR/body.$1" 2>/dev/null | sed 's/"run_id":"\(.*\)"/\1/'; }

# follow_run <run_id>: reads the event stream until that run reaches a terminal state, prints it.
follow_run() {
  local run_id=$1
  local -a extra=()
  mapfile -t extra < <(visitor_args main)
  curl -sS -N --max-time "$RUN_TIMEOUT" "${extra[@]}" "$API/api/events" 2>/dev/null \
    | grep --line-buffered '^data: ' \
    | grep --line-buffered "\"run_id\":\"$run_id\"" \
    | grep -m1 -o '"state":"\(finished\|failed\|timeout\)"' \
    | sed 's/"state":"\(.*\)"/\1/' || true
}

# ---------------------------------------------------------------------------- preflight

step "preflight ($API${FAKE_IPS:+, fake visitor addresses})"

read -r code _ < <(request main GET /api/healthz)
[ "$code" = 200 ] || die "GET /api/healthz answered $code; is the API reachable at $API?"
pass "API is up"

read -r code _ < <(request main GET /api/scenarios)
[ "$code" = 200 ] || die "GET /api/scenarios answered $code"
if [ -z "$SCENARIO" ]; then
  SCENARIO=$(grep -o '"id":"[a-z0-9-]*"' "$WORK_DIR/body.main" | head -1 | sed 's/"id":"\(.*\)"/\1/')
fi
[ -n "$SCENARIO" ] || die "the API lists no scenarios; is the scenarios ConfigMap deployed?"
pass "scenario under test: $SCENARIO"

# ---------------------------------------------------------------------------- 1. refusals that cost nothing

step "unknown scenarios and cross-origin requests are refused without spending quota"

# expect <want> <got> <what>
expect() { if [ "$2" = "$1" ]; then pass "$3 -> $2"; else fail "$3 -> $2, want $1"; fi; }

read -r code _ < <(request main POST /api/attack/no-such-scenario-abuse-test)
expect 404 "$code" "unknown scenario"
read -r code _ < <(request main POST "/api/attack/$SCENARIO" -H 'Origin: https://attacker.example')
expect 403 "$code" "foreign Origin"
read -r code _ < <(request main POST "/api/attack/$SCENARIO" -H 'Sec-Fetch-Site: cross-site')
expect 403 "$code" "Sec-Fetch-Site: cross-site"

# ---------------------------------------------------------------------------- 2. the burst

step "a burst of 10 parallel attack requests: at most one is accepted"

for i in $(seq 1 10); do
  ( read -r code retry < <(request "burst$i" POST "/api/attack/$SCENARIO")
    printf '%s %s %s\n' "$code" "$retry" "$(run_id_of "burst$i")" > "$WORK_DIR/burst.$i" ) &
done
wait

accepted=0; busy=0; limited=0; other=0; burst_run=
for i in $(seq 1 10); do
  read -r code retry run_id < "$WORK_DIR/burst.$i" || true
  case $code in
    202) accepted=$((accepted + 1)); burst_run=$run_id ;;
    409) busy=$((busy + 1)) ;;
    429) limited=$((limited + 1)); [ "$retry" != - ] || fail "429 without Retry-After" ;;
    *) other=$((other + 1)); fail "burst request answered $code" ;;
  esac
done
printf '        202 x%s, 409 x%s, 429 x%s, other x%s\n' "$accepted" "$busy" "$limited" "$other"
if [ "$accepted" -le 1 ]; then pass "at most one run accepted"; else fail "$accepted runs accepted at once"; fi
if [ $((busy + limited)) -ge 9 ]; then pass "the rest were refused with 409 / 429"; else fail "only $((busy + limited)) refusals"; fi

if [ -n "$burst_run" ]; then
  state=$(follow_run "$burst_run")
  if [ -n "$state" ]; then
    pass "burst run $burst_run ended: $state"
  else
    fail "burst run $burst_run did not end within ${RUN_TIMEOUT}s"
  fi
fi

# ---------------------------------------------------------------------------- 3. one visitor's quota

step "one visitor: at most 3 runs per 10 minutes, then 429 with Retry-After"

runs=0
refused=
deadline=$((SECONDS + 4 * RUN_TIMEOUT))
while [ "$SECONDS" -lt "$deadline" ]; do
  read -r code retry < <(request main POST "/api/attack/$SCENARIO")
  case $code in
    202)
      runs=$((runs + 1))
      run_id=$(run_id_of main)
      state=$(follow_run "$run_id")
      [ -n "$state" ] || fail "run $run_id did not end within ${RUN_TIMEOUT}s"
      printf '        run %s: %s\n' "$runs" "${state:-?}"
      ;;
    409) sleep 3 ;;  # someone else's run (or the burst's) is in progress
    429) refused=$retry; break ;;
    *) fail "attack answered $code"; break ;;
  esac
done

if [ -z "$refused" ]; then
  fail "never refused after $runs accepted runs"
else
  if [ "$runs" -le 3 ]; then pass "$runs run(s) accepted before the 429"; else fail "$runs runs accepted, limit is 3"; fi
  if [ "$refused" != - ] && [ "$refused" -ge 1 ] && [ "$refused" -le 3600 ]; then
    pass "429 carries Retry-After: $refused"
  else
    fail "429 Retry-After is '$refused'"
  fi
fi

read -r code _ < <(request main POST "/api/attack/$SCENARIO")
expect 429 "$code" "the next attempt"

# ---------------------------------------------------------------------------- 4. stream cap

step "event streams: at most 4 per visitor"

for i in 1 2 3 4; do
  mapfile -t extra < <(visitor_args main)
  curl -sS -N --max-time 30 "${extra[@]}" -o /dev/null "$API/api/events" 2>/dev/null &
  PIDS+=("$!")
done
sleep 2
read -r code retry < <(request main GET /api/events --max-time 3)
if [ "$code" = 429 ]; then
  pass "5th concurrent stream -> 429 (Retry-After: $retry)"
else
  fail "5th concurrent stream -> $code, want 429"
fi
for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
PIDS=()

# ---------------------------------------------------------------------------- 5. request budget

step "request budget: 130 quick requests to /api/scenarios"

limited=0
for _ in $(seq 1 130); do
  read -r code _ < <(request budget GET /api/scenarios)
  if [ "$code" = 429 ]; then limited=$((limited + 1)); fi
done
if [ "$limited" -ge 1 ]; then pass "$limited of 130 answered 429"; else fail "no 429 in 130 requests (budget is 120 / min)"; fi

step "result"
if [ "$failures" -ne 0 ]; then
  printf '  %s assertion(s) failed\n' "$failures" >&2
  exit 1
fi
printf '  abuse tests: ok\n'
