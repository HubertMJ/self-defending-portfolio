#!/usr/bin/env bash
# Smoke test of the built web image, run the way the hello Deployment runs it (read-only root, uid
# 101, no capabilities, tmpfs for nginx's three writable paths). Checks what only the real nginx can
# get wrong, not the dev server: the cache policy by status (ADR 0019, amendment) and the headers.
# Also what only the image build can get wrong (ADR 0035): /build.json names the commit it was built
# from, and no file the image serves carries a trace of the MockBackend.
#
#   app/web/test/image-smoke.sh <image ref>      e.g. ghcr.io/hubertmj/self-defending-portfolio/web@sha256:...
#
# With GITHUB_SHA and GITHUB_RUN_ID set (always, in Actions), /build.json must name exactly that commit
# and that run. Needs curl and jq.
#
# build-images.yml runs it after the push and before signing, for every app/<name> that has a
# test/image-smoke.sh: an image that fails it is never signed, so Kyverno never admits it.
set -euo pipefail
IMAGE=${1:?usage: $0 <image ref>}
command -v jq >/dev/null || { echo "image-smoke: jq is required (it parses /build.json)" >&2; exit 2; }
DOCKER=${DOCKER:-docker}
PORT=${PORT:-18089}
name=web-smoke-$$

cleanup() { $DOCKER rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

$DOCKER run -d --name "$name" --read-only --user 101:101 --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp --tmpfs /var/cache/nginx --tmpfs /var/run -p "127.0.0.1:$PORT:8080" "$IMAGE" >/dev/null

base=http://127.0.0.1:$PORT
for _ in $(seq 1 30); do
  curl -fsS -o /dev/null "$base/healthz" 2>/dev/null && break
  sleep 0.5
done

failures=0
check() { # description, actual, expected
  if [ "$2" = "$3" ]; then printf '  PASS  %s\n' "$1"; else printf '  FAIL  %s: got %q, want %q\n' "$1" "$2" "$3" >&2; failures=$((failures + 1)); fi
}
status() { curl -s -o /dev/null -w '%{http_code}' "$1"; }
header() { curl -s -o /dev/null -D - "$1" | tr -d '\r' | sed -n "s/^$2: //Ip" | head -1; }

index=$(curl -fsS "$base/")
asset=$(grep -o '/assets/main-[A-Za-z0-9_-]*\.js' <<<"$index" | head -1)
check "index.html references a hashed main bundle" "${asset:+yes}" yes

check "index.html: 200" "$(status "$base/")" 200
check "index.html: Cache-Control" "$(header "$base/" Cache-Control)" "no-cache"
check "index.html: CSP present" "$(header "$base/" Content-Security-Policy | grep -c "require-trusted-types-for 'script'")" 1
check "existing asset: 200" "$(status "$base$asset")" 200
check "existing asset: Cache-Control" "$(header "$base$asset" Cache-Control)" "public, max-age=31536000, immutable"
check "missing asset: 404" "$(status "$base/assets/main-NOTBUILT.js")" 404
check "missing asset: never cacheable" "$(header "$base/assets/main-NOTBUILT.js" Cache-Control)" "no-store"
check "missing page: 404" "$(status "$base/no-such-page")" 404
check "missing page: never cacheable" "$(header "$base/no-such-page" Cache-Control)" "no-store"
check "/api is never served by nginx" "$(status "$base/api/events")" 404

# /build.json (ADR 0035): written by the Dockerfile from GIT_SHA and CI_RUN_ID, each value either of
# the right shape or "".
build=$(curl -s "$base/build.json")
check "/build.json: 200" "$(status "$base/build.json")" 200
check "/build.json: Cache-Control" "$(header "$base/build.json" Cache-Control)" "no-cache"
check "/build.json: valid JSON with a commit and a run id of the right shape" \
  "$(jq -r '(.commit | type == "string" and test("^([0-9a-f]{40})?$")) and (.ci_run_id | type == "string" and test("^([0-9]{1,20})?$"))' <<<"$build" 2>/dev/null)" true
if [ -n "${GITHUB_SHA:-}" ]; then
  check "/build.json: commit is GITHUB_SHA" "$(jq -r .commit <<<"$build" 2>/dev/null)" "$GITHUB_SHA"
fi
if [ -n "${GITHUB_RUN_ID:-}" ]; then
  check "/build.json: ci_run_id is GITHUB_RUN_ID" "$(jq -r .ci_run_id <<<"$build" 2>/dev/null)" "$GITHUB_RUN_ID"
fi

# The MockBackend is not shipped (ADR 0035, amending ADR 0033): the production build aliases it away,
# so none of its markers may be in any file the image serves (read from the image itself, so a chunk
# the page does not reference yet is caught too), and `?mock=1` gets the same page as anyone else.
# The scan must be able to see the tree at all, or an empty answer would read as "clean".
check "the marker scan reads the served tree" \
  "$($DOCKER exec "$name" grep -rlF -- '/assets/main-' /usr/share/nginx/html 2>/dev/null | grep -c 'index\.html$')" 1
for marker in sdpMock mock-speed mock-stream-refuse; do
  check "no served file carries the mock marker '$marker'" \
    "$($DOCKER exec "$name" grep -rlF -- "$marker" /usr/share/nginx/html 2>/dev/null | tr '\n' ' ')" ""
done
# The banner's markup, not its name: styles.css may keep a `#mock-banner` rule for the mock build.
check "index.html has no mock banner" "$(grep -c -F 'mock-banner' <<<"$index")" 0
check "/?mock=1 serves the same index.html" "$([ "$(curl -fsS "$base/?mock=1")" = "$index" ] && echo same)" same

if [ "$failures" -ne 0 ]; then
  echo "image-smoke: $failures check(s) failed" >&2
  exit 1
fi
echo "image-smoke: ok"
