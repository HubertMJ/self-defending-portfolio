#!/usr/bin/env bash
# The live site as a visitor sees it: every page and the API answer on their paths with the
# security headers. EXPECT=landing (the default) is the site after the landing page took `/`;
# EXPECT=cluster is the state before it, when `/` still served the cluster page and the bare /api
# was routed. Read-only: GETs only, nothing that spends the attack quota.
#
#   scripts/check-live.sh                 (or: EXPECT=cluster BASE=https://... scripts/check-live.sh)
set -euo pipefail

BASE=${BASE:-https://hubertjablon.ski}
EXPECT=${EXPECT:-landing}
failures=0
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# check <path> <status> [text the body must contain]
check() {
  local path=$1 want=$2 needle=${3:-} got
  got=$(curl -sS -o "$WORK/body" -D "$WORK/headers" -w '%{http_code}' --max-time 20 "$BASE$path") || got=000
  if [ "$got" != "$want" ]; then
    printf '  FAIL  %-26s %s, want %s\n' "$path" "$got" "$want"; failures=$((failures + 1)); return
  fi
  if [ -n "$needle" ] && ! grep -qF -- "$needle" "$WORK/body"; then
    printf '  FAIL  %-26s %s but the body lacks "%s"\n' "$path" "$got" "$needle"; failures=$((failures + 1)); return
  fi
  for h in strict-transport-security content-security-policy x-content-type-options; do
    if ! grep -qi "^$h:" "$WORK/headers"; then
      printf '  FAIL  %-26s %s without %s\n' "$path" "$got" "$h"; failures=$((failures + 1)); return
    fi
  done
  printf '  ok    %-26s %s\n' "$path" "$got"
}

printf '%s (expect: %s)\n' "$BASE" "$EXPECT"
check /cluster/ 200 'id="tour"'
check /cluster/api/healthz 200
check /cluster/api/scenarios 200 '"id"'
case $EXPECT in
  landing)
    check / 200 'What I work with'
    check /lab/ 200 'Detection lab'
    check /api/healthz 404
    # About lives on the landing page only (owner decision 2026-10-14).
    if curl -sS --max-time 20 "$BASE/cluster/" | grep -qF 'id="about"'; then
      printf '  FAIL  %-26s still carries About\n' /cluster/; failures=$((failures + 1))
    else
      printf '  ok    %-26s no About\n' /cluster/
    fi
    ;;
  cluster)
    check / 200 'id="tour"'
    check /api/healthz 200
    ;;
  *) printf 'check-live.sh: EXPECT is landing or cluster, not %s\n' "$EXPECT" >&2; exit 2 ;;
esac

# The pages slide like desktops (2026-10-16): the stylesheets and scripts each page loads carry the
# slide keyframes and the direction logic, so a page still on an older image shows up here.
assets_have() {
  local page=$1 needle=$2 urls
  urls=$(curl -sS --max-time 20 "$BASE$page" | grep -oE '(href|src)="/[^"]+\.(css|js)"' | sed -E 's/^(href|src)="//; s/"$//' | sort -u)
  { curl -sS --max-time 20 "$BASE$page"; for u in $urls; do curl -sS --max-time 20 "$BASE$u"; done; } | grep -qF -- "$needle"
}
if [ "$EXPECT" = landing ]; then
  for page in / /lab/ /cluster/; do
    for needle in vt-slide-from-left pagereveal; do
      if assets_have "$page" "$needle"; then printf '  ok    %-26s has %s\n' "$page" "$needle"
      else printf '  FAIL  %-26s lacks %s\n' "$page" "$needle"; failures=$((failures + 1)); fi
    done
  done
fi

# What the cluster runs, as the API sees it (the same data the page's Verify section shows).
for api in /cluster/api /api; do
  if curl -sSf --max-time 20 -o "$WORK/prov" "$BASE$api/provenance" 2>/dev/null; then
    python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); print("  running web:", *p["web"]["images"], "\n  running api:", *p["api"]["images"], "\n  observed:", p.get("images_observed_at"))' "$WORK/prov" || true
    break
  fi
done

if [ "$failures" -ne 0 ]; then printf '%s check(s) failed\n' "$failures" >&2; exit 1; fi
