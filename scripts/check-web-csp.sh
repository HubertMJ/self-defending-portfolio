#!/usr/bin/env bash
# ADR 0019: the Content-Security-Policy the hello HTTPRoute sets must be exactly the one the web image
# sends (app/web/security-headers.conf). The route's ResponseHeaderModifier uses `set`, so in the
# cluster its value replaces nginx's; the Playwright suite only ever sees nginx's (scripts/serve.mjs
# parses the same file). Two different strings would mean the page is tested against one policy and
# served with another - the phase 3 route's `script-src 'none'` would have blocked the whole frontend.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 - app/web/security-headers.conf cluster/infra/hello/httproute.yaml <<'PY'
import re, sys, yaml

conf, route = sys.argv[1], sys.argv[2]
m = re.search(r'add_header\s+Content-Security-Policy\s+"([^"]+)"', open(conf).read())
if not m:
    sys.exit(f"check-web-csp: no Content-Security-Policy in {conf}")
image_csp = m.group(1)

route_csps = []
for rule in yaml.safe_load(open(route))["spec"]["rules"]:
    for f in rule.get("filters", []):
        for h in (f.get("responseHeaderModifier") or {}).get("set", []):
            if h["name"].lower() == "content-security-policy":
                route_csps.append(h["value"])
if not route_csps:
    sys.exit(f"check-web-csp: {route} sets no Content-Security-Policy")
bad = [c for c in route_csps if c != image_csp]
if bad:
    print(f"check-web-csp: {route} and {conf} disagree", file=sys.stderr)
    print(f"  image: {image_csp}", file=sys.stderr)
    for c in bad:
        print(f"  route: {c}", file=sys.stderr)
    sys.exit(1)
print(f"ok - hello HTTPRoute CSP matches app/web/security-headers.conf")
PY

# The landing page's route (cluster/infra/site, image from HubertMJ/hubertjablon.ski) shares the
# hostname, so it must send hello's headers exactly, and every path it serves over https must also
# be redirected when it arrives as plain http: its exact `/` and longer prefixes outrank hello's
# redirect rule.
python3 - cluster/infra/hello/httproute.yaml cluster/infra/site/httproute.yaml <<'PY'
import sys, yaml

hello, site = (yaml.safe_load(open(p)) for p in sys.argv[1:3])

def headers(route):
    out = []
    for rule in route["spec"]["rules"]:
        for f in rule.get("filters", []):
            s = (f.get("responseHeaderModifier") or {}).get("set")
            if s:
                out.append({h["name"].lower(): h["value"] for h in s})
    return out

h, s = headers(hello), headers(site)
if len(h) != 1 or not s or any(x != h[0] for x in s):
    sys.exit(f"check-web-csp: {sys.argv[2]} must set exactly hello's response headers")

served, redirected = set(), set()
for rule in site["spec"]["rules"]:
    is_redirect = any(f["type"] == "RequestRedirect" for f in rule.get("filters", []))
    for m in rule["matches"]:
        key = (m["path"]["type"], m["path"]["value"])
        if is_redirect:
            if m.get("headers") != [{"name": "X-Forwarded-Proto", "value": "http"}]:
                sys.exit(f"check-web-csp: {sys.argv[2]} redirects {key} without matching X-Forwarded-Proto: http")
            redirected.add(key)
        else:
            served.add(key)
if served != redirected:
    sys.exit(f"check-web-csp: {sys.argv[2]} serves {sorted(served - redirected)} without an http redirect")
print(f"ok - site HTTPRoute sends hello's headers and redirects http on all {len(served)} paths")
PY
