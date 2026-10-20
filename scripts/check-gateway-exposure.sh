#!/usr/bin/env bash
# Nothing in cluster/ is reachable on a node address (ADR 0003, ADR 0010 amendment 2026-10-20). With
# kube-proxy replacement, Cilium's eBPF load balancer answers a NodePort or LoadBalancer frontend on
# the node before nftables' input drop sees the packet, so the host firewall cannot be relied on for
# them:
#   - every Gateway carries spec.infrastructure.annotations service.cilium.io/type: ClusterIP, which
#     Cilium copies onto the generated LoadBalancer Service so only its ClusterIP is installed;
#   - no Service written here is of type NodePort or LoadBalancer.
set -euo pipefail
cd "$(dirname "$0")/.."
mapfile -t files < <(grep -rlE --include="*.yaml" "^kind: (Gateway|Service)$" cluster)
python3 - "${files[@]}" <<'PY'
import sys, yaml

failures = 0
gateways = 0
for path in sys.argv[1:]:
    for doc in yaml.safe_load_all(open(path)):
        if not doc:
            continue
        kind = doc.get("kind")
        name = f"{path}: {kind} {doc.get('metadata', {}).get('name')}"
        spec = doc.get("spec") or {}
        if kind == "Gateway":
            gateways += 1
            ann = (spec.get("infrastructure") or {}).get("annotations") or {}
            if ann.get("service.cilium.io/type") != "ClusterIP":
                failures += 1
                print(f"check-gateway-exposure: {name} lacks infrastructure.annotations service.cilium.io/type: ClusterIP", file=sys.stderr)
        elif kind == "Service" and spec.get("type") in ("NodePort", "LoadBalancer"):
            failures += 1
            print(f"check-gateway-exposure: {name} is of type {spec['type']}", file=sys.stderr)
if failures:
    sys.exit(1)
print(f"ok - {gateways} Gateway(s) expose a ClusterIP only, no NodePort or LoadBalancer Service")
PY
