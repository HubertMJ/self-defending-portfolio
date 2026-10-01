# shellcheck shell=bash
# The Helm image both scripts/render-charts.sh and scripts/validate-cluster.sh render charts with,
# pinned by tag and digest (ADR 0008): the same Helm release Argo CD v3.5.3 bundles
# (hack/tool-versions.sh: helm4_version=4.2.1). Sourced, so the pin has one home.
HELM_IMAGE=${HELM_IMAGE:-alpine/helm:4.2.1@sha256:8647f126de3578d74f947ba735e4cfa0ea6aea7d6e2f36bceb86f31415944dca}
