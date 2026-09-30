# ADR 0008: Pin every version, bump deliberately

Date: 2026-09-30 · Status: accepted

## Context
k3s, Helm, Cilium, Argo CD, Kyverno, Falco all move fast. Unpinned installs make "rebuild from zero"
non-reproducible and make it impossible to say what was tested.

## Decision
Every binary, chart, image and GitHub Action is pinned (semantic version for charts/binaries, digest
or SHA for images and actions). Bumps come as separate commits; Renovate is enabled once the repo is public.
`:latest` is forbidden by a Kyverno policy in the cluster.

## Consequences
- Checksums are verified on download (k3s, Helm) so a rebuild fails loudly instead of silently drifting.
- More small PRs; that is the point.
