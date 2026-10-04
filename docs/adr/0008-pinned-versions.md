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

## Amendment 2026-10-04: apt packages from third-party repositories

**Context.** OpenSearch and OpenSearch Dashboards (ADR 0034) come from the OpenSearch project's apt
repositories, not from a release tarball with a checksum file, and outside the image pipeline.

**Decision.** A third-party deb is pinned four ways: the repository key is trusted only after its
primary fingerprint equals the pinned one (and the file holds no other primary key); the package's
SHA256 in the signed index must equal the pinned hash before anything is installed (apt then checks
the download against that index); an apt preference pins the version at priority 1001; and dpkg holds
the package. unattended-upgrades follows the Debian archive only, so nothing upgrades it unattended.
Version, hash and fingerprint live in `group_vars/siem_nodes.yml` next to the other pins.

**Consequences.** A rebuild installs exactly the reviewed package or stops before installing anything.
A repository key rotation stops the role until the new fingerprint is reviewed and pinned; the
current key's signing subkey expires on 2027-03-06.
