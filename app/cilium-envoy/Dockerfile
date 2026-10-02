# cilium-envoy (DaemonSet `cilium-envoy` in kube-system, the Gateway API / L7 data plane, ADR 0010):
# upstream's image at the exact digest Cilium 1.19.8 pins, with the base OS's OpenSSL raised to the
# fixed Ubuntu security update (ADR 0028). Built, Trivy-gated, SBOM'd and signed by
# .github/workflows/build-images.yml like every image under app/ (ADR 0016).
#
# Why not the upstream image as is: quay.io/cilium/cilium-envoy:v1.37.6-1789133542-cbec91f6... has 2
# HIGH with Trivy 0.75.0 on 2026-10-02, both CVE-2026-84782 in Ubuntu's libssl3t64/openssl
# 3.0.13-0ubuntu3.15 (fixed in 3.0.13-0ubuntu3.16). Envoy itself is clean.
#
# Why not rebuild Envoy, and why not a newer upstream build:
#   * Envoy does not use that OpenSSL. cilium-envoy is statically linked against BoringSSL
#     (`cilium-envoy --version` ends in "/BoringSSL"; `ldd` lists no libssl/libcrypto). In this image
#     the system library serves only /usr/bin/openssl and coreutils' checksum tools. Rebuilding Envoy
#     (Bazel, hours, tens of GB) would change the one component that matters for nothing.
#   * The newest upstream build of the same Envoy minor, v1.37.7-1790879678-3aca86e6... (2026-10-01),
#     has the fixed OpenSSL but adds a Go binary, /usr/bin/cilium-envoy-healthcheck, compiled with
#     Go 1.24.6: 22 CRITICAL+HIGH. And it is an Envoy patch release Cilium 1.19.8 was not released
#     with (the agent checks the Envoy version it was built for, requiredEnvoyVersionSHA=cbec91f6...).
# So this is upstream's image, layer for layer, plus one layer that upgrades exactly two packages to
# exactly the fixed version. cilium-envoy, cilium-envoy-starter, libcilium.so and every other file
# outside those two packages are upstream's bytes (ADR 0028, "Verified").
#
# The package index is the Ubuntu snapshot service at a fixed date, so it cannot move under a
# rebuild; apt still verifies the archive's signatures against the keyring already in the image.
#
# Bumping: with Cilium (app/cilium): take the CILIUM_ENVOY_IMAGE upstream's images/cilium/Dockerfile
# pins at the new release commit (it is also the chart's envoy.image), rescan it; if it is clean, this
# directory can go and the chart's own envoy image comes back.
#
# Base pinned by tag and digest (ADR 0008): the chart's envoy.image at 1.19.8.
FROM quay.io/cilium/cilium-envoy:v1.37.6-1789133542-cbec91f666af0bf742da986d43832932dbb26b82@sha256:af7382699576b9e65e9184efa52eeca0b58aea70ad6e511bf260c91d9f740463
RUN printf '%s\n' 'Types: deb' 'URIs: http://snapshot.ubuntu.com/ubuntu/20261002T000000Z/' \
      'Suites: noble-security' 'Components: main' \
      'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' > /tmp/snapshot.sources \
 && apt-get -q -o Dir::Etc::SourceList=/tmp/snapshot.sources -o Dir::Etc::SourceParts=/dev/null update \
 && apt-get -q -y -o Dir::Etc::SourceList=/tmp/snapshot.sources -o Dir::Etc::SourceParts=/dev/null \
      install --no-install-recommends --only-upgrade \
      libssl3t64=3.0.13-0ubuntu3.16 openssl=3.0.13-0ubuntu3.16 \
 && rm -rf /tmp/snapshot.sources /var/lib/apt/lists/* \
 && /usr/bin/cilium-envoy --version | grep -q '/1\.37\.6/Distribution/RELEASE/BoringSSL$'
LABEL org.opencontainers.image.title="self-defending-portfolio cilium-envoy" \
      org.opencontainers.image.description="cilium-envoy v1.37.6 (as pinned by Cilium 1.19.8) with the base OS OpenSSL security update" \
      org.opencontainers.image.source="https://github.com/HubertMJ/self-defending-portfolio" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="v1.37.6-1789133542-cbec91f666af0bf742da986d43832932dbb26b82"
