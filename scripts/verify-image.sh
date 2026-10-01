#!/usr/bin/env bash
# The other half of .github/workflows/build-images.yml: proves, from outside the cluster, that an image
# was signed by that workflow running on main, and that its SBOM attestation came from the same
# place. This is the same assertion Kyverno makes at admission (ADR 0011) -- having it as a script
# means a human can check a digest in ten seconds without a cluster, and a broken policy can be told
# apart from a genuinely unsigned image.
#
# Keyless verification has no key to pass, so the *identity* is the whole check and both flags are
# mandatory: --certificate-oidc-issuer says Sigstore must have minted the certificate from a GitHub
# Actions OIDC token, and --certificate-identity-regexp says the subject must be exactly the image
# workflow file on refs/heads/main. Without them, any valid Fulcio certificate in the world passes.
#
# Usage: scripts/verify-image.sh ghcr.io/hubertmj/self-defending-portfolio/web@sha256:<digest>
#
# cosign is used from the host if installed, otherwise from a pinned container (ADR 0008).
# Set DOCKER=... to use a wrapper such as "sudo -n docker", as in scripts/lint.sh.
set -euo pipefail

IMAGE=${1:-}
if [ -z "$IMAGE" ]; then
  echo "usage: $(basename "$0") <image>@sha256:<digest>" >&2
  exit 2
fi
case $IMAGE in
  *@sha256:*) ;;
  # A tag can be repointed at an unsigned image between the check and the pull, which makes a
  # tag-based verification worth nothing. Refuse rather than give a misleading OK.
  *) echo "verify-image: refusing a tag; pass <image>@sha256:<digest>" >&2; exit 2 ;;
esac

DOCKER=${DOCKER:-docker}
COSIGN_IMAGE=${COSIGN_IMAGE:-ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8}

OIDC_ISSUER=${OIDC_ISSUER:-https://token.actions.githubusercontent.com}
# Anchored at both ends on purpose: an unanchored pattern would also accept
# .../build-images.yml@refs/heads/main-attacker-branch or a fork's path that merely contains ours.
# Character-for-character the regexp in cluster/infra/kyverno-policies/verify-portfolio-images.yaml,
# including its TRANSITION alternative for the phase 3 build-web.yml (ADR 0016); drop it in both
# places together.
IDENTITY_REGEXP=${IDENTITY_REGEXP:-'^https://github\.com/HubertMJ/self-defending-portfolio/\.github/workflows/(build-images|build-web)\.yml@refs/heads/main$'}

if command -v cosign >/dev/null 2>&1; then
  cosign() { command cosign "$@"; }
else
  # --network host so Rekor and Fulcio are reachable the same way they are from the host; the
  # container is throwaway and gets nothing mounted, because verification needs no local state.
  cosign() { $DOCKER run --rm --network host "$COSIGN_IMAGE" "$@"; }
fi

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

printf 'verifying %s\n' "$IMAGE"

printf '  signature ... '
if out=$(cosign verify \
           --certificate-oidc-issuer "$OIDC_ISSUER" \
           --certificate-identity-regexp "$IDENTITY_REGEXP" \
           "$IMAGE" 2>&1); then
  printf 'ok\n'
else
  printf '\n%s\n' "$out" >&2
  fail "no signature from the image workflow on refs/heads/main for $IMAGE"
fi

printf '  sbom attestation ... '
if out=$(cosign verify-attestation \
           --type spdxjson \
           --certificate-oidc-issuer "$OIDC_ISSUER" \
           --certificate-identity-regexp "$IDENTITY_REGEXP" \
           "$IMAGE" 2>&1); then
  printf 'ok\n'
else
  printf '\n%s\n' "$out" >&2
  fail "no spdxjson SBOM attestation from the image workflow on refs/heads/main for $IMAGE"
fi

printf 'OK: %s is signed and has a verified SPDX SBOM attestation\n' "$IMAGE"
