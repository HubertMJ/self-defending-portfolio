# ADR 0002: GitHub + GitHub Actions + GHCR

Date: 2026-09-30 · Status: accepted

## Context
Alternatives: self-hosted Forgejo (with Forgejo Actions runner and a registry) or GitHub.
The audience is recruiters and engineers who will read the repo, not run it.

## Decision
Public repo on GitHub, CI on GitHub Actions, images in GHCR, signatures with cosign keyless
(GitHub OIDC → Sigstore Fulcio/Rekor).

## Consequences
- Zero infrastructure to maintain for CI; runners, OIDC identity and registry are free for public repos.
- Keyless signing gives Kyverno a verifiable identity (`https://github.com/<owner>/<repo>/.github/workflows/...@refs/heads/main`)
  instead of a private key that would have to be stored somewhere.
- Vendor lock-in is accepted: the workflows are small and easy to port.
- Forgejo would have added a second service to secure and back up, with no benefit to the story.
