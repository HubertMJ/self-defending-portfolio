# ADR 0006: SOPS + age for secrets in git

Date: 2026-09-30 · Status: accepted

## Context
The repo is public. The cluster needs a Cloudflare API token (DNS-01), a tunnel credential,
and the Argo CD admin password. Options: External Secrets with a vault, Sealed Secrets, SOPS.

## Decision
SOPS with age. One age key pair per environment; the public key lives in `.sops.yaml`, the private key
lives only on the operator machine and in the cluster (as a Secret created during bootstrap).
Argo CD decrypts via the KSOPS plugin (Kustomize generator).

## Consequences
- Secrets are versioned, reviewable (keys visible, values encrypted) and rotated by re-encrypting.
- No external vault to run. Losing the age private key means re-creating all secrets, which is a
  known and cheap operation here.
- CI (`scripts/check-secrets-encrypted.sh`) refuses any `kind: Secret` under `cluster/` that is not SOPS-encrypted.

## Amendment 2026-10-04: a second KSOPS Secret, made by a script (ADR 0034)

**Decision.** `cluster/infra/portfolio-api/siem-client.sops.yaml` (the API's SIEM client certificate)
uses the same mechanism and recipient. It is never written by hand: `scripts/siem-api-cert.sh`
generates the key in a private scratch directory (`.siem-tmp/`, git-ignored, shredded on exit), has
siem01 sign the CSR, and writes the file through `sops --encrypt`; the plaintext never lands in the
tree. A generator naming a file that is not committed now fails `make validate` and CI, with or
without the age key (Argo builds from git; without the key only the decryption is skipped), so the
encrypted file lands with, or before, the generator that names it.

**Consequences.** Losing the age key now also means re-issuing the API's SIEM certificate (a new
generation, mapped on siem01 first).
