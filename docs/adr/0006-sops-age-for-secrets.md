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
- `pre-commit`/CI check refuses any `kind: Secret` that is not SOPS-encrypted.
