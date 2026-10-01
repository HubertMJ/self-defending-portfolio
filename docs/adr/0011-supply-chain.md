# ADR 0011: Build, scan, describe and sign our own image; verify it at admission

Date: 2026-10-01 · Status: accepted

## Context
Phase 2 served the page from `nginxinc/nginx-unprivileged` plus a ConfigMap of `index.html`. That is
reproducible, but it makes the phase 3 definition of done ("unsigned image fails admission")
impossible to demonstrate: there is nothing of ours to sign, and requiring a signature on an
upstream image would mean trusting whoever happens to sign it.

So the page has to become an image we publish. That raises the questions this record answers: who
signs, with what identity, how is "what is in it" recorded, what blocks a known-vulnerable build,
and how do the manifests refer to the result.

Alternatives considered for signing: a cosign key pair (private key in a GitHub secret, public key
in the Kyverno policy), GitHub's native `attestations: write` provenance alone, or notation/notary.

## Decision

**Keyless cosign, identity = this workflow file on main.** `.github/workflows/build-web.yml` signs
with cosign in keyless mode: GitHub's OIDC provider mints a token for the job, Sigstore Fulcio
returns a certificate whose subject is
`https://github.com/HubertMJ/self-defending-portfolio/.github/workflows/build-web.yml@refs/heads/main`,
cosign signs with the matching ephemeral key and logs the entry in Rekor. Kyverno's
`verifyImages` rule requires exactly that issuer and that subject, anchored at both ends.

A key pair was rejected: the private key would have to live in a GitHub secret, which means the
thing protecting admission is a string an org admin can read, and rotating it means touching a
cluster policy. Keyless has no key at rest; the trust anchor is a path in a public repository that
anyone can read and that git history makes tamper-evident. Native GitHub attestations were rejected
as the *only* mechanism because Kyverno verifies Sigstore signatures natively, and because the
identity model should not be specific to one CI vendor's API.

**The SBOM is an attestation, not just an artifact.** syft produces SPDX JSON for the pushed digest;
it is uploaded as a workflow artifact for convenience and attached with
`cosign attest --type spdxjson` for permanence. An artifact expires in 90 days and is only readable
by people with repo access; an attestation is a signed statement about a digest, verifiable by
anyone, with the same trust root as the signature. "What was in the image running in March" is then
a question with an answer.

**Trivy gates on fixable HIGH and CRITICAL.** `severity: CRITICAL,HIGH`, `ignore-unfixed: true`,
`exit-code: 1`, run against the digest that was just pushed rather than a tag. Unfixed CVEs are
excluded deliberately: there is no action this pipeline can take about a vulnerability with no
upstream patch, so failing on it would train us to ignore a red build — the worst possible outcome
for a gate. A second, non-failing run emits SARIF to the Security tab so unfixed findings are still
visible; a problem uploading SARIF does not fail the build.

**Digests only in manifests, and no `latest`.** The published tags are `sha-<short>` and `main`.
`main` exists so a human can see where the branch points; nothing deploys from it. `cluster/` refers
to the image by digest, which is what `cosign verify` and Kyverno can actually make a statement
about — a tag is a mutable pointer and can be repointed at an unsigned image between the check and
the pull. `scripts/verify-image.sh` refuses a tag argument for the same reason. `:latest` is also
forbidden cluster-wide by a Kyverno policy (ADR 0008).

**buildx provenance and SBOM attestations are off** (`provenance: false, sbom: false`). They attach
extra manifests to the image index, which makes it ambiguous what `cosign sign <image>@<digest>`
covered. The SBOM is produced explicitly instead, and the signature covers the image manifest that
was pushed.

**The GHCR package must be public.** Kyverno pulls the signature and the Rekor entry from the
registry at admission time, with no credentials. A private package means admission fails closed on
every image, including good ones.

## Consequences
- Phase 3's definition of done is now demonstrable: an image built anywhere else, or built from a
  branch that is not `main`, gets a certificate with a different subject and is refused at admission.
- `scripts/verify-image.sh <image>@<digest>` gives the same verdict from a laptop with no cluster,
  which separates "the policy is broken" from "the image really is unsigned" during an incident.
- The first push needs one manual step: GHCR creates the package private, and it has to be made
  public once (see `docs/bootstrap.md`).
- **Known gap:** bumping the digest in `cluster/infra/hello/` is a manual commit. The workflow prints
  the exact lines to paste, but nothing closes the loop automatically. Renovate will do it once the
  repo is public (ADR 0008); until then a published image is not a deployed image, on purpose —
  the deploy stays a reviewable commit rather than a side effect of a build.
- `cluster/infra/hello/index.html` and the ConfigMap that mounts it are superseded by
  `app/web/public/index.html`. The content was copied, not moved, so the page keeps serving until the
  digest bump lands; the ConfigMap is removed in the same commit as that bump.
- Every action in the workflow is pinned to a full commit SHA with its tag in a comment (ADR 0008),
  and so are the cosign and tooling container images.

## Amendment 2026-10-01: Kyverno verifies cosign v3 Sigstore bundles

**Context.** cosign v3 (the workflow pins v3.1.3) writes the new Sigstore bundle format by default.
The signature and the SPDX attestation are no longer pushed as `sha256-<digest>.sig` / `.att` tags;
each is an OCI 1.1 referrer of the image digest with artifactType
`application/vnd.dev.sigstore.bundle.v0.3+json`. Kyverno v1.19.1's default verifier (`type: Cosign`)
only looks for the tags, so admission failed with "no signatures found" / "no matching attestations"
for images that `cosign verify` accepts, and Argo CD could not sync the `hello` Deployment.

**Decision.** Keep cosign's default bundle format and switch both `verifyImages` entries in
`cluster/infra/kyverno-policies/verify-portfolio-images.yaml` to `type: SigstoreBundle`, which
discovers bundles through the OCI referrers API. In that mode the attestation `type` is compared
exactly with the in-toto `predicateType`, so the policy names `https://spdx.dev/Document`, never the
cosign CLI short name `spdxjson` (which the CLI, and therefore `scripts/verify-image.sh`, still maps
for itself). Issuer, subject regexp and the `mutateDigest` split (true on `verify-signature`, false
on `verify-sbom-attestation`) are unchanged. The `rekor.url` field stays in the policy but this mode
ignores it: Rekor, Fulcio and TSA trust come from the Sigstore TUF `trusted_root.json`, and only
`ignoreTlog` (left false, so a log entry is still required) is honoured.

**Rejected: signing with `--new-bundle-format=false --use-signing-config=false`.** That would bring
back the `.sig`/`.att` tags the old verifier understands, but both flags are deprecated in cosign v3
and slated for removal. It would move the same breakage to a future cosign bump, and leave the
pipeline producing a format the Sigstore ecosystem is moving away from.

**Deferred: ImageValidatingPolicy (`policies.kyverno.io/v1`).** `ClusterPolicy` is deprecated as of
Kyverno 1.19, and ImageValidatingPolicy is its successor with first-class bundle support. Migrating is
a rewrite of the policy and of `tests/admission/`, not a field change, so it is a candidate for a
later phase rather than part of this fix.

**Consequence / known limitation.** In SigstoreBundle mode the `verify-signature` rule has no
predicate filter: any bundle that verifies against the pinned identity satisfies it, including the
SBOM attestation bundle on its own. This is accepted because the identity is this one workflow file
on `refs/heads/main` — anything that satisfies it came out of our own pipeline — and the SBOM's
presence is asserted separately, by predicate type, in `verify-sbom-attestation`.
