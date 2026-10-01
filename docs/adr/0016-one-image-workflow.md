# ADR 0016: One matrix workflow builds and signs every image; the admission identity stays one file on main

Date: 2026-10-01 · Status: accepted

## Context
Phase 3 built exactly one image, `web`, in `.github/workflows/build-web.yml`, and pinned Kyverno's
`verify-portfolio-images` to that file's keyless identity on `refs/heads/main` (ADR 0011). Phase 5 adds
two more images of our own: `api` (ADR 0015) and `scenario` (the attack images that run in `sandbox`).
All three need the same pipeline - build, Trivy gate, SPDX SBOM, cosign keyless signature and SBOM
attestation, GHCR - and all three must be admissible under the same policy without weakening it.

Options considered:

1. **One workflow file per image**, copies of `build-web.yml`. Three files to keep in step by hand,
   and the policy's subject grows an alternation per image.
2. **A reusable workflow** (`workflow_call`) with the pipeline, called by three thin per-image
   workflows. One copy of the pipeline - but Fulcio puts the **called** workflow into the
   certificate: the SAN is `job_workflow_ref`, i.e. `.../build-image.yml@refs/heads/main`, not the
   caller. Any workflow in the repository that calls it on main gets the trusted identity, and so,
   for a public repository, does any workflow in *any* repository that calls
   `HubertMJ/self-defending-portfolio/.github/workflows/build-image.yml@main` - its certificate
   carries exactly our SAN. Pinning that safely needs extra certificate-extension checks
   (`githubWorkflowRepository`, the caller's workflow ref) in Kyverno and in `verify-image.sh`,
   which is more policy, not less.
3. **One workflow with a matrix** over the images, discovered from `app/*/Dockerfile`.

## Decision
**Option 3: `.github/workflows/build-images.yml`.** A `discover` job lists `app/<name>/Dockerfile`
(names must be DNS-label-like) and selects the images whose directory changed in the push - all of
them when the workflow itself changed, when the push cannot be diffed, and on `workflow_dispatch`.
A `build` job runs the ADR 0011 pipeline unchanged once per selected image, as
`ghcr.io/hubertmj/self-defending-portfolio/<name>`, `fail-fast: false` so one broken image does not
hold back the others. Adding an image is adding a directory with a Dockerfile; nothing in the
workflow names an image. `build-web.yml` is deleted.

Every matrix job's certificate has the same SAN, this file at `refs/heads/main`. The admission
identity therefore stays "one specific workflow file on main", and nothing outside this file - no
other workflow, no other repository - can obtain it.

**Least privilege per job.** Workflow-level `permissions: {}`; `discover` gets `contents: read`;
`build` gets `contents: read`, `packages: write`, `id-token: write`, `security-events: write`. The
phase 3 `attestations: write` is dropped: `cosign attest` writes the attestation to the registry
(`packages: write`), not to GitHub's attestation API, which nothing here uses.

**Per-image isolation where it matters.** The buildx GHA cache is scoped per image (otherwise the
images evict each other's layers), SARIF uploads use the category `trivy-image-<name>` (otherwise each
upload replaces the previous image's alerts), and the SBOM artifact is named per image.

**Transition for the running `web` digest.** `cluster/infra/hello` runs a digest that
`build-web.yml` signed. If the policy only accepted `build-images.yml`, every new hello pod (a
reschedule, a node reboot) would be refused until hello's digest is re-pinned, and `make validate`,
which verifies hello's digest for real, would fail on the merge commit. So both subjects - in both
`verify-portfolio-images` rules and in `scripts/verify-image.sh`, character for character - accept
`(build-images|build-web)\.yml@refs/heads/main`, still anchored at both ends, still for this
repository and branch only. This is not a weakening: `build-web.yml` no longer exists on main, and
putting it back there takes exactly the write access that editing `build-images.yml` takes. The
alternative is marked `TRANSITION` and is removed in the commit that re-pins hello to a digest
built by `build-images.yml` (the first push touching `app/web` or this workflow rebuilds it).

**`portfolio-api` joins the policy scope.** `verify-portfolio-images` and `restrict-image-registries`
now match Pods in `hello`, `sandbox` and `portfolio-api`. The API is the one workload of ours with
API permissions (it creates and execs into pods in `sandbox`), so it is the last place an
unverified image should be able to run.

## Consequences
- One pipeline, one identity, any number of images. A new image costs a Dockerfile and a digest pin
  in `cluster/`; it costs no workflow and no policy change.
- The images are signed by one identity, so the signature says "built by our pipeline from main", not
  "this is the api image". An image cannot be swapped for another of ours by name alone, because
  every reference in `cluster/` is a digest; a digest pinned to the wrong image is a review error,
  not something the policy can catch. (This was already true of tags; it is stated now that there is
  more than one image.)
- A push that changes several apps builds them in parallel jobs; the `main` tags of different
  images move independently, and the workflow-level concurrency group still serialises two pushes.
- New images reach main in two merges (docs/bootstrap.md, section 7). The first carries the sources,
  this workflow and the widened identity, and changes nothing Argo CD deploys apart from the two image
  policies; CI on main then builds and signs every image. The second pins the digests from the
  workflow summaries (`scripts/bump-image-digest.sh <name> <digest>`) and adds what uses them. Until
  then the manifests carry an all-zero placeholder digest, and `scripts/check-image-digests.sh`
  fails `make validate` and CI on it, so a placeholder cannot reach main.
- `docs/bootstrap.md` and `scripts/verify-image.sh` use the same transitional regexp as the policy.
  All three drop `|build-web` together, in a commit of its own once hello runs a digest built by
  `build-images.yml` and has been seen working; keeping the alternative until then is what lets
  that switch be reverted without a rebuild.
