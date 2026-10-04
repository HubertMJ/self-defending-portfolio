// What a visitor needs to check the running images themselves (ADR 0035): the cosign command for an
// image by digest, and links to the commit, the CI run and the Rekor transparency log entry. Links
// only: the page fetches nothing cross-origin (CSP connect-src 'self').

import { isCommit } from "./contract";
import { REPO_URL } from "../ui/common";

// The keyless identity every image of this repository is verified against (ADR 0011, 0016, 0035): character for
// character the defaults of scripts/verify-image.sh (OIDC_ISSUER :34, IDENTITY_REGEXP :40). make validate fails if they
// differ (scripts/check-web-identity.sh). `|build-web` is ADR 0016's TRANSITION and leaves with the policy's.
export const COSIGN_IDENTITY_REGEXP = String.raw`^https://github\.com/HubertMJ/self-defending-portfolio/\.github/workflows/(build-images|build-web)\.yml@refs/heads/main$`;
export const COSIGN_ISSUER = "https://token.actions.githubusercontent.com";
export function cosignVerifyCommand(imageAtDigest: string): string {
  // A visitor pastes this into a shell: it is only ever built from a strictly validated pinned reference.
  if (!isPinnedImageRef(imageAtDigest)) throw new TypeError("cosignVerifyCommand: not a pinned image reference");
  return [`cosign verify ${imageAtDigest}`, `  --certificate-identity-regexp '${COSIGN_IDENTITY_REGEXP}'`, `  --certificate-oidc-issuer ${COSIGN_ISSUER}`].join(" \\\n");
}

/**
 * registry[:port]/path@sha256:<64 hex>, lowercase, nothing a shell would read as more than one word.
 * The only thing a copied cosign command may name.
 */
const IMAGE_REF = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)+@sha256:[0-9a-f]{64}$/;
export const isPinnedImageRef = (s: string): boolean => s.length <= 300 && IMAGE_REF.test(s);

/** The command on one line, as the Copy buttons put it on the clipboard. */
export const oneLine = (command: string): string => command.replace(/ \\\n\s*/g, " ");

const DIGEST = /^sha256:[0-9a-f]{64}$/;

/** search.sigstore.dev for the Rekor entries of a digest; null for anything that is not one. */
export function rekorSearchUrl(digest: string): string | null {
  return DIGEST.test(digest) ? `https://search.sigstore.dev/?hash=${digest}` : null;
}

/** The commit on GitHub; null unless it is 7-40 lowercase hex. */
export function commitUrl(sha: string): string | null {
  return isCommit(sha) ? `${REPO_URL}/commit/${sha}` : null;
}

/** The GitHub Actions run; null unless the id is 1-20 digits. */
export function ciRunUrl(id: string): string | null {
  return /^[0-9]{1,20}$/.test(id) ? `${REPO_URL}/actions/runs/${id}` : null;
}

/** The digest of "repo@sha256:…", or "" when the reference is not pinned by one. */
export function digestOf(imageAtDigest: string): string {
  const at = imageAtDigest.lastIndexOf("@");
  const d = at < 0 ? "" : imageAtDigest.slice(at + 1);
  return DIGEST.test(d) ? d : "";
}

/** "sha256:be0895f4…" for the evidence card; the full value goes in a title and the copied text. */
export const shortDigest = (digest: string): string => (digest ? `${digest.slice(0, 15)}…` : "");
