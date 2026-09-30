#!/usr/bin/env bash
# ADR 0006: every `kind: Secret` committed under cluster/ must be SOPS-encrypted
# (has a top-level `sops:` block with an age recipient). `.example` templates are exempt.
set -euo pipefail
cd "$(dirname "$0")/.."
rc=0
while IFS= read -r f; do
  if grep -qE '^kind:[[:space:]]*Secret[[:space:]]*$' "$f" \
     && ! grep -qE '^sops:' "$f"; then
    echo "UNENCRYPTED SECRET: $f" >&2; rc=1
  fi
done < <(git ls-files 'cluster/**/*.yaml' 'cluster/**/*.yml' | grep -v '\.example$')
[[ $rc -eq 0 ]] && echo "ok - no plaintext Secret objects under cluster/"
exit $rc
