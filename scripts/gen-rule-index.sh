#!/usr/bin/env bash
# Generates app/api/internal/ruleindex/index.json: where in this repository each Falco rule, Falco
# Talon rule and admission/network policy that a scenario runs into is defined, as file and line.
# The portfolio API embeds it and serves it in GET /api/scenarios/{id}/details, and the page turns it
# into links to github.com/.../blob/<commit>/<file>#L<line> - the commit being the one the API image
# was built from (ADR 0021).
#
# Generated rather than resolved at run time because the API image is built from app/api alone and
# has no copy of cluster/, and rather than written by hand because a line number written by hand is
# wrong after the next edit above it. `--check` regenerates into a temporary file and fails if the
# committed index differs; the API's unit tests check every entry against the files as well.
#
# Text parsing on purpose (no YAML library): the files are ours and follow one layout -
#   cluster/infra/falco/*.yaml                    `- rule: <name>` at any indentation (customRules)
#   cluster/infra/falco-response/talon/rules.yaml `- rule: <name>` at column 0, followed by
#                                                 `match: rules:` and the Falco rule names it answers
#   cluster/infra/kyverno-policies/*.yaml,
#   cluster/infra/sandbox/*.yaml                  documents with top-level `kind:` and `metadata.name`
# Falco rules that come with the Falco image (stock rules) are not in this repository and have no
# entry; the API then reports an empty file.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=app/api/internal/ruleindex/index.json

generate() {
  local falco talon policies
  # name<TAB>file<TAB>line
  falco=$(for f in cluster/infra/falco/*.yaml; do
    awk -v f="$f" '/^[[:space:]]*- rule: / { n=$0; sub(/^[[:space:]]*- rule: /, "", n); printf "%s\t%s\t%d\n", n, f, NR }' "$f"
  done)
  # falco rule<TAB>talon rule<TAB>file<TAB>line
  talon=$(awk -v f=cluster/infra/falco-response/talon/rules.yaml '
    /^- rule: /                 { rule=$0; sub(/^- rule: /, "", rule); line=NR; inmatch=0; next }
    /^- /                       { rule=""; next }
    rule != "" && /^    rules:/ { inmatch=1; next }
    inmatch && /^      - /      { n=$0; sub(/^      - /, "", n); printf "%s\t%s\t%s\t%d\n", n, rule, f, line; next }
    inmatch                     { inmatch=0 }
  ' cluster/infra/falco-response/talon/rules.yaml)
  # kind<TAB>name<TAB>file
  policies=$(for f in cluster/infra/kyverno-policies/*.yaml cluster/infra/sandbox/*.yaml; do
    awk -v f="$f" '
      /^---/                       { kind=""; meta=0; next }
      /^kind: /                    { kind=$2; next }
      /^metadata:/                 { meta=1; next }
      /^[^ ]/                      { meta=0 }
      meta && /^  name: / && kind  { printf "%s\t%s\t%s\n", kind, $2, f; kind="" }
    ' "$f"
  done | grep -E '^(ClusterPolicy|Policy|NetworkPolicy|CiliumNetworkPolicy|CiliumClusterwideNetworkPolicy)	' || true)

  jq -n --arg falco "$falco" --arg talon "$talon" --arg policies "$policies" '
    def rows($s): $s | split("\n") | map(select(length > 0) | split("\t"));
    {
      falco: (rows($falco) | map({key: .[0], value: {file: .[1], line: (.[2] | tonumber)}}) | from_entries),
      talon: (rows($talon) | map({key: .[0], value: {name: .[1], file: .[2], line: (.[3] | tonumber)}}) | from_entries),
      policies: (rows($policies) | map({kind: .[0], name: .[1], file: .[2]}))
    }'
}

if [ "${1:-}" = --check ]; then
  tmp=$(mktemp)
  trap 'rm -f "$tmp"' EXIT
  generate > "$tmp"
  if ! diff -u "$OUT" "$tmp"; then
    echo "$OUT is stale: run scripts/gen-rule-index.sh" >&2
    exit 1
  fi
  echo "ok - $OUT is up to date"
  exit 0
fi
generate > "$OUT"
echo "wrote $OUT"
