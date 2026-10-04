#!/usr/bin/env bash
# The portfolio API's SIEM client certificate (ADR 0034: the one SIEM credential in git, as a KSOPS
# Secret; ADR 0006). The key is generated here, on the operator's host, in a private scratch
# directory; only the CSR goes to siem01, where siem.yml's remote entry point signs it for exactly
# CN=portfolio-api-g<N>,OU=siem,O=sdp (the name comes from the playbook, never from the CSR). The
# certificate, the key and siem01's CA certificate are written into
# cluster/infra/portfolio-api/siem-client.sops.yaml and encrypted with sops before anything else
# can read the file; the scratch directory is shredded on every exit.
#
# Usage: scripts/siem-api-cert.sh <generation>
#   Generation 1 the first time; a rotation is the next generation: add it to opensearch_config's
#   extra generations or bump opensearch_cert_generations[portfolio-api] in group_vars/siem_nodes.yml
#   and run `make siem` so siem01 maps it, run this script, commit, let Argo roll the API, then drop
#   the old generation from the mapping (ADR 0034 amendment "Certificates").
# Needs: openssl, sops (with .sops.yaml's age recipient), docker and SSH to siem01 for `make siem`.
# DOCKER=... as for make.
set -euo pipefail
cd "$(dirname "$0")/.."
generation=${1:?usage: scripts/siem-api-cert.sh <generation>}
[[ $generation =~ ^[1-9][0-9]{0,3}$ ]] || { echo "siem-api-cert: generation must be a number from 1" >&2; exit 2; }
out=cluster/infra/portfolio-api/siem-client.sops.yaml
cn=portfolio-api-g$generation

umask 077
mkdir -p .siem-tmp
chmod 0700 .siem-tmp
tmp=$(mktemp -d "$PWD/.siem-tmp/api-cert.XXXXXX")
cleanup() {
  find "$tmp" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$tmp/portfolio-api.key" 2>/dev/null
openssl req -new -key "$tmp/portfolio-api.key" -subj "/O=sdp/OU=siem/CN=$cn" -out "$tmp/portfolio-api.csr"
# The tooling container (root) writes the certificate next to the CSR.
chmod 0711 "$tmp"
chmod 0644 "$tmp/portfolio-api.csr"

make --no-print-directory siem DOCKER="${DOCKER:-docker}" \
  ARGS="--tags api-cert -e siem_api_csr=/work/${tmp#"$PWD"/}/portfolio-api.csr -e siem_api_generation=$generation"

crt=$tmp/portfolio-api.crt ca=$tmp/portfolio-api.ca.crt
if [ ! -s "$crt" ] || [ ! -s "$ca" ]; then echo "siem-api-cert: no certificate came back" >&2; exit 1; fi
subject=$(openssl x509 -in "$crt" -noout -subject -nameopt RFC2253)
[ "$subject" = "subject=CN=$cn,OU=siem,O=sdp" ] || { echo "siem-api-cert: unexpected $subject" >&2; exit 1; }
openssl verify -CAfile "$ca" "$crt" >/dev/null
[ "$(openssl x509 -in "$crt" -noout -pubkey)" = "$(openssl pkey -in "$tmp/portfolio-api.key" -pubout)" ] \
  || { echo "siem-api-cert: the certificate is not for the key made here" >&2; exit 1; }

# The plaintext Secret exists only in the scratch directory; what lands in the tree is sops' output.
python3 - "$crt" "$tmp/portfolio-api.key" "$ca" > "$tmp/secret.yaml" <<'PY'
import sys, yaml
crt, key, ca = (open(p).read() for p in sys.argv[1:4])
secret = {
    "apiVersion": "v1",
    "kind": "Secret",
    "metadata": {"name": "portfolio-api-siem", "namespace": "portfolio-api"},
    "type": "Opaque",
    "stringData": {"tls.crt": crt, "tls.key": key, "ca.crt": ca},
}
print("# The portfolio API's SIEM client certificate (ADR 0034), made by scripts/siem-api-cert.sh.")
print(yaml.safe_dump(secret, sort_keys=False), end="")
PY
# --filename-override only selects the .sops.yaml creation rule for the target path.
# Encrypted into the scratch directory and moved into the tree only after the check (review code L8):
# an existing file is never truncated or half-written.
sops --encrypt --filename-override "$out" "$tmp/secret.yaml" > "$tmp/secret.sops.yaml"
grep -q '^sops:' "$tmp/secret.sops.yaml" || { echo "siem-api-cert: sops did not encrypt; $out unchanged" >&2; exit 1; }
! grep -q 'BEGIN .*PRIVATE KEY' "$tmp/secret.sops.yaml" || { echo "siem-api-cert: plaintext key in the output; $out unchanged" >&2; exit 1; }
mv "$tmp/secret.sops.yaml" "$out"
echo "siem-api-cert: wrote $out ($cn, $(openssl x509 -in "$crt" -noout -enddate)); commit it"
