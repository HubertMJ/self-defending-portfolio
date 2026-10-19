#!/usr/bin/env bash
# The detection lab CronJob's SIEM client certificate (ADR 0034 amendment 2026-10-18: lab-runner, the
# one lab identity a cluster pod holds, as a KSOPS Secret in git; ADR 0006). It mirrors
# scripts/siem-api-cert.sh but in two phases, because the CSR is signed inside the combined siem01 run
# that also deploys the rules sync (.omc/plans/lab-runner-deploy-cmd.txt), not inline from here:
#
#   generate  (default)  make the RSA-4096 PKCS#8 key and a CN=lab-runner-g<N> clientAuth CSR; write
#                         the CSR to cluster/infra/lab/lab-runner.csr (a CSR carries only the public
#                         key, so it is safe in git) and a SOPS Secret holding the real key with
#                         PLACEHOLDER tls.crt/ca.crt. Then run the combined command, which signs the
#                         CSR and drops lab-runner.crt + lab-runner.ca.crt next to it.
#   finalize             fold the signed certificate and siem01's CA into the Secret, keeping the key
#                         that is already there (read back from the encrypted Secret, never a loose
#                         plaintext file), after proving the certificate is for that key.
#
# Usage:
#   scripts/siem-lab-runner-cert.sh generate <generation>
#   scripts/siem-lab-runner-cert.sh finalize <generation> [<cert.crt> <ca.crt>]
#     cert/ca default to cluster/infra/lab/lab-runner.crt and .ca.crt (where the signing run writes them).
# Needs: openssl, sops (with .sops.yaml's age recipient; finalize also needs the age private key to
# read the key back). The scratch directory is shredded on every exit.
set -euo pipefail
cd "$(dirname "$0")/.."

phase=${1:?usage: scripts/siem-lab-runner-cert.sh generate|finalize <generation> [cert ca]}
generation=${2:?usage: scripts/siem-lab-runner-cert.sh generate|finalize <generation> [cert ca]}
[[ $generation =~ ^[1-9][0-9]{0,3}$ ]] || { echo "siem-lab-runner-cert: generation must be a number from 1" >&2; exit 2; }
cn=lab-runner-g$generation
out=cluster/infra/lab/lab-runner-siem.sops.yaml
csr=cluster/infra/lab/lab-runner.csr

umask 077
mkdir -p .siem-tmp
chmod 0700 .siem-tmp
tmp=$(mktemp -d "$PWD/.siem-tmp/lab-runner-cert.XXXXXX")
cleanup() {
  find "$tmp" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT

# The plaintext Secret only ever exists in the scratch directory; what lands in the tree is sops' output.
write_secret() {  # <key-file> <crt-file> <ca-file>
  python3 - "$1" "$2" "$3" > "$tmp/secret.yaml" <<'PY'
import sys, yaml
key, crt, ca = (open(p).read() for p in sys.argv[1:4])
secret = {
    "apiVersion": "v1",
    "kind": "Secret",
    "metadata": {"name": "lab-runner-siem", "namespace": "lab"},
    "type": "Opaque",
    "stringData": {"tls.crt": crt, "tls.key": key, "ca.crt": ca},
}
print("# The detection lab CronJob's SIEM client certificate (ADR 0034), made by")
print("# scripts/siem-lab-runner-cert.sh. The key is real and sops-encrypted; until the combined")
print("# siem01 signing run (.omc/plans/lab-runner-deploy-cmd.txt) and `finalize`, tls.crt and ca.crt")
print("# are PLACEHOLDERs, so the CronJob stays suspended (cluster/infra/lab/cronjob.yaml).")
print(yaml.safe_dump(secret, sort_keys=False), end="")
PY
  sops --encrypt --filename-override "$out" "$tmp/secret.yaml" > "$tmp/secret.sops.yaml"
  grep -q '^sops:' "$tmp/secret.sops.yaml" || { echo "siem-lab-runner-cert: sops did not encrypt; $out unchanged" >&2; exit 1; }
  ! grep -q 'BEGIN .*PRIVATE KEY' "$tmp/secret.sops.yaml" || { echo "siem-lab-runner-cert: plaintext key in the output; $out unchanged" >&2; exit 1; }
  mv "$tmp/secret.sops.yaml" "$out"
}

case $phase in
generate)
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$tmp/lab-runner.key" 2>/dev/null
  openssl req -new -key "$tmp/lab-runner.key" -subj "/O=sdp/OU=siem/CN=$cn" -out "$tmp/lab-runner.csr"
  cp "$tmp/lab-runner.csr" "$csr"
  chmod 0644 "$csr"
  printf '%s\n' "PLACEHOLDER-lab-runner-cert-fill-with-finalize-after-siem01-signing" > "$tmp/placeholder"
  write_secret "$tmp/lab-runner.key" "$tmp/placeholder" "$tmp/placeholder"
  echo "siem-lab-runner-cert: wrote $csr and $out ($cn, key + PLACEHOLDER cert/ca); commit both."
  echo "Next: run the combined command in .omc/plans/lab-runner-deploy-cmd.txt, then:"
  echo "  scripts/siem-lab-runner-cert.sh finalize $generation"
  ;;
finalize)
  crt=${3:-cluster/infra/lab/lab-runner.crt}
  ca=${4:-cluster/infra/lab/lab-runner.ca.crt}
  if [ ! -s "$crt" ] || [ ! -s "$ca" ]; then echo "siem-lab-runner-cert: need $crt and $ca from the signing run" >&2; exit 1; fi
  [ -s "$out" ] || { echo "siem-lab-runner-cert: $out does not exist; run generate first" >&2; exit 1; }
  # The key is read back from the encrypted Secret, so it lives in exactly one place.
  sops --decrypt "$out" > "$tmp/current.yaml"
  python3 - "$tmp/current.yaml" > "$tmp/lab-runner.key" <<'PY'
import sys, yaml
print(yaml.safe_load(open(sys.argv[1]))["stringData"]["tls.key"], end="")
PY
  grep -q 'BEGIN .*PRIVATE KEY' "$tmp/lab-runner.key" || { echo "siem-lab-runner-cert: no key in $out" >&2; exit 1; }
  subject=$(openssl x509 -in "$crt" -noout -subject -nameopt RFC2253)
  [ "$subject" = "subject=CN=$cn,OU=siem,O=sdp" ] || { echo "siem-lab-runner-cert: unexpected $subject" >&2; exit 1; }
  openssl verify -CAfile "$ca" "$crt" >/dev/null
  [ "$(openssl x509 -in "$crt" -noout -pubkey)" = "$(openssl pkey -in "$tmp/lab-runner.key" -pubout)" ] \
    || { echo "siem-lab-runner-cert: the certificate is not for the key in $out" >&2; exit 1; }
  write_secret "$tmp/lab-runner.key" "$crt" "$ca"
  echo "siem-lab-runner-cert: folded the signed certificate into $out ($cn, $(openssl x509 -in "$crt" -noout -enddate)); commit it."
  echo "Then set cluster/infra/lab/cronjob.yaml spec.suspend to false and pin the lab-runner image digest."
  ;;
*)
  echo "siem-lab-runner-cert: unknown phase '$phase' (generate|finalize)" >&2; exit 2;;
esac
