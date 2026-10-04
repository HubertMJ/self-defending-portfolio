#!/usr/bin/env bash
# The remote CSR entry point signs exactly the expected client identity and nothing more
# (siem contract C1, ansible/roles/opensearch/tasks/sign_client_csr.yml). Runs the real task file
# in the tooling container against generated CSRs and a throwaway CA:
#   refused: the expected name admin; a CSR for CN=admin-g1 when shipper-k3s01 is expected; an
#            extra RDN; a multi-valued RDN; a different DN; CA:TRUE; a SAN; a broken signature;
#            a local identity; generation 0
#   accepted: the expected DN - and the certificate has exactly that subject, CA:FALSE (critical),
#            keyUsage digitalSignature (critical), EKU clientAuth only, no SAN and no extension the
#            CSR asked for, 365 days, issued by the CA.
# Mutations that must fail it: drop the subject compare; copy the CSR's extensions.
set -euo pipefail
cd "$(dirname "$0")/../.."
DOCKER=${DOCKER:-docker}

if [ "${1:-}" != "--inside" ]; then
  $DOCKER image inspect sdp-tooling >/dev/null 2>&1 || $DOCKER build -q -t sdp-tooling -f scripts/Dockerfile.tooling .
  exec $DOCKER run --rm -i --user "$(id -u):$(id -g)" -e HOME=/tmp -e USER=csr-test \
    -v "$PWD":/repo:ro -w /tmp sdp-tooling bash /repo/tests/siem/csr-signer.sh --inside
fi

# --- inside the tooling container ---
w=$(mktemp -d)
export ANSIBLE_ROLES_PATH=/repo/ansible/roles ANSIBLE_COLLECTIONS_PATH=$w/collections \
  ANSIBLE_LOCAL_TEMP=$w/tmp ANSIBLE_REMOTE_TMP=$w/rtmp
ansible-galaxy collection install 'community.crypto>=2.20.0' -p "$w/collections" >/dev/null
mkdir -p "$w/pki"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$w/pki/ca.key" -out "$w/pki/ca.crt" -days 30 \
  -subj "/O=sdp/OU=siem/CN=csr-test-ca" -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

n=0 fail=0
csr() { # <file> <subject> [openssl req args...]
  local f=$1 subj=$2; shift 2
  openssl req -new -newkey rsa:2048 -nodes -keyout "$w/$f.key" -out "$w/$f.csr" -subj "$subj" "$@" 2>/dev/null
}
sign() { # <csr file> <name> <generation> -> exit code of the playbook; certificate in $w/<csr>.crt
  rm -f "$w/$1.crt"
  ansible-playbook /repo/tests/siem/csr-signer.yml -e csr_test_pki="$w/pki" -e csr_test_csr="$w/$1.csr" \
    -e csr_test_name="$2" -e csr_test_generation="$3" -e csr_test_out="$w/$1.crt" >"$w/$1.log" 2>&1
}
refused() { # <description> <csr file> <name> <generation>
  n=$((n + 1))
  if sign "$2" "$3" "$4"; then
    echo "FAIL refused: $1 - a certificate was issued"; fail=1
  elif [ -e "$w/$2.crt" ]; then
    echo "FAIL refused: $1 - the run failed but left a certificate"; fail=1
  elif reason=$(grep -oE 'Refused[^.(]*|self-signature verify failure' "$w/$2.log" | head -n 1) && [ -n "$reason" ]; then
    echo "ok   refused: $1 ($reason)"
  else
    echo "FAIL refused: $1 - failed for another reason:"; tail -n 15 "$w/$2.log"; fail=1
  fi
}

csr admin "/O=sdp/OU=siem/CN=admin-g1"
refused "expected name admin through the remote entry point" admin admin 1
refused "CSR for CN=admin-g1,OU=siem,O=sdp when shipper-k3s01 is expected" admin shipper-k3s01 1
csr extra "/O=sdp/OU=siem/OU=extra/CN=shipper-k3s01-g1"
refused "CN=shipper-k3s01-g1 with an extra RDN" extra shipper-k3s01 1
csr multi "/O=sdp/OU=siem+CN=shipper-k3s01-g1" -multivalue-rdn
refused "multi-valued RDN OU=siem+CN=shipper-k3s01-g1" multi shipper-k3s01 1
csr other "/O=sdp/OU=siem/CN=portfolio-api-g1"
refused "a DN different from the expected one" other shipper-k3s01 1
csr ca "/O=sdp/OU=siem/CN=shipper-k3s01-g1" -addext "basicConstraints=critical,CA:TRUE"
refused "CSR requesting basicConstraints CA:TRUE" ca shipper-k3s01 1
csr san "/O=sdp/OU=siem/CN=shipper-k3s01-g1" -addext "subjectAltName=DNS:siem01,IP:10.4.2.10"
refused "CSR with a SAN" san shipper-k3s01 1
csr local "/O=sdp/OU=siem/CN=shipper-siem01-g1"
refused "local identity shipper-siem01" local shipper-siem01 1
csr gen0 "/O=sdp/OU=siem/CN=shipper-k3s01-g0"
refused "generation 0" gen0 shipper-k3s01 0
csr broken "/O=sdp/OU=siem/CN=shipper-k3s01-g1"
python3 - "$w/broken.csr" <<'PY'
import base64, sys
p = sys.argv[1]
lines = open(p).read().split("\n")
der = bytearray(base64.b64decode("".join(lines[1:-2])))
der[-8] ^= 0xFF  # inside the signature value
b64 = base64.b64encode(bytes(der)).decode()
open(p, "w").write(lines[0] + "\n" + "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64)) + "\n" + lines[-2] + "\n")
PY
refused "CSR with a broken self-signature" broken shipper-k3s01 1

# Accepted: the CSR asks for server use, certificate signing and a policy on top of the right DN;
# none of it may reach the certificate.
csr good "/O=sdp/OU=siem/CN=shipper-test-g1" -addext "extendedKeyUsage=serverAuth,clientAuth" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign" -addext "certificatePolicies=1.2.3.4"
n=$((n + 1))
if ! sign good shipper-test 1; then
  echo "FAIL accepted: the expected DN was refused"; tail -n 20 "$w/good.log"; fail=1
else
  c=$w/good.crt
  ext=$(openssl x509 -in "$c" -noout -text | sed -n '/X509v3 extensions:/,/Signature Algorithm:/p')
  check() { if "$@"; then :; else echo "FAIL accepted: $d"; fail=1; return 0; fi; echo "ok   accepted: $d"; }
  d="subject is CN=shipper-test-g1,OU=siem,O=sdp"
  check test "$(openssl x509 -in "$c" -noout -subject -nameopt RFC2253)" = "subject=CN=shipper-test-g1,OU=siem,O=sdp"
  d="issued by the CA and valid for client authentication"
  verifies() { openssl verify -CAfile "$w/pki/ca.crt" -purpose sslclient "$c" >/dev/null; }
  check verifies
  d="basicConstraints critical CA:FALSE"
  check grep -qzE 'Basic Constraints: critical\s+CA:FALSE' <<<"$ext"
  d="keyUsage critical digitalSignature only"
  check grep -qzE 'Key Usage: critical\s+Digital Signature\s' <<<"$ext"
  d="EKU clientAuth only"
  check grep -qzE 'Extended Key Usage: *\s+TLS Web Client Authentication\s' <<<"$ext"
  d="no SAN"
  no_san() { ! grep -q "Subject Alternative Name" <<<"$ext"; }
  check no_san
  d="no extension beyond BC, KU, EKU, SKI, AKI (nothing copied from the CSR)"
  # extension headers are the lines indented by exactly 12 spaces
  check test "$(grep -cE '^ {12}[^ ]' <<<"$ext")" = 5
  d="valid for 365 days"
  check test "$(( ($(date -d "$(openssl x509 -in "$c" -noout -enddate | cut -d= -f2)" +%s) - $(date +%s) + 43200) / 86400 ))" = 365
fi
csr api "/O=sdp/OU=siem/CN=portfolio-api-g2"
n=$((n + 1))
if sign api portfolio-api 2 && [ -s "$w/api.crt" ]; then echo "ok   accepted: portfolio-api generation 2"
else echo "FAIL accepted: portfolio-api generation 2 was refused"; fail=1; fi

rm -rf "$w"
if [ "$fail" != 0 ]; then echo "csr-signer: FAIL"; exit 1; fi
echo "csr-signer: PASS ($n cases)"
