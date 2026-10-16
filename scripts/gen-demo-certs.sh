#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Generate the DEMO-ONLY certificate authority and MQTT broker certificate.
#
#   certs/generated/demo-ca.key      CA private key        (git-ignored, stays local)
#   certs/generated/demo-ca.crt      CA certificate (PEM)  (used by mosquitto_sub)
#   certs/generated/demo-ca.der      CA certificate (DER)  (embedded in the firmware)
#   certs/generated/server.key       broker private key    (committed: demo only)
#   certs/generated/server.crt       broker certificate, SAN: mosquitto, localhost
#
# ECDSA P-256 everywhere, matching the single cipher suite the firmware enables.
# The firmware has no real-time clock source, so it does not check validity dates.
#
# Regenerating the CA changes the embedded certificate and therefore the
# firmware hash, so existing files are kept unless FORCE=1. Everything except
# demo-ca.key is committed, so all clones build the same firmware (certs/README.md).
set -euo pipefail

out="${1:-certs/generated}"
mkdir -p "${out}"

if [[ -f "${out}/demo-ca.der" && "${FORCE:-0}" != "1" ]]; then
  echo "certs: ${out} already exists (FORCE=1 to regenerate; changes the firmware hash)"
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
umask 077

openssl ecparam -name prime256v1 -genkey -noout -out "${out}/demo-ca.key"
openssl req -x509 -new -key "${out}/demo-ca.key" -sha256 -days 3650 \
  -subj "/O=DEMO ONLY/CN=CRA demo CA - not for production" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "${out}/demo-ca.crt"
openssl x509 -in "${out}/demo-ca.crt" -outform DER -out "${out}/demo-ca.der"

openssl ecparam -name prime256v1 -genkey -noout -out "${out}/server.key"
openssl req -new -key "${out}/server.key" \
  -subj "/O=DEMO ONLY/CN=mosquitto" -out "${tmp}/server.csr"
cat > "${tmp}/server.ext" <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:mosquitto,DNS:localhost
EXT
openssl x509 -req -in "${tmp}/server.csr" -CA "${out}/demo-ca.crt" -CAkey "${out}/demo-ca.key" \
  -CAcreateserial -CAserial "${tmp}/ca.srl" -days 3650 -sha256 \
  -extfile "${tmp}/server.ext" -out "${out}/server.crt"

chmod 0644 "${out}/demo-ca.crt" "${out}/demo-ca.der" "${out}/server.crt"
openssl verify -CAfile "${out}/demo-ca.crt" "${out}/server.crt"
echo "certs: demo CA sha256 $(sha256sum "${out}/demo-ca.der" | cut -c1-16)..."
