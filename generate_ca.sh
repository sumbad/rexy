#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

mkdir -p ca

openssl ecparam \
  -name prime256v1 \
  -genkey \
  -noout \
  -out ca/hudsucker-ec.key

openssl pkcs8 \
  -topk8 \
  -nocrypt \
  -in ca/hudsucker-ec.key \
  -out ca/rexy.key

rm ca/hudsucker-ec.key

openssl req \
  -x509 \
  -new \
  -key ca/rexy.key \
  -sha256 \
  -days 3650 \
  -out ca/rexy.cer \
  -subj "/CN=Rexy Local CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

echo
echo "CA generated:"
echo "  ca/rexy.key"
echo "  ca/rexy.cer"
echo
echo "IMPORTANT:"
echo "  rexy.key is private and must never be committed."
