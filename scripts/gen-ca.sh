#!/usr/bin/env bash
# mTLS 用の自前 CA を作る。CA 秘密鍵は 1Password 等に退避する。
set -euo pipefail
OUT="${1:-certs}"
mkdir -p "$OUT"
if [ -f "$OUT/ca.pem" ]; then
  echo "$OUT/ca.pem が既にあります。上書きしません。" >&2
  exit 1
fi
openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/ca.key"
chmod 600 "$OUT/ca.key"
openssl req -x509 -new -key "$OUT/ca.key" -sha256 -days 3650 \
  -subj "/CN=remote-gpg-agent CA" -out "$OUT/ca.pem" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
echo "wrote $OUT/ca.pem"
