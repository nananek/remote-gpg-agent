#!/usr/bin/env bash
# mTLS 用のサーバ証明書とクライアント証明書を CA から発行する。
#   ./scripts/issue-client-cert.sh <client-name> <server-hostname>
set -euo pipefail
NAME="${1:?usage: issue-client-cert.sh <client-name> <server-hostname>}"
HOST="${2:?usage: issue-client-cert.sh <client-name> <server-hostname>}"
OUT=certs
[ -f "$OUT/ca.pem" ] || { echo "先に scripts/gen-ca.sh を実行してください" >&2; exit 1; }

openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/$NAME.key"
chmod 600 "$OUT/$NAME.key"
openssl req -new -key "$OUT/$NAME.key" -subj "/CN=$NAME" -out "$OUT/$NAME.csr"
openssl x509 -req -in "$OUT/$NAME.csr" -CA "$OUT/ca.pem" -CAkey "$OUT/ca.key" -CAcreateserial \
  -days 825 -sha256 \
  -extfile <(printf "extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\nbasicConstraints=critical,CA:FALSE\n") \
  -out "$OUT/$NAME.pem"

if [ ! -f "$OUT/server.pem" ]; then
  openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/server.key"
  chmod 600 "$OUT/server.key"
  openssl req -new -key "$OUT/server.key" -subj "/CN=$HOST" -out "$OUT/server.csr"
  openssl x509 -req -in "$OUT/server.csr" -CA "$OUT/ca.pem" -CAkey "$OUT/ca.key" -CAcreateserial \
    -days 825 -sha256 \
    -extfile <(printf "subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\nbasicConstraints=critical,CA:FALSE\n" "$HOST") \
    -out "$OUT/server.pem"
fi

echo "client: $OUT/$NAME.pem ($OUT/$NAME.key)"
echo "server: $OUT/server.pem ($OUT/server.key)"
