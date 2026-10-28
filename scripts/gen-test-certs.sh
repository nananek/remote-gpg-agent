#!/usr/bin/env bash
# テスト用の CA + サーバ証明書 + クライアント証明書を一気に作る。
# 本番用は gen-ca.sh / issue-client-cert.sh を使う。
set -euo pipefail
OUT="${1:-test/fixtures/certs}"
HOST="${2:-localhost}"
mkdir -p "$OUT"
cd "$OUT"

openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 3650 -subj "/CN=rga test CA" -out ca.pem \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -subj "/CN=$HOST" -out server.csr
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 -sha256 \
  -extfile <(printf "subjectAltName=DNS:%s,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n" "$HOST") \
  -out server.pem

openssl ecparam -name prime256v1 -genkey -noout -out client.key
openssl req -new -key client.key -subj "/CN=test-client" -out client.csr
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 -sha256 \
  -extfile <(printf "extendedKeyUsage=clientAuth\nbasicConstraints=critical,CA:FALSE\n") \
  -out client.pem
