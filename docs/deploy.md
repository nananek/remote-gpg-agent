# 配備手順（別サーバ + docker-compose + tailscale サイドカー）

このリポジトリのサーバは**このマシンには置かない**。tailnet に入った別ホストに置く。
`deploy/` 以下だけで完結する。

## 前提

- 配備先: Linux、Docker（rootful 可）、`docker compose` v2
- tailnet に参加できること（`TS_AUTHKEY` を用意）
- そのホストの 443 と 8443 が空いていること

## イメージ

CI（`.github/workflows/image.yml`）が main への push と `v*` タグで
`ghcr.io/nananek/remote-gpg-agent` を amd64 / arm64 のマルチアーキで publish する。

- 実行イメージは **distroless static の `nonroot`（uid/gid 65532）固定**。`/data` の所有者を
  65532 にするのはこのため（下の 3. を参照）。
- shell も curl も入っていない。healthcheck は `/rga-server healthcheck` を直接叩いている。
- タグ: `latest`（main）、`vX.Y.Z` / `X.Y`（`v*` タグ）、`sha-<commit>`。
- リポジトリが private のときは、配備先で `docker login ghcr.io`（`read:packages` を持つトークン）が必要。
- 独自ビルドは `docker compose build` でもよい（`deploy/Dockerfile` は同じものを使う）。
  compose は `image:` と `build:` の両方を持つので、build したイメージがそのまま使われる。
  使うタグを固定したいときは `.env` に `RGA_IMAGE=ghcr.io/nananek/remote-gpg-agent:vX.Y.Z` を書く。

## 1. CA を作る（手元で 1 回だけ）

```sh
./scripts/gen-ca.sh certs
# wrote certs/ca.pem
```

`certs/ca.key` は 1Password などに退避して、作業ツリーからは消す。`certs/` は `.gitignore` 済み。

## 2. サーバ証明書とクライアント証明書を発行する

```sh
./scripts/issue-client-cert.sh <client-name> <host>.<tailnet>.ts.net
# client: certs/<client-name>.pem (certs/<client-name>.key)
# server: certs/server.pem (certs/server.key)
```

`<client-name>` は端末ごとに分ける（`laptop`、`workstation` など）。証明書は台数分発行でき、
どれも同じサーバ・同じ vault につながる。クライアント証明書は端末の識別に使うだけで、
署名できる鍵の範囲は証明書では制限しない。

発行し直しても古い証明書は失効しない（サーバは CRL/OCSP を見ていない）。古い証明書は
有効期限（825 日）まで通り続けるので、1 台だけ確実に切るには CA ごと作り直して
`server.pem` と全クライアントの証明書を配り直す。端末を手放すときはこの点に注意する。

## 3. 配備先にファイルを置く

```sh
rsync -a deploy/ server:/srv/rga/
rsync -a certs/ca.pem certs/server.pem certs/server.key server:/srv/rga/certs/
mkdir -p /srv/rga/data
```

**`data` の所有者を 65532 にする**（distroless の nonroot）。これを忘れると起動に失敗する:

```
level=ERROR msg=startup err="open /data/rga.db: permission denied"
```

```sh
chown -R 65532:65532 /srv/rga/data
```

## 4. 環境変数

```sh
cd /srv/rga
cp .env.example .env
cp rga.env.example rga.env
```

`.env`（compose 側。`${}` が展開される）:

```
TS_HOSTNAME=rga
TS_TAILNET=<your-tailnet>.ts.net
TS_AUTHKEY=tskey-auth-...
```

`rga.env`（コンテナ側。実値をそのまま書く）:

```
RGA_DATA_DIR=/data
RGA_DB=/data/rga.db
RGA_ORIGIN=https://<host>.<tailnet>.ts.net
RGA_RPID=<host>.<tailnet>.ts.net
RGA_WEB_ADDR=127.0.0.1:3080
RGA_CLIENT_ADDR=0.0.0.0:8443
RGA_TLS_CERT=/certs/server.pem
RGA_TLS_KEY=/certs/server.key
RGA_TLS_CA=/certs/ca.pem
RGA_VAPID_SUBJECT=mailto:you@example.com
RGA_VAPID_PUBLIC=...
RGA_VAPID_PRIVATE=...
RGA_BOOTSTRAP_TOKEN=...
```

VAPID 鍵とブートストラップトークンは生成する:

```sh
docker run --rm --entrypoint /rga-server remote-gpg-agent:local vapid
# RGA_VAPID_PUBLIC=...
# RGA_VAPID_PRIVATE=...
openssl rand -base64 24     # RGA_BOOTSTRAP_TOKEN
```

`RGA_ORIGIN` と `RGA_RPID` は **PWA の URL と完全に一致**させる（WebAuthn の RP ID になる）。
ポートは書かない（443 の暗黙）。

## 5. 起動

```sh
cd /srv/rga
docker compose pull        # ghcr のイメージ（distroless nonroot, amd64/arm64）
docker compose up -d
docker compose ps          # 2 つとも healthy
```

自前でビルドする場合は `docker compose pull` の代わりに `docker compose build`。

## 6. 動作確認

```sh
# tailscale 側で 443/8443 が生えているか
docker compose exec tailscale tailscale status | head -3
docker compose exec tailscale tailscale serve status

# コンテナ内 healthcheck（distroless なので curl は無い）
docker compose exec rga-server /rga-server healthcheck; echo $?   # 0

# PWA（tailnet 内の端末から）
curl -s https://<host>.<tailnet>.ts.net/healthz
# {"mode":"web","ok":true}

# mTLS: 証明書ありは通る
curl -s --cacert certs/ca.pem --cert certs/<client-name>.pem --key certs/<client-name>.key \
  https://<host>.<tailnet>.ts.net:8443/healthz
# {"mode":"client","ok":true}

# mTLS: 証明書なしは弾かれる（exit 56）
curl -s --cacert certs/ca.pem https://<host>.<tailnet>.ts.net:8443/healthz; echo $?
# 56
```

サーバ側には `tls: client didn't provide a certificate` が残る。

## 7. 端末側

`certs/<client-name>.pem` / `.key` / `ca.pem` を `~/.config/remote-gpg-agent/` に置き、
`config.json` を書く（[README](../README.md#クライアントの設定)）。`chmod 600` を忘れない。

```sh
rga ping     # {"mode":"client","ok":true}
```

## 8. パスキーと鍵

`https://<host>.<tailnet>.ts.net` を開いてパスキー作成 → 鍵生成 → バックアップ保存。
サーバに平文鍵は渡らない。`/srv/rga/data/rga.db`（bbolt）には envelope しか入らない。

## トラブルシュート

| 症状 | 原因 | 対処 |
| --- | --- | --- |
| `open /data/rga.db: permission denied` | `/data` が 65532 所有でない | `chown -R 65532:65532 /srv/rga/data` |
| `tls: client didn't provide a certificate`（クライアント側で失敗） | `clientCert`/`clientKey` 未設定 or 期限切れ | 再発行して `config.json` を更新 |
| PWA でパスキー登録が `PRF 非対応` で失敗 | authenticator が PRF 拡張非対応 | iOS 18+ / 対応ブラウザを使う |
| PWA が `NotAllowedError` | `RGA_ORIGIN` / `RGA_RPID` が実際の URL と違う | 環境変数を直して再起動 |
| 443 に繋がらない | tailscaled が証明書を取れていない | `docker compose logs tailscale` を見る。`TS_CERT_DOMAIN` を確認 |
| 8443 で TLS エラーが `tlsv1 alert` になる | serve.json が `TCPForward` でなく `HTTPS` になっている | 8443 は必ず `"TCPForward": "127.0.0.1:8443"` |

## tailscale まわりの注意

`deploy/tailscale/serve.json` で 2 本だけ開けている。

- `443`: tailscaled が TLS 終端して PWA（`127.0.0.1:3080`）へプロキシ
- `8443`: 素の TCP 転送。**TLS 終端しない**（終端するとクライアント証明書が消えて mTLS が壊れる）

`rga-server` は `network_mode: "service:tailscale"` でサイドカーとネットワークを共有しているので、
tailnet からの入口はこの 2 本しかない。

ACL はクライアント → サーバ方向だけ通せばよい（`rga client` は 8443、PWA は 443）。
サーバからクライアントへ接続する処理はない（Web Push は Apple/Google 向けの外向き通信で、
tailnet の ACL は通らない）。
