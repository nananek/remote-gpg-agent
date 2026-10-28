# remote-gpg-agent

PWA から `git commit -S` / `makepkg --sign` を完了させるための署名基盤。
秘密鍵は PWA の中で生まれ、PWA の中だけで使われる。サーバは **passkey(PRF) で暗号化された
バイト列を預かるだけ**で、平文の秘密鍵もパスフレーズも持たない。

```
[git / makepkg]
      │ gpg 互換の引数
      ▼
[rga client × N] ── mTLS (8443) ──▶ [rga-server] ◀── HTTPS ── [PWA × N]
      │                                │  envelope の出し入れだけ        │ passkey で解錠
      │ 返ってきた署名を検証            │                              │ 署名はここで完結
      ▼                                ▼
[gpg で GOODSIG]                    [bbolt]
```

利用者は 1 人。1 台のサーバに、署名する端末（`rga client`）と承認する PWA を何台でもつなぐ。
鍵束（vault）は 1 つで、クライアント証明書は端末の識別に使うだけ。どの鍵を署名できるかは
承認するパスキーがその鍵を解錠できるかで決まり、クライアントごとに鍵を分ける仕組みはない
（分けたいならサーバを分ける）。

## セキュリティモデル

| 場所 | 持つもの | 持たないもの |
| --- | --- | --- |
| PWA（各端末） | 秘密鍵（メモリ上）、パスキー | — |
| rga-server | 暗号化済み envelope、公開鍵、パスキーの公開鍵 | 秘密鍵、パスフレーズ、PRF 出力 |
| rga client | クライアント証明書、ピン留めした fingerprint | 秘密鍵 |

- envelope は `HKDF-SHA256(PRF出力, salt)` → AES-256-GCM。AAD は鍵の fingerprint。
- envelope を紐付けるには、その鍵の秘密鍵による所持証明（credential・keyId・salt・IV・ciphertext への署名）が要る。
  サーバは公開鍵で検証し、封印先の credential がセッションと一致しない要求も拒否する。
- PRF 非対応の authenticator は登録時に拒否する（解錠できないパスキーを作らせない）。
- パスキーは増やせる。追加したパスキーには、そのとき解錠していたパスキーが開ける鍵だけが再封印される
  （全鍵を自動で引き継ぐわけではない。他のパスキーでしか開けない鍵は、そのパスキーで解錠して扱う）。
- 解錠時に復号できなかった envelope はスキップし、残りの鍵はそのまま使える（壊れた鍵だけバックアップから戻す）。
- クライアントは、返ってきた署名を **自分が送ったバイト列とピン留め fingerprint** で必ず検証する。
  サーバがデータをすり替えても通らない。
- 通信は Tailscale の上に mTLS を重ねる。8443 は tailscaled で TLS 終端しない（証明書を消さないため）。

## リポジトリ構成

```
cmd/rga-server/    サーバ（PWA 配信 + mTLS API + WebAuthn + Web Push）
cmd/rga/           クライアント CLI（ping / sign / gpg-compat / keys / public-key）
internal/protocol/ JSON 契約と keyId 導出
internal/store/    bbolt 永続化
internal/server/   2 listener、WebAuthn、vault、承認 API
internal/client/   gpg 引数パース、mTLS transport、署名ループ
internal/pgpverify/ 返却署名のローカル検証
web/               PWA（Vite + TypeScript + OpenPGP.js v6）。ビルド成果物 dist/ は commit 済み
deploy/            Dockerfile / docker-compose.yml / tailscale serve 設定
.github/           CI（テスト + ghcr への distroless nonroot イメージ publish）
```

## 開発

Go も Node もホストに入れず、Docker で回す。

```sh
make test    # golang:1.27 コンテナで go test ./... （vendor 使用、ネットワーク不要）
make vet
make build   # bin/rga-server と bin/rga
make web     # PWA をビルドして web/dist を更新
```

PWA の単体テストは `cd web && NODE_ENV=development npm ci && npx vitest run`。

### 相互運用テスト（e2e）

`internal/e2e` は「OpenPGP.js の署名を本物の gpg が受け入れるか」「git commit -S が通るか」を
実際の `gpg` / `git` で確かめる。gpg の無い環境では自動で skip するので、ホストで実行する。

```sh
GOFLAGS="-mod=vendor" GOPROXY=off go test ./internal/e2e -v
# --- PASS: TestOpenPGPJSFixtureVerifiesWithGPG
# --- PASS: TestSignLoopProducesGPGVerifiableSignature
# --- PASS: TestGitCommitWithRemoteSigning
```

fixture を作り直すときは `cd web && node scripts/gen-openpgp-fixture.mjs ../internal/e2e/testdata`。

## サーバの配備

別サーバに docker-compose（tailscale サイドカー + rga-server）で置く。手順は
[docs/deploy.md](docs/deploy.md)。

## クライアントの設定

`~/.config/remote-gpg-agent/config.json`（`RGA_CONFIG` で変更可、mode 600 推奨）:

```json
{
  "url": "https://<host>.<tailnet>.ts.net:8443",
  "caCert": "~/.config/remote-gpg-agent/ca.pem",
  "clientCert": "~/.config/remote-gpg-agent/client.pem",
  "clientKey": "~/.config/remote-gpg-agent/client.key",
  "defaultKeyFingerprint": "<40桁の fingerprint>",
  "timeoutSec": 180
}
```

動作確認:

```sh
rga ping        # {"mode":"client","ok":true}
rga keys        # PWA で作った鍵が出る
```

### git

`gpg.program` は実行ファイル 1 つしか取れないので、ラッパーを置く:

```sh
install -m 755 scripts/rga-gpg-sign ~/.local/bin/rga-gpg-sign
git config --global gpg.program ~/.local/bin/rga-gpg-sign
git config --global gpg.format openpgp
git config --global user.signingkey <fingerprint>
git config --global commit.gpgsign true
```

`rga gpg-compat` は `--detach-sign` だけを遠隔署名に回し、`--verify` などは本物の gpg
（`REAL_GPG`、既定 `/usr/bin/gpg`）にそのまま渡す。これで `git log --show-signature` も動く。

### makepkg

`makepkg --sign` は PATH 上の `gpg` を呼ぶので、シムを前段に置く:

```sh
install -m 755 scripts/gpg-shim ~/.local/bin/gpg
export PATH="$HOME/.local/bin:$PATH"
```

## PWA の使い方

1. `https://<host>.<tailnet>.ts.net` を開く（ホーム画面に追加しておく）。
2. 「パスキーを作って鍵を生成」— 名前とメールを入れる。これが鍵の uid になる。
3. 表示されるバックアップ（パスフレーズ付き `.asc`）を保存する。
4. 端末で `git commit -S` すると、PWA に承認待ちが出る。Face ID で解錠して署名。
5. 2 台目以降のパスキーは「パスキーを追加」から。いま解錠中のパスキーが開ける鍵が再封印される
   （他のパスキーでしか開けない鍵は引き継がれない）。

## 既知の制約

- パスキーの PRF 拡張が必須（iOS 18+ / Safari、Chrome など）。非対応環境では登録できない。
- 鍵は OpenPGP.js の `curve25519Legacy`（v4）。GnuPG 2.4 との相互運用を e2e で固定している。
- サーバを落とすと署名できない。バックアップ `.asc` から gpg に戻す道は常に残す。
- 利用者 1 人・vault 1 つが前提。クライアント証明書は台数分発行できるが、鍵は全クライアントで共有される。
- クライアント証明書の失効は未対応（CRL/OCSP を見ていない）。古い証明書は期限まで有効なので、
  1 台だけ確実に切るには CA ごと作り直してサーバ証明書と全クライアントを配り直す。
- `web/dist/` は commit 済み。PWA を変えたら `make web` して一緒にコミットする。
