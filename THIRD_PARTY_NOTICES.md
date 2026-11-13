# Third-party notices

`remote-gpg-agent` のオリジナルコードは [MIT License](LICENSE) です。
このファイルは、リポジトリが同梱・バンドルしている第三者コンポーネントの
ライセンスと、LGPL 対象部分の再ビルド方法をまとめたものです。

## OpenPGP.js

- コンポーネント: `openpgp` 6.3.2
- ライセンス: LGPL-3.0-or-later
- 同梱場所: `web/dist/assets/index-*.js`（Vite が `web/src` からバンドル）
- 対応するソース: <https://github.com/openpgpjs/openpgpjs/tree/v6.3.2>
  （`web/package-lock.json` が同じバージョンを固定しています）

`web/dist` は commit 済みで、サーバのバイナリに `go:embed` されます。
MIT License はオリジナルコードに適用され、OpenPGP.js の部分は LGPL-3.0-or-later
のままです。LGPL の全文は [LICENSES/LGPL-3.0-or-later.txt](LICENSES/LGPL-3.0-or-later.txt)、
LGPL v3 が参照する GPL v3 は [LICENSES/GPL-3.0-or-later.txt](LICENSES/GPL-3.0-or-later.txt)
にあります。

OpenPGP.js を差し替える場合は `web/package.json` の依存を変更し、
リポジトリの手順（`make web`）で `web/dist` を再生成してください。
アプリ側のソース、ビルド設定、lockfile はすべてこのリポジトリに含まれています。

## Go の依存関係

Go の依存関係は `vendor/` にソースとライセンス全文を同梱しています。
主なライセンスは MIT、BSD-3-Clause、ISC、Apache-2.0 です。
Apache-2.0 の全文は [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt) にあります。
各モジュールの著作権表示と条件は、それぞれの `vendor/**/LICENSE*` を参照してください。

## 開発時のみ使う依存関係

`web/package-lock.json` の開発依存（Vite、TypeScript、Vitest など）は
`web/dist` にはバンドルされません。それぞれのライセンスは npm パッケージに
含まれる LICENSE に従います。
