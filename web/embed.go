// Package webdist はビルド済み PWA を embedded FS として公開する。
// `make web` が web/dist を作り、go:embed がバイナリに取り込む。
// dist は空でも 1 ファイル置いてあれば embed できる（プレースホルダを commit 済み）。
package webdist

import "embed"

//go:embed all:dist
var FS embed.FS
