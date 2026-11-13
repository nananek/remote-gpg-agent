package client

import (
	"path/filepath"
	"strings"
)

// 署名要求の purpose。PWA はこの値で表示を切り替える。
const (
	PurposeGitCommit = "git-commit"
	PurposeMakepkg   = "makepkg"
	PurposeRepoDB    = "repo-db"
	PurposeFile      = "file"
	PurposeSign      = "sign"
)

// ClassifyPurpose は gpg の起動引数から署名の種類を決める。
//
// git はコミット対象を標準入力で渡す（File が空）ので git-commit。
// makepkg / repo-add は対象ファイルを引数で渡すので、拡張子で判別する。
// RGA_PURPOSE が設定されていればそれを優先する（シムを挟めない道具の逃げ道）。
func ClassifyPurpose(inv GpgInvocation, override string) string {
	if p := strings.TrimSpace(override); p != "" {
		return p
	}
	if inv.File == "" {
		return PurposeGitCommit
	}
	base := strings.ToLower(filepath.Base(inv.File))
	switch {
	case strings.Contains(base, ".pkg.tar"):
		return PurposeMakepkg
	case strings.Contains(base, ".db.tar"), strings.Contains(base, ".files.tar"),
		strings.HasSuffix(base, ".db"), strings.HasSuffix(base, ".files"):
		return PurposeRepoDB
	default:
		return PurposeFile
	}
}

// DescriptionFor は PWA に出す短い説明を決める。
// ファイル署名なら対象のファイル名、標準入力なら作業ディレクトリ。
func DescriptionFor(inv GpgInvocation, cwd, override string) string {
	if d := strings.TrimSpace(override); d != "" {
		return d
	}
	if inv.File != "" {
		return filepath.Base(inv.File)
	}
	if cwd != "" {
		return cwd
	}
	return "rga"
}
