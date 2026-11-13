package pgpverify

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// Dearmor は armored 署名をバイナリの署名に戻す。
//
// gpg は `--no-armor` を付けたときバイナリで書く。makepkg は
// `gpg --detach-sign --no-armor` で .sig を作り、pacman は armored の .sig を
// 「パッケージに armored 署名を使うことはできません」で拒否する。
// rga のサーバは armored しか返さないので、gpg の契約に合わせるにはここで戻す。
func Dearmor(sigArmored string) ([]byte, error) {
	block, err := armor.Decode(strings.NewReader(sigArmored))
	if err != nil {
		return nil, fmt.Errorf("armored 署名を読めません: %w", err)
	}
	if block.Type != "PGP SIGNATURE" {
		return nil, fmt.Errorf("armored ブロックの種類が %s です（PGP SIGNATURE ではない）", block.Type)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, block.Body); err != nil {
		return nil, fmt.Errorf("armored 署名をデコードできません: %w", err)
	}
	return buf.Bytes(), nil
}
