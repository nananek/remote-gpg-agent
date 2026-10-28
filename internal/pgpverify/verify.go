// Package pgpverify は「返ってきた署名を、自分の送ったバイト列と
// ピン留めした fingerprint で検証する」ためだけの薄いラッパー。
package pgpverify

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// ArmoredDetached は detached 署名を検証する。
//   - keyArmored の fingerprint が expectFpr と一致すること
//   - data がその鍵で署名されていること
//
// どちらかが崩れればエラー。サーバがデータを差し替えても、PWA が別の鍵で
// 署名しても、ここで止まる。
func ArmoredDetached(keyArmored, expectFpr string, data []byte, sigArmored string) error {
	el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(keyArmored))
	if err != nil {
		return fmt.Errorf("公開鍵を読めません: %w", err)
	}
	if len(el) != 1 {
		return fmt.Errorf("公開鍵は 1 本だけであるべきです（%d 本）", len(el))
	}
	got := strings.ToUpper(hex.EncodeToString(el[0].PrimaryKey.Fingerprint[:]))
	if got != strings.ToUpper(strings.TrimSpace(expectFpr)) {
		return fmt.Errorf("公開鍵の fingerprint が一致しません: %s", got)
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(
		el, bytes.NewReader(data), strings.NewReader(sigArmored), nil,
	); err != nil {
		return fmt.Errorf("署名の検証に失敗しました: %w", err)
	}
	return nil
}

var ErrEmptyPublicKey = errors.New("public key is empty")
