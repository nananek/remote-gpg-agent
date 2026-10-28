package cryptoutil

import (
	"encoding/base64"
	"strings"
)

func B64(b []byte) string    { return base64.StdEncoding.EncodeToString(b) }
func B64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func B64Decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// B64URLDecode は padding 有無どちらも受け付ける（ブラウザは常に padding なし）。
func B64URLDecode(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	return base64.RawURLEncoding.DecodeString(s)
}
