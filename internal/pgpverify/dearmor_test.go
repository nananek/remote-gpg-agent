package pgpverify

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

func armorSig(t *testing.T, raw []byte) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, "PGP SIGNATURE", nil)
	if err != nil {
		t.Fatalf("armor.Encode: %v", err)
	}
	if _, err := w.Write(raw); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return buf.String()
}

func TestDearmorRoundTrip(t *testing.T) {
	// detached 署名のバイナリのつもり（先頭は old format の署名パケット 0x88）。
	// 中身そのものは往復の確認用なので、任意のバイト列でよい。
	raw := []byte{0x88, 0x5d, 0x00, 0x04, 0x16, 0x08, 0x00, 0x0a, 0xff, 0x00}
	got, err := Dearmor(armorSig(t, raw))
	if err != nil {
		t.Fatalf("Dearmor: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("Dearmor = %x, want %x", got, raw)
	}
}

func TestDearmorRejectsNonSignature(t *testing.T) {
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		t.Fatalf("armor.Encode: %v", err)
	}
	_, _ = w.Write([]byte{0x99})
	_ = w.Close()
	if _, err := Dearmor(buf.String()); err == nil {
		t.Fatal("公開鍵ブロックを受け付けました")
	}
}

func TestDearmorRejectsGarbage(t *testing.T) {
	if _, err := Dearmor("not a signature"); err == nil {
		t.Fatal("armored でない入力を読みました")
	}
	if _, err := Dearmor(strings.Join([]string{
		"-----BEGIN PGP SIGNATURE-----",
		"",
		"!!!!",
		"-----END PGP SIGNATURE-----",
	}, "\n")); err == nil {
		t.Fatal("base64 でない本体を読みました")
	}
}
