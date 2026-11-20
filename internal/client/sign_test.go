package client

import (
	"context"
	"errors"
	"testing"
	"time"

	rgaproto "github.com/nananek/remote-gpg-agent/internal/protocol"
)

// fakeTransport は決められた順に応答を返す。
type fakeTransport struct {
	posts      int
	gets       int
	statuses   []string
	keys       []rgaproto.KeyMeta
	lastCreate *rgaproto.CreateSignRequest
}

func (f *fakeTransport) Do(method, path string, body any, out any) error {
	switch method {
	case "POST":
		if path == "/api/v1/requests" {
			f.posts++
			if req, ok := body.(rgaproto.CreateSignRequest); ok {
				f.lastCreate = &req
			}
			*(out.(*rgaproto.CreateSignRequestResponse)) = rgaproto.CreateSignRequestResponse{
				ID: "req-1234567890", ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339),
			}
		}
		return nil
	case "GET":
		if path == "/api/v1/keys" {
			*(out.(*struct {
				Keys []rgaproto.KeyMeta `json:"keys"`
			})) = struct {
				Keys []rgaproto.KeyMeta `json:"keys"`
			}{Keys: f.keys}
			return nil
		}
		f.gets++
		status := f.statuses[0]
		if len(f.statuses) > 1 {
			f.statuses = f.statuses[1:]
		}
		res := &rgaproto.SignResult{Status: status}
		switch status {
		case "signed":
			res.SignatureArmored = "-----BEGIN PGP SIGNATURE-----\nX\n-----END PGP SIGNATURE-----"
		case "denied":
			res.DeniedReason = "not me"
		}
		*(out.(*rgaproto.SignResult)) = *res
		return nil
	}
	return errors.New("unexpected method " + method)
}

func TestRequestSignatureReturnsWhenSigned(t *testing.T) {
	ft := &fakeTransport{statuses: []string{"pending", "pending", "signed"}}
	sig, err := RequestSignature(context.Background(), ft, SignInput{
		Purpose: "git-commit", Description: "x", Fingerprint: "0123456789ABCDEF0123456789ABCDEF01234567", Data: []byte("hello"), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sig == "" || ft.gets != 3 || ft.posts != 1 {
		t.Fatalf("sig=%q gets=%d posts=%d", sig, ft.gets, ft.posts)
	}
}

func TestRequestSignatureReportsDenied(t *testing.T) {
	ft := &fakeTransport{statuses: []string{"denied"}}
	_, err := RequestSignature(context.Background(), ft, SignInput{
		Purpose: "x", Description: "x", Fingerprint: "0123456789ABCDEF0123456789ABCDEF01234567", Data: []byte("x"), Timeout: time.Second,
	})
	if err == nil || !contains(err.Error(), "拒否") {
		t.Fatalf("want denied error, got %v", err)
	}
}

func TestRequestSignatureReportsExpired(t *testing.T) {
	ft := &fakeTransport{statuses: []string{"expired"}}
	_, err := RequestSignature(context.Background(), ft, SignInput{
		Purpose: "x", Description: "x", Fingerprint: "0123456789ABCDEF0123456789ABCDEF01234567", Data: []byte("x"), Timeout: time.Second,
	})
	if err == nil || !contains(err.Error(), "期限切れ") {
		t.Fatalf("want expired error, got %v", err)
	}
}

func TestRequestSignatureTimesOut(t *testing.T) {
	ft := &fakeTransport{statuses: []string{"pending"}}
	_, err := RequestSignature(context.Background(), ft, SignInput{
		Purpose: "x", Description: "x", Fingerprint: "0123456789ABCDEF0123456789ABCDEF01234567", Data: []byte("x"), Timeout: 20 * time.Millisecond,
	})
	if err == nil || !contains(err.Error(), "タイムアウト") {
		t.Fatalf("want timeout error, got %v", err)
	}
}

func TestResolveFingerprint(t *testing.T) {
	fpr := "0123456789ABCDEF0123456789ABCDEF01234567"
	ft := &fakeTransport{keys: []rgaproto.KeyMeta{{KeyID: fpr[24:], Fingerprint: fpr, Label: "personal"}}}

	got, err := ResolveFingerprint(ft, fpr, "")
	if err != nil || got != fpr {
		t.Fatalf("full fingerprint: %q %v", got, err)
	}
	got, err = ResolveFingerprint(ft, "89ABCDEF01234567", "")
	if err != nil || got != fpr {
		t.Fatalf("short id: %q %v", got, err)
	}
	got, err = ResolveFingerprint(ft, fpr+"!", "")
	if err != nil || got != fpr {
		t.Fatalf("primary-key suffix: %q %v", got, err)
	}
	got, err = ResolveFingerprint(ft, "89ABCDEF01234567!", "")
	if err != nil || got != fpr {
		t.Fatalf("short id with primary-key suffix: %q %v", got, err)
	}
	got, err = ResolveFingerprint(ft, "", fpr)
	if err != nil || got != fpr {
		t.Fatalf("fallback: %q %v", got, err)
	}
	if _, err := ResolveFingerprint(ft, "DEADBEEF", ""); err == nil {
		t.Fatal("unknown id must fail")
	}
	if _, err := ResolveFingerprint(ft, "", ""); err == nil {
		t.Fatal("empty must fail")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestRequestSignatureSendsOnlyDigestForLargeData(t *testing.T) {
	ft := &fakeTransport{statuses: []string{"pending", "signed"}}
	data := make([]byte, smallDataLimit+1)
	if _, err := RequestSignature(context.Background(), ft, SignInput{
		Purpose: "makepkg", Description: "x", Fingerprint: "0123456789ABCDEF0123456789ABCDEF01234567",
		Data: data, Timeout: time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	if ft.lastCreate == nil || ft.lastCreate.DataB64 != "" {
		t.Fatalf("大きいデータを送ってはいけません: %+v", ft.lastCreate)
	}
	if ft.lastCreate.DigestB64 == "" || ft.lastCreate.SigMetaB64 == "" {
		t.Fatalf("digest と sigMeta が必要です: %+v", ft.lastCreate)
	}
}

func TestRequestSignatureSendsSmallDataForPwaVerification(t *testing.T) {
	ft := &fakeTransport{statuses: []string{"pending", "signed"}}
	if _, err := RequestSignature(context.Background(), ft, SignInput{
		Purpose: "git-commit", Description: "x", Fingerprint: "0123456789ABCDEF0123456789ABCDEF01234567",
		Data: []byte("hello"), Timeout: time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	if ft.lastCreate == nil || ft.lastCreate.DataB64 == "" {
		t.Fatalf("小さいデータは PWA の検証用に同梱する: %+v", ft.lastCreate)
	}
}
