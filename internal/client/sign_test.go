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
	posts    int
	gets     int
	statuses []string
	keys     []rgaproto.KeyMeta
}

func (f *fakeTransport) Do(method, path string, body any, out any) error {
	switch method {
	case "POST":
		f.posts++
		*(out.(*rgaproto.CreateSignRequestResponse)) = rgaproto.CreateSignRequestResponse{
			ID: "req-1234567890", ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339),
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
		Purpose: "git-commit", Description: "x", Fingerprint: "A", Data: []byte("hello"), Timeout: 5 * time.Second,
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
		Purpose: "x", Description: "x", Fingerprint: "A", Data: []byte("x"), Timeout: time.Second,
	})
	if err == nil || !contains(err.Error(), "拒否") {
		t.Fatalf("want denied error, got %v", err)
	}
}

func TestRequestSignatureReportsExpired(t *testing.T) {
	ft := &fakeTransport{statuses: []string{"expired"}}
	_, err := RequestSignature(context.Background(), ft, SignInput{
		Purpose: "x", Description: "x", Fingerprint: "A", Data: []byte("x"), Timeout: time.Second,
	})
	if err == nil || !contains(err.Error(), "期限切れ") {
		t.Fatalf("want expired error, got %v", err)
	}
}

func TestRequestSignatureTimesOut(t *testing.T) {
	ft := &fakeTransport{statuses: []string{"pending"}}
	_, err := RequestSignature(context.Background(), ft, SignInput{
		Purpose: "x", Description: "x", Fingerprint: "A", Data: []byte("x"), Timeout: 20 * time.Millisecond,
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
