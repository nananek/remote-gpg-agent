package cryptoutil

import "testing"

func TestB64URLRoundTrip(t *testing.T) {
	in := []byte{0, 1, 2, 250, 255}
	s := B64URL(in)
	if s != "AAEC-v8" {
		t.Fatalf("got %q", s)
	}
	out, err := B64URLDecode(s)
	if err != nil || string(out) != string(in) {
		t.Fatalf("roundtrip failed: %v %v", out, err)
	}
	if _, err := B64URLDecode(s + "="); err != nil {
		t.Fatalf("padding must be tolerated: %v", err)
	}
}

func TestB64RoundTrip(t *testing.T) {
	in := []byte("hello")
	if got := B64(in); got != "aGVsbG8=" {
		t.Fatalf("got %q", got)
	}
	out, err := B64Decode("aGVsbG8=")
	if err != nil || string(out) != "hello" {
		t.Fatalf("roundtrip failed: %v %v", out, err)
	}
}
