package protocol

import (
	"encoding/json"
	"testing"
)

const testFpr = "0123456789ABCDEF0123456789ABCDEF01234567"

func TestSignResultOmitsEmptyFields(t *testing.T) {
	b, err := json.Marshal(SignResult{Status: "pending"})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"status":"pending"}` {
		t.Fatalf("got %s", b)
	}
}

func TestKeyIDFromFingerprint(t *testing.T) {
	if got := KeyIDFromFingerprint(testFpr); got != "89ABCDEF01234567" {
		t.Fatalf("got %s", got)
	}
	if got := KeyIDFromFingerprint(testFpr[:39]); got != "" {
		t.Fatalf("want empty for 39 chars, got %s", got)
	}
	if got := KeyIDFromFingerprint("0123456789abcdef0123456789abcdef01234567"); got != "89ABCDEF01234567" {
		t.Fatalf("lowercase must be accepted, got %s", got)
	}
	if got := KeyIDFromFingerprint("ZZZ3456789ABCDEF0123456789ABCDEF01234567"); got != "" {
		t.Fatalf("non-hex must be rejected, got %s", got)
	}
}
