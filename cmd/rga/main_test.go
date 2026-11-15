package main

import (
	"testing"
)

const testArmored = "-----BEGIN PGP SIGNATURE-----\n\nwrsE\n-----END PGP SIGNATURE-----\n"

func TestEncodeSignatureArmored(t *testing.T) {
	out, err := encodeSignature(testArmored, true)
	if err != nil {
		t.Fatalf("encodeSignature: %v", err)
	}
	if string(out) != testArmored {
		t.Fatalf("armored output = %q, want %q", out, testArmored)
	}
}

func TestEncodeSignatureBinary(t *testing.T) {
	out, err := encodeSignature(testArmored, false)
	if err != nil {
		t.Fatalf("encodeSignature: %v", err)
	}
	// "wrsE" = C2 BB 04。末尾に改行は足さない (gpg の binary 署名と同じ)。
	want := []byte{0xC2, 0xBB, 0x04}
	if len(out) != len(want) {
		t.Fatalf("binary output = % x, want % x", out, want)
	}
	for i := range want {
		if out[i] != want[i] {
			t.Fatalf("binary output = % x, want % x", out, want)
		}
	}
}
