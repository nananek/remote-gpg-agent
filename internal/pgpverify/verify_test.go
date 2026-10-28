package pgpverify

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

func makeKey(t *testing.T) (privArmored, pubArmored, fpr string) {
	t.Helper()
	ent, err := openpgp.NewEntity("Test User", "", "test@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	var priv, pub bytes.Buffer
	privW, err := armor.Encode(&priv, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ent.SerializePrivate(privW, nil); err != nil {
		t.Fatal(err)
	}
	privW.Close()

	pubW, err := armor.Encode(&pub, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ent.Serialize(pubW); err != nil {
		t.Fatal(err)
	}
	pubW.Close()

	return priv.String(), pub.String(), strings.ToUpper(hex.EncodeToString(ent.PrimaryKey.Fingerprint[:]))
}

func sign(t *testing.T, privArmored string, data []byte) string {
	t.Helper()
	el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(privArmored))
	if err != nil {
		t.Fatal(err)
	}
	var sig bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&sig, el[0], bytes.NewReader(data), nil); err != nil {
		t.Fatal(err)
	}
	return sig.String()
}

func TestArmoredDetachedHappyPath(t *testing.T) {
	priv, pub, fpr := makeKey(t)
	data := []byte("tree 0000\n\nmsg\n")
	sig := sign(t, priv, data)

	if err := ArmoredDetached(pub, fpr, data, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestArmoredDetachedRejectsTamperedPayload(t *testing.T) {
	priv, pub, fpr := makeKey(t)
	sig := sign(t, priv, []byte("tree 0000\n"))

	if err := ArmoredDetached(pub, fpr, []byte("tree 0001\n"), sig); err == nil {
		t.Fatal("tampered payload must fail")
	}
}

func TestArmoredDetachedRejectsWrongFingerprint(t *testing.T) {
	priv, pub, _ := makeKey(t)
	data := []byte("hello")
	sig := sign(t, priv, data)

	if err := ArmoredDetached(pub, strings.Repeat("B", 40), data, sig); err == nil {
		t.Fatal("wrong fingerprint must fail")
	} else if !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestArmoredDetachedRejectsGarbageKey(t *testing.T) {
	if err := ArmoredDetached("not a key", strings.Repeat("A", 40), []byte("x"), "sig"); err == nil {
		t.Fatal("garbage key must fail")
	}
}
