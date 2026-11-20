package client

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// OpenPGP v4 signature packet の固定値。鍵は curve25519Legacy（EdDSA）で、
// ハッシュは SHA-256 を使う。
const (
	sigVersion       = 4
	sigTypeBinary    = 0x00
	pubKeyAlgoEdDSA  = 22
	hashAlgoSHA256   = 8
	smallDataLimit   = 1 << 20 // PWA が内容を検証できるデータの上限
	saltNotationName = "salt@notations.openpgpjs.org"
)

// BuildSigMeta は v4 signature packet の signatureData（hashed area）を組む。
// PWA はこのバイト列をそのまま digest 計算に使うので、client と PWA で
// 同じものを見る必要がある。
func BuildSigMeta(fingerprint string, created time.Time) ([]byte, error) {
	fpr, err := hex.DecodeString(fingerprint)
	if err != nil || len(fpr) != 20 {
		return nil, errors.New("fingerprint must be 40 hex chars")
	}
	keyID := fpr[len(fpr)-8:]

	var hashed []byte
	hashed = append(hashed, subpacket(2, uint32be(uint32(created.Unix())))...) // creation time
	hashed = append(hashed, subpacket(16, keyID)...)                           // issuer key ID
	hashed = append(hashed, subpacket(33, append([]byte{4}, fpr...))...)       // issuer fingerprint
	salt := make([]byte, 16)                                                   // EdDSA の fault 対策
	if _, err := rand.Read(salt); err != nil {                                 // OpenPGP.js と同じ長さ
		return nil, fmt.Errorf("salt: %w", err)
	}
	hashed = append(hashed, subpacket(20, saltNotation(salt))...) // notation data

	meta := []byte{sigVersion, sigTypeBinary, pubKeyAlgoEdDSA, hashAlgoSHA256}
	meta = append(meta, uint16be(uint16(len(hashed)))...)
	meta = append(meta, hashed...)
	return meta, nil
}

// SignedDigest は OpenPGP の署名対象 digest を返す。
// EdDSA はこの digest をメッセージとして署名する。
func SignedDigest(data, meta []byte) []byte {
	h := sha256.New()
	h.Write(data)
	h.Write(meta)
	h.Write(trailer(meta))
	return h.Sum(nil)
}

// ArmoredSignature は raw 64 byte の Ed25519 署名を v4 signature packet に
// 包んで armored にする。gpg はこれを通常の detached signature として検証する。
func ArmoredSignature(meta, digest, rawSig []byte) (string, error) {
	if len(digest) != sha256.Size {
		return "", errors.New("digest must be 32 bytes")
	}
	if len(rawSig) != 64 {
		return "", errors.New("Ed25519 signature must be 64 bytes")
	}

	body := make([]byte, 0, len(meta)+2+2+70)
	body = append(body, meta...)
	body = append(body, 0, 0) // unhashed subpackets は空
	body = append(body, digest[0], digest[1])
	body = append(body, mpi(rawSig[:32])...)
	body = append(body, mpi(rawSig[32:])...)

	packet := []byte{0xC2} // new format, tag 2 (signature)
	packet = append(packet, newLen(len(body))...)
	packet = append(packet, body...)

	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgpSignatureType, nil)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(packet); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// openpgpSignatureType は armor の type 文字列。ProtonMail の定数と同じ。
const openpgpSignatureType = "PGP SIGNATURE"

func trailer(meta []byte) []byte {
	n := len(meta)
	return []byte{sigVersion, 0xFF, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

func saltNotation(salt []byte) []byte {
	body := make([]byte, 0, 4+2+2+len(saltNotationName)+len(salt))
	body = append(body, 0, 0, 0, 0) // flags: human-readable なし、critical なし
	body = append(body, uint16be(uint16(len(saltNotationName)))...)
	body = append(body, uint16be(uint16(len(salt)))...)
	body = append(body, saltNotationName...)
	body = append(body, salt...)
	return body
}

func subpacket(typ byte, body []byte) []byte {
	out := newLen(len(body) + 1)
	out = append(out, typ)
	out = append(out, body...)
	return out
}

// newLen は OpenPGP の new-format length を書く。
func newLen(n int) []byte {
	switch {
	case n < 192:
		return []byte{byte(n)}
	case n < 8384:
		n -= 192
		return []byte{byte(192 + n>>8), byte(n)}
	default:
		return []byte{0xFF, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

func uint16be(n uint16) []byte { return []byte{byte(n >> 8), byte(n)} }
func uint32be(n uint32) []byte {
	return []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// mpi は OpenPGP.js の uint8ArrayToMPI と同じ表現にする。EdDSA の s は
// little-endian のまま MPI に入れる取り決めなので、ここで変換しない。
func mpi(b []byte) []byte {
	i := 0
	for i < len(b) && b[i] == 0 {
		i++
	}
	if i == len(b) {
		return []byte{0, 0}
	}
	s := b[i:]
	bitLen := (len(s)-1)*8 + nbits(s[0])
	out := []byte{byte(bitLen >> 8), byte(bitLen)}
	return append(out, s...)
}

func nbits(x byte) int {
	n := 0
	for x > 0 {
		n++
		x >>= 1
	}
	return n
}
