package protocol

import "strings"

const (
	Version       = 1
	MaxDataBytes  = 1_000_000
	RequestTTLSec = 300
)

// KeyIDFromFingerprint は 40 hex の fingerprint から下位 16 hex を返す。不正なら空文字。
func KeyIDFromFingerprint(fpr string) string {
	fpr = strings.ToUpper(strings.TrimSpace(fpr))
	if len(fpr) != 40 {
		return ""
	}
	for _, c := range fpr {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
			return ""
		}
	}
	return fpr[24:]
}

type CreateSignRequest struct {
	Purpose        string `json:"purpose"`
	Description    string `json:"description"`
	KeyFingerprint string `json:"keyFingerprint"`
	TextMode       bool   `json:"textMode"`
	DataB64        string `json:"dataB64"`
}

type CreateSignRequestResponse struct {
	ID        string `json:"id"`
	ExpiresAt string `json:"expiresAt"`
}

type SignResult struct {
	Status           string `json:"status"`
	SignatureArmored string `json:"signatureArmored,omitempty"`
	DeniedReason     string `json:"deniedReason,omitempty"`
}

type KeyMeta struct {
	KeyID            string `json:"keyId"`
	Fingerprint      string `json:"fingerprint"`
	Label            string `json:"label"`
	PublicKeyArmored string `json:"publicKeyArmored,omitempty"`
}

type Envelope struct {
	CredentialID  string `json:"credentialId"`
	KeyID         string `json:"keyId"`
	HKDFSaltB64   string `json:"hkdfSaltB64"`
	IVB64         string `json:"ivB64"`
	CiphertextB64 string `json:"ciphertextB64"`
}

type CredentialMeta struct {
	CredentialID string `json:"credentialId"`
	Label        string `json:"label"`
}

type State struct {
	CredentialID string           `json:"credentialId"`
	Credentials  []CredentialMeta `json:"credentials"`
	Keys         []KeyMeta        `json:"keys"`
	Envelopes    []Envelope       `json:"envelopes"`
}

type PendingSignRequest struct {
	ID             string `json:"id"`
	Purpose        string `json:"purpose"`
	Description    string `json:"description"`
	ClientName     string `json:"clientName"`
	KeyFingerprint string `json:"keyFingerprint"`
	DataSHA256     string `json:"dataSha256"`
	DataSize       int    `json:"dataSize"`
	DataB64        string `json:"dataB64"`
	TextMode       bool   `json:"textMode"`
	CreatedAt      string `json:"createdAt"`
	ExpiresAt      string `json:"expiresAt"`
}

type SealKeyRequest struct {
	// CredentialID は封印先の credential。セッションと一致しない要求は拒否する。
	CredentialID     string `json:"credentialId"`
	Fingerprint      string `json:"fingerprint"`
	Label            string `json:"label"`
	PublicKeyArmored string `json:"publicKeyArmored"`
	HKDFSaltB64      string `json:"hkdfSaltB64"`
	IVB64            string `json:"ivB64"`
	CiphertextB64    string `json:"ciphertextB64"`
	// Proof は envelope をこの鍵で封印したことの detached signature。
	Proof string `json:"proof"`
}

type SealedEnvelope struct {
	KeyID         string `json:"keyId"`
	HKDFSaltB64   string `json:"hkdfSaltB64"`
	IVB64         string `json:"ivB64"`
	CiphertextB64 string `json:"ciphertextB64"`
	Proof         string `json:"proof"`
}

// EnvelopeProofV1 は所持証明のドメイン分離ラベル。
const EnvelopeProofV1 = "rga-envelope:v1"

// EnvelopeProofMessage は envelope の所持証明で署名する正規化メッセージ。
// credential と envelope の全フィールドを束ねるので、別 credential・別鍵・
// 別 ciphertext への差し替えは検証で落ちる。PWA 側と同じ順序で組むこと。
func EnvelopeProofMessage(credentialID, keyID, hkdfSaltB64, ivB64, ciphertextB64 string) []byte {
	return []byte(strings.Join([]string{
		EnvelopeProofV1, credentialID, keyID, hkdfSaltB64, ivB64, ciphertextB64,
	}, "\n"))
}
