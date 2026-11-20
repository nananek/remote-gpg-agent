package protocol

import "strings"

const (
	Version = 1
	// RequestTTLSec は署名要求の既定の寿命。PWA を開いて内容を確認し、
	// パスキーで解錠するまでの時間を確保する（15 分）。
	RequestTTLSec = 900
	// RequestTTLGraceSec は、client が指定した待ち時間より後に server 側の
	// 要求を失効させるための余裕。client の timeout と同時に期限切れになる
	// 競合を避ける。
	RequestTTLGraceSec = 120
	// MaxClientTimeoutSec は client が要求できる待ち時間の上限。
	MaxClientTimeoutSec = 3600
)

// SignMode は署名要求の種類。
//
//	digest: client が OpenPGP の署名対象 digest を計算し、PWA はその digest に
//	        署名する。データ本体は server に送らない（大きいファイル向け）。
//	data:   従来どおりデータ本体を送り、PWA が OpenPGP.js で署名する。
const (
	SignModeDigest = "digest"
	SignModeData   = "data"
)

// MaxDataBytes は署名対象の上限。makepkg の .pkg.tar.zst (数十 MB) を
// 扱うため、git commit 用の 1 MB から広げている。テストで上限を下げられる
// よう const ではなく var。
var MaxDataBytes = 512 << 20

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
	// Mode は "digest" か "data"。空なら data（旧 client との互換）。
	Mode string `json:"mode,omitempty"`
	// TimeoutSec は client が承認を待つ秒数。server はこれに余裕を足して
	// 要求の寿命を決める。0 なら server の既定値。
	TimeoutSec int `json:"timeoutSec,omitempty"`

	// data モード用。digest モードでも、小さいデータなら PWA が内容を
	// 検証できるように入れてよい。
	DataB64 string `json:"dataB64,omitempty"`

	// digest モード用。DigestB64 は OpenPGP の署名対象 digest（SHA-256）。
	// SigMetaB64 は v4 signature packet の signatureData（hashed area）。
	DigestB64  string `json:"digestB64,omitempty"`
	SigMetaB64 string `json:"sigMetaB64,omitempty"`
	// DataSHA256 はデータ本体の SHA-256（hex）。PWA の表示と記録用。
	DataSHA256 string `json:"dataSha256,omitempty"`
	DataSize   int    `json:"dataSize,omitempty"`
	// Preview はデータ本体を送らないときの人間向け説明。
	Preview string `json:"preview,omitempty"`
}

type CreateSignRequestResponse struct {
	ID        string `json:"id"`
	ExpiresAt string `json:"expiresAt"`
	Mode      string `json:"mode"`
}

type SignResult struct {
	Status           string `json:"status"`
	Mode             string `json:"mode,omitempty"`
	SignatureArmored string `json:"signatureArmored,omitempty"`
	// SignatureB64 は digest モードの raw Ed25519 署名（64 byte）。
	SignatureB64 string `json:"signatureB64,omitempty"`
	DeniedReason string `json:"deniedReason,omitempty"`
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

// PendingRequestsResponse は PWA の承認待ち一覧。ServerNow は PWA の時計が
// ずれていてもカウントダウンを正しく出すための基準時刻。
type PendingRequestsResponse struct {
	Requests  []PendingSignRequest `json:"requests"`
	ServerNow string               `json:"serverNow"`
}

type PendingSignRequest struct {
	ID             string `json:"id"`
	Purpose        string `json:"purpose"`
	Description    string `json:"description"`
	ClientName     string `json:"clientName"`
	KeyFingerprint string `json:"keyFingerprint"`
	Mode           string `json:"mode"`
	DataSHA256     string `json:"dataSha256"`
	DataSize       int    `json:"dataSize"`
	// DataPreviewB64 は一覧表示用の先頭部分だけ。本体は
	// GET /api/v1/requests/{id}/data で承認時に取得する。
	DataPreviewB64 string `json:"dataPreviewB64,omitempty"`
	DataAvailable  bool   `json:"dataAvailable"`
	TextMode       bool   `json:"textMode"`
	DigestB64      string `json:"digestB64,omitempty"`
	SigMetaB64     string `json:"sigMetaB64,omitempty"`
	Preview        string `json:"preview,omitempty"`
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
