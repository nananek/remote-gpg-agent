package protocol

import "time"

// 端末追加（ペアリング）の契約。
//
// 追加する端末はパスキーを 1 つも持っていないので、通常の「追加パスキー」の
// 経路（要セッション）は使えない。作成側（解錠済みの端末）が短命の
// pairing を作り、QR に埋めた秘密で参加側の登録を認可する。
// 鍵素材は WebRTC の DataChannel 上を端末間で直接流し、サーバは
// シグナリング（SDP / ICE）だけを中継する。

const (
	// PairingTTL は QR を表示してから登録と転送を終えるまでの猶予。
	PairingTTL = 2 * time.Minute
	// PairingJoinV1 は join 証明のドメイン分離ラベル。PWA 側と同じ値にする。
	PairingJoinV1 = "rga-pair-join:v1"
	// PairingIDBytes は pairing ID の長さ。
	PairingIDBytes = 16
	// PairingProofBytes は join 証明（SHA-256）の長さ。
	PairingProofBytes = 32
	// MaxPairingSignalBytes は 1 メッセージ（SDP / ICE）の上限。
	MaxPairingSignalBytes = 16 << 10
	// MaxPairingSignalTotal は pairing 全体で中継する量の上限。
	MaxPairingSignalTotal = 128 << 10
	// MaxPairingSignals は pairing 全体のメッセージ数上限。
	MaxPairingSignals = 128
)

// Pairing の状態。
const (
	PairingCreated   = "created"
	PairingJoined    = "joined"
	PairingDelivered = "delivered"
	PairingAborted   = "aborted"
)

// シグナリングの種類。SDP の offer/answer と ICE candidate だけを通す。
const (
	PairingSignalOffer     = "offer"
	PairingSignalAnswer    = "answer"
	PairingSignalCandidate = "candidate"
)

type PairingCreateRequest struct {
	PairingID string `json:"pairingId"`
	// JoinProof は SHA-256(PairingJoinV1|秘密|pairingId)。秘密そのものは
	// サーバに送らない（QR のフラグメントにだけ置く）。
	JoinProof string `json:"joinProof"`
}

type PairingCreateResponse struct {
	PairingID string `json:"pairingId"`
	ExpiresAt string `json:"expiresAt"`
}

type PairingJoinRequest struct {
	PairingID string `json:"pairingId"`
	JoinProof string `json:"joinProof"`
}

type PairingStatus struct {
	State               string `json:"state"`
	CreatorCredentialID string `json:"creatorCredentialId"`
	JoinerCredentialID  string `json:"joinerCredentialId,omitempty"`
	JoinerLabel         string `json:"joinerLabel,omitempty"`
	Receipt             string `json:"receipt,omitempty"`
	ExpiresAt           string `json:"expiresAt"`
}

type PairingSignalRequest struct {
	Kind string `json:"kind"`
	Blob string `json:"blob"`
}

type PairingSignal struct {
	Seq  int64  `json:"seq"`
	From string `json:"from"`
	Kind string `json:"kind"`
	Blob string `json:"blob"`
	At   string `json:"at"`
}

type PairingSignalsResponse struct {
	Signals []PairingSignal `json:"signals"`
}

type PairingCompleteRequest struct {
	Receipt string `json:"receipt"`
	// Nonce は作成側が転送の直前に登録した値。参加側はこれをそのまま返す。
	Nonce string `json:"nonce"`
}

type PairingNonceRequest struct {
	Nonce string `json:"nonce"`
}

const (
	PairingRoleCreator = "creator"
	PairingRoleJoiner  = "joiner"
)

// PairingSignalAllowedFor はロールと種類の対応を返す。offer は作成側、
// answer は参加側だけが送れる。ロールを取り違えた要求を通すと、相手の
// シグナリング枠を占有できてしまう。
func PairingSignalAllowedFor(role, kind string) bool {
	switch kind {
	case PairingSignalCandidate:
		return true
	case PairingSignalOffer:
		return role == PairingRoleCreator
	case PairingSignalAnswer:
		return role == PairingRoleJoiner
	}
	return false
}

// ValidPairingSignalKind は中継してよい種類か。クライアントが勝手に
// 独自メッセージを流せないよう、サーバ側でも絞る。
func ValidPairingSignalKind(kind string) bool {
	switch kind {
	case PairingSignalOffer, PairingSignalAnswer, PairingSignalCandidate:
		return true
	}
	return false
}
