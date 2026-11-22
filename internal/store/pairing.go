package store

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/nananek/remote-gpg-agent/internal/protocol"
)

var (
	ErrPairingExists = errors.New("pairing already exists")
	ErrPairingState  = errors.New("pairing is in the wrong state")
	ErrPairingFull   = errors.New("pairing has no room for more signals")
)

// Pairing は端末追加の 1 セッション。参加側の credential は登録が完了する
// まで空で、完了した時点で固定される（3 人目は入れない）。
type Pairing struct {
	ID          string `json:"id"`
	CreatorCred string `json:"creatorCredentialId"`
	JoinerCred  string `json:"joinerCredentialId,omitempty"`
	JoinerLabel string `json:"joinerLabel,omitempty"`
	State       string `json:"state"`
	JoinProof   string `json:"joinProof"`
	Receipt     string `json:"receipt,omitempty"`
	NextSeq     int64  `json:"nextSeq"`
	SignalBytes int    `json:"signalBytes"`
	CreatedAt   string `json:"createdAt"`
	ExpiresAt   string `json:"expiresAt"`
}

func pairingExpired(p Pairing, now time.Time) bool {
	when, err := time.Parse(time.RFC3339, p.ExpiresAt)
	return err != nil || !when.After(now)
}

// CreatePairing は新しい pairing を作る。ID はクライアントが生成する
// （QR を先に組み立てるため）。既存 ID との衝突はエラーにする。
func CreatePairing(_ context.Context, s *Store, id, creatorCred, joinProof string, ttl time.Duration) (Pairing, error) {
	now := time.Now().UTC()
	p := Pairing{
		ID:          id,
		CreatorCred: creatorCred,
		State:       protocol.PairingCreated,
		JoinProof:   joinProof,
		CreatedAt:   now.Format(time.RFC3339),
		ExpiresAt:   now.Add(ttl).Format(time.RFC3339),
	}
	err := s.Update(func(tx *bolt.Tx) error {
		if err := prunePairings(tx, now); err != nil {
			return err
		}
		b := tx.Bucket(bPair)
		if b.Get([]byte(id)) != nil {
			return ErrPairingExists
		}
		return putJSON(b, []byte(id), p)
	})
	return p, err
}

func GetPairing(_ context.Context, s *Store, id string) (Pairing, error) {
	var p Pairing
	err := s.View(func(tx *bolt.Tx) error {
		return getJSON(tx.Bucket(bPair), []byte(id), &p)
	})
	if err != nil {
		return Pairing{}, ErrNotFound
	}
	if pairingExpired(p, time.Now().UTC()) {
		return Pairing{}, ErrNotFound
	}
	return p, nil
}

// AttachJoiner は参加側の credential を確定する。登録の検証が通った直後に
// 呼ぶ。既に別の端末が join していれば ErrPairingState を返す。
func AttachJoiner(_ context.Context, s *Store, id, credID, label string) error {
	now := time.Now().UTC()
	return s.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bPair)
		var p Pairing
		if err := getJSON(b, []byte(id), &p); err != nil {
			return ErrNotFound
		}
		if pairingExpired(p, now) {
			return ErrNotFound
		}
		if p.State != protocol.PairingCreated {
			return ErrPairingState
		}
		p.JoinerCred = credID
		p.JoinerLabel = label
		p.State = protocol.PairingJoined
		return putJSON(b, []byte(id), p)
	})
}

func signalKey(id string, seq int64) []byte {
	key := make([]byte, 0, len(id)+1+8)
	key = append(key, id...)
	key = append(key, 0)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(seq))
	return append(key, b[:]...)
}

// AppendSignal は SDP / ICE を 1 件足し、サーバ採番の seq を返す。
// 送信元はセッションから決めるので、クライアントは詐称できない。
func AppendSignal(_ context.Context, s *Store, id, from, kind, blob string, now time.Time) (int64, error) {
	var seq int64
	err := s.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bPair)
		var p Pairing
		if err := getJSON(b, []byte(id), &p); err != nil {
			return ErrNotFound
		}
		if pairingExpired(p, now) {
			return ErrNotFound
		}
		if p.State != protocol.PairingJoined {
			return ErrPairingState
		}
		if p.NextSeq >= protocol.MaxPairingSignals || p.SignalBytes+len(blob) > protocol.MaxPairingSignalTotal {
			return ErrPairingFull
		}
		p.NextSeq++
		p.SignalBytes += len(blob)
		seq = p.NextSeq
		if err := putJSON(b, []byte(id), p); err != nil {
			return err
		}
		return putJSON(tx.Bucket(bPairSig), signalKey(id, seq), protocol.PairingSignal{
			Seq: seq, From: from, Kind: kind, Blob: blob,
			At: now.UTC().Format(time.RFC3339),
		})
	})
	return seq, err
}

// ListSignals は after より後のメッセージを seq 順に返す。
func ListSignals(_ context.Context, s *Store, id string, after int64) ([]protocol.PairingSignal, error) {
	prefix := append([]byte(id), 0)
	out := make([]protocol.PairingSignal, 0, 8)
	err := s.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bPairSig).Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			if len(k) != len(prefix)+8 {
				continue
			}
			seq := int64(binary.BigEndian.Uint64(k[len(prefix):]))
			if seq <= after {
				continue
			}
			var sig protocol.PairingSignal
			if err := jsonUnmarshal(v, &sig); err != nil {
				return err
			}
			out = append(out, sig)
		}
		return nil
	})
	return out, err
}

// SetReceipt は参加側が「封印してアップロードできた鍵の一覧」を預ける。
func SetReceipt(_ context.Context, s *Store, id, credID, receipt string) error {
	now := time.Now().UTC()
	return s.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bPair)
		var p Pairing
		if err := getJSON(b, []byte(id), &p); err != nil {
			return ErrNotFound
		}
		if pairingExpired(p, now) {
			return ErrNotFound
		}
		if p.JoinerCred == "" || p.JoinerCred != credID {
			return ErrPairingState
		}
		if p.State != protocol.PairingJoined && p.State != protocol.PairingDelivered {
			return ErrPairingState
		}
		p.Receipt = receipt
		p.State = protocol.PairingDelivered
		return putJSON(b, []byte(id), p)
	})
}

func AbortPairing(_ context.Context, s *Store, id string) error {
	now := time.Now().UTC()
	return s.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bPair)
		var p Pairing
		if err := getJSON(b, []byte(id), &p); err != nil {
			return ErrNotFound
		}
		if p.State == protocol.PairingAborted {
			return nil
		}
		if pairingExpired(p, now) {
			return ErrNotFound
		}
		p.State = protocol.PairingAborted
		return putJSON(b, []byte(id), p)
	})
}

// prunePairings は期限切れの pairing と、そのシグナリングを消す。
func prunePairings(tx *bolt.Tx, now time.Time) error {
	b := tx.Bucket(bPair)
	if b == nil {
		return nil
	}
	var stale []string
	if err := forEach(b, func(k, v []byte) error {
		var p Pairing
		if err := jsonUnmarshal(v, &p); err != nil {
			stale = append(stale, string(k))
			return nil
		}
		if pairingExpired(p, now) {
			stale = append(stale, string(k))
		}
		return nil
	}); err != nil {
		return err
	}
	sig := tx.Bucket(bPairSig)
	for _, id := range stale {
		if err := b.Delete([]byte(id)); err != nil {
			return err
		}
		if sig == nil {
			continue
		}
		prefix := append([]byte(id), 0)
		c := sig.Cursor()
		var keys [][]byte
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			keys = append(keys, append([]byte(nil), k...))
		}
		for _, k := range keys {
			if err := sig.Delete(k); err != nil {
				return err
			}
		}
	}
	return nil
}
