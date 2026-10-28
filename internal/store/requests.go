package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

type Request struct {
	ID               string `json:"id"`
	Purpose          string `json:"purpose"`
	Description      string `json:"description"`
	ClientName       string `json:"clientName"`
	KeyFingerprint   string `json:"keyFingerprint"`
	DataSHA256       string `json:"dataSha256"`
	DataB64          string `json:"dataB64"`
	DataSize         int    `json:"dataSize"`
	TextMode         bool   `json:"textMode"`
	CreatedAt        string `json:"createdAt"`
	ExpiresAt        string `json:"expiresAt"`
	Status           string `json:"status"`
	SignatureArmored string `json:"signatureArmored,omitempty"`
	DeniedReason     string `json:"deniedReason,omitempty"`
}

type NewRequestInput struct {
	Purpose, Description, ClientName, KeyFingerprint, DataB64 string
	TextMode                                                  bool
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// CreateRequest は署名要求を作る。ctx は受け取るが bbolt は context を取らない
// （呼び出し側の形をそろえるためだけに存在する）。
func CreateRequest(_ context.Context, s *Store, in NewRequestInput, ttl time.Duration) (*Request, error) {
	raw, err := base64.StdEncoding.DecodeString(in.DataB64)
	if err != nil {
		return nil, fmt.Errorf("dataB64: %w", err)
	}
	sum := sha256.Sum256(raw)
	now := time.Now().UTC()
	r := &Request{
		ID: newID(), Purpose: in.Purpose, Description: in.Description,
		ClientName: in.ClientName, KeyFingerprint: in.KeyFingerprint,
		DataSHA256: hex.EncodeToString(sum[:]), DataB64: in.DataB64, DataSize: len(raw),
		TextMode: in.TextMode, CreatedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(ttl).Format(time.RFC3339), Status: "pending",
	}
	if err := s.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bReqs), []byte(r.ID), r)
	}); err != nil {
		return nil, err
	}
	return r, nil
}

func GetRequest(_ context.Context, s *Store, id string) (*Request, error) {
	var r Request
	if err := s.View(func(tx *bolt.Tx) error {
		return getJSON(tx.Bucket(bReqs), []byte(id), &r)
	}); err != nil {
		return nil, err
	}
	return &r, nil
}

func ListPending(ctx context.Context, s *Store) ([]*Request, error) {
	if err := ExpireStale(ctx, s); err != nil {
		return nil, err
	}
	out := make([]*Request, 0, 8)
	if err := s.View(func(tx *bolt.Tx) error {
		return forEach(tx.Bucket(bReqs), func(_, raw []byte) error {
			var r Request
			if err := jsonUnmarshal(raw, &r); err != nil {
				return err
			}
			if r.Status == "pending" {
				cp := r
				out = append(out, &cp)
			}
			return nil
		})
	}); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out, nil
}

// CompleteRequest は pending のときだけ signed にする。2 回目は ok=false。
func CompleteRequest(_ context.Context, s *Store, id, sig string) (bool, error) {
	ok := false
	err := s.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bReqs)
		var r Request
		if err := getJSON(b, []byte(id), &r); err != nil {
			return err
		}
		if r.Status != "pending" {
			return nil
		}
		r.Status, r.SignatureArmored = "signed", sig
		// 署名が済んだら、サーバが平文の署名対象を持つ必要はない。
		r.DataB64, r.Description = "", ""
		ok = true
		return putJSON(b, []byte(id), &r)
	})
	return ok, err
}

func DenyRequest(_ context.Context, s *Store, id, reason string) (bool, error) {
	ok := false
	err := s.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bReqs)
		var r Request
		if err := getJSON(b, []byte(id), &r); err != nil {
			return err
		}
		if r.Status != "pending" {
			return nil
		}
		r.Status, r.DeniedReason = "denied", reason
		r.DataB64, r.Description = "", ""
		ok = true
		return putJSON(b, []byte(id), &r)
	})
	return ok, err
}

func ExpireStale(_ context.Context, s *Store) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return s.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bReqs)
		return forEach(b, func(key, raw []byte) error {
			var r Request
			if err := jsonUnmarshal(raw, &r); err != nil {
				return err
			}
			if r.Status == "pending" && r.ExpiresAt < now {
				r.Status = "expired"
				r.DataB64, r.Description = "", ""
				return putJSON(b, key, &r)
			}
			return nil
		})
	})
}
