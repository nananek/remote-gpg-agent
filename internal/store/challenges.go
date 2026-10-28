package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	bolt "go.etcd.io/bbolt"
)

var ErrChallengeGone = errors.New("challenge not found or expired")

type challengeRecord struct {
	Kind      string `json:"kind"`
	Data      []byte `json:"data"`
	ExpiresAt string `json:"expiresAt"`
}

func SaveChallenge(_ context.Context, s *Store, kind string, data []byte, ttl time.Duration) (string, error) {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	rec := challengeRecord{Kind: kind, Data: data, ExpiresAt: time.Now().UTC().Add(ttl).Format(time.RFC3339)}
	err := s.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bChal), []byte(id), rec)
	})
	return id, err
}

// TakeChallenge は単回消費。読み出しと削除を 1 トランザクションで行う。
func TakeChallenge(_ context.Context, s *Store, id, kind string) ([]byte, error) {
	var out []byte
	err := s.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bChal)
		var rec challengeRecord
		if err := getJSON(b, []byte(id), &rec); err != nil {
			return ErrChallengeGone
		}
		if err := b.Delete([]byte(id)); err != nil {
			return err
		}
		if rec.Kind != kind {
			return ErrChallengeGone
		}
		when, err := time.Parse(time.RFC3339, rec.ExpiresAt)
		if err != nil || when.Before(time.Now().UTC()) {
			return ErrChallengeGone
		}
		out = rec.Data
		return nil
	})
	return out, err
}
