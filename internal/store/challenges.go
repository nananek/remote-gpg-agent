package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

var ErrChallengeGone = errors.New("challenge not found or expired")

// maxChallenges は同時に保持するチャレンジの上限。TTL は 2 分なので、
// 通常のログインでは到底届かない。未認証で連打されても bbolt が
// 無制限に膨らまないようにするための最後の歯止め。
const maxChallenges = 512

type challengeRecord struct {
	Kind      string `json:"kind"`
	Data      []byte `json:"data"`
	ExpiresAt string `json:"expiresAt"`
}

func SaveChallenge(_ context.Context, s *Store, kind string, data []byte, ttl time.Duration) (string, error) {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	now := time.Now().UTC()
	rec := challengeRecord{Kind: kind, Data: data, ExpiresAt: now.Add(ttl).Format(time.RFC3339)}
	err := s.Update(func(tx *bolt.Tx) error {
		// 期限切れを毎回掃除する。TakeChallenge は消費した分しか消さないため、
		// これがないと login/options を叩くだけでレコードが溜まり続ける。
		if err := pruneExpiredChallenges(tx, now); err != nil {
			return err
		}
		if err := capChallenges(tx); err != nil {
			return err
		}
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

// pruneExpiredChallenges は期限切れ・壊れたレコードを削除する。
// SaveChallenge と起動時の両方から呼ぶ。
func pruneExpiredChallenges(tx *bolt.Tx, now time.Time) error {
	b := tx.Bucket(bChal)
	if b == nil {
		return nil
	}
	var stale [][]byte
	if err := forEach(b, func(k, v []byte) error {
		var rec challengeRecord
		if err := jsonUnmarshal(v, &rec); err != nil {
			stale = append(stale, append([]byte(nil), k...))
			return nil
		}
		when, err := time.Parse(time.RFC3339, rec.ExpiresAt)
		if err != nil || !when.After(now) {
			stale = append(stale, append([]byte(nil), k...))
		}
		return nil
	}); err != nil {
		return err
	}
	for _, k := range stale {
		if err := b.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

// capChallenges は上限を超えた分を期限の古い順に削除する。
// pruneExpiredChallenges の直後に呼ぶ前提。
func capChallenges(tx *bolt.Tx) error {
	b := tx.Bucket(bChal)
	if b == nil {
		return nil
	}
	type entry struct {
		key     []byte
		expires time.Time
	}
	var entries []entry
	if err := forEach(b, func(k, v []byte) error {
		var rec challengeRecord
		if err := jsonUnmarshal(v, &rec); err != nil {
			return nil
		}
		when, err := time.Parse(time.RFC3339, rec.ExpiresAt)
		if err != nil {
			return nil
		}
		entries = append(entries, entry{key: append([]byte(nil), k...), expires: when})
		return nil
	}); err != nil {
		return err
	}
	if len(entries) < maxChallenges {
		return nil
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].expires.Before(entries[j].expires) })
	drop := len(entries) - maxChallenges + 1
	for i := 0; i < drop; i++ {
		if err := b.Delete(entries[i].key); err != nil {
			return err
		}
	}
	return nil
}
