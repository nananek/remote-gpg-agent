package store

import (
	"encoding/json"
	"errors"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	bCreds = []byte("credentials")
	bKeys  = []byte("keys")
	bFpr   = []byte("key_by_fpr")
	bEnvs  = []byte("envelopes")
	bSess  = []byte("sessions")
	bChal  = []byte("challenges")
	bReqs  = []byte("requests")
	bPush  = []byte("push")
)

// ErrNotFound は該当キーが無いことを示す。
var ErrNotFound = errors.New("not found")

// Store は bbolt 上の単一ファイル DB。書き手は 1 プロセスだけ。
type Store struct{ db *bolt.DB }

func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bCreds, bKeys, bFpr, bEnvs, bSess, bChal, bReqs, bPush} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) View(fn func(*bolt.Tx) error) error   { return s.db.View(fn) }
func (s *Store) Update(fn func(*bolt.Tx) error) error { return s.db.Update(fn) }

func putJSON(b *bolt.Bucket, key []byte, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Put(key, raw)
}

func getJSON(b *bolt.Bucket, key []byte, v any) error {
	raw := b.Get(key)
	if raw == nil {
		return ErrNotFound
	}
	return json.Unmarshal(raw, v)
}

func jsonUnmarshal(raw []byte, v any) error { return json.Unmarshal(raw, v) }

// forEach はバケット全件を走査する（ネストバケットは無視）。
func forEach(b *bolt.Bucket, fn func(key, raw []byte) error) error {
	return b.ForEach(func(k, v []byte) error {
		if v == nil {
			return nil
		}
		return fn(k, v)
	})
}
