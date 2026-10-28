package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	bolt "go.etcd.io/bbolt"
)

const SessionCookie = "rga_session"

const sessionTTL = 7 * 24 * time.Hour

var ErrNoSession = errors.New("no session")

type sessionRecord struct {
	CredentialID string `json:"credentialId"`
	ExpiresAt    string `json:"expiresAt"`
}

func CreateSession(_ context.Context, s *Store, credentialID string) (string, error) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	rec := sessionRecord{CredentialID: credentialID, ExpiresAt: time.Now().UTC().Add(sessionTTL).Format(time.RFC3339)}
	err := s.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bSess), []byte(id), rec)
	})
	return id, err
}

func SessionCredential(_ context.Context, s *Store, id string) (string, error) {
	if id == "" {
		return "", ErrNoSession
	}
	var rec sessionRecord
	if err := s.View(func(tx *bolt.Tx) error {
		return getJSON(tx.Bucket(bSess), []byte(id), &rec)
	}); err != nil {
		return "", ErrNoSession
	}
	when, err := time.Parse(time.RFC3339, rec.ExpiresAt)
	if err != nil || when.Before(time.Now().UTC()) {
		return "", ErrNoSession
	}
	return rec.CredentialID, nil
}

func DeleteSession(_ context.Context, s *Store, id string) error {
	return s.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bSess).Delete([]byte(id))
	})
}
