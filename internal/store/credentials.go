package store

import (
	"context"
	"errors"

	bolt "go.etcd.io/bbolt"
	"github.com/go-webauthn/webauthn/webauthn"
)

type CredentialRecord struct {
	CredentialID string              `json:"credentialId"`
	Label        string              `json:"label"`
	PRFEnabled   bool                `json:"prfEnabled"`
	Record       webauthn.Credential `json:"record"`
}

var ErrCredentialExists = errors.New("credential already exists")

func InsertCredential(_ context.Context, s *Store, c CredentialRecord) error {
	return s.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bCreds)
		if b.Get([]byte(c.CredentialID)) != nil {
			return ErrCredentialExists
		}
		return putJSON(b, []byte(c.CredentialID), c)
	})
}

func ListCredentials(_ context.Context, s *Store) ([]CredentialRecord, error) {
	out := make([]CredentialRecord, 0, 4)
	err := s.View(func(tx *bolt.Tx) error {
		return forEach(tx.Bucket(bCreds), func(_, raw []byte) error {
			var c CredentialRecord
			if err := jsonUnmarshal(raw, &c); err != nil {
				return err
			}
			out = append(out, c)
			return nil
		})
	})
	return out, err
}

func GetCredential(_ context.Context, s *Store, id string) (CredentialRecord, error) {
	var c CredentialRecord
	err := s.View(func(tx *bolt.Tx) error {
		return getJSON(tx.Bucket(bCreds), []byte(id), &c)
	})
	return c, err
}

// UpdateCredentialRecord は signCount / flags の書き戻しに使う。
func UpdateCredentialRecord(_ context.Context, s *Store, c CredentialRecord) error {
	return s.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bCreds), []byte(c.CredentialID), c)
	})
}
