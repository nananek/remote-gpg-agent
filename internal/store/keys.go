package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"

	"github.com/nananek/remote-gpg-agent/internal/protocol"
)

func envelopeKey(credID, keyID string) []byte {
	return []byte(credID + "\x00" + keyID)
}

// UpsertKey は鍵を登録し、その credential 用の envelope を書く。
// 既存の fingerprint に別の公開鍵を渡した場合はエラー（鍵の取り違え防止）。
func UpsertKey(_ context.Context, s *Store, k protocol.KeyMeta, env protocol.Envelope) error {
	if protocol.KeyIDFromFingerprint(k.Fingerprint) != k.KeyID {
		return errors.New("keyId does not match fingerprint")
	}
	env.KeyID = k.KeyID
	return s.Update(func(tx *bolt.Tx) error {
		kb := tx.Bucket(bKeys)
		var existing protocol.KeyMeta
		switch err := getJSON(kb, []byte(k.KeyID), &existing); {
		case errors.Is(err, ErrNotFound):
			if err := putJSON(kb, []byte(k.KeyID), k); err != nil {
				return err
			}
			if err := tx.Bucket(bFpr).Put([]byte(k.Fingerprint), []byte(k.KeyID)); err != nil {
				return err
			}
		case err != nil:
			return err
		case existing.PublicKeyArmored != k.PublicKeyArmored:
			return fmt.Errorf("public key for %s does not match the stored one", k.Fingerprint)
		}
		return putJSON(tx.Bucket(bEnvs), envelopeKey(env.CredentialID, env.KeyID), env)
	})
}

func AttachEnvelope(_ context.Context, s *Store, env protocol.Envelope) error {
	return s.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bEnvs), envelopeKey(env.CredentialID, env.KeyID), env)
	})
}

func ListKeys(_ context.Context, s *Store) ([]protocol.KeyMeta, error) {
	out := make([]protocol.KeyMeta, 0, 4)
	err := s.View(func(tx *bolt.Tx) error {
		return forEach(tx.Bucket(bKeys), func(_, raw []byte) error {
			var k protocol.KeyMeta
			if err := jsonUnmarshal(raw, &k); err != nil {
				return err
			}
			out = append(out, k)
			return nil
		})
	})
	return out, err
}

func GetKeyByFingerprint(_ context.Context, s *Store, fpr string) (protocol.KeyMeta, error) {
	var k protocol.KeyMeta
	err := s.View(func(tx *bolt.Tx) error {
		keyID := tx.Bucket(bFpr).Get([]byte(fpr))
		if keyID == nil {
			return ErrNotFound
		}
		return getJSON(tx.Bucket(bKeys), keyID, &k)
	})
	return k, err
}

func ListEnvelopesForCredential(_ context.Context, s *Store, credID string) ([]protocol.Envelope, error) {
	prefix := []byte(credID + "\x00")
	out := make([]protocol.Envelope, 0, 4)
	err := s.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bEnvs).Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var e protocol.Envelope
			if err := jsonUnmarshal(v, &e); err != nil {
				return err
			}
			out = append(out, e)
		}
		return nil
	})
	return out, err
}

func KeyIDsForCredential(ctx context.Context, s *Store, credID string) (map[string]bool, error) {
	envs, err := ListEnvelopesForCredential(ctx, s, credID)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, e := range envs {
		out[e.KeyID] = true
	}
	return out, nil
}
