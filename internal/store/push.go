package store

import (
	"context"

	bolt "go.etcd.io/bbolt"
)

type PushSubscription struct {
	Endpoint     string `json:"endpoint"`
	CredentialID string `json:"credentialId"`
	P256dh       string `json:"p256dh"`
	Auth         string `json:"auth"`
	Label        string `json:"label"`
}

func UpsertPushSubscription(_ context.Context, s *Store, sub PushSubscription) error {
	return s.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bPush), []byte(sub.Endpoint), sub)
	})
}

func ListPushSubscriptions(_ context.Context, s *Store) ([]PushSubscription, error) {
	out := make([]PushSubscription, 0, 4)
	err := s.View(func(tx *bolt.Tx) error {
		return forEach(tx.Bucket(bPush), func(_, raw []byte) error {
			var sub PushSubscription
			if err := jsonUnmarshal(raw, &sub); err != nil {
				return err
			}
			out = append(out, sub)
			return nil
		})
	})
	return out, err
}

func DeletePushSubscription(_ context.Context, s *Store, endpoint string) error {
	return s.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bPush).Delete([]byte(endpoint))
	})
}
