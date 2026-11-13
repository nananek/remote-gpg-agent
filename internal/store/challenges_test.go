package store

import (
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func challengeCount(t *testing.T, s *Store) int {
	t.Helper()
	n := 0
	if err := s.View(func(tx *bolt.Tx) error {
		return forEach(tx.Bucket(bChal), func(_, _ []byte) error {
			n++
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSaveChallengePrunesExpired(t *testing.T) {
	s := mustOpen(t)
	oldID, err := SaveChallenge(ctx, s, "login", []byte("old"), -time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SaveChallenge(ctx, s, "login", []byte("new"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if n := challengeCount(t, s); n != 1 {
		t.Fatalf("expired challenge must be pruned, got %d records", n)
	}
	if _, err := TakeChallenge(ctx, s, oldID, "login"); err != ErrChallengeGone {
		t.Fatalf("pruned challenge must be gone, got %v", err)
	}
}

func TestSaveChallengeCapsTotal(t *testing.T) {
	s := mustOpen(t)
	for i := 0; i < maxChallenges+20; i++ {
		if _, err := SaveChallenge(ctx, s, "login", []byte("x"), time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if n := challengeCount(t, s); n > maxChallenges {
		t.Fatalf("challenge bucket exceeded cap: %d > %d", n, maxChallenges)
	}
}
