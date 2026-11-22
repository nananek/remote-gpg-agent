package store

import (
	"errors"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/nananek/remote-gpg-agent/internal/protocol"
)

func TestPairingSignalsRoundTrip(t *testing.T) {
	s := mustOpen(t)
	id := "pair-1"
	if _, err := CreatePairing(ctx, s, id, "cred-a", "proof", time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := CreatePairing(ctx, s, id, "cred-a", "proof", time.Minute); !errors.Is(err, ErrPairingExists) {
		t.Fatalf("duplicate pairing must be rejected, got %v", err)
	}

	// 参加側が決まるまでシグナリングは通さない。
	if _, err := AppendSignal(ctx, s, id, "creator", protocol.PairingSignalOffer, "AAAA", time.Now()); !errors.Is(err, ErrPairingState) {
		t.Fatalf("signal before join must be rejected, got %v", err)
	}

	if err := AttachJoiner(ctx, s, id, "cred-b", "Android"); err != nil {
		t.Fatal(err)
	}
	if err := AttachJoiner(ctx, s, id, "cred-c", "third"); !errors.Is(err, ErrPairingState) {
		t.Fatalf("a third device must not join, got %v", err)
	}

	for i, kind := range []string{protocol.PairingSignalOffer, protocol.PairingSignalCandidate} {
		seq, err := AppendSignal(ctx, s, id, "creator", kind, "AAAA", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if want := int64(i + 1); seq != want {
			t.Fatalf("seq = %d, want %d", seq, want)
		}
	}

	all, err := ListSignals(ctx, s, id, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].Kind != protocol.PairingSignalOffer || all[1].From != "creator" {
		t.Fatalf("unexpected signals: %+v", all)
	}
	after, err := ListSignals(ctx, s, id, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 || after[0].Seq != 2 {
		t.Fatalf("after=1 returned %+v", after)
	}

	if err := SetTransferNonce(ctx, s, id, "cred-b", "nonce", time.Now()); !errors.Is(err, ErrPairingState) {
		t.Fatalf("only the creator may register the nonce, got %v", err)
	}
	if err := SetTransferNonce(ctx, s, id, "cred-a", "nonce", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := SetReceipt(ctx, s, id, "cred-a", "receipt", "nonce"); !errors.Is(err, ErrPairingState) {
		t.Fatalf("only the joiner may complete, got %v", err)
	}
	if err := SetReceipt(ctx, s, id, "cred-b", "receipt", "other"); !errors.Is(err, ErrPairingProof) {
		t.Fatalf("a receipt for another transfer must be rejected, got %v", err)
	}
	if err := SetReceipt(ctx, s, id, "cred-b", "receipt", "nonce"); err != nil {
		t.Fatal(err)
	}
	p, err := GetPairing(ctx, s, id)
	if err != nil {
		t.Fatal(err)
	}
	if p.State != protocol.PairingDelivered || p.Receipt != "receipt" {
		t.Fatalf("unexpected pairing: %+v", p)
	}
}

func TestPairingSignalCaps(t *testing.T) {
	s := mustOpen(t)
	id := "pair-caps"
	if _, err := CreatePairing(ctx, s, id, "cred-a", "proof", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := AttachJoiner(ctx, s, id, "cred-b", "Android"); err != nil {
		t.Fatal(err)
	}
	blob := make([]byte, protocol.MaxPairingSignalBytes)
	for i := range blob {
		blob[i] = 'A'
	}
	sent := 0
	for {
		_, err := AppendSignal(ctx, s, id, "creator", protocol.PairingSignalCandidate, string(blob), time.Now())
		if errors.Is(err, ErrPairingFull) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		sent++
		if sent > protocol.MaxPairingSignals+1 {
			t.Fatal("cap was never reached")
		}
	}
	if sent == 0 {
		t.Fatal("expected at least one signal to fit")
	}
}

func TestPairingExpiryIsHiddenAndPruned(t *testing.T) {
	s := mustOpen(t)
	old := "pair-old"
	if _, err := CreatePairing(ctx, s, old, "cred-a", "proof", -time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := GetPairing(ctx, s, old); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired pairing must look missing, got %v", err)
	}
	// 次の作成時に掃除される。
	if _, err := CreatePairing(ctx, s, "pair-new", "cred-a", "proof", time.Minute); err != nil {
		t.Fatal(err)
	}
	err := s.View(func(tx *bolt.Tx) error {
		if tx.Bucket(bPair).Get([]byte(old)) != nil {
			t.Fatal("expired pairing was not pruned")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
