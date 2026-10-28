package store

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	bolt "go.etcd.io/bbolt"

	"github.com/nananek/remote-gpg-agent/internal/protocol"
)

var ctx = context.Background()

const fprMain = "0123456789ABCDEF0123456789ABCDEF01234567"

func mustOpen(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func seedCredential(t *testing.T, s *Store, id string, prf bool) {
	t.Helper()
	if err := InsertCredential(ctx, s, CredentialRecord{
		CredentialID: id, Label: id, PRFEnabled: prf,
		Record: webauthn.Credential{ID: []byte(id), PublicKey: []byte{0x01, 0x02}},
	}); err != nil {
		t.Fatal(err)
	}
}

func baseInput() NewRequestInput {
	return NewRequestInput{
		Purpose: "git-commit", Description: "repos/foo", ClientName: "workstation",
		KeyFingerprint: fprMain, DataB64: "aGVsbG8=", TextMode: true,
	}
}

func TestOpenCreatesAllBuckets(t *testing.T) {
	s := mustOpen(t)
	for _, name := range [][]byte{bCreds, bKeys, bFpr, bEnvs, bSess, bChal, bReqs, bPush} {
		if err := s.View(func(tx *bolt.Tx) error {
			if tx.Bucket(name) == nil {
				t.Fatalf("missing bucket %s", name)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOpenRejectsSecondWriter(t *testing.T) {
	path := t.TempDir() + "/a.db"
	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	if _, err := Open(path); err == nil {
		t.Fatal("bbolt must refuse a second writer")
	}
}

func TestRequestLifecycle(t *testing.T) {
	s := mustOpen(t)
	r, err := CreateRequest(ctx, s, baseInput(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if r.DataSHA256 != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("sha256: %s", r.DataSHA256)
	}
	if r.DataSize != 5 || !r.TextMode || r.Status != "pending" {
		t.Fatalf("unexpected request: %+v", r)
	}
	if ok, err := CompleteRequest(ctx, s, r.ID, "SIG"); err != nil || !ok {
		t.Fatalf("complete: %v %v", ok, err)
	}
	if ok, _ := CompleteRequest(ctx, s, r.ID, "SIG2"); ok {
		t.Fatal("second complete must fail")
	}
	got, _ := GetRequest(ctx, s, r.ID)
	if got.SignatureArmored != "SIG" {
		t.Fatalf("signature: %s", got.SignatureArmored)
	}
	if got.DataB64 != "" || got.Description != "" {
		t.Fatalf("payload must be cleared after signing: %+v", got)
	}
	if ok, _ := DenyRequest(ctx, s, r.ID, "no"); ok {
		t.Fatal("deny must fail after signing")
	}

	denied, err := CreateRequest(ctx, s, baseInput(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := DenyRequest(ctx, s, denied.ID, "no"); err != nil || !ok {
		t.Fatalf("deny: %v %v", ok, err)
	}
	gotDenied, _ := GetRequest(ctx, s, denied.ID)
	if gotDenied.DataB64 != "" || gotDenied.Description != "" {
		t.Fatalf("payload must be cleared after denial: %+v", gotDenied)
	}
}

func TestListPendingSkipsHandled(t *testing.T) {
	s := mustOpen(t)
	a, _ := CreateRequest(ctx, s, baseInput(), time.Minute)
	CreateRequest(ctx, s, baseInput(), time.Minute)
	if _, err := CompleteRequest(ctx, s, a.ID, "SIG"); err != nil {
		t.Fatal(err)
	}
	pending, err := ListPending(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending: %d", len(pending))
	}
}

func TestExpireStale(t *testing.T) {
	s := mustOpen(t)
	r, _ := CreateRequest(ctx, s, baseInput(), -time.Second)
	if err := ExpireStale(ctx, s); err != nil {
		t.Fatal(err)
	}
	got, _ := GetRequest(ctx, s, r.ID)
	if got.Status != "expired" {
		t.Fatalf("status: %s", got.Status)
	}
	if got.DataB64 != "" || got.Description != "" {
		t.Fatalf("payload must be cleared after expiry: %+v", got)
	}
	pending, _ := ListPending(ctx, s)
	if len(pending) != 0 {
		t.Fatalf("expired request must not be listed: %d", len(pending))
	}
}

func TestCreateRequestRejectsOversizedPayload(t *testing.T) {
	s := mustOpen(t)
	in := baseInput()
	in.DataB64 = base64.StdEncoding.EncodeToString(make([]byte, protocol.MaxDataBytes+1))
	if _, err := CreateRequest(ctx, s, in, time.Minute); err == nil {
		t.Fatal("payload over MaxDataBytes must be rejected")
	}
}

func TestCompleteAndDenyRejectExpiredRequest(t *testing.T) {
	s := mustOpen(t)
	for _, complete := range []bool{true, false} {
		r, err := CreateRequest(ctx, s, baseInput(), -time.Second)
		if err != nil {
			t.Fatal(err)
		}
		var ok bool
		if complete {
			ok, err = CompleteRequest(ctx, s, r.ID, "SIG")
		} else {
			ok, err = DenyRequest(ctx, s, r.ID, "no")
		}
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Fatalf("expired request must not be completed (complete=%v)", complete)
		}
		got, _ := GetRequest(ctx, s, r.ID)
		if got.Status != "expired" || got.DataB64 != "" || got.Description != "" {
			t.Fatalf("expired request was not swept: %+v", got)
		}
	}
}

func TestExpireRequestOnlyTouchesOneRequest(t *testing.T) {
	s := mustOpen(t)
	expired, _ := CreateRequest(ctx, s, baseInput(), -time.Second)
	fresh, _ := CreateRequest(ctx, s, baseInput(), time.Minute)
	if err := ExpireRequest(ctx, s, expired.ID); err != nil {
		t.Fatal(err)
	}
	gotExpired, _ := GetRequest(ctx, s, expired.ID)
	if gotExpired.Status != "expired" {
		t.Fatalf("expired: %+v", gotExpired)
	}
	gotFresh, _ := GetRequest(ctx, s, fresh.ID)
	if gotFresh.Status != "pending" {
		t.Fatalf("fresh must stay pending: %+v", gotFresh)
	}
}

func TestUpsertKeyAddsEnvelope(t *testing.T) {
	s := mustOpen(t)
	seedCredential(t, s, "cred-a", true)
	keyID := protocol.KeyIDFromFingerprint(fprMain)
	k := protocol.KeyMeta{KeyID: keyID, Fingerprint: fprMain, Label: "personal", PublicKeyArmored: "PUB"}
	env := protocol.Envelope{CredentialID: "cred-a", KeyID: keyID, HKDFSaltB64: "AA", IVB64: "BB", CiphertextB64: "CC"}
	if err := UpsertKey(ctx, s, k, env); err != nil {
		t.Fatal(err)
	}
	envs, _ := ListEnvelopesForCredential(ctx, s, "cred-a")
	if len(envs) != 1 || envs[0].CiphertextB64 != "CC" {
		t.Fatalf("envelopes: %+v", envs)
	}
	keys, _ := ListKeys(ctx, s)
	if len(keys) != 1 || keys[0].Fingerprint != fprMain {
		t.Fatalf("keys: %+v", keys)
	}
	byFpr, err := GetKeyByFingerprint(ctx, s, fprMain)
	if err != nil || byFpr.KeyID != keyID {
		t.Fatalf("by fingerprint: %+v %v", byFpr, err)
	}
}

func TestUpsertKeyRejectsMismatchedPublicKey(t *testing.T) {
	s := mustOpen(t)
	seedCredential(t, s, "cred-a", true)
	keyID := protocol.KeyIDFromFingerprint(fprMain)
	k := protocol.KeyMeta{KeyID: keyID, Fingerprint: fprMain, Label: "p", PublicKeyArmored: "AAA"}
	env := protocol.Envelope{CredentialID: "cred-a", HKDFSaltB64: "x", IVB64: "y", CiphertextB64: "z"}
	if err := UpsertKey(ctx, s, k, env); err != nil {
		t.Fatal(err)
	}
	k.PublicKeyArmored = "BBB"
	if err := UpsertKey(ctx, s, k, env); err == nil {
		t.Fatal("want conflict error")
	}
}

func TestEnvelopesAreIsolatedPerCredential(t *testing.T) {
	s := mustOpen(t)
	seedCredential(t, s, "cred-a", true)
	seedCredential(t, s, "cred-b", true)
	keyID := protocol.KeyIDFromFingerprint(fprMain)
	k := protocol.KeyMeta{KeyID: keyID, Fingerprint: fprMain, Label: "p", PublicKeyArmored: "PUB"}
	_ = UpsertKey(ctx, s, k, protocol.Envelope{CredentialID: "cred-a", KeyID: keyID, HKDFSaltB64: "a", IVB64: "a", CiphertextB64: "a"})
	_ = UpsertKey(ctx, s, k, protocol.Envelope{CredentialID: "cred-b", KeyID: keyID, HKDFSaltB64: "b", IVB64: "b", CiphertextB64: "b"})

	a, _ := ListEnvelopesForCredential(ctx, s, "cred-a")
	b, _ := ListEnvelopesForCredential(ctx, s, "cred-b")
	if len(a) != 1 || a[0].IVB64 != "a" {
		t.Fatalf("cred-a: %+v", a)
	}
	if len(b) != 1 || b[0].IVB64 != "b" {
		t.Fatalf("cred-b: %+v", b)
	}
	ids, _ := KeyIDsForCredential(ctx, s, "cred-a")
	if !ids[keyID] || len(ids) != 1 {
		t.Fatalf("key ids: %+v", ids)
	}
}

func TestSessionsAndChallenges(t *testing.T) {
	s := mustOpen(t)
	seedCredential(t, s, "cred-a", true)

	sid, err := CreateSession(ctx, s, "cred-a")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := SessionCredential(ctx, s, sid); err != nil || got != "cred-a" {
		t.Fatalf("session: %q %v", got, err)
	}
	if _, err := SessionCredential(ctx, s, "bogus"); err != ErrNoSession {
		t.Fatalf("want ErrNoSession, got %v", err)
	}
	if err := DeleteSession(ctx, s, sid); err != nil {
		t.Fatal(err)
	}
	if _, err := SessionCredential(ctx, s, sid); err != ErrNoSession {
		t.Fatal("deleted session must be rejected")
	}

	cid, err := SaveChallenge(ctx, s, "register", []byte("data"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	got, err := TakeChallenge(ctx, s, cid, "register")
	if err != nil || string(got) != "data" {
		t.Fatalf("challenge: %q %v", got, err)
	}
	if _, err := TakeChallenge(ctx, s, cid, "register"); err != ErrChallengeGone {
		t.Fatal("challenge must be single use")
	}
	cid2, _ := SaveChallenge(ctx, s, "login", []byte("x"), time.Minute)
	if _, err := TakeChallenge(ctx, s, cid2, "register"); err != ErrChallengeGone {
		t.Fatal("kind mismatch must be rejected")
	}
}

func TestPushSubscriptions(t *testing.T) {
	s := mustOpen(t)
	sub := PushSubscription{Endpoint: "https://push.example/1", CredentialID: "cred-a", P256dh: "p", Auth: "a"}
	if err := UpsertPushSubscription(ctx, s, sub); err != nil {
		t.Fatal(err)
	}
	sub.Auth = "b"
	if err := UpsertPushSubscription(ctx, s, sub); err != nil {
		t.Fatal(err)
	}
	subs, _ := ListPushSubscriptions(ctx, s)
	if len(subs) != 1 || subs[0].Auth != "b" {
		t.Fatalf("subs: %+v", subs)
	}
	if err := DeletePushSubscription(ctx, s, sub.Endpoint); err != nil {
		t.Fatal(err)
	}
	subs, _ = ListPushSubscriptions(ctx, s)
	if len(subs) != 0 {
		t.Fatalf("subs after delete: %+v", subs)
	}
}

func TestCredentialRoundTrip(t *testing.T) {
	s := mustOpen(t)
	seedCredential(t, s, "cred-a", true)
	if err := InsertCredential(ctx, s, CredentialRecord{CredentialID: "cred-a"}); err != ErrCredentialExists {
		t.Fatalf("want ErrCredentialExists, got %v", err)
	}
	got, err := GetCredential(ctx, s, "cred-a")
	if err != nil || !got.PRFEnabled || len(got.Record.ID) == 0 {
		t.Fatalf("credential: %+v %v", got, err)
	}
	got.Record.Authenticator.SignCount = 7
	if err := UpdateCredentialRecord(ctx, s, got); err != nil {
		t.Fatal(err)
	}
	again, _ := GetCredential(ctx, s, "cred-a")
	if again.Record.Authenticator.SignCount != 7 {
		t.Fatalf("sign count not persisted: %+v", again.Record.Authenticator)
	}
}
