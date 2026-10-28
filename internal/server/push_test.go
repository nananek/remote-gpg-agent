package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/SherClockHolmes/webpush-go"

	"github.com/nananek/remote-gpg-agent/internal/store"
)

func withSendPush(t *testing.T, fn func(context.Context, []byte, *webpush.Subscription, *webpush.Options) (int, error)) {
	t.Helper()
	orig := sendPush
	sendPush = fn
	t.Cleanup(func() { sendPush = orig })
}

func seedSubscription(t *testing.T, h *testStack) {
	t.Helper()
	if err := store.UpsertPushSubscription(context.Background(), h.server.db, store.PushSubscription{
		Endpoint: "https://push.example/1", CredentialID: "cred-a", P256dh: "p", Auth: "a",
	}); err != nil {
		t.Fatal(err)
	}
}

func mustCreateRequest(t *testing.T, h *testStack) *store.Request {
	t.Helper()
	row, err := store.CreateRequest(context.Background(), h.server.db, store.NewRequestInput{
		Purpose: "git-commit", Description: "repos/foo", ClientName: "workstation",
		KeyFingerprint: fprForTest, DataB64: "aGVsbG8=", TextMode: true,
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func TestNotifyPushSendsToLiveSubscription(t *testing.T) {
	h := newTestServer(t)
	seedSubscription(t, h)
	called := 0
	withSendPush(t, func(_ context.Context, payload []byte, sub *webpush.Subscription, o *webpush.Options) (int, error) {
		called++
		if sub.Endpoint != "https://push.example/1" {
			t.Fatalf("endpoint: %s", sub.Endpoint)
		}
		if len(payload) == 0 || o.VAPIDPublicKey != "test-public" {
			t.Fatalf("bad payload/options")
		}
		return http.StatusCreated, nil
	})

	h.server.notifyPush(mustCreateRequest(t, h))
	if called != 1 {
		t.Fatalf("sendPush calls: %d", called)
	}
	subs, _ := store.ListPushSubscriptions(context.Background(), h.server.db)
	if len(subs) != 1 {
		t.Fatalf("live subscription must be kept: %+v", subs)
	}
}

func TestNotifyPushDropsGoneSubscription(t *testing.T) {
	h := newTestServer(t)
	seedSubscription(t, h)
	withSendPush(t, func(context.Context, []byte, *webpush.Subscription, *webpush.Options) (int, error) {
		return http.StatusGone, nil
	})

	h.server.notifyPush(mustCreateRequest(t, h))
	subs, _ := store.ListPushSubscriptions(context.Background(), h.server.db)
	if len(subs) != 0 {
		t.Fatalf("gone subscription must be deleted: %+v", subs)
	}
}
