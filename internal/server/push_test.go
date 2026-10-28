package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
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
	seedKey(t, h)
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

func TestNotifyPushSkipsCredentialWithoutKey(t *testing.T) {
	h := newTestServer(t)
	seedKey(t, h)
	for _, sub := range []store.PushSubscription{
		{Endpoint: "https://push.example/owner", CredentialID: "cred-a", P256dh: "p", Auth: "a"},
		{Endpoint: "https://push.example/other", CredentialID: "cred-b", P256dh: "p", Auth: "b"},
	} {
		if err := store.UpsertPushSubscription(context.Background(), h.server.db, sub); err != nil {
			t.Fatal(err)
		}
	}
	called := []string{}
	withSendPush(t, func(_ context.Context, _ []byte, sub *webpush.Subscription, _ *webpush.Options) (int, error) {
		called = append(called, sub.Endpoint)
		return http.StatusCreated, nil
	})

	h.server.notifyPush(mustCreateRequest(t, h))
	if len(called) != 1 || called[0] != "https://push.example/owner" {
		t.Fatalf("push endpoints = %v, want only the key owner", called)
	}
}

func TestNotifyPushDropsGoneSubscription(t *testing.T) {
	h := newTestServer(t)
	seedKey(t, h)
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

func TestPushStatusUnsubscribeAndTest(t *testing.T) {
	h := newTestServer(t)
	seedKey(t, h)
	seedSubscription(t, h)
	sid, err := createSessionFor(t, h, "cred-a")
	if err != nil {
		t.Fatal(err)
	}
	c := h.pwaClient(t)
	setCookie(t, c, h, sid)

	resp, body := pwaGet(t, c, h.webURL("/api/v1/push/status"))
	if resp.StatusCode != http.StatusOK || body["webpush"] != true || body["discord"] != false {
		t.Fatalf("status: %d %+v", resp.StatusCode, body)
	}

	called := 0
	withSendPush(t, func(context.Context, []byte, *webpush.Subscription, *webpush.Options) (int, error) {
		called++
		return http.StatusCreated, nil
	})
	resp, body = pwaPost(t, c, h.webURL("/api/v1/push/test"), map[string]any{"channel": "webpush"}, nil)
	if resp.StatusCode != http.StatusOK || body["sent"] != float64(1) || called != 1 {
		t.Fatalf("test push: %d %+v called=%d", resp.StatusCode, body, called)
	}

	req, err := http.NewRequest(http.MethodDelete, h.webURL("/api/v1/push/subscribe"), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp2, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("unsubscribe: %d", resp2.StatusCode)
	}

	resp, body = pwaGet(t, c, h.webURL("/api/v1/push/status"))
	if resp.StatusCode != http.StatusOK || body["webpush"] != false {
		t.Fatalf("status after unsubscribe: %d %+v", resp.StatusCode, body)
	}

	resp, _ = pwaPost(t, c, h.webURL("/api/v1/push/test"), map[string]any{"channel": "webpush"}, nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("test without subscription: %d", resp.StatusCode)
	}
}

func TestPushTestRequiresSession(t *testing.T) {
	h := newTestServer(t)
	c := h.pwaClient(t)
	resp, _ := pwaPost(t, c, h.webURL("/api/v1/push/test"), map[string]any{"channel": "discord"}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

func TestNotifyDiscordPayload(t *testing.T) {
	h := newTestServer(t)
	h.server.cfg.DiscordWebhook = "https://discord.example/webhook"
	var got []byte
	orig := sendDiscord
	sendDiscord = func(_ context.Context, webhook string, payload []byte) (int, error) {
		if webhook != h.server.cfg.DiscordWebhook {
			t.Fatalf("webhook: %s", webhook)
		}
		got = append([]byte(nil), payload...)
		return http.StatusNoContent, nil
	}
	t.Cleanup(func() { sendDiscord = orig })

	h.server.notifyDiscord(mustCreateRequest(t, h))
	var msg map[string]any
	if err := json.Unmarshal(got, &msg); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if msg["content"] != "署名の承認待ち" {
		t.Fatalf("content: %v", msg["content"])
	}
	if strings.Contains(string(got), "@everyone") {
		t.Fatal("payload must not ping")
	}
}

func TestDiscordTestEndpoint(t *testing.T) {
	h := newTestServer(t)
	h.server.cfg.DiscordWebhook = "https://discord.example/webhook"
	sid, err := createSessionFor(t, h, "cred-a")
	if err != nil {
		t.Fatal(err)
	}
	c := h.pwaClient(t)
	setCookie(t, c, h, sid)
	orig := sendDiscord
	sendDiscord = func(context.Context, string, []byte) (int, error) { return http.StatusNoContent, nil }
	t.Cleanup(func() { sendDiscord = orig })

	resp, body := pwaGet(t, c, h.webURL("/api/v1/push/status"))
	if resp.StatusCode != http.StatusOK || body["discord"] != true {
		t.Fatalf("status: %d %+v", resp.StatusCode, body)
	}
	resp, body = pwaPost(t, c, h.webURL("/api/v1/push/test"), map[string]any{"channel": "discord"}, nil)
	if resp.StatusCode != http.StatusOK || body["ok"] != true {
		t.Fatalf("discord test: %d %+v", resp.StatusCode, body)
	}
}
