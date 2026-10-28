package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nananek/remote-gpg-agent/internal/store"
)

// TestLogoutCookieAttributes はログアウト時の Set-Cookie が
// セッション発行時と同じ属性（HttpOnly / SameSite / Secure）を持つことを確かめる。
func TestLogoutCookieAttributes(t *testing.T) {
	cases := []struct {
		name   string
		origin string
		secure bool
	}{
		{name: "https origin", origin: "https://rga.example.ts.net", secure: true},
		{name: "http origin", origin: "http://localhost:3080", secure: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{cfg: &Config{Origin: tc.origin}}
			rec := httptest.NewRecorder()
			s.handleLogout(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}
			c := findCookie(rec.Result().Cookies(), store.SessionCookie)
			if c == nil {
				t.Fatal("session cookie is not cleared")
			}
			if c.Value != "" {
				t.Errorf("Value = %q, want empty", c.Value)
			}
			if c.MaxAge >= 0 {
				t.Errorf("MaxAge = %d, want negative", c.MaxAge)
			}
			if !c.HttpOnly {
				t.Error("HttpOnly = false, want true")
			}
			if c.SameSite != http.SameSiteLaxMode {
				t.Errorf("SameSite = %v, want Lax", c.SameSite)
			}
			if c.Secure != tc.secure {
				t.Errorf("Secure = %v, want %v", c.Secure, tc.secure)
			}
		})
	}
}

// TestLogoutDeletesSession はクッキーを消すだけでなく、サーバ側のセッションも
// 失効することを確かめる。
func TestLogoutDeletesSession(t *testing.T) {
	h := newTestServer(t)
	sid, err := createSessionFor(t, h, "cred-logout")
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, h.webURL("/api/v1/auth/logout"), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: store.SessionCookie, Value: sid})
	resp, err := h.webClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	if _, err := store.SessionCredential(context.Background(), h.server.db, sid); err == nil {
		t.Fatal("session is still valid after logout")
	}
}

// TestLogoutDeletesPushSubscriptions はログアウト時に、その credential の
// Push 購読だけを消すことを確かめる。
func TestLogoutDeletesPushSubscriptions(t *testing.T) {
	h := newTestServer(t)
	sid, err := createSessionFor(t, h, "cred-logout")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, sub := range []store.PushSubscription{
		{Endpoint: "https://push.example/logout", CredentialID: "cred-logout", P256dh: "p", Auth: "a"},
		{Endpoint: "https://push.example/keep", CredentialID: "cred-other", P256dh: "p", Auth: "b"},
	} {
		if err := store.UpsertPushSubscription(ctx, h.server.db, sub); err != nil {
			t.Fatal(err)
		}
	}

	req, err := http.NewRequest(http.MethodPost, h.webURL("/api/v1/auth/logout"), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: store.SessionCookie, Value: sid})
	resp, err := h.webClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	subs, err := store.ListPushSubscriptions(ctx, h.server.db)
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 1 || subs[0].CredentialID != "cred-other" {
		t.Fatalf("push subscriptions after logout: %+v", subs)
	}
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}
