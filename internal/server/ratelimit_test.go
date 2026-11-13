package server

import (
	"testing"
	"time"
)

func TestTokenBucket(t *testing.T) {
	b := newTokenBucket(60, 2)
	now := time.Now()
	if !b.allow(now) || !b.allow(now) {
		t.Fatal("burst tokens must be available")
	}
	if b.allow(now) {
		t.Fatal("bucket must be empty after the burst")
	}
	if !b.allow(now.Add(2 * time.Second)) {
		t.Fatal("one token must refill after two seconds at 60/min")
	}
}

// 認証前の login/options は回数制限され、429 を返す。
func TestLoginOptionsIsRateLimited(t *testing.T) {
	h := newTestServer(t)
	seedKey(t, h)
	c := h.pwaClient(t)

	saw429 := false
	for i := 0; i < 80; i++ {
		resp, _ := pwaPost(t, c, h.webURL("/api/v1/auth/login/options"), map[string]any{}, nil)
		if resp.StatusCode == 429 {
			saw429 = true
			break
		}
	}
	if !saw429 {
		t.Fatal("login/options must be rate limited")
	}
}
