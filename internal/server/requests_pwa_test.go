package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nananek/remote-gpg-agent/internal/store"
)

func TestSignExpiredRequestIsRejected(t *testing.T) {
	h := newTestServer(t)
	seedKey(t, h)
	sid, err := createSessionFor(t, h, "cred-a")
	if err != nil {
		t.Fatal(err)
	}
	c := h.pwaClient(t)
	setCookie(t, c, h, sid)

	row, err := store.CreateRequest(t.Context(), h.server.db, store.NewRequestInput{
		Purpose: "git-commit", Description: "expired", ClientName: "test-client",
		KeyFingerprint: fprForTest, DataB64: "aGVsbG8=",
	}, -time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	sig := "-----BEGIN PGP SIGNATURE-----\n" + strings.Repeat("A", 64) + "\n-----END PGP SIGNATURE-----"
	resp, _ := pwaPost(t, c, h.webURL("/api/v1/requests/"+row.ID+"/sign"),
		map[string]any{"signatureArmored": sig}, nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expired request must not be signed: got %d", resp.StatusCode)
	}
	got, _ := store.GetRequest(t.Context(), h.server.db, row.ID)
	if got.Status != "expired" {
		t.Fatalf("status after rejected sign: %s", got.Status)
	}
}

func TestAPIResponsesAreNotCacheable(t *testing.T) {
	h := newTestServer(t)
	seedKey(t, h)
	sid, err := createSessionFor(t, h, "cred-a")
	if err != nil {
		t.Fatal(err)
	}
	c := h.pwaClient(t)
	setCookie(t, c, h, sid)

	for _, path := range []string{"/api/v1/state", "/api/v1/requests"} {
		resp, _ := pwaGet(t, c, h.webURL(path))
		if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
			t.Fatalf("%s: Cache-Control = %q, want no-store", path, cc)
		}
	}
}

func TestStateChangingAPIRejectsCrossOrigin(t *testing.T) {
	h := newTestServer(t)
	seedKey(t, h)
	sid, err := createSessionFor(t, h, "cred-a")
	if err != nil {
		t.Fatal(err)
	}
	c := h.pwaClient(t)
	setCookie(t, c, h, sid)
	reqID := createRequestFor(t, h)

	resp, _ := pwaPost(t, c, h.webURL("/api/v1/requests/"+reqID+"/deny"),
		map[string]any{"reason": "csrf"}, map[string]string{"Origin": "https://evil.example"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin POST: want 403, got %d", resp.StatusCode)
	}
	if row, _ := store.GetRequest(context.Background(), h.server.db, reqID); row.Status != "pending" {
		t.Fatalf("cross-origin deny must not change the request: %+v", row)
	}

	resp, _ = pwaPost(t, c, h.webURL("/api/v1/requests/"+reqID+"/deny"),
		map[string]any{"reason": "ok"}, map[string]string{"Origin": h.cfg.Origin})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("same-origin POST: want 200, got %d", resp.StatusCode)
	}
}

// 署名要求は「その鍵の envelope を持つ credential」にだけ見える/完了できる。
// 解錠できない credential のセッションは、ペイロードの閲覧も要求の消費もできない。
func TestPendingRequestsAreScopedToUnlockableKeys(t *testing.T) {
	h := newTestServer(t)
	seedKey(t, h) // cred-a + 鍵 + envelope
	reqForSign := createRequestFor(t, h)
	createRequestFor(t, h) // 一覧が 2 件になることの確認用

	sig := "-----BEGIN PGP SIGNATURE-----\n" + strings.Repeat("A", 64) + "\n-----END PGP SIGNATURE-----"

	// cred-b は envelope を 1 つも持たない。
	sidB, err := createSessionFor(t, h, "cred-b")
	if err != nil {
		t.Fatal(err)
	}
	b := h.pwaClient(t)
	setCookie(t, b, h, sidB)

	_, list := pwaGet(t, b, h.webURL("/api/v1/requests"))
	if reqs, _ := list["requests"].([]any); len(reqs) != 0 {
		t.Fatalf("credential without the key must not list requests: %v", reqs)
	}
	resp, _ := pwaPost(t, b, h.webURL("/api/v1/requests/"+reqForSign+"/sign"),
		map[string]any{"signatureArmored": sig}, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("sign without the key: want 404, got %d", resp.StatusCode)
	}
	row, err := store.GetRequest(context.Background(), h.server.db, reqForSign)
	if err != nil || row.Status != "pending" {
		t.Fatalf("request must stay pending: %+v %v", row, err)
	}

	// cred-a は従来どおり見える/署名できる。
	sidA, err := createSessionFor(t, h, "cred-a")
	if err != nil {
		t.Fatal(err)
	}
	a := h.pwaClient(t)
	setCookie(t, a, h, sidA)
	_, list = pwaGet(t, a, h.webURL("/api/v1/requests"))
	if reqs, _ := list["requests"].([]any); len(reqs) != 2 {
		t.Fatalf("credential with the key must see both requests: %v", reqs)
	}
	resp, body := pwaPost(t, a, h.webURL("/api/v1/requests/"+reqForSign+"/sign"),
		map[string]any{"signatureArmored": sig}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign with the key: %d %v", resp.StatusCode, body)
	}
}
