package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nananek/remote-gpg-agent/internal/protocol"
	"github.com/nananek/remote-gpg-agent/internal/store"
)

func TestMTLSRejectsClientWithoutCertificate(t *testing.T) {
	h := newTestServer(t)

	if _, err := h.plainClient(t).Get(h.clientURL("/healthz")); err == nil {
		t.Fatal("expected TLS handshake failure without a client certificate")
	}

	resp, err := h.mtlsClient(t).Get(h.clientURL("/healthz"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "client") {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
}

func TestWebListenerIsPlainHTTP(t *testing.T) {
	h := newTestServer(t)
	resp, err := h.webClient().Get(h.webURL("/healthz"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "web") {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
}

func postJSON(t *testing.T, c *http.Client, url string, v any) (*http.Response, []byte) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Post(url, "application/json", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, body
}

func TestCreateRequestRecordsClientName(t *testing.T) {
	h := newTestServer(t)
	c := h.mtlsClient(t)

	resp, body := postJSON(t, c, h.clientURL("/api/v1/requests"), protocol.CreateSignRequest{
		Purpose: "git-commit", Description: "repos/foo",
		KeyFingerprint: fprForTest, TextMode: true,
		DataB64: "aGVsbG8=",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	var created protocol.CreateSignRequestResponse
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.ExpiresAt == "" {
		t.Fatalf("bad response: %s", body)
	}

	pending, err := checkPending(h)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].ClientName != "test-client" {
		t.Fatalf("pending: %+v", pending)
	}
}

func TestCreateRequestRejectsBadInput(t *testing.T) {
	h := newTestServer(t)
	c := h.mtlsClient(t)

	for _, in := range []protocol.CreateSignRequest{
		{Purpose: "x", Description: "y", KeyFingerprint: "ABC", DataB64: "aGVsbG8="},
		{Purpose: "", Description: "y", KeyFingerprint: fprForTest, DataB64: "aGVsbG8="},
		{Purpose: "x", Description: "", KeyFingerprint: fprForTest, DataB64: "aGVsbG8="},
		{Purpose: "x", Description: "y", KeyFingerprint: fprForTest, DataB64: ""},
	} {
		resp, body := postJSON(t, c, h.clientURL("/api/v1/requests"), in)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%+v: status=%d body=%s", in, resp.StatusCode, body)
		}
	}
}

func TestPollReturnsPendingThenSigned(t *testing.T) {
	h := newTestServer(t)
	c := h.mtlsClient(t)

	_, body := postJSON(t, c, h.clientURL("/api/v1/requests"), protocol.CreateSignRequest{
		Purpose: "git-commit", Description: "x", KeyFingerprint: fprForTest,
		TextMode: true, DataB64: "aGVsbG8=",
	})
	var created protocol.CreateSignRequestResponse
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}

	// 20ms ポーリングなので、最初の GET は pending で返ってくる。
	first, err := c.Get(h.clientURL("/api/v1/requests/" + created.ID))
	if err != nil {
		t.Fatal(err)
	}
	var res protocol.SignResult
	_ = json.NewDecoder(first.Body).Decode(&res)
	first.Body.Close()
	if res.Status != "pending" {
		t.Fatalf("first poll: %+v", res)
	}

	// ロングポール中に署名が入ることを確認する。
	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = completeRequestForTest(h, created.ID, "-----BEGIN PGP SIGNATURE-----\nX\n-----END PGP SIGNATURE-----")
	}()
	second, err := c.Get(h.clientURL("/api/v1/requests/" + created.ID))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Body.Close()
	if err := json.NewDecoder(second.Body).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if res.Status != "signed" || !strings.Contains(res.SignatureArmored, "BEGIN PGP SIGNATURE") {
		t.Fatalf("second poll: %+v", res)
	}
}

func TestPollUnknownRequestIs404(t *testing.T) {
	h := newTestServer(t)
	resp, err := h.mtlsClient(t).Get(h.clientURL("/api/v1/requests/nope"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestCreateRequestRejectsOversizedPayload(t *testing.T) {
	h := newTestServer(t)
	c := h.mtlsClient(t)
	resp, body := postJSON(t, c, h.clientURL("/api/v1/requests"), protocol.CreateSignRequest{
		Purpose: "git-commit", Description: "big", KeyFingerprint: fprForTest,
		DataB64: base64.StdEncoding.EncodeToString(make([]byte, protocol.MaxDataBytes+1)),
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for oversized payload, got %d: %s", resp.StatusCode, body)
	}
}

func TestPollExpiredRequestReturnsExpired(t *testing.T) {
	h := newTestServer(t)
	row, err := store.CreateRequest(t.Context(), h.server.db, store.NewRequestInput{
		Purpose: "git-commit", Description: "expired", ClientName: "test-client",
		KeyFingerprint: fprForTest, DataB64: "aGVsbG8=",
	}, -time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := h.mtlsClient(t).Get(h.clientURL("/api/v1/requests/" + row.ID))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var res protocol.SignResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if res.Status != "expired" {
		t.Fatalf("expired request must not stay pending: %+v", res)
	}
}

func TestKeysEndpoints(t *testing.T) {
	h := newTestServer(t)
	c := h.mtlsClient(t)

	resp, err := c.Get(h.clientURL("/api/v1/keys/" + fprForTest))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown key: status=%d", resp.StatusCode)
	}

	seedKey(t, h)

	resp, err = c.Get(h.clientURL("/api/v1/keys"))
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Keys []protocol.KeyMeta `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(list.Keys) != 1 || list.Keys[0].Fingerprint != fprForTest {
		t.Fatalf("list: %+v", list)
	}
	if list.Keys[0].PublicKeyArmored != "" {
		t.Fatal("list must not include the public key body")
	}

	resp, err = c.Get(h.clientURL("/api/v1/keys/" + fprForTest))
	if err != nil {
		t.Fatal(err)
	}
	var one protocol.KeyMeta
	if err := json.NewDecoder(resp.Body).Decode(&one); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if one.PublicKeyArmored == "" || one.Label != "personal" {
		t.Fatalf("detail: %+v", one)
	}
}
