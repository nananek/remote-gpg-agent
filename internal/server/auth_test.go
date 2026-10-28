package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// fakeWA は検証フェーズだけを差し替える。Begin* は本物と同じ形の応答を返す。
type fakeWA struct {
	credentialID []byte
	prfEnabled   bool
}

func (f *fakeWA) BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	creation := &protocol.CredentialCreation{Response: protocol.PublicKeyCredentialCreationOptions{
		Challenge: protocol.URLEncodedBase64("Y2hhbGxlbmdl"),
	}}
	session := &webauthn.SessionData{Challenge: "Y2hhbGxlbmdl", Expires: time.Now().Add(time.Minute)}
	return creation, session, nil
}

func (f *fakeWA) FinishRegistration(user webauthn.User, session webauthn.SessionData, r *http.Request) (*webauthn.Credential, error) {
	enabled := f.prfEnabled
	return &webauthn.Credential{
		ID:          f.credentialID,
		PublicKey:   []byte{0x01, 0x02, 0x03},
		Transport:   []protocol.AuthenticatorTransport{protocol.Internal},
		Extensions:  webauthn.CredentialExtensions{PRFEnabled: &enabled},
		Authenticator: webauthn.Authenticator{SignCount: 1},
	}, nil
}

func (f *fakeWA) BeginLogin(user webauthn.User, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	assertion := &protocol.CredentialAssertion{Response: protocol.PublicKeyCredentialRequestOptions{
		Challenge: protocol.URLEncodedBase64("Y2hhbGxlbmdl"),
	}}
	session := &webauthn.SessionData{Challenge: "Y2hhbGxlbmdl", Expires: time.Now().Add(time.Minute)}
	return assertion, session, nil
}

func (f *fakeWA) FinishLogin(user webauthn.User, session webauthn.SessionData, r *http.Request) (*webauthn.Credential, error) {
	enabled := true
	return &webauthn.Credential{
		ID:            f.credentialID,
		PublicKey:     []byte{0x01, 0x02, 0x03},
		Extensions:    webauthn.CredentialExtensions{PRFEnabled: &enabled},
		Authenticator: webauthn.Authenticator{SignCount: 2},
	}, nil
}

// pwaClient は cookie を保持する PWA 側のクライアント。
func (h *testStack) pwaClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar, Timeout: 10 * time.Second}
}

func pwaPost(t *testing.T, c *http.Client, url string, v any, headers map[string]string) (*http.Response, map[string]any) {
	t.Helper()
	var body io.Reader = http.NoBody
	if v != nil {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		body = strings.NewReader(string(raw))
	}
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("content-type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	raw, _ := io.ReadAll(resp.Body)
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return resp, out
}

func pwaGet(t *testing.T, c *http.Client, url string) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	raw, _ := io.ReadAll(resp.Body)
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return resp, out
}

func TestRegisterOptionsRequiresBootstrapToken(t *testing.T) {
	h := newTestServer(t)
	c := h.pwaClient(t)

	resp, _ := pwaPost(t, c, h.webURL("/api/v1/auth/register/options"), map[string]any{}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}

	resp, body := pwaPost(t, c, h.webURL("/api/v1/auth/register/options"), map[string]any{},
		map[string]string{"X-RGA-Bootstrap": "test-bootstrap"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d: %v", resp.StatusCode, body)
	}
}

func TestRegisterOptionsRequestsPRF(t *testing.T) {
	h := newTestServer(t)
	c := h.pwaClient(t)

	resp, body := pwaPost(t, c, h.webURL("/api/v1/auth/register/options"), map[string]any{},
		map[string]string{"X-RGA-Bootstrap": "test-bootstrap"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d: %v", resp.StatusCode, body)
	}
	options, _ := json.Marshal(body["options"])
	if !strings.Contains(string(options), `"prf"`) {
		t.Fatalf("registration options must request PRF: %s", options)
	}
	if !strings.Contains(string(options), "challenge") {
		t.Fatalf("missing challenge: %s", options)
	}
}

func TestLoginOptionsRequestsPrfEval(t *testing.T) {
	h := newTestServer(t)
	seedKey(t, h)
	c := h.pwaClient(t)

	resp, body := pwaPost(t, c, h.webURL("/api/v1/auth/login/options"), map[string]any{}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d: %v", resp.StatusCode, body)
	}
	options, _ := json.Marshal(body["options"])
	if !strings.Contains(string(options), `"prf"`) || !strings.Contains(string(options), `"eval"`) {
		t.Fatalf("assertion options must evaluate PRF: %s", options)
	}
	if !strings.Contains(string(options), "allowCredentials") {
		t.Fatalf("missing allowCredentials: %s", options)
	}
}

func TestRegisterVerifyRejectsNonPRFCredential(t *testing.T) {
	h := newTestServer(t)
	h.server.wa = &fakeWA{credentialID: []byte("cred-x"), prfEnabled: false}
	c := h.pwaClient(t)

	_, body := pwaPost(t, c, h.webURL("/api/v1/auth/register/options"), map[string]any{},
		map[string]string{"X-RGA-Bootstrap": "test-bootstrap"})
	ceremonyID, _ := body["ceremonyId"].(string)

	resp, _ := pwaPost(t, c, h.webURL("/api/v1/auth/register/verify"), map[string]any{
		"ceremonyId": ceremonyID,
		"response":   map[string]any{"id": "cred-x"},
	}, map[string]string{"X-RGA-Bootstrap": "test-bootstrap"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for PRF-less authenticator, got %d", resp.StatusCode)
	}
	if n := len(mustListCredentials(t, h)); n != 0 {
		t.Fatalf("credential must not be stored, got %d", n)
	}
}

func TestRegisterVerifyFirstPasskeySetsSession(t *testing.T) {
	h := newTestServer(t)
	h.server.wa = &fakeWA{credentialID: []byte("cred-new"), prfEnabled: true}
	c := h.pwaClient(t)

	_, body := pwaPost(t, c, h.webURL("/api/v1/auth/register/options"), map[string]any{},
		map[string]string{"X-RGA-Bootstrap": "test-bootstrap"})
	ceremonyID, _ := body["ceremonyId"].(string)

	resp, respBody := pwaPost(t, c, h.webURL("/api/v1/auth/register/verify"), map[string]any{
		"ceremonyId": ceremonyID,
		"response":   map[string]any{"id": "cred-new"},
		"envelopes":  []any{},
	}, map[string]string{"X-RGA-Bootstrap": "test-bootstrap"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d: %v", resp.StatusCode, respBody)
	}
	if respBody["credentialId"] == "" {
		t.Fatalf("missing credentialId: %v", respBody)
	}

	_, me := pwaGet(t, c, h.webURL("/api/v1/auth/me"))
	if me["authenticated"] != true {
		t.Fatalf("session cookie missing: %v", me)
	}
	if me["credentialCount"].(float64) != 1 {
		t.Fatalf("credentialCount: %v", me)
	}
}

func TestRegisterVerifyRejectsEnvelopesWithoutSession(t *testing.T) {
	h := newTestServer(t)
	h.server.wa = &fakeWA{credentialID: []byte("cred-new"), prfEnabled: true}
	c := h.pwaClient(t)

	_, body := pwaPost(t, c, h.webURL("/api/v1/auth/register/options"), map[string]any{},
		map[string]string{"X-RGA-Bootstrap": "test-bootstrap"})
	ceremonyID, _ := body["ceremonyId"].(string)

	resp, _ := pwaPost(t, c, h.webURL("/api/v1/auth/register/verify"), map[string]any{
		"ceremonyId": ceremonyID,
		"response":   map[string]any{"id": "cred-new"},
		"envelopes": []map[string]any{{
			"keyId": "89ABCDEF01234567", "hkdfSaltB64": "a", "ivB64": "b", "ciphertextB64": "c",
		}},
	}, map[string]string{"X-RGA-Bootstrap": "test-bootstrap"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}

func TestSecondPasskeyMustCoverAllUnlockedKeys(t *testing.T) {
	h := newTestServer(t)
	seedKey(t, h) // cred-a と鍵 1 本
	h.server.wa = &fakeWA{credentialID: []byte("cred-b"), prfEnabled: true}

	ctx := t.Context()
	sid, err := createSessionFor(t, h, "cred-a")
	if err != nil {
		t.Fatal(err)
	}
	c := h.pwaClient(t)
	setCookie(t, c, h, sid)

	// envelope なし → 400
	_, body := pwaPost(t, c, h.webURL("/api/v1/auth/register/options"), map[string]any{}, nil)
	ceremonyID, _ := body["ceremonyId"].(string)
	resp, _ := pwaPost(t, c, h.webURL("/api/v1/auth/register/verify"), map[string]any{
		"ceremonyId": ceremonyID,
		"response":   map[string]any{"id": "cred-b"},
		"envelopes":  []any{},
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 without envelopes, got %d", resp.StatusCode)
	}

	// 全部そろえる → 200
	_, body = pwaPost(t, c, h.webURL("/api/v1/auth/register/options"), map[string]any{}, nil)
	ceremonyID, _ = body["ceremonyId"].(string)
	resp, respBody := pwaPost(t, c, h.webURL("/api/v1/auth/register/verify"), map[string]any{
		"ceremonyId": ceremonyID,
		"response":   map[string]any{"id": "cred-b"},
		"envelopes": []map[string]any{{
			"keyId": "89ABCDEF01234567", "hkdfSaltB64": "a2", "ivB64": "b2", "ciphertextB64": "c2",
		}},
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d: %v", resp.StatusCode, respBody)
	}
	_ = ctx

	// credential ID は base64url 化されて保存される（ブラウザ側の ID と一致）。
	newCredID, _ := respBody["credentialId"].(string)
	if newCredID == "" {
		t.Fatalf("missing credentialId: %v", respBody)
	}
	envs, err := storeEnvelopesFor(t, h, newCredID)
	if err != nil {
		t.Fatal(err)
	}
	if len(envs) != 1 || envs[0].IVB64 != "b2" {
		t.Fatalf("envelopes for %s: %+v", newCredID, envs)
	}
}

func TestStateRequiresSession(t *testing.T) {
	h := newTestServer(t)
	resp, _ := pwaGet(t, h.pwaClient(t), h.webURL("/api/v1/state"))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

func TestSealKeyThenState(t *testing.T) {
	h := newTestServer(t)
	c := h.pwaClient(t)
	sid, err := createSessionFor(t, h, "cred-a")
	if err != nil {
		t.Fatal(err)
	}
	setCookie(t, c, h, sid)

	resp, body := pwaPost(t, c, h.webURL("/api/v1/keys"), map[string]any{
		"fingerprint":      fprForTest,
		"label":            "personal",
		"publicKeyArmored": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----",
		"hkdfSaltB64":      "a",
		"ivB64":            "b",
		"ciphertextB64":    "c",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("seal: %d %v", resp.StatusCode, body)
	}

	_, state := pwaGet(t, c, h.webURL("/api/v1/state"))
	keys, _ := state["keys"].([]any)
	envs, _ := state["envelopes"].([]any)
	if len(keys) != 1 || len(envs) != 1 {
		t.Fatalf("state: %v", state)
	}
	if state["credentialId"] != "cred-a" {
		t.Fatalf("credentialId: %v", state["credentialId"])
	}

	// 同じ fingerprint で別の公開鍵 → 409
	resp, _ = pwaPost(t, c, h.webURL("/api/v1/keys"), map[string]any{
		"fingerprint":      fprForTest,
		"publicKeyArmored": "-----BEGIN PGP PUBLIC KEY BLOCK-----\ny\n-----END PGP PUBLIC KEY BLOCK-----",
		"hkdfSaltB64":      "a", "ivB64": "b", "ciphertextB64": "c",
	}, nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("want 409, got %d", resp.StatusCode)
	}
}

func TestSignIsSingleUseAndDenyWorks(t *testing.T) {
	h := newTestServer(t)
	c := h.pwaClient(t)
	sid, err := createSessionFor(t, h, "cred-a")
	if err != nil {
		t.Fatal(err)
	}
	setCookie(t, c, h, sid)

	reqID := createRequestFor(t, h)
	sig := "-----BEGIN PGP SIGNATURE-----\n" + strings.Repeat("A", 64) + "\n-----END PGP SIGNATURE-----"

	resp, body := pwaPost(t, c, h.webURL("/api/v1/requests/"+reqID+"/sign"), map[string]any{
		"signatureArmored": sig,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign: %d %v", resp.StatusCode, body)
	}
	resp, _ = pwaPost(t, c, h.webURL("/api/v1/requests/"+reqID+"/sign"), map[string]any{
		"signatureArmored": sig,
	}, nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("second sign must be 409, got %d", resp.StatusCode)
	}

	otherID := createRequestFor(t, h)
	resp, _ = pwaPost(t, c, h.webURL("/api/v1/requests/"+otherID+"/deny"), map[string]any{
		"reason": "not me",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deny: %d", resp.StatusCode)
	}
	_, list := pwaGet(t, c, h.webURL("/api/v1/requests"))
	reqs, _ := list["requests"].([]any)
	if len(reqs) != 0 {
		t.Fatalf("pending after deny: %v", reqs)
	}
}
