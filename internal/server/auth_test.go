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

	"github.com/nananek/remote-gpg-agent/internal/cryptoutil"
	rgaproto "github.com/nananek/remote-gpg-agent/internal/protocol"
	"github.com/nananek/remote-gpg-agent/internal/store"
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
		ID:            f.credentialID,
		PublicKey:     []byte{0x01, 0x02, 0x03},
		Transport:     []protocol.AuthenticatorTransport{protocol.Internal},
		Extensions:    webauthn.CredentialExtensions{PRFEnabled: &enabled},
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
	// 登録時にも salt を渡して評価させる。渡さないと認証器は PRF 出力を返さず、
	// 既存パスキーで取り直した PRF で封印する事故になる（増設パスキーが開かなくなる）。
	if !strings.Contains(string(options), `"eval"`) {
		t.Fatalf("registration options must evaluate PRF (prf.eval.first): %s", options)
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
	// cred-a が実鍵を 1 本持っている状態にする（所持証明の検証を通すため実鍵を使う）。
	k := newTestPGPKey(t)
	keyID := rgaproto.KeyIDFromFingerprint(k.fpr)
	ctx := t.Context()
	if err := store.InsertCredential(ctx, h.server.db, store.CredentialRecord{
		CredentialID: "cred-a", Label: "cred-a", PRFEnabled: true,
		Record: webauthn.Credential{ID: []byte("cred-a"), PublicKey: []byte{1}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertKey(ctx, h.server.db, rgaproto.KeyMeta{
		KeyID: keyID, Fingerprint: k.fpr, Label: "personal", PublicKeyArmored: k.publicArmored,
	}, rgaproto.Envelope{
		CredentialID: "cred-a", KeyID: keyID, HKDFSaltB64: "a", IVB64: "b", CiphertextB64: "c",
	}); err != nil {
		t.Fatal(err)
	}
	h.server.wa = &fakeWA{credentialID: []byte("cred-b"), prfEnabled: true}

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
	newCredID := cryptoutil.B64URL([]byte("cred-b"))
	resp, respBody := pwaPost(t, c, h.webURL("/api/v1/auth/register/verify"), map[string]any{
		"ceremonyId": ceremonyID,
		"response":   map[string]any{"id": "cred-b"},
		"envelopes": []map[string]any{{
			"keyId": keyID, "hkdfSaltB64": "a2", "ivB64": "b2", "ciphertextB64": "c2",
			"proof": k.proof(t, newCredID, keyID, "a2", "b2", "c2"),
		}},
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d: %v", resp.StatusCode, respBody)
	}

	// credential ID は base64url 化されて保存される（ブラウザ側の ID と一致）。
	gotCredID, _ := respBody["credentialId"].(string)
	if gotCredID != newCredID {
		t.Fatalf("credentialId: want %s, got %v", newCredID, respBody)
	}
	envs, err := storeEnvelopesFor(t, h, newCredID)
	if err != nil {
		t.Fatal(err)
	}
	if len(envs) != 1 || envs[0].IVB64 != "b2" {
		t.Fatalf("envelopes for %s: %+v", newCredID, envs)
	}
}

// 別の credential 用に作られた証明は受け付けない（登録セレモニーの envelope）。
func TestSecondPasskeyRejectsProofForAnotherCredential(t *testing.T) {
	h := newTestServer(t)
	k := newTestPGPKey(t)
	keyID := rgaproto.KeyIDFromFingerprint(k.fpr)
	ctx := t.Context()
	if err := store.InsertCredential(ctx, h.server.db, store.CredentialRecord{
		CredentialID: "cred-a", Label: "cred-a", PRFEnabled: true,
		Record: webauthn.Credential{ID: []byte("cred-a"), PublicKey: []byte{1}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertKey(ctx, h.server.db, rgaproto.KeyMeta{
		KeyID: keyID, Fingerprint: k.fpr, Label: "personal", PublicKeyArmored: k.publicArmored,
	}, rgaproto.Envelope{
		CredentialID: "cred-a", KeyID: keyID, HKDFSaltB64: "a", IVB64: "b", CiphertextB64: "c",
	}); err != nil {
		t.Fatal(err)
	}
	h.server.wa = &fakeWA{credentialID: []byte("cred-b"), prfEnabled: true}

	sid, err := createSessionFor(t, h, "cred-a")
	if err != nil {
		t.Fatal(err)
	}
	c := h.pwaClient(t)
	setCookie(t, c, h, sid)

	_, body := pwaPost(t, c, h.webURL("/api/v1/auth/register/options"), map[string]any{}, nil)
	ceremonyID, _ := body["ceremonyId"].(string)
	resp, _ := pwaPost(t, c, h.webURL("/api/v1/auth/register/verify"), map[string]any{
		"ceremonyId": ceremonyID,
		"response":   map[string]any{"id": "cred-b"},
		"envelopes": []map[string]any{{
			"keyId": keyID, "hkdfSaltB64": "a2", "ivB64": "b2", "ciphertextB64": "c2",
			"proof": k.proof(t, "some-other-credential", keyID, "a2", "b2", "c2"),
		}},
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 for a proof bound to another credential, got %d", resp.StatusCode)
	}
	if _, err := store.GetCredential(ctx, h.server.db, cryptoutil.B64URL([]byte("cred-b"))); err == nil {
		t.Fatal("credential must not be stored when the proof fails")
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

	k := newTestPGPKey(t)
	keyID := rgaproto.KeyIDFromFingerprint(k.fpr)
	resp, body := pwaPost(t, c, h.webURL("/api/v1/keys"), map[string]any{
		"credentialId":     "cred-a",
		"fingerprint":      k.fpr,
		"label":            "personal",
		"publicKeyArmored": k.publicArmored,
		"hkdfSaltB64":      "a",
		"ivB64":            "b",
		"ciphertextB64":    "c",
		"proof":            k.proof(t, "cred-a", keyID, "a", "b", "c"),
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

	// 同じ fingerprint を名乗る別の公開鍵は、所持証明が一致しないので保存されない。
	other := newTestPGPKey(t)
	resp, _ = pwaPost(t, c, h.webURL("/api/v1/keys"), map[string]any{
		"credentialId":     "cred-a",
		"fingerprint":      k.fpr,
		"publicKeyArmored": other.publicArmored,
		"hkdfSaltB64":      "a", "ivB64": "b", "ciphertextB64": "c",
		"proof": other.proof(t, "cred-a", keyID, "a", "b", "c"),
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 when the armor does not match the fingerprint, got %d", resp.StatusCode)
	}
}

// 封印先の credential とセッションが食い違う要求は保存しない（マルチタブ対策）。
func TestSealKeyRejectsCredentialMismatch(t *testing.T) {
	h := newTestServer(t)
	c := h.pwaClient(t)
	sid, err := createSessionFor(t, h, "cred-a")
	if err != nil {
		t.Fatal(err)
	}
	setCookie(t, c, h, sid)

	k := newTestPGPKey(t)
	keyID := rgaproto.KeyIDFromFingerprint(k.fpr)
	resp, _ := pwaPost(t, c, h.webURL("/api/v1/keys"), map[string]any{
		"credentialId":     "cred-b",
		"fingerprint":      k.fpr,
		"publicKeyArmored": k.publicArmored,
		"hkdfSaltB64":      "a", "ivB64": "b", "ciphertextB64": "c",
		"proof": k.proof(t, "cred-b", keyID, "a", "b", "c"),
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 for a mismatched credentialId, got %d", resp.StatusCode)
	}
	if _, err := store.GetKeyByFingerprint(t.Context(), h.server.db, k.fpr); err == nil {
		t.Fatal("the key must not be stored")
	}
}

// 秘密鍵を持たない credential は、公開鍵を知っていても envelope を名乗れない。
func TestSealKeyRejectsEnvelopeWithoutPossession(t *testing.T) {
	h := newTestServer(t)
	victim := newTestPGPKey(t)
	keyID := rgaproto.KeyIDFromFingerprint(victim.fpr)
	ctx := t.Context()
	if err := store.InsertCredential(ctx, h.server.db, store.CredentialRecord{
		CredentialID: "cred-a", Label: "cred-a", PRFEnabled: true,
		Record: webauthn.Credential{ID: []byte("cred-a"), PublicKey: []byte{1}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertKey(ctx, h.server.db, rgaproto.KeyMeta{
		KeyID: keyID, Fingerprint: victim.fpr, Label: "personal", PublicKeyArmored: victim.publicArmored,
	}, rgaproto.Envelope{
		CredentialID: "cred-a", KeyID: keyID, HKDFSaltB64: "a", IVB64: "b", CiphertextB64: "c",
	}); err != nil {
		t.Fatal(err)
	}

	sid, err := createSessionFor(t, h, "cred-b")
	if err != nil {
		t.Fatal(err)
	}
	c := h.pwaClient(t)
	setCookie(t, c, h, sid)

	attacker := newTestPGPKey(t)
	resp, _ := pwaPost(t, c, h.webURL("/api/v1/keys"), map[string]any{
		"credentialId":     "cred-b",
		"fingerprint":      victim.fpr,
		"publicKeyArmored": victim.publicArmored,
		"hkdfSaltB64":      "a", "ivB64": "b", "ciphertextB64": "c",
		"proof": attacker.proof(t, "cred-b", keyID, "a", "b", "c"),
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 without the private key, got %d", resp.StatusCode)
	}
	envs, err := storeEnvelopesFor(t, h, "cred-b")
	if err != nil {
		t.Fatal(err)
	}
	if len(envs) != 0 {
		t.Fatalf("cred-b must not get an envelope: %+v", envs)
	}
}

func TestSignIsSingleUseAndDenyWorks(t *testing.T) {
	h := newTestServer(t)
	seedKey(t, h) // cred-a が鍵を解錠できる状態にする
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
