package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/nananek/remote-gpg-agent/internal/cryptoutil"
	rgaproto "github.com/nananek/remote-gpg-agent/internal/protocol"
	"github.com/nananek/remote-gpg-agent/internal/store"
)

// userRecord は単一ユーザー（自分）を表す。credential は N 個あり得る。
type userRecord struct {
	id    []byte
	creds []webauthn.Credential
}

func (u userRecord) WebAuthnID() []byte                         { return u.id }
func (u userRecord) WebAuthnName() string                       { return "rga-user" }
func (u userRecord) WebAuthnDisplayName() string                { return "remote-gpg-agent" }
func (u userRecord) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (s *Server) loadUser(ctx context.Context) (userRecord, error) {
	recs, err := store.ListCredentials(ctx, s.db)
	if err != nil {
		return userRecord{}, err
	}
	u := userRecord{id: []byte("rga-user")}
	for _, r := range recs {
		u.creds = append(u.creds, r.Record)
	}
	return u, nil
}

func (s *Server) registerAuthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/register/options", s.handleRegisterOptions)
	mux.HandleFunc("POST /api/v1/auth/register/verify", s.handleRegisterVerify)
	mux.HandleFunc("POST /api/v1/auth/login/options", s.handleLoginOptions)
	mux.HandleFunc("POST /api/v1/auth/login/verify", s.handleLoginVerify)
	mux.HandleFunc("POST /api/v1/auth/logout", s.handleLogout)
	mux.HandleFunc("GET /api/v1/auth/me", s.handleMe)
}

func (s *Server) handleRegisterOptions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	recs, err := store.ListCredentials(ctx, s.db)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(recs) == 0 {
		if r.Header.Get("X-RGA-Bootstrap") != s.cfg.BootstrapToken {
			writeError(w, http.StatusUnauthorized, "bootstrap token required")
			return
		}
	} else if _, err := s.sessionCredential(r); err != nil {
		writeError(w, http.StatusUnauthorized, "session required")
		return
	}

	u, err := s.loadUser(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	excl := make([]protocol.CredentialDescriptor, 0, len(u.creds))
	for _, c := range u.creds {
		excl = append(excl, protocol.CredentialDescriptor{Type: "public-key", CredentialID: c.ID})
	}

	creation, session, err := s.wa.BeginRegistration(u,
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(excl),
		// PRF が使えるかを登録時に問い、さらに salt を渡して評価させる。
		// salt を渡さないと認証器は PRF 出力を返さず、封印鍵を作れない。
		webauthn.WithExtensions(
			webauthn.WithExtensionPRFSupport(),
			webauthn.WithExtensionPRF(protocol.PRFValues{First: protocol.URLEncodedBase64(PRFSalt)}),
		),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	raw, err := json.Marshal(session)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ceremonyID, err := store.SaveChallenge(ctx, s.db, "register", raw, 2*time.Minute)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ceremonyId": ceremonyID, "options": creation})
}

type registerVerifyBody struct {
	CeremonyID string                    `json:"ceremonyId"`
	Response   json.RawMessage           `json:"response"`
	Label      string                    `json:"label"`
	Envelopes  []rgaproto.SealedEnvelope `json:"envelopes"`
}

func (s *Server) handleRegisterVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var body registerVerifyBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	raw, err := store.TakeChallenge(ctx, s.db, body.CeremonyID, "register")
	if err != nil {
		writeError(w, http.StatusBadRequest, "unknown or expired challenge")
		return
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(raw, &session); err != nil {
		writeError(w, http.StatusBadRequest, "corrupt challenge")
		return
	}
	u, err := s.loadUser(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// go-webauthn は *http.Request の body を読むので、credential JSON だけの要求を作り直す。
	sub := r.Clone(ctx)
	sub.Body = io.NopCloser(bytes.NewReader(body.Response))

	cred, err := s.wa.FinishRegistration(u, session, sub)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if cred.Extensions.PRFEnabled == nil || !*cred.Extensions.PRFEnabled {
		writeError(w, http.StatusBadRequest,
			"この認証器は PRF 非対応です（iOS 18.4+ / iCloud キーチェーンのパスキーが必要）")
		return
	}

	credID := cryptoutil.B64URL(cred.ID)
	label := body.Label
	if label == "" {
		label = fmt.Sprintf("パスキー %d", len(u.creds)+1)
	}

	if curCred, sessErr := s.sessionCredential(r); sessErr == nil {
		// 追加パスキー: いま解錠中の鍵を全て再封印してもらう。
		required, err := store.KeyIDsForCredential(ctx, s.db, curCred)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		got := map[string]bool{}
		for _, e := range body.Envelopes {
			if got[e.KeyID] {
				writeError(w, http.StatusBadRequest, "duplicate envelope for key "+e.KeyID)
				return
			}
			got[e.KeyID] = true
		}
		if len(required) != len(got) {
			writeError(w, http.StatusBadRequest, "envelopes must cover every unlocked key")
			return
		}
		for k := range required {
			if !got[k] {
				writeError(w, http.StatusBadRequest, "missing envelope for key "+k)
				return
			}
		}
	} else if len(body.Envelopes) != 0 {
		writeError(w, http.StatusBadRequest, "the first passkey must not carry envelopes")
		return
	}

	if err := store.InsertCredential(ctx, s.db, store.CredentialRecord{
		CredentialID: credID, Label: label, PRFEnabled: true, Record: *cred,
	}); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	for _, e := range body.Envelopes {
		if err := store.AttachEnvelope(ctx, s.db, rgaproto.Envelope{
			CredentialID: credID, KeyID: e.KeyID, HKDFSaltB64: e.HKDFSaltB64,
			IVB64: e.IVB64, CiphertextB64: e.CiphertextB64,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	sid, err := store.CreateSession(ctx, s.db, credID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.setSessionCookie(w, sid)
	writeJSON(w, http.StatusOK, map[string]string{"credentialId": credID})
}

func (s *Server) handleLoginOptions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	recs, err := store.ListCredentials(ctx, s.db)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(recs) == 0 {
		writeError(w, http.StatusConflict, "no passkey registered")
		return
	}
	u, err := s.loadUser(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	allow := make([]protocol.CredentialDescriptor, 0, len(recs))
	for _, c := range recs {
		allow = append(allow, protocol.CredentialDescriptor{
			Type: "public-key", CredentialID: c.Record.ID, Transport: c.Record.Transport,
		})
	}
	assertion, session, err := s.wa.BeginLogin(u,
		webauthn.WithAllowedCredentials(allow),
		webauthn.WithUserVerification(protocol.VerificationRequired),
		// PRF の評価をサーバから要求する（salt はサーバが持つ）。
		webauthn.WithAssertionExtensions(webauthn.WithExtensionPRF(protocol.PRFValues{
			First: protocol.URLEncodedBase64(PRFSalt),
		})),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	raw, err := json.Marshal(session)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ceremonyID, err := store.SaveChallenge(ctx, s.db, "login", raw, 2*time.Minute)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ceremonyId": ceremonyID, "options": assertion})
}

func (s *Server) handleLoginVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var body struct {
		CeremonyID string          `json:"ceremonyId"`
		Response   json.RawMessage `json:"response"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	raw, err := store.TakeChallenge(ctx, s.db, body.CeremonyID, "login")
	if err != nil {
		writeError(w, http.StatusBadRequest, "unknown or expired challenge")
		return
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(raw, &session); err != nil {
		writeError(w, http.StatusBadRequest, "corrupt challenge")
		return
	}
	u, err := s.loadUser(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sub := r.Clone(ctx)
	sub.Body = io.NopCloser(bytes.NewReader(body.Response))

	cred, err := s.wa.FinishLogin(u, session, sub)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	credID := cryptoutil.B64URL(cred.ID)
	if rec, err := store.GetCredential(ctx, s.db, credID); err == nil {
		rec.Record = *cred // signCount / flags を書き戻す
		_ = store.UpdateCredentialRecord(ctx, s.db, rec)
	}
	sid, err := store.CreateSession(ctx, s.db, credID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.setSessionCookie(w, sid)
	writeJSON(w, http.StatusOK, map[string]string{"credentialId": credID})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	recs, err := store.ListCredentials(ctx, s.db)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := map[string]any{"authenticated": false, "credentialCount": len(recs)}
	if credID, err := s.sessionCredential(r); err == nil {
		out["authenticated"] = true
		out["credentialId"] = credID
		if envs, _ := store.ListEnvelopesForCredential(ctx, s.db, credID); len(envs) > 0 {
			out["hasVault"] = true
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(store.SessionCookie); err == nil {
		_ = store.DeleteSession(r.Context(), s.db, c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: store.SessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
