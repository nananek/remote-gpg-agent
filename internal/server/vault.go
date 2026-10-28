package server

import (
	"encoding/json"
	"net/http"

	"github.com/nananek/remote-gpg-agent/internal/pgpverify"
	"github.com/nananek/remote-gpg-agent/internal/protocol"
	"github.com/nananek/remote-gpg-agent/internal/store"
)

func (s *Server) registerVaultRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/state", s.handleState)
	mux.HandleFunc("POST /api/v1/keys", s.handleSealKey)
}

// handleState は解錠に必要な材料を 1 回で返す（envelope はログイン中の credential の分だけ）。
func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	credID, err := s.sessionCredential(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	ctx := r.Context()
	recs, err := store.ListCredentials(ctx, s.db)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	keys, err := store.ListKeys(ctx, s.db)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	envs, err := store.ListEnvelopesForCredential(ctx, s.db, credID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	state := protocol.State{
		CredentialID: credID,
		Keys:         keys,
		Envelopes:    envs,
		Credentials:  make([]protocol.CredentialMeta, 0, len(recs)),
	}
	for _, c := range recs {
		state.Credentials = append(state.Credentials, protocol.CredentialMeta{
			CredentialID: c.CredentialID, Label: c.Label,
		})
	}
	for i := range state.Keys {
		state.Keys[i].PublicKeyArmored = "" // 本文は /api/v1/keys/{fpr} で取る
	}
	writeJSON(w, http.StatusOK, state)
}

// handleSealKey は鍵を登録し、ログイン中の credential 用の envelope を 1 つ書く。
func (s *Server) handleSealKey(w http.ResponseWriter, r *http.Request) {
	credID, err := s.sessionCredential(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	var in protocol.SealKeyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	// クライアントが封印した相手と、いま書き込もうとしているセッションが同じかを
	// サーバ側でも確かめる。確認と書き込みの間にセッションが変わっても、
	// 別 credential 用の ciphertext が保存されることはない。
	if in.CredentialID != credID {
		writeError(w, http.StatusBadRequest, "credentialId does not match the session")
		return
	}
	keyID := protocol.KeyIDFromFingerprint(in.Fingerprint)
	if keyID == "" {
		writeError(w, http.StatusBadRequest, "fingerprint must be 40 hex chars")
		return
	}
	if in.PublicKeyArmored == "" || in.CiphertextB64 == "" || in.HKDFSaltB64 == "" || in.IVB64 == "" {
		writeError(w, http.StatusBadRequest, "publicKeyArmored and envelope fields are required")
		return
	}
	if in.Proof == "" {
		writeError(w, http.StatusBadRequest, "proof is required")
		return
	}
	// その鍵の秘密鍵を持っていることの証明。公開鍵の fingerprint が申告値と
	// 一致することもここで確認する（armored と fingerprint の取り違え防止）。
	if err := pgpverify.ArmoredDetached(in.PublicKeyArmored, in.Fingerprint,
		protocol.EnvelopeProofMessage(credID, keyID, in.HKDFSaltB64, in.IVB64, in.CiphertextB64),
		in.Proof,
	); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if in.Label == "" {
		in.Label = "key " + keyID
	}
	if err := store.UpsertKey(r.Context(), s.db,
		protocol.KeyMeta{
			KeyID: keyID, Fingerprint: in.Fingerprint, Label: in.Label,
			PublicKeyArmored: in.PublicKeyArmored,
		},
		protocol.Envelope{
			CredentialID: credID, KeyID: keyID, HKDFSaltB64: in.HKDFSaltB64,
			IVB64: in.IVB64, CiphertextB64: in.CiphertextB64,
		},
	); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"keyId": keyID})
}
