package server

import (
	"encoding/json"
	"net/http"

	"github.com/nananek/remote-gpg-agent/internal/protocol"
	"github.com/nananek/remote-gpg-agent/internal/store"
)

func (s *Server) registerPwaRequestRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/requests", s.handlePendingRequests)
	mux.HandleFunc("POST /api/v1/requests/{id}/sign", s.handleSign)
	mux.HandleFunc("POST /api/v1/requests/{id}/deny", s.handleDeny)
}

// credentialCanSign は、セッションの credential がその fingerprint の鍵を
// 解錠できるか（= その鍵の envelope を持っているか）を返す。
// 署名要求のペイロードは鍵の持ち主だけに見せる。
func (s *Server) credentialCanSign(r *http.Request, credID, fingerprint string) bool {
	keyID := protocol.KeyIDFromFingerprint(fingerprint)
	if keyID == "" {
		return false
	}
	ids, err := store.KeyIDsForCredential(r.Context(), s.db, credID)
	if err != nil {
		return false
	}
	return ids[keyID]
}

func (s *Server) handlePendingRequests(w http.ResponseWriter, r *http.Request) {
	credID, err := s.sessionCredential(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	allowed, err := store.KeyIDsForCredential(r.Context(), s.db, credID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rows, err := store.ListPending(r.Context(), s.db)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]protocol.PendingSignRequest, 0, len(rows))
	for _, row := range rows {
		if !allowed[protocol.KeyIDFromFingerprint(row.KeyFingerprint)] {
			continue
		}
		out = append(out, protocol.PendingSignRequest{
			ID: row.ID, Purpose: row.Purpose, Description: row.Description, ClientName: row.ClientName,
			KeyFingerprint: row.KeyFingerprint, DataSHA256: row.DataSHA256, DataSize: row.DataSize,
			DataB64: row.DataB64, TextMode: row.TextMode, CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": out})
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	credID, err := s.sessionCredential(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	var body struct {
		SignatureArmored string `json:"signatureArmored"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if len(body.SignatureArmored) < 64 || len(body.SignatureArmored) > 200_000 {
		writeError(w, http.StatusBadRequest, "signatureArmored has an implausible length")
		return
	}
	id := r.PathValue("id")
	row, err := store.GetRequest(r.Context(), s.db, id)
	if err != nil {
		writeError(w, http.StatusNotFound, "unknown request")
		return
	}
	if !s.credentialCanSign(r, credID, row.KeyFingerprint) {
		writeError(w, http.StatusNotFound, "unknown request")
		return
	}
	ok, err := store.CompleteRequest(r.Context(), s.db, id, body.SignatureArmored)
	if err != nil {
		writeError(w, http.StatusNotFound, "unknown request")
		return
	}
	if !ok {
		writeError(w, http.StatusConflict, "request is not pending")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleDeny(w http.ResponseWriter, r *http.Request) {
	credID, err := s.sessionCredential(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body)
	if body.Reason == "" {
		body.Reason = "denied"
	}
	id := r.PathValue("id")
	row, err := store.GetRequest(r.Context(), s.db, id)
	if err != nil {
		writeError(w, http.StatusNotFound, "unknown request")
		return
	}
	if !s.credentialCanSign(r, credID, row.KeyFingerprint) {
		writeError(w, http.StatusNotFound, "unknown request")
		return
	}
	ok, err := store.DenyRequest(r.Context(), s.db, id, body.Reason)
	if err != nil {
		writeError(w, http.StatusNotFound, "unknown request")
		return
	}
	if !ok {
		writeError(w, http.StatusConflict, "request is not pending")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
