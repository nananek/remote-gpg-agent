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

func (s *Server) handlePendingRequests(w http.ResponseWriter, r *http.Request) {
	if _, err := s.sessionCredential(r); err != nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	rows, err := store.ListPending(r.Context(), s.db)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]protocol.PendingSignRequest, 0, len(rows))
	for _, row := range rows {
		out = append(out, protocol.PendingSignRequest{
			ID: row.ID, Purpose: row.Purpose, Description: row.Description, ClientName: row.ClientName,
			KeyFingerprint: row.KeyFingerprint, DataSHA256: row.DataSHA256, DataSize: row.DataSize,
			DataB64: row.DataB64, TextMode: row.TextMode, CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": out})
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	if _, err := s.sessionCredential(r); err != nil {
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
	ok, err := store.CompleteRequest(r.Context(), s.db, r.PathValue("id"), body.SignatureArmored)
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
	if _, err := s.sessionCredential(r); err != nil {
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
	ok, err := store.DenyRequest(r.Context(), s.db, r.PathValue("id"), body.Reason)
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
