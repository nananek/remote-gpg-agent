package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/nananek/remote-gpg-agent/internal/protocol"
	"github.com/nananek/remote-gpg-agent/internal/store"
)

func (s *Server) clientHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mode": "client"})
	})
	mux.HandleFunc("POST /api/v1/requests", s.handleCreateRequest)
	mux.HandleFunc("GET /api/v1/requests/{id}", s.handlePollRequest)
	mux.HandleFunc("GET /api/v1/keys", s.handleListKeys)
	mux.HandleFunc("GET /api/v1/keys/{fpr}", s.handleGetKey)
	return mux
}

func clientName(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "unknown"
	}
	if cn := r.TLS.PeerCertificates[0].Subject.CommonName; cn != "" {
		return cn
	}
	return "unknown"
}

func (s *Server) handleCreateRequest(w http.ResponseWriter, r *http.Request) {
	var in protocol.CreateSignRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512<<20)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if protocol.KeyIDFromFingerprint(in.KeyFingerprint) == "" {
		writeError(w, http.StatusBadRequest, "keyFingerprint must be 40 hex chars")
		return
	}
	if in.Purpose == "" || in.Description == "" || in.DataB64 == "" {
		writeError(w, http.StatusBadRequest, "purpose, description and dataB64 are required")
		return
	}
	row, err := store.CreateRequest(r.Context(), s.db, store.NewRequestInput{
		Purpose: in.Purpose, Description: in.Description, ClientName: clientName(r),
		KeyFingerprint: in.KeyFingerprint, DataB64: in.DataB64, TextMode: in.TextMode,
	}, s.cfg.RequestTTL)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	go s.notifyPush(row)
	go s.notifyDiscord(row)
	writeJSON(w, http.StatusCreated, protocol.CreateSignRequestResponse{ID: row.ID, ExpiresAt: row.ExpiresAt})
}

func (s *Server) handlePollRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	deadline := time.Now().Add(s.cfg.PollDeadline)
	for {
		// 期限切れをポーリング中にも反映する。GetRequest は状態を変えないため、
		// ここで落とさないと期限後も pending を返し続ける。
		_ = store.ExpireRequest(r.Context(), s.db, id)
		row, err := store.GetRequest(r.Context(), s.db, id)
		if err != nil {
			writeError(w, http.StatusNotFound, "unknown request")
			return
		}
		if row.Status != "pending" {
			writeJSON(w, http.StatusOK, protocol.SignResult{
				Status: row.Status, SignatureArmored: row.SignatureArmored, DeniedReason: row.DeniedReason,
			})
			return
		}
		if time.Now().After(deadline) {
			writeJSON(w, http.StatusOK, protocol.SignResult{Status: "pending"})
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(s.cfg.PollInterval):
		}
	}
}

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := store.ListKeys(r.Context(), s.db)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for i := range keys {
		keys[i].PublicKeyArmored = ""
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

func (s *Server) handleGetKey(w http.ResponseWriter, r *http.Request) {
	k, err := store.GetKeyByFingerprint(r.Context(), s.db, r.PathValue("fpr"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "unknown key")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, k)
}
