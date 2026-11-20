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
	mux.HandleFunc("POST /api/v1/requests/{id}/cancel", s.handleCancelRequest)
	mux.HandleFunc("GET /api/v1/keys", s.handleListKeys)
	mux.HandleFunc("GET /api/v1/keys/{fpr}", s.handleGetKey)
	return mux
}

// handleCancelRequest は client が待つのをやめたときに、PWA の承認待ちから
// 要求を外す。放置すると、client がいない要求を後から承認できてしまう。
func (s *Server) handleCancelRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	row, err := store.GetRequest(r.Context(), s.db, id)
	if err != nil || row.ClientName != clientName(r) {
		writeError(w, http.StatusNotFound, "unknown request")
		return
	}
	if row.Status != "pending" {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	ok, err := store.DenyRequest(r.Context(), s.db, id, "client canceled")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusConflict, "request is not pending")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
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
	mode := in.Mode
	if mode == "" {
		mode = protocol.SignModeData
	}
	switch mode {
	case protocol.SignModeData:
		if in.DataB64 == "" {
			writeError(w, http.StatusBadRequest, "dataB64 is required in data mode")
			return
		}
	case protocol.SignModeDigest:
		if in.DigestB64 == "" || in.SigMetaB64 == "" {
			writeError(w, http.StatusBadRequest, "digestB64 and sigMetaB64 are required in digest mode")
			return
		}
	default:
		writeError(w, http.StatusBadRequest, "mode must be digest or data")
		return
	}
	if in.Purpose == "" || in.Description == "" {
		writeError(w, http.StatusBadRequest, "purpose and description are required")
		return
	}
	if in.DataSize < 0 || len(in.SigMetaB64) > 64<<10 {
		writeError(w, http.StatusBadRequest, "request metadata is invalid")
		return
	}

	row, err := store.CreateRequest(r.Context(), s.db, store.NewRequestInput{
		Purpose: in.Purpose, Description: in.Description, ClientName: clientName(r),
		KeyFingerprint: in.KeyFingerprint, Mode: mode,
		DataB64: in.DataB64, DataSHA256: in.DataSHA256, DataSize: in.DataSize,
		DigestB64: in.DigestB64, SigMetaB64: in.SigMetaB64, Preview: in.Preview,
		TextMode: in.TextMode,
	}, s.requestTTL(in.TimeoutSec))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	go s.notifyPush(row)
	go s.notifyDiscord(row)
	writeJSON(w, http.StatusCreated, protocol.CreateSignRequestResponse{
		ID: row.ID, ExpiresAt: row.ExpiresAt, Mode: row.Mode,
	})
}

// requestTTL は client の待ち時間に余裕を足した要求の寿命を返す。
// client と server の設定が食い違っても、server が先に失効しないようにする。
func (s *Server) requestTTL(clientTimeoutSec int) time.Duration {
	ttl := s.cfg.RequestTTL
	if clientTimeoutSec <= 0 {
		return ttl
	}
	if clientTimeoutSec > protocol.MaxClientTimeoutSec {
		clientTimeoutSec = protocol.MaxClientTimeoutSec
	}
	requested := time.Duration(clientTimeoutSec+protocol.RequestTTLGraceSec) * time.Second
	if requested > ttl {
		ttl = requested
	}
	return ttl
}

func (s *Server) handlePollRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	deadline := time.Now().Add(s.cfg.PollDeadline)
	for {
		// 期限切れをポーリング中にも反映する。GetRequest は状態を変えないため、
		// ここで落とさないと期限後も pending を返し続ける。
		_ = store.ExpireRequest(r.Context(), s.db, id)
		row, err := store.GetRequest(r.Context(), s.db, id)
		if err != nil || row.ClientName != clientName(r) {
			writeError(w, http.StatusNotFound, "unknown request")
			return
		}
		if row.Status != "pending" {
			writeJSON(w, http.StatusOK, protocol.SignResult{
				Status: row.Status, Mode: row.Mode,
				SignatureArmored: row.SignatureArmored, SignatureB64: row.SignatureB64,
				DeniedReason: row.DeniedReason,
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
