package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nananek/remote-gpg-agent/internal/protocol"
	"github.com/nananek/remote-gpg-agent/internal/store"
)

func (s *Server) registerPwaRequestRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/requests", s.handlePendingRequests)
	mux.HandleFunc("GET /api/v1/requests/{id}/data", s.handleRequestData)
	mux.HandleFunc("POST /api/v1/requests/{id}/sign", s.handleSign)
	mux.HandleFunc("POST /api/v1/requests/{id}/deny", s.handleDeny)
}

// previewDataB64 は base64 の先頭だけをデコードして、一覧表示用の
// base64 を返す。数十 MB の要求でも全量をデコードしない。
func previewDataB64(dataB64 string, maxBytes int) string {
	if dataB64 == "" || maxBytes <= 0 {
		return ""
	}
	encoded := ((maxBytes + 2) / 3) * 4
	if encoded > len(dataB64) {
		encoded = len(dataB64)
	}
	encoded -= encoded % 4
	raw, err := base64.StdEncoding.DecodeString(dataB64[:encoded])
	if err != nil {
		return ""
	}
	if len(raw) > maxBytes {
		raw = raw[:maxBytes]
	}
	return base64.StdEncoding.EncodeToString(raw)
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
			KeyFingerprint: row.KeyFingerprint, Mode: row.Mode,
			DataSHA256: row.DataSHA256, DataSize: row.DataSize,
			DataPreviewB64: previewDataB64(row.DataB64, 16<<10),
			DataAvailable:  row.DataB64 != "",
			TextMode:       row.TextMode, DigestB64: row.DigestB64, SigMetaB64: row.SigMetaB64,
			Preview: row.Preview, CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, protocol.PendingRequestsResponse{
		Requests:  out,
		ServerNow: time.Now().UTC().Format(time.RFC3339),
	})
}

// handleRequestData は承認時にだけデータ本体を返す。一覧 API に本体を
// 載せると、PWA の 3 秒ポーリングが数十 MB のダウンロードを繰り返してしまう。
func (s *Server) handleRequestData(w http.ResponseWriter, r *http.Request) {
	credID, err := s.sessionCredential(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	id := r.PathValue("id")
	_ = store.ExpireRequest(r.Context(), s.db, id)
	row, err := store.GetRequest(r.Context(), s.db, id)
	if err != nil || row.Status != "pending" || row.DataB64 == "" {
		writeError(w, http.StatusNotFound, "unknown request")
		return
	}
	if !s.credentialCanSign(r, credID, row.KeyFingerprint) {
		writeError(w, http.StatusNotFound, "unknown request")
		return
	}
	w.Header().Set("content-type", "application/octet-stream")
	w.Header().Set("content-length", strconv.Itoa(row.DataSize))
	w.Header().Set("cache-control", "no-store")
	w.Header().Set("x-content-type-options", "nosniff")
	dec := base64.NewDecoder(base64.StdEncoding, strings.NewReader(row.DataB64))
	_, _ = io.Copy(w, dec)
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	credID, err := s.sessionCredential(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	var body struct {
		SignatureArmored string `json:"signatureArmored"`
		SignatureB64     string `json:"signatureB64"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
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
	switch row.Mode {
	case protocol.SignModeDigest:
		raw, err := base64.StdEncoding.DecodeString(body.SignatureB64)
		if err != nil || len(raw) != 64 {
			writeError(w, http.StatusBadRequest, "signatureB64 must be a 64-byte Ed25519 signature")
			return
		}
	case protocol.SignModeData:
		if len(body.SignatureArmored) < 64 || len(body.SignatureArmored) > 200_000 {
			writeError(w, http.StatusBadRequest, "signatureArmored has an implausible length")
			return
		}
	default:
		writeError(w, http.StatusConflict, "request has an unknown mode")
		return
	}
	ok, err := store.CompleteRequest(r.Context(), s.db, id, body.SignatureArmored, body.SignatureB64)
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
