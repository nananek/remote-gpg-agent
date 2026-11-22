package server

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/nananek/remote-gpg-agent/internal/cryptoutil"
	"github.com/nananek/remote-gpg-agent/internal/protocol"
	"github.com/nananek/remote-gpg-agent/internal/store"
)

// pairChallenge は「未認証の参加側」用の登録チャレンジ。通常の登録と
// 取り違えないよう、別の kind で保存し pairingId を束縛する。
type pairChallenge struct {
	Session   webauthn.SessionData `json:"session"`
	PairingID string               `json:"pairingId"`
}

func (s *Server) registerPairingRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/pair/create", s.handlePairCreate)
	mux.HandleFunc("POST /api/v1/pair/join", s.handlePairJoin)
	mux.HandleFunc("GET /api/v1/pair/{id}", s.handlePairStatus)
	mux.HandleFunc("GET /api/v1/pair/{id}/signal", s.handlePairListSignals)
	mux.HandleFunc("POST /api/v1/pair/{id}/signal", s.handlePairSignal)
	mux.HandleFunc("POST /api/v1/pair/{id}/complete", s.handlePairComplete)
	mux.HandleFunc("POST /api/v1/pair/{id}/abort", s.handlePairAbort)
}

// pairingFor はセッションの credential がこの pairing の当事者かを確かめる。
// 参加側の credential は登録が終わるまで空なので、その間は作成側だけが触れる。
func (s *Server) pairingFor(w http.ResponseWriter, r *http.Request) (store.Pairing, string, bool) {
	credID, err := s.sessionCredential(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return store.Pairing{}, "", false
	}
	p, err := store.GetPairing(r.Context(), s.db, r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "unknown or expired pairing")
		return store.Pairing{}, "", false
	}
	switch {
	case credID == p.CreatorCred:
		return p, "creator", true
	case p.JoinerCred != "" && credID == p.JoinerCred:
		return p, "joiner", true
	}
	writeError(w, http.StatusForbidden, "not a pairing participant")
	return store.Pairing{}, "", false
}

func b64urlExact(s string, n int) bool {
	raw, err := cryptoutil.B64URLDecode(s)
	return err == nil && len(raw) == n
}

// handlePairCreate は解錠済みの端末が pairing を開く。ID はクライアントが
// 生成する（QR に埋めるため）。秘密そのものは受け取らず、QR のフラグメントに
// だけ置かれる join 証明のハッシュを預かる。
func (s *Server) handlePairCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	credID, err := s.sessionCredential(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	var in protocol.PairingCreateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if !b64urlExact(in.PairingID, protocol.PairingIDBytes) {
		writeError(w, http.StatusBadRequest, "pairingId must be 16 bytes of base64url")
		return
	}
	if !b64urlExact(in.JoinProof, protocol.PairingProofBytes) {
		writeError(w, http.StatusBadRequest, "joinProof must be a 32-byte hash")
		return
	}
	if s.pairLimiter != nil && !s.pairLimiter.allow(time.Now()) {
		writeError(w, http.StatusTooManyRequests, "too many pairing attempts; retry later")
		return
	}
	p, err := store.CreatePairing(ctx, s.db, in.PairingID, credID, in.JoinProof, s.cfg.PairingTTL)
	if err != nil {
		if errors.Is(err, store.ErrPairingExists) {
			writeError(w, http.StatusConflict, "pairingId already in use")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, protocol.PairingCreateResponse{
		PairingID: p.ID, ExpiresAt: p.ExpiresAt,
	})
}

// handlePairJoin は QR を読んだ端末が、パスキーを作る前の登録 options を取る。
// 認証は join 証明（QR の秘密のハッシュ）だけで、ここでは何も消費しない。
func (s *Server) handlePairJoin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in protocol.PairingJoinRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if !b64urlExact(in.PairingID, protocol.PairingIDBytes) || !b64urlExact(in.JoinProof, protocol.PairingProofBytes) {
		writeError(w, http.StatusBadRequest, "pairingId or joinProof has the wrong shape")
		return
	}
	if s.pairLimiter != nil && !s.pairLimiter.allow(time.Now()) {
		writeError(w, http.StatusTooManyRequests, "too many pairing attempts; retry later")
		return
	}
	p, err := store.GetPairing(ctx, s.db, in.PairingID)
	if err != nil {
		writeError(w, http.StatusNotFound, "unknown or expired pairing")
		return
	}
	if p.State != protocol.PairingCreated {
		writeError(w, http.StatusConflict, "pairing is no longer open")
		return
	}
	if subtle.ConstantTimeCompare([]byte(p.JoinProof), []byte(in.JoinProof)) != 1 {
		writeError(w, http.StatusForbidden, "invalid join proof")
		return
	}
	u, err := s.loadUser(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	creation, session, err := s.registrationOptions(u)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	raw, err := json.Marshal(pairChallenge{Session: *session, PairingID: p.ID})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ceremonyID, err := store.SaveChallenge(ctx, s.db, "pair", raw, 2*time.Minute)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ceremonyId": ceremonyID, "options": creation})
}

func (s *Server) handlePairStatus(w http.ResponseWriter, r *http.Request) {
	p, _, ok := s.pairingFor(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, protocol.PairingStatus{
		State:               p.State,
		CreatorCredentialID: p.CreatorCred,
		JoinerCredentialID:  p.JoinerCred,
		JoinerLabel:         p.JoinerLabel,
		Receipt:             p.Receipt,
		ExpiresAt:           p.ExpiresAt,
	})
}

func (s *Server) handlePairSignal(w http.ResponseWriter, r *http.Request) {
	p, role, ok := s.pairingFor(w, r)
	if !ok {
		return
	}
	var in protocol.PairingSignalRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if !protocol.ValidPairingSignalKind(in.Kind) {
		writeError(w, http.StatusBadRequest, "unknown signal kind")
		return
	}
	raw, err := cryptoutil.B64URLDecode(in.Blob)
	if err != nil || len(raw) == 0 || len(raw) > protocol.MaxPairingSignalBytes {
		writeError(w, http.StatusBadRequest, "signal blob is empty or too large")
		return
	}
	seq, err := store.AppendSignal(r.Context(), s.db, p.ID, role, in.Kind, in.Blob, time.Now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "unknown or expired pairing")
		return
	case errors.Is(err, store.ErrPairingState):
		writeError(w, http.StatusConflict, "pairing is not ready for signaling")
		return
	case errors.Is(err, store.ErrPairingFull):
		writeError(w, http.StatusTooManyRequests, "pairing signaling limit reached")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"seq": seq})
}

func (s *Server) handlePairListSignals(w http.ResponseWriter, r *http.Request) {
	p, _, ok := s.pairingFor(w, r)
	if !ok {
		return
	}
	var after int64
	if v := r.URL.Query().Get("after"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "after must be a non-negative integer")
			return
		}
		after = n
	}
	signals, err := store.ListSignals(r.Context(), s.db, p.ID, after)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, protocol.PairingSignalsResponse{Signals: signals})
}

func (s *Server) handlePairComplete(w http.ResponseWriter, r *http.Request) {
	p, role, ok := s.pairingFor(w, r)
	if !ok {
		return
	}
	if role != "joiner" {
		writeError(w, http.StatusForbidden, "only the joining device can complete")
		return
	}
	var in protocol.PairingCompleteRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if in.Receipt == "" || len(in.Receipt) > 8<<10 {
		writeError(w, http.StatusBadRequest, "receipt has an implausible length")
		return
	}
	if err := store.SetReceipt(r.Context(), s.db, p.ID, p.JoinerCred, in.Receipt); err != nil {
		if errors.Is(err, store.ErrPairingState) || errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusConflict, "pairing is no longer open")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"state": protocol.PairingDelivered})
}

func (s *Server) handlePairAbort(w http.ResponseWriter, r *http.Request) {
	p, _, ok := s.pairingFor(w, r)
	if !ok {
		return
	}
	if err := store.AbortPairing(r.Context(), s.db, p.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "unknown or expired pairing")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
