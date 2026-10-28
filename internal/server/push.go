package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/SherClockHolmes/webpush-go"

	"github.com/nananek/remote-gpg-agent/internal/store"
)

type vapidKeys struct{ subject, public, private string }

// sendPush はテストで差し替える。返り値は HTTP ステータス。
var sendPush = func(ctx context.Context, payload []byte, sub *webpush.Subscription, o *webpush.Options) (int, error) {
	resp, err := webpush.SendNotificationWithContext(ctx, payload, sub, o)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

func (s *Server) notifyPush(row *store.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	subs, err := store.ListPushSubscriptions(ctx, s.db)
	if err != nil {
		return
	}
	payload, err := json.Marshal(map[string]string{
		"title": "署名の承認待ち",
		"body":  row.Description,
		"id":    row.ID,
	})
	if err != nil {
		return
	}
	for _, sub := range subs {
		code, err := sendPush(ctx, payload,
			&webpush.Subscription{
				Endpoint: sub.Endpoint,
				Keys:     webpush.Keys{P256dh: sub.P256dh, Auth: sub.Auth},
			},
			&webpush.Options{
				Subscriber:      s.vapid.subject,
				VAPIDPublicKey:  s.vapid.public,
				VAPIDPrivateKey: s.vapid.private,
				TTL:             300,
			})
		if err != nil || code == http.StatusNotFound || code == http.StatusGone {
			_ = store.DeletePushSubscription(ctx, s.db, sub.Endpoint)
		}
	}
}

func (s *Server) handleVapidPublicKey(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"publicKey": s.vapid.public})
}

func (s *Server) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	credID, err := s.sessionCredential(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	var in struct {
		Endpoint string `json:"endpoint"`
		P256dh   string `json:"p256dh"`
		Auth     string `json:"auth"`
		Label    string `json:"label"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if !strings.HasPrefix(in.Endpoint, "https://") || in.P256dh == "" || in.Auth == "" {
		writeError(w, http.StatusBadRequest, "endpoint, p256dh and auth are required")
		return
	}
	if err := store.UpsertPushSubscription(r.Context(), s.db, store.PushSubscription{
		Endpoint: in.Endpoint, CredentialID: credID, P256dh: in.P256dh, Auth: in.Auth, Label: in.Label,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
