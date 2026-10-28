package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/SherClockHolmes/webpush-go"

	"github.com/nananek/remote-gpg-agent/internal/protocol"
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

var discordHTTPClient = &http.Client{Timeout: 10 * time.Second}

// sendDiscord はテストで差し替える。返り値は HTTP ステータス。
var sendDiscord = func(ctx context.Context, webhook string, payload []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("content-type", "application/json")
	resp, err := discordHTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

func (s *Server) pushOptions() *webpush.Options {
	return &webpush.Options{
		Subscriber:      s.vapid.subject,
		VAPIDPublicKey:  s.vapid.public,
		VAPIDPrivateKey: s.vapid.private,
		TTL:             300,
	}
}

func (s *Server) sendWebPush(ctx context.Context, sub store.PushSubscription, payload []byte) (int, error) {
	return sendPush(ctx, payload,
		&webpush.Subscription{
			Endpoint: sub.Endpoint,
			Keys:     webpush.Keys{P256dh: sub.P256dh, Auth: sub.Auth},
		},
		s.pushOptions())
}

func (s *Server) notifyPush(row *store.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	subs, err := store.ListPushSubscriptions(ctx, s.db)
	if err != nil {
		return
	}
	keyID := protocol.KeyIDFromFingerprint(row.KeyFingerprint)
	if keyID == "" {
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
		// 解錠できない鍵の要求を、その credential の端末へ知らせない。
		// 可視範囲は /api/v1/requests と同じ（envelope の有無）に揃える。
		keys, err := store.KeyIDsForCredential(ctx, s.db, sub.CredentialID)
		if err != nil || !keys[keyID] {
			continue
		}
		code, err := s.sendWebPush(ctx, sub, payload)
		if err != nil || code == http.StatusNotFound || code == http.StatusGone {
			_ = store.DeletePushSubscription(ctx, s.db, sub.Endpoint)
		}
	}
}

// notifyDiscord は署名要求を Discord の webhook にも流す。Web Push が
// 届かない環境 (集中モード / PWA を閉じている等) の控えとして使う。
// webhook は環境変数 RGA_DISCORD_WEBHOOK で設定する。未設定なら何もしない。
func (s *Server) notifyDiscord(row *store.Request) {
	if s.cfg.DiscordWebhook == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	payload, err := json.Marshal(map[string]any{
		"content": "署名の承認待ち",
		"embeds": []map[string]any{{
			"title":       "署名の承認待ち",
			"description": row.Description,
			"url":         strings.TrimRight(s.cfg.Origin, "/") + "/",
			"color":       0x2f6feb,
			"fields": []map[string]any{
				{"name": "purpose", "value": row.Purpose, "inline": true},
				{"name": "client", "value": row.ClientName, "inline": true},
				{"name": "key", "value": row.KeyFingerprint, "inline": false},
			},
			"footer":    map[string]string{"text": "remote-gpg-agent"},
			"timestamp": row.CreatedAt,
		}},
		"allowed_mentions": map[string]any{"parse": []string{}},
	})
	if err != nil {
		return
	}
	code, err := sendDiscord(ctx, s.cfg.DiscordWebhook, payload)
	if err != nil || code >= 300 {
		s.log.Warn("discord notification failed", "status", code, "err", err)
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

func (s *Server) handlePushStatus(w http.ResponseWriter, r *http.Request) {
	credID, err := s.sessionCredential(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	subs, err := store.ListPushSubscriptionsForCredential(r.Context(), s.db, credID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{
		"webpush": len(subs) > 0,
		"discord": s.cfg.DiscordWebhook != "",
	})
}

// handleUnsubscribe はその credential の Web Push 購読を全部消す。
// ブラウザ側の PushSubscription.unsubscribe() とセットで呼ぶ。
func (s *Server) handleUnsubscribe(w http.ResponseWriter, r *http.Request) {
	credID, err := s.sessionCredential(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	if err := store.DeletePushSubscriptionsForCredential(r.Context(), s.db, credID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func testPushPayload() []byte {
	b, _ := json.Marshal(map[string]string{
		"title": "remote-gpg-agent テスト",
		"body":  "通知は届いています。",
		"id":    "test",
	})
	return b
}

// handleTestNotification は通知経路の疎通確認。channel は webpush / discord。
func (s *Server) handleTestNotification(w http.ResponseWriter, r *http.Request) {
	credID, err := s.sessionCredential(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	var in struct {
		Channel string `json:"channel"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	switch in.Channel {
	case "webpush":
		subs, err := store.ListPushSubscriptionsForCredential(r.Context(), s.db, credID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if len(subs) == 0 {
			writeError(w, http.StatusConflict, "Web Push の購読がありません")
			return
		}
		sent := 0
		for _, sub := range subs {
			code, err := s.sendWebPush(r.Context(), sub, testPushPayload())
			if err != nil {
				continue
			}
			if code == http.StatusNotFound || code == http.StatusGone {
				_ = store.DeletePushSubscription(r.Context(), s.db, sub.Endpoint)
				continue
			}
			if code < 300 {
				sent++
			}
		}
		if sent == 0 {
			writeError(w, http.StatusBadGateway, "Web Push の送信に失敗しました")
			return
		}
		writeJSON(w, http.StatusOK, map[string]int{"sent": sent})

	case "discord":
		if s.cfg.DiscordWebhook == "" {
			writeError(w, http.StatusConflict, "RGA_DISCORD_WEBHOOK が未設定です")
			return
		}
		payload, _ := json.Marshal(map[string]any{
			"content":          "remote-gpg-agent のテスト通知です。",
			"allowed_mentions": map[string]any{"parse": []string{}},
		})
		code, err := sendDiscord(r.Context(), s.cfg.DiscordWebhook, payload)
		if err != nil || code >= 300 {
			writeError(w, http.StatusBadGateway, "Discord への送信に失敗しました")
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})

	default:
		writeError(w, http.StatusBadRequest, "channel must be webpush or discord")
	}
}
