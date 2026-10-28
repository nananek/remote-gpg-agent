package client

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	rgaproto "github.com/nananek/remote-gpg-agent/internal/protocol"
)

// Transport は署名ループが使う最小の面（テストで差し替える）。
type Transport interface {
	Do(method, path string, body any, out any) error
}

type SignInput struct {
	Purpose     string
	Description string
	Fingerprint string
	Data        []byte
	Timeout     time.Duration
}

// RequestSignature は要求を積み、PWA の承認をロングポールで待つ。
func RequestSignature(ctx context.Context, t Transport, in SignInput) (string, error) {
	var created rgaproto.CreateSignRequestResponse
	if err := t.Do("POST", "/api/v1/requests", rgaproto.CreateSignRequest{
		Purpose:        in.Purpose,
		Description:    in.Description,
		KeyFingerprint: in.Fingerprint,
		TextMode:       true,
		DataB64:        base64.StdEncoding.EncodeToString(in.Data),
	}, &created); err != nil {
		return "", err
	}

	short := created.ID
	if len(short) > 8 {
		short = short[:8]
	}
	fmt.Fprintf(os.Stderr, "rga: PWA の承認待ちです（要求 %s）\n", short)

	deadline := time.Now().Add(in.Timeout)
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		var res rgaproto.SignResult
		if err := t.Do("GET", "/api/v1/requests/"+created.ID, nil, &res); err != nil {
			return "", err
		}
		switch res.Status {
		case "signed":
			if res.SignatureArmored == "" {
				return "", fmt.Errorf("署名が空でした")
			}
			return res.SignatureArmored, nil
		case "denied":
			return "", fmt.Errorf("署名が拒否されました: %s", res.DeniedReason)
		case "expired":
			return "", fmt.Errorf("署名要求が期限切れになりました")
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("承認待ちがタイムアウトしました")
		}
	}
}

// ResolveFingerprint は -u / user.signingkey の値を 40 hex に解決する。
// 40 hex はそのまま、16 hex はサーバ上の鍵一覧から後方一致で探す。
func ResolveFingerprint(t Transport, ref, fallback string) (string, error) {
	if ref == "" {
		ref = fallback
	}
	if ref == "" {
		return "", fmt.Errorf("user.signingkey か config.defaultKeyFingerprint を設定してください")
	}
	ref = strings.ToUpper(strings.TrimSpace(ref))
	if len(ref) == 40 {
		return ref, nil
	}

	var list struct {
		Keys []rgaproto.KeyMeta `json:"keys"`
	}
	if err := t.Do("GET", "/api/v1/keys", nil, &list); err != nil {
		return "", err
	}
	for _, k := range list.Keys {
		if strings.HasSuffix(k.Fingerprint, ref) {
			return k.Fingerprint, nil
		}
	}
	return "", fmt.Errorf("%s に一致する鍵がサーバにありません（PWA で鍵を作成してください）", ref)
}
