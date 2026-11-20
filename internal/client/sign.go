package client

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
//
// 通常は digest モード: client が OpenPGP の署名対象 digest を計算し、
// PWA にはその digest だけを送る。データ本体は server に送らないので、
// 大きいパッケージでも通信量と bbolt の使用量が増えない。
func RequestSignature(ctx context.Context, t Transport, in SignInput) (string, error) {
	meta, err := BuildSigMeta(in.Fingerprint, time.Now())
	if err != nil {
		return "", err
	}
	digest := SignedDigest(in.Data, meta)
	dataSHA := sha256.Sum256(in.Data)

	req := rgaproto.CreateSignRequest{
		Purpose:        in.Purpose,
		Description:    in.Description,
		KeyFingerprint: in.Fingerprint,
		Mode:           rgaproto.SignModeDigest,
		TimeoutSec:     int(in.Timeout / time.Second),
		DigestB64:      base64.StdEncoding.EncodeToString(digest),
		SigMetaB64:     base64.StdEncoding.EncodeToString(meta),
		DataSHA256:     hex.EncodeToString(dataSHA[:]),
		DataSize:       len(in.Data),
		Preview:        in.Description,
	}
	// 小さいデータは PWA が内容と digest の対応を検証できるように同梱する。
	// 大きいデータは送らない（PWA には digest だけが届く）。
	if len(in.Data) <= smallDataLimit {
		req.DataB64 = base64.StdEncoding.EncodeToString(in.Data)
	}

	var created rgaproto.CreateSignRequestResponse
	if err := t.Do("POST", "/api/v1/requests", req, &created); err != nil {
		return "", err
	}

	short := created.ID
	if len(short) > 8 {
		short = short[:8]
	}
	fmt.Fprintf(os.Stderr, "rga: PWA の承認待ちです（要求 %s）\n", short)

	deadline := time.Now().Add(in.Timeout)
	if when, err := time.Parse(time.RFC3339, created.ExpiresAt); err == nil {
		// server の寿命を優先する。client の timeout より server が先に
		// 切れる設定でも、期限の意味がずれない。
		if when.Before(deadline) {
			deadline = when
		}
	}
	cancel := func() {
		// 待つのをやめた要求を PWA の一覧に残さない。
		_ = t.Do("POST", "/api/v1/requests/"+created.ID+"/cancel", nil, nil)
	}

	for {
		select {
		case <-ctx.Done():
			cancel()
			return "", ctx.Err()
		default:
		}

		var res rgaproto.SignResult
		if err := t.Do("GET", "/api/v1/requests/"+created.ID, nil, &res); err != nil {
			return "", err
		}
		switch res.Status {
		case "signed":
			if res.SignatureB64 != "" {
				raw, err := base64.StdEncoding.DecodeString(res.SignatureB64)
				if err != nil {
					return "", fmt.Errorf("署名をデコードできません: %w", err)
				}
				return ArmoredSignature(meta, digest, raw)
			}
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
			cancel()
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
	// gpg の `--local-user FPR!` は「subkey を選ばず primary に固定」の
	// 指示。rga は fingerprint から鍵を引くだけなので `!` は落とす。
	ref = strings.TrimSuffix(strings.ToUpper(strings.TrimSpace(ref)), "!")
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
