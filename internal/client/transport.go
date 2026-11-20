package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Client は mTLS でサーバに繋ぐ薄いクライアント。
type Client struct {
	base string
	http *http.Client
}

// New は mTLS の http.Client を作る。ServerFingerprintSHA256 が設定されていれば
// サーバ証明書のピン留めも行う。
func New(cfg *Config) (*Client, error) {
	cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("クライアント証明書: %w", err)
	}
	pem, err := os.ReadFile(cfg.CACert)
	if err != nil {
		return nil, fmt.Errorf("CA 証明書: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("CA 証明書を読めません")
	}

	want := strings.ToUpper(strings.ReplaceAll(cfg.ServerFingerprintSHA256, ":", ""))
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if want == "" {
				return nil
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if got := strings.ToUpper(hex.EncodeToString(sum[:])); got != want {
				return fmt.Errorf("サーバ証明書のピンが一致しません: %s", got)
			}
			return nil
		},
	}}
	// timeout は Do の中で method ごとに決める。http.Client 全体に 70 秒を
	// 掛けると、大きいデータのアップロードが承認待ちに入る前に切れてしまう。
	return &Client{base: cfg.URL, http: &http.Client{Transport: tr}}, nil
}

// Do は JSON を送って JSON を受ける。out が nil なら本文は捨てる。
func (c *Client) Do(method, path string, body any, out any) error {
	var rdr *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		// strings.NewReader(string(raw)) は大きい JSON をもう一度コピーする。
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")

	// GET は server の long-poll（50 秒）より少し長く、書き込みは
	// 大きいデータを送れるように長めにする。
	timeout := 10 * time.Minute
	if method == http.MethodGet {
		timeout = 70 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return fmt.Errorf("サーバが %d を返しました: %s", resp.StatusCode, e.Error)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
