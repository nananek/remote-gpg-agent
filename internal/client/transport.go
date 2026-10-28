package client

import (
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
	return &Client{base: cfg.URL, http: &http.Client{Transport: tr, Timeout: 70 * time.Second}}, nil
}

// Do は JSON を送って JSON を受ける。out が nil なら本文は捨てる。
func (c *Client) Do(method, path string, body any, out any) error {
	var rdr *strings.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = strings.NewReader(string(raw))
	} else {
		rdr = strings.NewReader("")
	}
	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")

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
