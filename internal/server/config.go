package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"time"
)

type Config struct {
	DataDir      string
	DBPath       string
	WebAddr      string // PWA listener（既定 127.0.0.1:3080）
	ClientAddr   string // mTLS listener（既定 0.0.0.0:8443）
	Origin       string // https://<host>.<tailnet>.ts.net
	RPID         string // <host>.<tailnet>.ts.net
	RPName       string
	TLSCert      string
	TLSKey       string
	TLSCA        string
	BootstrapToken string
	VAPIDSubject string
	VAPIDPublic  string
	VAPIDPrivate string
	PollInterval time.Duration
	PollDeadline time.Duration
	RequestTTL   time.Duration
}

func Load() (*Config, error) {
	get := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	c := &Config{
		DataDir:        get("RGA_DATA_DIR", "data"),
		WebAddr:        get("RGA_WEB_ADDR", "127.0.0.1:3080"),
		ClientAddr:     get("RGA_CLIENT_ADDR", "0.0.0.0:8443"),
		Origin:         os.Getenv("RGA_ORIGIN"),
		RPID:           os.Getenv("RGA_RPID"),
		RPName:         get("RGA_RP_NAME", "remote-gpg-agent"),
		TLSCert:        os.Getenv("RGA_TLS_CERT"),
		TLSKey:         os.Getenv("RGA_TLS_KEY"),
		TLSCA:          os.Getenv("RGA_TLS_CA"),
		BootstrapToken: os.Getenv("RGA_BOOTSTRAP_TOKEN"),
		VAPIDSubject:   get("RGA_VAPID_SUBJECT", "mailto:admin@example.com"),
		VAPIDPublic:    os.Getenv("RGA_VAPID_PUBLIC"),
		VAPIDPrivate:   os.Getenv("RGA_VAPID_PRIVATE"),
		PollInterval:   time.Second,
		PollDeadline:   50 * time.Second,
		RequestTTL:     300 * time.Second,
	}
	c.DBPath = get("RGA_DB", c.DataDir+"/rga.db")
	if c.Origin == "" || c.RPID == "" {
		return nil, fmt.Errorf("RGA_ORIGIN and RGA_RPID are required")
	}
	if c.TLSCert == "" || c.TLSKey == "" || c.TLSCA == "" {
		return nil, fmt.Errorf("RGA_TLS_CERT, RGA_TLS_KEY and RGA_TLS_CA are required")
	}
	if c.VAPIDPublic == "" || c.VAPIDPrivate == "" {
		return nil, fmt.Errorf("RGA_VAPID_PUBLIC and RGA_VAPID_PRIVATE are required")
	}
	if c.BootstrapToken == "" {
		b := make([]byte, 24)
		_, _ = rand.Read(b)
		c.BootstrapToken = base64.RawURLEncoding.EncodeToString(b)
		fmt.Fprintf(os.Stderr, "rga-server: generated bootstrap token: %s\n", c.BootstrapToken)
	}
	return c, nil
}
