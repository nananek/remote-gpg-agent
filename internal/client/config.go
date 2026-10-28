package client

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	URL                     string `json:"url"`
	CACert                  string `json:"caCert"`
	ClientCert              string `json:"clientCert"`
	ClientKey               string `json:"clientKey"`
	ServerFingerprintSHA256 string `json:"serverFingerprintSHA256"`
	DefaultKeyFingerprint   string `json:"defaultKeyFingerprint"`
	TimeoutSec              int    `json:"timeoutSec"`
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

func parseConfig(raw []byte) (*Config, error) {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(c.URL, "https://") {
		return nil, errors.New("config.url must start with https://")
	}
	for name, v := range map[string]string{
		"caCert": c.CACert, "clientCert": c.ClientCert, "clientKey": c.ClientKey,
	} {
		if v == "" {
			return nil, errors.New("config." + name + " is required")
		}
	}
	if c.DefaultKeyFingerprint != "" && len(c.DefaultKeyFingerprint) != 40 {
		return nil, errors.New("config.defaultKeyFingerprint must be 40 hex chars")
	}
	if c.TimeoutSec <= 0 {
		c.TimeoutSec = 180
	}
	c.CACert, c.ClientCert, c.ClientKey = expandHome(c.CACert), expandHome(c.ClientCert), expandHome(c.ClientKey)
	c.DefaultKeyFingerprint = strings.ToUpper(c.DefaultKeyFingerprint)
	c.URL = strings.TrimRight(c.URL, "/")
	return &c, nil
}

// LoadConfig は RGA_CONFIG か ~/.config/remote-gpg-agent/config.json を読む。
func LoadConfig() (*Config, error) {
	path := os.Getenv("RGA_CONFIG")
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(home, ".config/remote-gpg-agent/config.json")
	}
	raw, err := os.ReadFile(expandHome(path))
	if err != nil {
		return nil, err
	}
	return parseConfig(raw)
}
