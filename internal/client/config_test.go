package client

import (
	"testing"
)

func TestParseConfig(t *testing.T) {
	base := `{"url":"https://rga.example:8443","caCert":"/x/ca.pem","clientCert":"/x/c.pem","clientKey":"/x/k.pem"}`

	c, err := parseConfig([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	if c.TimeoutSec != 180 {
		t.Fatalf("default timeout: %d", c.TimeoutSec)
	}

	if _, err := parseConfig([]byte(`{"url":"http://x","caCert":"a","clientCert":"b","clientKey":"c"}`)); err == nil {
		t.Fatal("http must be rejected")
	}
	if _, err := parseConfig([]byte(`{"url":"https://x","caCert":"","clientCert":"b","clientKey":"c"}`)); err == nil {
		t.Fatal("missing caCert must be rejected")
	}
	if _, err := parseConfig([]byte(`{"url":"https://x","caCert":"a","clientCert":"b","clientKey":"c","defaultKeyFingerprint":"zz"}`)); err == nil {
		t.Fatal("bad fingerprint must be rejected")
	}

	c, err = parseConfig([]byte(`{"url":"https://x/","caCert":"a","clientCert":"b","clientKey":"c","defaultKeyFingerprint":"0123456789abcdef0123456789abcdef01234567","timeoutSec":30}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.URL != "https://x" {
		t.Fatalf("trailing slash: %q", c.URL)
	}
	if c.DefaultKeyFingerprint != "0123456789ABCDEF0123456789ABCDEF01234567" {
		t.Fatalf("fingerprint must be uppercased: %q", c.DefaultKeyFingerprint)
	}
	if c.TimeoutSec != 30 {
		t.Fatalf("timeout: %d", c.TimeoutSec)
	}
}
