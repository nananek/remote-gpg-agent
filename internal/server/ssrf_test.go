package server

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"testing"
)

func TestBlockedIP(t *testing.T) {
	cases := []struct {
		ip   net.IP
		want bool
	}{
		{net.IPv4(127, 0, 0, 1), true},
		{net.IPv4(10, 1, 2, 3), true},
		{net.IPv4(172, 16, 0, 1), true},
		{net.IPv4(192, 168, 1, 1), true},
		{net.IPv4(169, 254, 169, 254), true},
		{net.IPv4(100, 64, 0, 1), true},
		{net.IPv4(0, 0, 0, 0), true},
		{net.ParseIP("::1"), true},
		{net.ParseIP("fd00::1"), true},
		{net.ParseIP("fe80::1"), true},
		{net.ParseIP("::ffff:127.0.0.1"), true},
		{net.ParseIP("8.8.8.8"), false},
		{net.ParseIP("1.1.1.1"), false},
		{net.ParseIP("2606:4700:4700::1111"), false},
	}
	for _, c := range cases {
		if got := blockedIP(c.ip); got != c.want {
			t.Errorf("blockedIP(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestValidatePushEndpointRejectsPrivateTargets(t *testing.T) {
	for _, endpoint := range []string{
		"https://127.0.0.1/push",
		"https://localhost/push",
		"https://[::1]/push",
		"https://169.254.169.254/latest/meta-data",
		"https://100.64.0.1/push",
		"http://127.0.0.1/push",
	} {
		if err := validatePushEndpoint(context.Background(), endpoint); err == nil {
			t.Errorf("endpoint %q must be rejected", endpoint)
		}
	}

	// userinfo 付きの endpoint も拒否する。文字列を分割して、URL 中の
	// 認証情報らしきリテラルをテストデータに残さない。
	withUser := fmt.Sprintf("https://%s@127.0.0.1/push", url.UserPassword("u", "p"))
	if err := validatePushEndpoint(context.Background(), withUser); err == nil {
		t.Error("endpoint with userinfo must be rejected")
	}
}

func TestValidatePushEndpointAllowsPublicIP(t *testing.T) {
	if err := validatePushEndpoint(context.Background(), "https://8.8.8.8/push"); err != nil {
		t.Fatalf("public IP must be accepted: %v", err)
	}
}

func TestSafeDialContextBlocksLoopback(t *testing.T) {
	if _, err := safeDialContext(context.Background(), "tcp", "127.0.0.1:9"); err == nil {
		t.Fatal("loopback dial must be blocked")
	}
}
