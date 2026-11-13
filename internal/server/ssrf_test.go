package server

import (
	"context"
	"net"
	"testing"
)

func TestBlockedIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"10.1.2.3", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true},
		{"100.64.0.1", true},
		{"0.0.0.0", true},
		{"::1", true},
		{"fd00::1", true},
		{"fe80::1", true},
		{"::ffff:127.0.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2606:4700:4700::1111", false},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", c.ip)
		}
		if got := blockedIP(ip); got != c.want {
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
		"https://user:pass@127.0.0.1/push",
	} {
		if err := validatePushEndpoint(context.Background(), endpoint); err == nil {
			t.Errorf("endpoint %q must be rejected", endpoint)
		}
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
