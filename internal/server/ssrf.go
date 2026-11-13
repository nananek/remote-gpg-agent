package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// blockedNets は SSRF 防止のため接続を拒否する範囲。net.IP.IsPrivate などで
// 拾えない予約・移行アドレスを補う。Tailscale の 100.64.0.0/10 も含める。
var blockedNets = mustCIDRs(
	"0.0.0.0/8",
	"100.64.0.0/10",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"240.0.0.0/4",
	"::/128",
	"::1/128",
	"64:ff9b::/96",
	"100::/64",
	"2001:db8::/32",
	"2002::/16",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
)

func mustCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("invalid blocked CIDR: " + c)
		}
		out = append(out, n)
	}
	return out
}

func blockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, n := range blockedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// validatePushEndpoint は購読登録時に endpoint の scheme と解決先を検査する。
// 実際の接続時にも safeDialContext で同じ判定をする（DNS rebinding 対策）。
func validatePushEndpoint(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("endpoint is not a valid URL")
	}
	if !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.Hostname() == "" {
		return errors.New("endpoint must be an https URL")
	}
	if u.User != nil {
		return errors.New("endpoint must not contain userinfo")
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(lookupCtx, u.Hostname())
	if err != nil || len(addrs) == 0 {
		return errors.New("endpoint host could not be resolved")
	}
	for _, a := range addrs {
		if blockedIP(a.IP) {
			return errors.New("endpoint must resolve to a public address")
		}
	}
	return nil
}

// safeDialContext はホスト名を接続直前に解決し、私有・ループバック・
// リンクローカル宛てなら拒否する。解決と接続の間で DNS を差し替えられても
// 検査済みの IP にだけ接続する。
func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var lastErr error
	for _, a := range addrs {
		if blockedIP(a.IP) {
			lastErr = fmt.Errorf("blocked address %s", a.IP)
			continue
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(a.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no public address")
	}
	return nil, lastErr
}
