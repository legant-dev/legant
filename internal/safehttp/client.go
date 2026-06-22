// Package safehttp provides an HTTP client hardened against SSRF, for fetching
// attacker-influenced URLs (CIMD documents, JWKS, MCP upstreams). It refuses to
// connect to loopback, private, link-local, or unspecified addresses — checked
// on the *resolved* IP and pinned for the dial, which defeats DNS-rebinding —
// allows only https, and bounds redirects, time, and response size.
package safehttp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Client builds an SSRF-hardened http.Client. allowLoopback permits connections
// to loopback addresses (for tests / local dev only).
func Client(allowLoopback bool) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("safehttp: no addresses for %q", host)
			}
			for _, ip := range ips {
				if blocked(ip.IP, allowLoopback) {
					return nil, fmt.Errorf("safehttp: refusing to connect to disallowed address %s", ip.IP)
				}
			}
			// Pin the dial to a vetted IP so a second resolution can't rebind to a
			// blocked target between check and connect.
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("safehttp: too many redirects")
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("safehttp: redirect to non-https blocked")
			}
			return nil
		},
	}
}

// extraBlocked holds ranges that are globally-routable (so IsGlobalUnicast is
// true) yet must be denied: CGNAT and IPv6 transition ranges that can embed the
// cloud-metadata address (169.254.169.254) and reach internal targets.
var extraBlocked = func() []*net.IPNet {
	cidrs := []string{
		"100.64.0.0/10",  // CGNAT (RFC 6598)
		"64:ff9b::/96",   // NAT64 well-known prefix (RFC 6052)
		"64:ff9b:1::/48", // NAT64 local-use prefix (RFC 8215)
		"2002:a9fe::/32", // 6to4-embedded 169.254.0.0/16 (link-local / metadata)
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// blocked uses an allow-list posture: only globally-routable, non-private,
// non-special addresses are permitted to dial.
func blocked(ip net.IP, allowLoopback bool) bool {
	if ip.IsLoopback() {
		return !allowLoopback
	}
	if !ip.IsGlobalUnicast() {
		// link-local, multicast, unspecified, etc.
		return true
	}
	if ip.IsPrivate() { // RFC 1918 + IPv6 ULA
		return true
	}
	for _, n := range extraBlocked {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// GetJSON fetches url with the hardened client and decodes the JSON body into v.
// Only https URLs are accepted, and the body is capped at maxBytes.
func GetJSON(ctx context.Context, client *http.Client, url string, v any, maxBytes int64) error {
	if !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("safehttp: only https URLs are allowed, got %q", url)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("safehttp: GET %s returned %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}
