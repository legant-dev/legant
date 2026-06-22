package safehttp

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBlocked(t *testing.T) {
	cases := []struct {
		ip            string
		allowLoopback bool
		want          bool
	}{
		{"127.0.0.1", false, true},          // loopback
		{"127.0.0.1", true, false},          // loopback allowed
		{"10.1.2.3", false, true},           // RFC1918 private
		{"192.168.1.1", false, true},        // RFC1918 private
		{"169.254.169.254", false, true},    // link-local (cloud metadata)
		{"::1", false, true},                // IPv6 loopback
		{"fd00::1", false, true},            // IPv6 ULA (private)
		{"0.0.0.0", false, true},            // unspecified
		{"100.64.0.1", false, true},         // CGNAT (RFC 6598)
		{"64:ff9b::a9fe:a9fe", false, true}, // NAT64-embedded 169.254.169.254 (cloud metadata)
		{"2002:a9fe:a9fe::1", false, true},  // 6to4-embedded link-local metadata
		{"8.8.8.8", false, false},           // public
		{"93.184.216.34", false, false},     // public
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test ip %q", c.ip)
		}
		if got := blocked(ip, c.allowLoopback); got != c.want {
			t.Errorf("blocked(%s, allowLoopback=%v) = %v, want %v", c.ip, c.allowLoopback, got, c.want)
		}
	}
}

func TestGetJSONRejectsNonHTTPS(t *testing.T) {
	var out map[string]any
	if err := GetJSON(context.Background(), Client(true), "http://example.com/x", &out, 1024); err == nil {
		t.Fatal("non-https URL must be rejected")
	}
}

func TestSSRFBlocksLoopbackByDefault(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	// The hardened client (loopback disallowed) must refuse to connect to the
	// loopback test server — the SSRF guard fires at dial time.
	var out map[string]any
	if err := GetJSON(context.Background(), Client(false), srv.URL, &out, 1024); err == nil {
		t.Fatal("connecting to a loopback address must be blocked by default")
	}
}
