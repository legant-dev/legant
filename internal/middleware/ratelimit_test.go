package middleware

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterAllow(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute, nil)
	base := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)

	if !rl.allow("a", base) || !rl.allow("a", base) {
		t.Fatal("the first 2 requests in the window must be allowed")
	}
	if rl.allow("a", base) {
		t.Fatal("the 3rd request in the same window must be denied")
	}
	// A different key has its own independent window.
	if !rl.allow("b", base) {
		t.Fatal("a different key must not share another key's window")
	}
	// After the interval elapses, the window resets: two allowed again, third denied.
	later := base.Add(time.Minute + time.Second)
	if !rl.allow("a", later) || !rl.allow("a", later) {
		t.Fatal("the window must reset after the interval")
	}
	if rl.allow("a", later) {
		t.Fatal("the reset window must still enforce the limit")
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.7:54321"
	if got := ClientIP(r); got != "203.0.113.7" {
		t.Errorf("ClientIP = %q, want 203.0.113.7 (port stripped)", got)
	}
	// A bare address with no port is returned unchanged.
	r.RemoteAddr = "203.0.113.7"
	if got := ClientIP(r); got != "203.0.113.7" {
		t.Errorf("ClientIP(no port) = %q, want 203.0.113.7", got)
	}
}
