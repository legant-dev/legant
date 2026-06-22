package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// RateLimiter is a simple in-memory fixed-window limiter keyed by a function of
// the request (client IP by default). It bounds token-exchange / token-mint
// abuse. In a multi-replica deployment this is per-process; back it with a shared
// store (e.g. Redis) for a global limit — documented as a known limitation.
type RateLimiter struct {
	mu       sync.Mutex
	windows  map[string]*window
	limit    int
	interval time.Duration
	keyFn    func(*http.Request) string
}

type window struct {
	count int
	reset time.Time
}

// NewRateLimiter allows up to limit requests per interval per key.
func NewRateLimiter(limit int, interval time.Duration, keyFn func(*http.Request) string) *RateLimiter {
	if keyFn == nil {
		keyFn = ClientIP
	}
	return &RateLimiter{windows: map[string]*window{}, limit: limit, interval: interval, keyFn: keyFn}
}

func (rl *RateLimiter) allow(key string, now time.Time) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Opportunistically drop a stale window so the map doesn't grow unbounded.
	if w, ok := rl.windows[key]; ok && now.After(w.reset) {
		delete(rl.windows, key)
	}

	w, ok := rl.windows[key]
	if !ok {
		rl.windows[key] = &window{count: 1, reset: now.Add(rl.interval)}
		return true
	}
	if w.count >= rl.limit {
		return false
	}
	w.count++
	return true
}

// Middleware enforces the limit, returning 429 when exceeded.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(rl.keyFn(r), time.Now()) {
			w.Header().Set("Retry-After", "1")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ClientIP extracts the client IP from the request's RemoteAddr.
func ClientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
