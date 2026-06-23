package sdk

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrRevoked is returned by Verify when the token's id is present in the
// configured revocation feed.
var ErrRevoked = errors.New("token revoked")

type feedClaims struct {
	jwt.RegisteredClaims
	Version int64    `json:"ver"`
	JTIs    []string `json:"jtis"`
}

// RevocationFeed is an offline, pull-based view of revoked tokens. The resource
// server fetches a signed feed from the issuer on a timer and checks token ids
// against an in-memory set — with NO per-request callback. A token revoked at
// the issuer takes effect here within the feed's refresh interval (and never
// later than the token's own short expiry, which is the always-present backstop).
//
// The feed is signed with the SAME key as the issuer's JWKS, so it adds no new
// trust root. A stale or missing feed can only ever MISS a revocation, never
// invent one; and a regressing version is rejected as a rollback/replay.
type RevocationFeed struct {
	url    string
	issuer string
	keys   map[string]*rsa.PublicKey
	client *http.Client

	mu        sync.RWMutex
	revoked   map[string]struct{}
	version   int64
	fetchedAt time.Time
}

// FetchRevocationFeed fetches and verifies the issuer's revocation feed once.
// keysByKID is the same JWKS key map the Verifier uses, so the feed's signature
// is checked under the established trust root.
func FetchRevocationFeed(ctx context.Context, feedURL, issuer string, keysByKID map[string]*rsa.PublicKey) (*RevocationFeed, error) {
	f := &RevocationFeed{
		url: feedURL, issuer: issuer, keys: keysByKID,
		client:  &http.Client{Timeout: 10 * time.Second},
		revoked: map[string]struct{}{},
	}
	if err := f.Refresh(ctx); err != nil {
		return nil, err
	}
	return f, nil
}

// ParseRevocationFeed verifies a signed revocation feed read from bytes (for
// example a local feed.jwt file written by `legant apply` / `legant revoke`), with
// no HTTP. It is the offline counterpart of FetchRevocationFeed: same signature
// and version checks, no network. To pick up later revocations, parse the file
// again. keysByKID is the same JWKS key map the Verifier uses.
func ParseRevocationFeed(feedJWT []byte, issuer string, keysByKID map[string]*rsa.PublicKey) (*RevocationFeed, error) {
	f := &RevocationFeed{
		issuer: issuer, keys: keysByKID,
		revoked: map[string]struct{}{},
	}
	if err := f.apply(feedJWT); err != nil {
		return nil, err
	}
	return f, nil
}

// Refresh fetches the feed and applies it (verify signature, enforce a monotonic
// version, atomically swap the in-memory set).
func (f *RevocationFeed) Refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revocation feed returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	return f.apply(body)
}

// apply verifies the feed JWT (RS256 under the issuer's kid), enforces a
// monotonic version, and atomically swaps the in-memory revoked set.
func (f *RevocationFeed) apply(body []byte) error {
	c := &feedClaims{}
	if _, err := jwt.ParseWithClaims(string(body), c, func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("feed missing kid")
		}
		pub, ok := f.keys[kid]
		if !ok {
			return nil, fmt.Errorf("unknown feed signing key %q", kid)
		}
		return pub, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(f.issuer), jwt.WithExpirationRequired()); err != nil {
		return fmt.Errorf("verify revocation feed: %w", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if c.Version < f.version {
		return fmt.Errorf("revocation feed version regressed (%d < %d) — possible rollback, keeping current", c.Version, f.version)
	}
	set := make(map[string]struct{}, len(c.JTIs))
	for _, j := range c.JTIs {
		set[j] = struct{}{}
	}
	f.revoked, f.version, f.fetchedAt = set, c.Version, time.Now()
	return nil
}

// IsRevoked reports whether a token id is in the latest feed snapshot.
func (f *RevocationFeed) IsRevoked(jti string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, ok := f.revoked[jti]
	return ok
}

// Staleness is how long since the feed was last successfully refreshed.
func (f *RevocationFeed) Staleness() time.Duration {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return time.Since(f.fetchedAt)
}

// StartPolling refreshes the feed on the given interval until ctx is cancelled.
// Refresh errors are non-fatal (the previous snapshot is retained); pass a
// logger-wrapped onError if you want visibility.
func (f *RevocationFeed) StartPolling(ctx context.Context, interval time.Duration, onError func(error)) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := f.Refresh(ctx); err != nil && onError != nil {
					onError(err)
				}
			}
		}
	}()
}
