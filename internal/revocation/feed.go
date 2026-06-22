package revocation

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FeedSigner provides the active signing key — the SAME key published in the
// issuer's JWKS — so the revocation feed shares the verifier's existing trust
// root (no new key to distribute).
type FeedSigner interface {
	ActiveKID() string
	ActiveSigner() *rsa.PrivateKey
}

// FeedClaims is the body of the signed revocation feed: a compact, TTL-bounded
// snapshot of currently-revoked-but-not-yet-expired token ids. Because tokens
// are short-lived, this set stays small (bounded by revoke-rate × max TTL), and
// a stale feed can only ever MISS a revoke — never forge one — with token expiry
// as the always-present backstop.
type FeedClaims struct {
	jwt.RegisteredClaims
	Version int64    `json:"ver"`  // monotonic; verifiers reject a regressing version
	JTIs    []string `json:"jtis"` // sorted list of revoked, unexpired token ids
}

// Feed builds and serves the signed revocation feed. It caches the signed bytes
// briefly so repeated scrapes don't hit the database on every request.
type Feed struct {
	pool     *pgxpool.Pool
	signer   FeedSigner
	issuer   string
	feedTTL  time.Duration // how long a published feed is valid (forces refresh)
	cacheFor time.Duration // how long to reuse the signed bytes between rebuilds

	mu      sync.Mutex
	cached  []byte
	builtAt time.Time
}

// NewFeed builds a revocation feed signer over the given pool and key source.
func NewFeed(pool *pgxpool.Pool, signer FeedSigner, issuer string) *Feed {
	return &Feed{pool: pool, signer: signer, issuer: issuer, feedTTL: time.Minute, cacheFor: 5 * time.Second}
}

func (f *Feed) build(ctx context.Context, now time.Time) ([]byte, error) {
	rows, err := f.pool.Query(ctx,
		`SELECT jti FROM exchanged_tokens
		 WHERE revoked_at IS NOT NULL AND expires_at > now()
		 ORDER BY jti`)
	if err != nil {
		return nil, fmt.Errorf("query revoked tokens: %w", err)
	}
	defer rows.Close()
	jtis := []string{}
	for rows.Next() {
		var jti string
		if err := rows.Scan(&jti); err != nil {
			return nil, err
		}
		jtis = append(jtis, jti)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var version int64
	if err := f.pool.QueryRow(ctx, `SELECT nextval('revocation_feed_version')`).Scan(&version); err != nil {
		return nil, fmt.Errorf("feed version: %w", err)
	}

	claims := FeedClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    f.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(f.feedTTL)),
		},
		Version: version,
		JTIs:    jtis,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = f.signer.ActiveKID()
	signed, err := tok.SignedString(f.signer.ActiveSigner())
	if err != nil {
		return nil, fmt.Errorf("sign feed: %w", err)
	}
	return []byte(signed), nil
}

// Snapshot returns the current signed feed (cached for cacheFor).
func (f *Feed) Snapshot(ctx context.Context) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cached != nil && time.Since(f.builtAt) < f.cacheFor {
		return f.cached, nil
	}
	b, err := f.build(ctx, time.Now())
	if err != nil {
		return nil, err
	}
	f.cached, f.builtAt = b, time.Now()
	return b, nil
}

// Handler serves the signed revocation feed at /.well-known/revoked.
func (f *Feed) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := f.Snapshot(r.Context())
		if err != nil {
			http.Error(w, "could not build revocation feed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/jwt")
		w.Header().Set("Cache-Control", "public, max-age=5")
		_, _ = w.Write(b)
	}
}
