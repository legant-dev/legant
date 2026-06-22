package ccguard

import (
	"crypto/rsa"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// feedClaims is the body of the signed revocation feed — identical in shape to
// the one Legant publishes at /.well-known/revoked and the one the SDK consumes,
// so the guard's local file feed and a real issuer feed are interchangeable.
type feedClaims struct {
	jwt.RegisteredClaims
	Version int64    `json:"ver"`
	JTIs    []string `json:"jtis"`
}

// SignedFeed is a verified, in-memory snapshot of revoked token ids. It is read
// from a compact JWS (a local file for the offline guard, or the issuer's
// /.well-known/revoked in a server deployment) and verified under the same JWKS
// keys that verify tokens — so it introduces no new trust root, and a tampered or
// forged feed is rejected rather than trusted.
type SignedFeed struct {
	revoked map[string]struct{}
	version int64
}

// LoadSignedFeedBytes verifies a compact-JWS feed and returns its revoked set.
// The signature must be RS256 under a known kid, the issuer must match, and the
// feed must carry an expiry. Anyone can read the jti list, but only the issuer's
// key can produce a feed the guard will trust.
func LoadSignedFeedBytes(compact []byte, issuer string, keys map[string]*rsa.PublicKey) (*SignedFeed, error) {
	c := &feedClaims{}
	_, err := jwt.ParseWithClaims(string(compact), c, func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("feed missing kid")
		}
		pub, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("unknown feed signing key %q", kid)
		}
		return pub, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(issuer), jwt.WithExpirationRequired())
	if err != nil {
		return nil, fmt.Errorf("verify revocation feed: %w", err)
	}
	set := make(map[string]struct{}, len(c.JTIs))
	for _, j := range c.JTIs {
		set[j] = struct{}{}
	}
	return &SignedFeed{revoked: set, version: c.Version}, nil
}

// LoadSignedFeedFile reads and verifies a feed file. An empty path returns
// (nil, nil): no offline revocation source, so revocation falls back to the
// token's short TTL (Tier C). A present-but-unreadable or invalid file is an
// error the caller decides how to treat (the guard fails closed on it).
func LoadSignedFeedFile(path, issuer string, keys map[string]*rsa.PublicKey) (*SignedFeed, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadSignedFeedBytes(b, issuer, keys)
}

// IsRevoked reports whether a token id is on the feed's kill-list.
func (f *SignedFeed) IsRevoked(jti string) bool {
	if f == nil {
		return false
	}
	_, ok := f.revoked[jti]
	return ok
}

// Version is the feed's monotonic version (verifiers reject a regress).
func (f *SignedFeed) Version() int64 {
	if f == nil {
		return 0
	}
	return f.version
}

// RevokedJTIs returns the sorted token ids currently on the feed — used when
// republishing the feed to add another id without dropping the existing ones.
func (f *SignedFeed) RevokedJTIs() []string {
	if f == nil {
		return nil
	}
	out := make([]string, 0, len(f.revoked))
	for j := range f.revoked {
		out = append(out, j)
	}
	sort.Strings(out)
	return out
}

// BuildSignedFeed mints a signed revocation feed over the given token ids. Used
// by `legant guard revoke` to publish a new kill-list signed with the same key
// the guard trusts. jtis are sorted for a stable, diffable output.
func BuildSignedFeed(jtis []string, version int64, issuer, kid string, key *rsa.PrivateKey, ttl time.Duration, now time.Time) (string, error) {
	sorted := append([]string(nil), jtis...)
	sort.Strings(sorted)
	claims := feedClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Version: version,
		JTIs:    sorted,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	return tok.SignedString(key)
}
