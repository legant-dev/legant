// Package sdk is a self-contained client for resource servers (and MCP servers)
// that accept Legant delegation tokens. It verifies a composite sub/act token
// against the issuer's published keys and authorizes a request's scope and
// constraints — entirely offline, with no callback to Legant and no dependency
// on Legant's internal packages. Its only dependency is golang-jwt.
//
// Typical use at a resource server:
//
//	keys, _ := sdk.FetchJWKS(ctx, "https://legant.example/.well-known/jwks.json")
//	v := sdk.NewVerifier("https://legant.example", "https://my-api.example/", keys)
//	claims, err := v.Verify(bearerToken)
//	if err != nil { /* 401 */ }
//	if err := claims.Authorize(sdk.Action{Scope: "expenses:submit", Amount: 120, Category: "travel"}); err != nil {
//	    /* 403 */
//	}
//	// claims.Provenance() == "user:alice -> agent:assistant"
package sdk

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Actor models the RFC 8693 "act" claim: the most recent actor on top, earlier
// actors nested inside.
type Actor struct {
	Sub string `json:"sub"`
	Act *Actor `json:"act,omitempty"`
}

// Constraints are the fine-grained limits carried in the token's "cnst" claim.
type Constraints struct {
	MaxAmount  *float64    `json:"max_amount,omitempty"`
	Categories []string    `json:"categories,omitempty"`
	Tools      []string    `json:"tools,omitempty"`
	Resources  []string    `json:"resources,omitempty"`
	TimeWindow *TimeWindow `json:"time_window,omitempty"`
	// Rate is informational at the resource server: a rolling-hour cap needs shared
	// state and is enforced by Legant at token-exchange time, not offline here.
	Rate *RateLimit `json:"rate,omitempty"`
}

// TimeWindow restricts when the authority may be used: an optional weekday
// allow-list (0=Sunday … 6=Saturday) and an inclusive minute-of-day range,
// evaluated in TZ (IANA name; empty = UTC). Enforced offline.
type TimeWindow struct {
	Weekdays []int  `json:"weekdays,omitempty"`
	StartMin int    `json:"start_min"`
	EndMin   int    `json:"end_min"`
	TZ       string `json:"tz,omitempty"`
}

// Allows reports whether the instant at falls inside the window; an unknown TZ
// fails closed.
func (w *TimeWindow) Allows(at time.Time) bool {
	loc := time.UTC
	if w.TZ != "" {
		l, err := time.LoadLocation(w.TZ)
		if err != nil {
			return false
		}
		loc = l
	}
	t := at.In(loc)
	if len(w.Weekdays) > 0 && !containsInt(w.Weekdays, int(t.Weekday())) {
		return false
	}
	m := t.Hour()*60 + t.Minute()
	return m >= w.StartMin && m <= w.EndMin
}

// RateLimit caps how often a delegation may be exercised per rolling hour.
type RateLimit struct {
	MaxPerHour int `json:"max_per_hour"`
}

// Claims is the verified body of a delegation token.
type Claims struct {
	jwt.RegisteredClaims
	Scope       string       `json:"scope"`
	Act         *Actor       `json:"act,omitempty"`
	Constraints *Constraints `json:"cnst,omitempty"`
}

// Action describes the concrete operation being attempted. Zero-value fields are
// "not applicable" and skip the corresponding constraint check.
type Action struct {
	Scope    string
	Amount   float64
	Category string
	Tool     string
	Resource string
	At       time.Time // instant of the action; zero means "now" (time-window check)
}

// Verifier verifies delegation tokens against a fixed issuer and audience.
type Verifier struct {
	issuer   string
	audience string
	keys     map[string]*rsa.PublicKey

	feed             *RevocationFeed
	feedFailClosed   bool
	feedMaxStaleness time.Duration
}

// Option configures an optional Verifier behavior.
type Option func(*Verifier)

// WithRevocationFeed makes the verifier reject tokens present in the revocation
// feed (Tier B). The feed is pulled out of band (no per-request callback); a
// token revoked at the issuer is rejected here within the feed's refresh window.
// Without this option the verifier behaves exactly as before (revocation bounded
// by the token's short TTL — Tier C).
func WithRevocationFeed(f *RevocationFeed) Option {
	return func(v *Verifier) { v.feed = f }
}

// WithFeedFailClosed makes Verify REJECT tokens when the revocation feed is older
// than maxStaleness (high-assurance: couples availability to the feed). The
// default is fail-open-to-TTL: a stale/unreachable feed reverts to TTL-bounded
// revocation rather than rejecting valid tokens.
func WithFeedFailClosed(maxStaleness time.Duration) Option {
	return func(v *Verifier) { v.feedFailClosed = true; v.feedMaxStaleness = maxStaleness }
}

// NewVerifier builds a verifier from public keys indexed by kid (e.g. from
// FetchJWKS). The audience must be this resource server's own identifier. It is
// compared against the token's aud after RFC 8707 canonicalization, so it is
// insensitive to host case, a default port (:443/:80), and a trailing slash —
// "https://api.example", "https://API.example:443", and "https://api.example/"
// all match the canonical "https://api.example/" the issuer mints.
func NewVerifier(issuer, audience string, keysByKID map[string]*rsa.PublicKey, opts ...Option) *Verifier {
	v := &Verifier{issuer: issuer, audience: audience, keys: keysByKID}
	for _, o := range opts {
		o(v)
	}
	return v
}

// Verify validates a token: RS256 signature under the key named by its kid, plus
// issuer, audience, and expiry. It requires an act claim (a delegation token, not
// a plain access token) and fails closed on an unknown kid.
func (v *Verifier) Verify(token string) (*Claims, error) {
	c := &Claims{}
	// Audience is checked manually (not via jwt.WithAudience) so it can be matched
	// after canonicalization rather than byte-for-byte against the issuer's
	// canonical form.
	_, err := jwt.ParseWithClaims(token, c, func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("token missing kid header")
		}
		pub, ok := v.keys[kid]
		if !ok {
			return nil, fmt.Errorf("unknown signing key %q", kid)
		}
		return pub, nil
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}
	if c.Act == nil {
		return nil, fmt.Errorf("not a delegation token (no act claim)")
	}
	if !audienceMatches(c.Audience, v.audience) {
		return nil, fmt.Errorf("token audience %v does not include %q", []string(c.Audience), v.audience)
	}
	// Tier B: offline revocation check against the pulled feed (no callback).
	if v.feed != nil {
		if v.feedFailClosed && v.feed.Staleness() > v.feedMaxStaleness {
			return nil, fmt.Errorf("revocation feed is stale (%s) and fail-closed is set", v.feed.Staleness())
		}
		if c.ID != "" && v.feed.IsRevoked(c.ID) {
			return nil, ErrRevoked
		}
	}
	return c, nil
}

// audienceMatches reports whether any of the token's audiences canonically
// equals the wanted audience (RFC 8707 canonicalization).
func audienceMatches(auds jwt.ClaimStrings, want string) bool {
	cw := canonicalizeAudience(want)
	for _, a := range auds {
		if canonicalizeAudience(a) == cw {
			return true
		}
	}
	return false
}

// canonicalizeAudience mirrors the issuer's RFC 8707 canonicalization for the
// purpose of comparison: lowercase scheme+host, strip a default port, drop
// userinfo/fragment, and treat an empty path as "/". Values that are not
// absolute URIs are returned unchanged and compared as-is.
func canonicalizeAudience(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return raw
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	if u.Scheme == "https" && strings.HasSuffix(host, ":443") {
		host = strings.TrimSuffix(host, ":443")
	} else if u.Scheme == "http" && strings.HasSuffix(host, ":80") {
		host = strings.TrimSuffix(host, ":80")
	}
	u.Host = host
	u.User = nil
	u.Fragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String()
}

// Authorize enforces that the token carries the required scope and that the
// action satisfies every constraint.
func (c *Claims) Authorize(a Action) error {
	if !hasScope(c.Scope, a.Scope) {
		return fmt.Errorf("missing required scope %q", a.Scope)
	}
	if c.Constraints == nil {
		return nil
	}
	k := c.Constraints
	if k.MaxAmount != nil && a.Amount > *k.MaxAmount {
		return fmt.Errorf("amount %.2f exceeds max_amount %.2f", a.Amount, *k.MaxAmount)
	}
	if err := permitList("category", k.Categories, a.Category, false); err != nil {
		return err
	}
	if err := permitList("tool", k.Tools, a.Tool, false); err != nil {
		return err
	}
	// Resources are compared after RFC 8707 canonicalization so a non-canonical
	// stored value still matches a canonical request (and vice versa).
	if err := permitList("resource", k.Resources, a.Resource, true); err != nil {
		return err
	}
	if k.TimeWindow != nil {
		at := a.At
		if at.IsZero() {
			at = time.Now()
		}
		if !k.TimeWindow.Allows(at) {
			return fmt.Errorf("action at %s is outside the delegated time window", at.Format(time.RFC3339))
		}
	}
	return nil
}

// Provenance renders the delegation path, e.g. "user:alice -> agent:assistant -> agent:ocr".
func (c *Claims) Provenance() string {
	parts := []string{c.Subject}
	var chain []string
	for a := c.Act; a != nil; a = a.Act {
		chain = append(chain, a.Sub)
	}
	for i := len(chain) - 1; i >= 0; i-- {
		parts = append(parts, chain[i])
	}
	return strings.Join(parts, " -> ")
}

// FetchJWKS fetches and parses an issuer's JSON Web Key Set into a kid->key map.
// The jwksURL is expected to be the resource server's own trusted issuer (a
// configured constant), not a value derived from request input — this is a
// startup/refresh call, not a per-request fetch, so it deliberately does not
// impose SSRF allow-listing. Pass a URL you control.
func FetchJWKS(ctx context.Context, jwksURL string) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return ParseJWKS(body)
}

// ParseJWKS parses a JWKS document into a kid->key map (RSA keys only).
func ParseJWKS(data []byte) (map[string]*rsa.PublicKey, error) {
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	out := make(map[string]*rsa.PublicKey)
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("jwk %q: bad modulus: %w", k.Kid, err)
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("jwk %q: bad exponent: %w", k.Kid, err)
		}
		n := new(big.Int).SetBytes(nb)
		if n.BitLen() < 2048 {
			return nil, fmt.Errorf("jwk %q: modulus too small (%d bits, want >= 2048)", k.Kid, n.BitLen())
		}
		e := new(big.Int).SetBytes(eb)
		// Reject exponents that do not fit a platform int (avoids the silent
		// truncation of Int64()->int) or that are implausible.
		if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
			return nil, fmt.Errorf("jwk %q: unsupported public exponent", k.Kid)
		}
		out[k.Kid] = &rsa.PublicKey{N: n, E: int(e.Int64())}
	}
	return out, nil
}

func hasScope(scopeStr, scope string) bool {
	return contains(strings.Fields(scopeStr), scope)
}

// denyAll is the sentinel Legant puts in an allow-list that was intersected to
// nothing during re-delegation. It matches no real value and denies the
// dimension entirely. It must match the constant in internal/delegation.
const denyAll = "\x00legant:deny-all"

// permitList enforces one allow-list dimension from the token's constraints. A
// deny-all sentinel denies unconditionally (never fails open). When canonical is
// true, values are compared after RFC 8707 canonicalization (used for resources).
func permitList(dim string, allowed []string, value string, canonical bool) error {
	if len(allowed) == 0 {
		return nil
	}
	if contains(allowed, denyAll) {
		return fmt.Errorf("%s access is fully restricted by the delegation", dim)
	}
	if value == "" {
		return nil
	}
	match := contains(allowed, value)
	if !match && canonical {
		cv := canonicalizeAudience(value)
		for _, a := range allowed {
			if canonicalizeAudience(a) == cv {
				match = true
				break
			}
		}
	}
	if !match {
		return fmt.Errorf("%s %q not permitted", dim, value)
	}
	return nil
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

func containsInt(set []int, v int) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}
