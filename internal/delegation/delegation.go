// Package delegation implements the core authorization primitives that make
// Legant an agent-identity layer rather than a generic OIDC server:
//
//   - scope attenuation        — a delegated grant can only ever narrow scopes
//   - constraint policy        — fine-grained limits carried in the token and
//     enforced at the resource server
//   - composite (sub/act)      — RFC 8693 delegation tokens that record the full
//     delegation tokens          user -> agent -> sub-agent provenance chain
//
// It is deliberately free of database or HTTP dependencies so it can be unit
// tested in isolation and reused both by the /oauth2/token exchange endpoint and
// by example apps. See examples/agent-obo for a runnable demonstration.
package delegation

import (
	"crypto/rsa"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	legantcrypto "github.com/legant-dev/legant/internal/crypto"
)

// DefaultMaxDepth bounds how deep a delegation chain may go
// (user -> agent -> sub-agent -> ...). It is a backstop against runaway or
// malicious re-delegation.
const DefaultMaxDepth = 5

// ---- Constraints -----------------------------------------------------------

// Constraints are fine-grained limits attached to a delegation. An empty field
// means "no restriction on this dimension". They are carried inside the issued
// token (the "cnst" claim) and re-checked by the resource server against the
// concrete action being attempted — this is the authorization layer that a
// plain OAuth scope cannot express.
type Constraints struct {
	// MaxAmount caps the monetary value of an action (e.g. an expense submission).
	MaxAmount *float64 `json:"max_amount,omitempty"`
	// Categories, when non-empty, is the allow-list of categories an action may target.
	Categories []string `json:"categories,omitempty"`
	// Tools, when non-empty, is the allow-list of MCP tool names the holder may invoke.
	Tools []string `json:"tools,omitempty"`
	// Resources, when non-empty, restricts which resource audiences (RFC 8707) are allowed.
	Resources []string `json:"resources,omitempty"`
	// TimeWindow, when set, restricts WHEN the authority may be used. It is enforced
	// offline by the resource server (and the SDK) against the request time.
	TimeWindow *TimeWindow `json:"time_window,omitempty"`
	// Rate, when set, caps how often the authority may be exercised. Because a rate
	// cap needs shared state, it is NOT enforced offline by a resource server; it is
	// enforced by Legant at token-exchange time (mint frequency per delegation). It
	// rides in the token for transparency and audit.
	Rate *RateLimit `json:"rate,omitempty"`
}

// TimeWindow restricts the times at which a delegation may be used: an optional
// weekday allow-list and an inclusive minute-of-day range, evaluated in TZ
// (an IANA location name; empty means UTC). It is stateless, so a resource
// server enforces it offline from the token alone.
type TimeWindow struct {
	Weekdays []int  `json:"weekdays,omitempty"` // 0=Sunday … 6=Saturday; empty = any day
	StartMin int    `json:"start_min"`          // inclusive minute-of-day [0,1439]
	EndMin   int    `json:"end_min"`            // inclusive minute-of-day [0,1439]
	TZ       string `json:"tz,omitempty"`       // IANA location; empty = UTC
}

// Allows reports whether the instant at is inside the window. An unknown TZ fails
// closed (denies).
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

// Validate checks the window is well-formed (used by the consent / re-delegation
// entry points before a window is persisted).
func (w *TimeWindow) Validate() error {
	if w.StartMin < 0 || w.StartMin > 1439 || w.EndMin < 0 || w.EndMin > 1439 {
		return fmt.Errorf("time window minutes must be within [0,1439]")
	}
	if w.StartMin > w.EndMin {
		return fmt.Errorf("time window start_min must be <= end_min (no wrap across midnight)")
	}
	for _, d := range w.Weekdays {
		if d < 0 || d > 6 {
			return fmt.Errorf("time window weekday must be 0..6")
		}
	}
	if w.TZ != "" {
		if _, err := time.LoadLocation(w.TZ); err != nil {
			return fmt.Errorf("time window tz %q is not a valid IANA location", w.TZ)
		}
	}
	return nil
}

// RateLimit caps how many times a delegation may be exercised per rolling hour.
type RateLimit struct {
	MaxPerHour int `json:"max_per_hour"`
}

// Action describes the concrete thing a token holder is trying to do. Fields
// left at their zero value are treated as "not applicable" and skip the
// corresponding constraint check.
type Action struct {
	Scope    string    // scope the operation requires, e.g. "expenses:submit"
	Amount   float64   // monetary value, if any
	Category string    // category the action targets, if any
	Tool     string    // MCP tool being invoked, if any
	Resource string    // resource audience being accessed, if any
	At       time.Time // instant of the action; zero means "now" (time-window check)
}

// permitList enforces one allow-list dimension. A deny-all sentinel (an
// allow-list intersected to nothing during re-delegation) denies UNCONDITIONALLY
// — even when the action leaves the dimension empty — so it can never fail open.
// Otherwise an empty action value is "not applicable" and skips the check.
func permitList(dim string, allowed []string, value string) error {
	if len(allowed) == 0 {
		return nil
	}
	if contains(allowed, denyAll) {
		return fmt.Errorf("%s access is fully restricted by the delegation", dim)
	}
	if value != "" && !contains(allowed, value) {
		return fmt.Errorf("%s %q not in allowed %v", dim, value, allowed)
	}
	return nil
}

// Permit reports whether the action satisfies the constraints, returning a
// human-readable reason when it does not.
func (c Constraints) Permit(a Action) error {
	if c.MaxAmount != nil && a.Amount > *c.MaxAmount {
		return fmt.Errorf("amount %.2f exceeds max_amount %.2f", a.Amount, *c.MaxAmount)
	}
	if err := permitList("category", c.Categories, a.Category); err != nil {
		return err
	}
	if err := permitList("tool", c.Tools, a.Tool); err != nil {
		return err
	}
	if err := permitList("resource", c.Resources, a.Resource); err != nil {
		return err
	}
	if c.TimeWindow != nil {
		at := a.At
		if at.IsZero() {
			at = time.Now()
		}
		if !c.TimeWindow.Allows(at) {
			return fmt.Errorf("action at %s is outside the delegated time window", at.Format(time.RFC3339))
		}
	}
	// Rate is intentionally not enforced here: a rolling-hour cap needs shared
	// state, which a stateless resource server does not have. It is enforced at
	// token-exchange time (see internal/auth/token_exchange.go).
	return nil
}

// Tighten merges two constraint sets into the strictest combination of both.
// It is used when a delegation is re-delegated: a child can only ever be at
// least as restricted as its parent, never looser.
func Tighten(parent, child Constraints) Constraints {
	out := Constraints{
		Categories: intersectAllow(parent.Categories, child.Categories),
		Tools:      intersectAllow(parent.Tools, child.Tools),
		Resources:  intersectAllow(parent.Resources, child.Resources),
		TimeWindow: tightenWindow(parent.TimeWindow, child.TimeWindow),
		Rate:       tightenRate(parent.Rate, child.Rate),
	}
	switch {
	case parent.MaxAmount == nil:
		out.MaxAmount = child.MaxAmount
	case child.MaxAmount == nil:
		out.MaxAmount = parent.MaxAmount
	case *child.MaxAmount < *parent.MaxAmount:
		out.MaxAmount = child.MaxAmount
	default:
		out.MaxAmount = parent.MaxAmount
	}
	return out
}

// denyAll is a sentinel allow-list element that matches no real value. It is
// produced when intersecting two disjoint non-empty allow-lists so the result
// denies everything (rather than collapsing to the empty "no restriction" list,
// which would WIDEN authority on re-delegation).
const denyAll = "\x00legant:deny-all"

// intersectAllow combines two allow-lists. An empty list means "no restriction",
// so an empty operand yields the other; two non-empty lists yield their
// intersection. A non-empty intersection of two non-empty lists that share no
// element yields a deny-all sentinel, never the (widening) empty list.
func intersectAllow(a, b []string) []string {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	var out []string
	for _, x := range a {
		if x != denyAll && contains(b, x) {
			out = append(out, x)
		}
	}
	if len(out) == 0 {
		return []string{denyAll} // disjoint → restrict to nothing, never to everything
	}
	return out
}

// tightenWindow narrows two time windows. Cross-timezone windows are not
// intersected (the parent — the ceiling — wins) since their minute ranges are
// not directly comparable; same-tz windows intersect both weekdays and the
// minute range. A disjoint intersection produces a deny-all window (StartMin >
// EndMin, or a sentinel weekday) that Allows() correctly rejects for every
// instant. Such a window is internal-only and intentionally NOT re-run through
// Validate (which requires a satisfiable window) — failing closed is the goal.
func tightenWindow(p, c *TimeWindow) *TimeWindow {
	switch {
	case p == nil:
		return c
	case c == nil:
		return p
	case p.TZ != c.TZ:
		return p
	default:
		return &TimeWindow{
			TZ:       p.TZ,
			Weekdays: intersectInts(p.Weekdays, c.Weekdays),
			StartMin: max(p.StartMin, c.StartMin),
			EndMin:   min(p.EndMin, c.EndMin),
		}
	}
}

// tightenRate keeps the stricter (smaller) per-hour cap.
func tightenRate(p, c *RateLimit) *RateLimit {
	switch {
	case p == nil:
		return c
	case c == nil:
		return p
	default:
		m := p.MaxPerHour
		if c.MaxPerHour < m {
			m = c.MaxPerHour
		}
		return &RateLimit{MaxPerHour: m}
	}
}

// ---- Scope attenuation -----------------------------------------------------

// Attenuate returns the requested scopes that are also present in the parent
// grant, preserving the requested order. A delegated token can never widen the
// scope it was granted.
func Attenuate(parent, requested []string) []string {
	var out []string
	for _, s := range requested {
		if contains(parent, s) {
			out = append(out, s)
		}
	}
	return out
}

// IsSubset reports whether every scope in child is present in parent.
func IsSubset(child, parent []string) bool {
	for _, s := range child {
		if !contains(parent, s) {
			return false
		}
	}
	return true
}

// HasScope reports whether scope is present in the space-delimited scope string.
func HasScope(scopeStr, scope string) bool {
	return contains(strings.Fields(scopeStr), scope)
}

// ---- Grants & delegation chains -------------------------------------------

// Grant is a single link in a delegation chain. A root grant has Parent == nil
// and is created by a human user delegating to an agent; subsequent links are
// agents re-delegating an attenuated slice of their authority to sub-agents.
type Grant struct {
	Delegator   string // who granted this authority ("user:alice", "agent:assistant", ...)
	Delegatee   string // who received it ("agent:assistant", ...)
	Scopes      []string
	Constraints Constraints
	ExpiresAt   time.Time
	Parent      *Grant
}

// NewRootGrant creates the first link of a chain: a user delegating to an agent.
func NewRootGrant(user, agent string, scopes []string, c Constraints, ttl time.Duration, now time.Time) *Grant {
	return &Grant{
		Delegator:   user,
		Delegatee:   agent,
		Scopes:      append([]string(nil), scopes...),
		Constraints: c,
		ExpiresAt:   now.Add(ttl),
	}
}

// Delegate re-delegates an attenuated slice of a parent grant to a new
// delegatee. It enforces the two invariants that make chains safe:
//
//   - monotonic attenuation: scopes must be a subset of the parent's scopes
//   - no cycles / bounded depth: the delegatee must not already appear in the
//     chain, and the chain may not exceed maxDepth links
//
// Constraints are tightened against the parent so a child is never looser.
func (parent *Grant) Delegate(delegatee string, scopes []string, c Constraints, ttl time.Duration, now time.Time, maxDepth int) (*Grant, error) {
	if !IsSubset(scopes, parent.Scopes) {
		return nil, fmt.Errorf("delegate %s: scopes %v exceed delegator's scopes %v", delegatee, scopes, parent.Scopes)
	}
	if parent.depth()+1 >= maxDepth {
		return nil, fmt.Errorf("delegate %s: delegation depth would exceed max %d", delegatee, maxDepth)
	}
	for g := parent; g != nil; g = g.Parent {
		if g.Delegatee == delegatee {
			return nil, fmt.Errorf("delegate %s: cycle detected, principal already in chain", delegatee)
		}
	}
	// A child can expire no later than its parent.
	exp := now.Add(ttl)
	if exp.After(parent.ExpiresAt) {
		exp = parent.ExpiresAt
	}
	return &Grant{
		Delegator:   parent.Delegatee,
		Delegatee:   delegatee,
		Scopes:      append([]string(nil), scopes...),
		Constraints: Tighten(parent.Constraints, c),
		ExpiresAt:   exp,
		Parent:      parent,
	}, nil
}

func (g *Grant) depth() int {
	d := 0
	for p := g.Parent; p != nil; p = p.Parent {
		d++
	}
	return d
}

// RootDelegator returns the human (or root principal) at the head of the chain —
// the resource owner on whose behalf the leaf agent ultimately acts.
func (g *Grant) RootDelegator() string {
	root := g
	for root.Parent != nil {
		root = root.Parent
	}
	return root.Delegator
}

// ActorChainRootToLeaf returns every delegatee in the chain ordered from the
// principal closest to the user to the leaf agent actually holding the grant,
// e.g. ["agent:assistant", "agent:ocr"].
func (g *Grant) ActorChainRootToLeaf() []string {
	var rev []string
	for p := g; p != nil; p = p.Parent {
		rev = append(rev, p.Delegatee)
	}
	// rev is leaf..root; flip to root..leaf
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev
}

// EffectiveScopes returns the requested scopes attenuated against this grant.
func (g *Grant) EffectiveScopes(requested []string) []string {
	return Attenuate(g.Scopes, requested)
}

// ---- Token exchange (RFC 8693, delegation pattern) ------------------------

// ActClaim models the RFC 8693 "act" claim. The most recent actor is the
// top-most member; earlier actors are nested inside, giving a verifiable record
// of the whole delegation chain.
type ActClaim struct {
	Sub string    `json:"sub"`
	Act *ActClaim `json:"act,omitempty"`
}

// DelegationClaims is the body of a composite delegation token: the subject is
// the resource owner, "act" records the acting agent chain, "scope" the
// effective (attenuated) scopes, and "cnst" the constraints to enforce.
type DelegationClaims struct {
	jwt.RegisteredClaims
	Scope       string       `json:"scope"`
	Act         *ActClaim    `json:"act,omitempty"`
	Constraints *Constraints `json:"cnst,omitempty"`
}

// Signer mints composite delegation tokens. In Legant proper this wraps the same
// RSA signing key used for ID tokens.
type Signer struct {
	issuer string
	kid    string
	key    *rsa.PrivateKey
}

func NewSigner(issuer, kid string, key *rsa.PrivateKey) *Signer {
	return &Signer{issuer: issuer, kid: kid, key: key}
}

// IssueForGrant performs the on-behalf-of token exchange for a grant: it
// attenuates the requested scopes, builds the nested act chain, and signs a
// short-lived token bound to a single resource audience. This is exactly what
// the /oauth2/token token-exchange grant will call.
func (s *Signer) IssueForGrant(g *Grant, requestedScopes []string, audience string, now time.Time) (string, error) {
	effective := g.EffectiveScopes(requestedScopes)
	if len(effective) == 0 {
		return "", fmt.Errorf("no effective scopes: requested %v not covered by grant %v", requestedScopes, g.Scopes)
	}
	if len(g.Constraints.Resources) > 0 && !contains(g.Constraints.Resources, audience) {
		return "", fmt.Errorf("audience %q not permitted by constraints %v", audience, g.Constraints.Resources)
	}

	// Build act chain: leaf (most recent actor) on top, root agent most nested.
	var act *ActClaim
	for _, actor := range g.ActorChainRootToLeaf() {
		act = &ActClaim{Sub: actor, Act: act}
	}

	jti, err := legantcrypto.RandomHex(16)
	if err != nil {
		return "", err
	}
	cnst := g.Constraints
	claims := DelegationClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   g.RootDelegator(),
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(g.ExpiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
		Scope:       strings.Join(effective, " "),
		Act:         act,
		Constraints: &cnst,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = s.kid
	return tok.SignedString(s.key)
}

// IssueClaims mints a composite delegation token from explicit claims. The MCP
// gateway uses it to mint a fresh, narrowly-scoped, audience-bound downstream
// token that PRESERVES the inbound provenance (sub + act chain) — confused-deputy
// protection, so the gateway never forwards the token it received.
func (s *Signer) IssueClaims(subject string, act *ActClaim, scopes []string, audience string, constraints *Constraints, exp, now time.Time) (string, error) {
	jti, err := legantcrypto.RandomHex(16)
	if err != nil {
		return "", err
	}
	claims := DelegationClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   subject,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
		Scope:       strings.Join(scopes, " "),
		Act:         act,
		Constraints: constraints,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = s.kid
	return tok.SignedString(s.key)
}

// ---- Verification (resource-server side) ----------------------------------

// Verifier validates delegation tokens at a resource server. It holds only
// public keys — the resource server never needs Legant's signing key or
// database. Keys are indexed by key id (kid) so that during a key rotation the
// resource server can verify tokens signed by either the old or the new key,
// and so that a retired key (removed from the set) immediately stops being
// trusted.
type Verifier struct {
	issuer string
	keys   map[string]*rsa.PublicKey
}

// NewVerifier builds a verifier over a set of public keys indexed by kid —
// typically sourced from the issuer's JWKS endpoint.
func NewVerifier(issuer string, keysByKID map[string]*rsa.PublicKey) *Verifier {
	return &Verifier{issuer: issuer, keys: keysByKID}
}

// NewSingleKeyVerifier is a convenience for the one-key case (tests, examples).
func NewSingleKeyVerifier(issuer, kid string, pub *rsa.PublicKey) *Verifier {
	return &Verifier{issuer: issuer, keys: map[string]*rsa.PublicKey{kid: pub}}
}

// keyFunc selects the verification key by the token's kid header, failing closed
// on a missing or unknown kid.
func (v *Verifier) keyFunc(t *jwt.Token) (interface{}, error) {
	kid, _ := t.Header["kid"].(string)
	if kid == "" {
		return nil, fmt.Errorf("token missing kid header")
	}
	pub, ok := v.keys[kid]
	if !ok {
		return nil, fmt.Errorf("unknown signing key %q", kid)
	}
	return pub, nil
}

// Verify parses and validates a token: RS256 signature under the key named by
// the token's kid header, plus issuer, audience, and expiry. It fails closed if
// the token carries no kid or names a key the verifier does not hold.
func (v *Verifier) Verify(tokenStr, expectedAudience string) (*DelegationClaims, error) {
	claims := &DelegationClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, v.keyFunc,
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(expectedAudience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// VerifyAny validates signature, issuer, and expiry without binding to a
// specific audience. Used by introspection, which does not know the audience the
// caller intends. Callers that consume scopes/resources must still check the
// audience and the revocation store themselves.
func (v *Verifier) VerifyAny(tokenStr string) (*DelegationClaims, error) {
	claims := &DelegationClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, v.keyFunc,
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// Authorize enforces, in order: that the token carries the scope the action
// requires, and that the action satisfies every constraint. This is the
// resource server's policy decision point.
func (c *DelegationClaims) Authorize(a Action) error {
	if !HasScope(c.Scope, a.Scope) {
		return fmt.Errorf("missing required scope %q (token has %q)", a.Scope, c.Scope)
	}
	if c.Constraints != nil {
		if err := c.Constraints.Permit(a); err != nil {
			return err
		}
	}
	return nil
}

// ActorChain returns the acting principals most-recent-first, for audit logging,
// e.g. ["agent:ocr", "agent:assistant"].
func (c *DelegationClaims) ActorChain() []string {
	var chain []string
	for a := c.Act; a != nil; a = a.Act {
		chain = append(chain, a.Sub)
	}
	return chain
}

// Provenance renders the full delegation path for human-readable audit lines,
// e.g. "user:alice -> agent:assistant -> agent:ocr".
func (c *DelegationClaims) Provenance() string {
	parts := []string{c.Subject}
	chain := c.ActorChain()
	for i := len(chain) - 1; i >= 0; i-- { // reverse to root..leaf
		parts = append(parts, chain[i])
	}
	return strings.Join(parts, " -> ")
}

// ---- helpers ---------------------------------------------------------------

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

// intersectInts intersects two weekday allow-lists with the same empty=="no
// restriction" semantics as intersectAllow; disjoint non-empty lists yield a
// sentinel (-1, an impossible weekday) so the result matches no day.
func intersectInts(a, b []int) []int {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	var out []int
	for _, x := range a {
		if x >= 0 && containsInt(b, x) {
			out = append(out, x)
		}
	}
	if len(out) == 0 {
		return []int{-1}
	}
	return out
}
