// Command gen mints golden conformance vectors with the REAL Legant signer and
// writes clients/conformance/vectors.json. Every language SDK (Go, TypeScript,
// Python) verifies the same vectors, so the implementations cannot silently
// drift. Regenerate with: go run ./clients/conformance/gen
//
// Timestamps are fixed absolute values (far past / far future) so the vectors
// stay valid against real wall-clock time without injecting a clock: "valid"
// tokens expire in 2099, "expired" ones in 2000.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/legant-dev/legant/internal/delegation"
)

const (
	issuer   = "https://legant.test"
	audience = "https://finance.example/" // canonical form the issuer mints
	kid      = "conf-key-1"
	denyAll  = "\x00legant:deny-all" // must match internal/delegation + sdk
)

var (
	now        = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	validExp   = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	expiredExp = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
)

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}
type verifyVec struct {
	Name          string `json:"name"`
	Token         string `json:"token"`
	Valid         bool   `json:"valid"`
	ErrorContains string `json:"errorContains,omitempty"`
	Provenance    string `json:"provenance,omitempty"`
}
type audVec struct {
	Name               string `json:"name"`
	ConfiguredAudience string `json:"configuredAudience"`
	Token              string `json:"token"`
	Valid              bool   `json:"valid"`
}
type actionVec struct {
	Scope    string  `json:"scope"`
	Amount   float64 `json:"amount,omitempty"`
	Category string  `json:"category,omitempty"`
	Tool     string  `json:"tool,omitempty"`
	Resource string  `json:"resource,omitempty"`
	At       string  `json:"at,omitempty"` // RFC3339; empty = now
}
type authVec struct {
	Name   string    `json:"name"`
	Token  string    `json:"token"`
	Action actionVec `json:"action"`
	Allow  bool      `json:"allow"`
}
type revVec struct {
	RevokedToken string `json:"revokedToken"`
	LiveToken    string `json:"liveToken"`
	RevokedJTI   string `json:"revokedJti"`
	LiveJTI      string `json:"liveJti"`
	Feed         string `json:"feed"`         // ver 5, lists revokedJti
	FeedRollback string `json:"feedRollback"` // ver 3 — must be rejected after ver 5
	FeedNewer    string `json:"feedNewer"`    // ver 6, empty — un-revokes
}
type vectors struct {
	Issuer    string          `json:"issuer"`
	Audience  string          `json:"audience"`
	JWKS      json.RawMessage `json:"jwks"`
	Verify    []verifyVec     `json:"verify"`
	Audience2 []audVec        `json:"audienceCanonicalization"`
	Authorize []authVec       `json:"authorize"`
	Revoke    revVec          `json:"revocation"`
}

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	signer := delegation.NewSigner(issuer, kid, key)

	f64 := func(v float64) *float64 { return &v }
	jtiOf := func(tok string) string {
		var c struct {
			JTI string `json:"jti"`
		}
		parts := strings.Split(tok, ".")
		b, _ := base64.RawURLEncoding.DecodeString(parts[1])
		_ = json.Unmarshal(b, &c)
		return c.JTI
	}
	// mint a delegation token with explicit claims via the REAL signer.
	mint := func(subject string, act *delegation.ActClaim, scope, aud string, cnst *delegation.Constraints, exp time.Time) string {
		tok, err := signer.IssueClaims(subject, act, strings.Fields(scope), aud, cnst, exp, now)
		must(err)
		return tok
	}

	out := vectors{Issuer: issuer, Audience: audience}
	out.JWKS = mustJSON(buildJWKS(&key.PublicKey))

	assistant := &delegation.ActClaim{Sub: "agent:assistant"}
	chain := &delegation.ActClaim{Sub: "agent:ocr", Act: &delegation.ActClaim{Sub: "agent:assistant"}}

	// ---- verify vectors ----
	valid := mint("user:alice", assistant, "expenses:read expenses:submit", audience, nil, validExp)
	multi := mint("user:alice", chain, "expenses:read", audience, nil, validExp)
	out.Verify = []verifyVec{
		{Name: "valid single-hop", Token: valid, Valid: true, Provenance: "user:alice -> agent:assistant"},
		{Name: "valid multi-hop chain", Token: multi, Valid: true, Provenance: "user:alice -> agent:assistant -> agent:ocr"},
		{Name: "expired", Token: mint("user:alice", assistant, "expenses:read", audience, nil, expiredExp), Valid: false, ErrorContains: "expired"},
		{Name: "wrong audience", Token: mint("user:alice", assistant, "expenses:read", "https://other.example/", nil, validExp), Valid: false, ErrorContains: "audience"},
		{Name: "no act claim (not a delegation token)", Token: mint("user:alice", nil, "expenses:read", audience, nil, validExp), Valid: false, ErrorContains: "act"},
		{Name: "wrong issuer", Token: mintWith(key, kid, "https://evil.test", audience, validExp), Valid: false, ErrorContains: "iss"},
		{Name: "unknown kid", Token: mintWith(key, "unknown-kid", issuer, audience, validExp), Valid: false, ErrorContains: "key"},
		{Name: "tampered signature", Token: tamper(valid), Valid: false, ErrorContains: "signature"},
		{Name: "not yet valid (nbf in future)", Token: mintNbf(key, validExp), Valid: false, ErrorContains: ""},
	}

	// ---- audience canonicalization (token aud is the canonical finance) ----
	out.Audience2 = []audVec{
		{Name: "exact canonical", ConfiguredAudience: "https://finance.example/", Token: valid, Valid: true},
		{Name: "no trailing slash", ConfiguredAudience: "https://finance.example", Token: valid, Valid: true},
		{Name: "uppercase host + explicit :443", ConfiguredAudience: "https://FINANCE.example:443", Token: valid, Valid: true},
		{Name: "different host", ConfiguredAudience: "https://other.example/", Token: valid, Valid: false},
	}

	// ---- authorize vectors ----
	// atok has value/list constraints but NO time window, so its cases are
	// clock-independent. twtok carries only a time window, exercised with an
	// explicit At so its cases are deterministic too.
	cnst := &delegation.Constraints{
		MaxAmount:  f64(500),
		Categories: []string{"travel", "meals"},
		Tools:      []string{"read_file"},
		Resources:  []string{audience},
	}
	atok := mint("user:alice", assistant, "expenses:read expenses:submit", audience, cnst, validExp)
	cnstTW := &delegation.Constraints{TimeWindow: &delegation.TimeWindow{Weekdays: []int{1, 2, 3, 4, 5}, StartMin: 540, EndMin: 1020}} // Mon–Fri 09:00–17:00 UTC
	twtok := mint("user:alice", assistant, "expenses:read", audience, cnstTW, validExp)
	deny := mint("user:alice", assistant, "x", audience, &delegation.Constraints{Categories: []string{denyAll}}, validExp)
	out.Authorize = []authVec{
		{Name: "within all constraints", Token: atok, Action: actionVec{Scope: "expenses:submit", Amount: 120, Category: "travel"}, Allow: true},
		{Name: "amount over max", Token: atok, Action: actionVec{Scope: "expenses:submit", Amount: 600, Category: "travel"}, Allow: false},
		{Name: "category not allowed", Token: atok, Action: actionVec{Scope: "expenses:submit", Amount: 50, Category: "entertainment"}, Allow: false},
		{Name: "missing scope", Token: atok, Action: actionVec{Scope: "expenses:delete"}, Allow: false},
		{Name: "tool allowed", Token: atok, Action: actionVec{Scope: "expenses:read", Tool: "read_file"}, Allow: true},
		{Name: "tool not allowed", Token: atok, Action: actionVec{Scope: "expenses:read", Tool: "drop_table"}, Allow: false},
		{Name: "resource canonical match", Token: atok, Action: actionVec{Scope: "expenses:read", Resource: "https://finance.example"}, Allow: true},
		{Name: "resource not allowed", Token: atok, Action: actionVec{Scope: "expenses:read", Resource: "https://evil.example/"}, Allow: false},
		{Name: "time window inside", Token: twtok, Action: actionVec{Scope: "expenses:read", At: "2020-01-06T10:00:00Z"}, Allow: true},       // Mon 10:00
		{Name: "time window after hours", Token: twtok, Action: actionVec{Scope: "expenses:read", At: "2020-01-06T18:00:00Z"}, Allow: false}, // Mon 18:00
		{Name: "time window weekend", Token: twtok, Action: actionVec{Scope: "expenses:read", At: "2020-01-04T10:00:00Z"}, Allow: false},     // Sat
		{Name: "deny-all sentinel category", Token: deny, Action: actionVec{Scope: "x", Category: "travel"}, Allow: false},
	}

	// ---- revocation feed ----
	revoked := mint("user:alice", assistant, "expenses:read", audience, nil, validExp)
	live := mint("user:alice", assistant, "expenses:read", audience, nil, validExp)
	rj, lj := jtiOf(revoked), jtiOf(live)
	out.Revoke = revVec{
		RevokedToken: revoked, LiveToken: live, RevokedJTI: rj, LiveJTI: lj,
		Feed:         feed(key, 5, []string{rj}),
		FeedRollback: feed(key, 3, []string{rj}),
		FeedNewer:    feed(key, 6, []string{}),
	}

	b, err := json.MarshalIndent(out, "", "  ")
	must(err)
	must(os.WriteFile("clients/conformance/vectors.json", append(b, '\n'), 0o644))
	println("wrote clients/conformance/vectors.json")
}

// buildJWKS renders an RSA public key as a one-key JWKS document.
func buildJWKS(pub *rsa.PublicKey) map[string]any {
	eb := big.NewInt(int64(pub.E)).Bytes()
	return map[string]any{"keys": []jwk{{
		Kty: "RSA", Kid: kid, Use: "sig", Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(eb),
	}}}
}

// feed signs a revocation-feed JWS exactly like internal/revocation.Feed.
func feed(key *rsa.PrivateKey, ver int64, jtis []string) string {
	claims := jwt.MapClaims{
		"iss": issuer, "iat": now.Unix(), "exp": validExp.Unix(),
		"ver": ver, "jtis": jtis,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	must(err)
	return s
}

// mintWith signs a delegation-shaped token with an arbitrary kid/issuer (for the
// unknown-kid and wrong-issuer cases).
func mintWith(key *rsa.PrivateKey, tokKid, iss, aud string, exp time.Time) string {
	claims := jwt.MapClaims{
		"iss": iss, "sub": "user:alice", "aud": aud,
		"exp": exp.Unix(), "iat": now.Unix(), "jti": "x",
		"scope": "expenses:read", "act": map[string]any{"sub": "agent:assistant"},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = tokKid
	s, err := tok.SignedString(key)
	must(err)
	return s
}

// mintNbf mints a token whose nbf is in the future (not yet valid).
func mintNbf(key *rsa.PrivateKey, exp time.Time) string {
	claims := jwt.MapClaims{
		"iss": issuer, "sub": "user:alice", "aud": audience,
		"exp": exp.Unix(), "iat": now.Unix(), "nbf": validExp.Unix(), "jti": "x",
		"scope": "expenses:read", "act": map[string]any{"sub": "agent:assistant"},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	must(err)
	return s
}

// tamper flips the last character of the signature so verification must fail.
func tamper(tok string) string {
	if tok == "" {
		return tok
	}
	last := tok[len(tok)-1]
	repl := byte('A')
	if last == 'A' {
		repl = 'B'
	}
	return tok[:len(tok)-1] + string(repl)
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	must(err)
	return b
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
