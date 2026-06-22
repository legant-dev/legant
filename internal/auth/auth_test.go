package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	legantcrypto "github.com/legant-dev/legant/internal/crypto"
)

// ID tokens must carry the active key id so verifiers can select the right JWKS
// key (and reject tokens signed by a retired key).
func TestNewSessionStampsActiveKID(t *testing.T) {
	SetSigningKID("rk_active123")
	sess := NewSession("user:alice")
	kid, _ := sess.Headers.Extra["kid"].(string)
	if kid != "rk_active123" {
		t.Fatalf("ID token header kid = %q, want rk_active123", kid)
	}
}

// The JWKS must publish every active key, and each must reconstruct exactly to
// the source public key (correct base64url modulus/exponent).
func TestJWKSHandlerServesAllKeysReconstructable(t *testing.T) {
	k1, _ := legantcrypto.GenerateRSAKey(2048)
	k2, _ := legantcrypto.GenerateRSAKey(2048)
	keys := map[string]*rsa.PublicKey{"kid-1": &k1.PublicKey, "kid-2": &k2.PublicKey}

	rec := httptest.NewRecorder()
	JWKSHandler(func() map[string]*rsa.PublicKey { return keys })(
		rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp JWKSResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Keys) != 2 {
		t.Fatalf("want 2 keys, got %d", len(resp.Keys))
	}

	for _, jwk := range resp.Keys {
		want, ok := keys[jwk.Kid]
		if !ok {
			t.Fatalf("served unexpected kid %q", jwk.Kid)
		}
		if jwk.Kty != "RSA" || jwk.Use != "sig" || jwk.Alg != "RS256" {
			t.Fatalf("kid %q wrong JWK metadata: %+v", jwk.Kid, jwk)
		}
		nb, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			t.Fatal(err)
		}
		eb, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil {
			t.Fatal(err)
		}
		if new(big.Int).SetBytes(nb).Cmp(want.N) != 0 {
			t.Fatalf("kid %q modulus does not round-trip", jwk.Kid)
		}
		if int(new(big.Int).SetBytes(eb).Int64()) != want.E {
			t.Fatalf("kid %q exponent does not round-trip", jwk.Kid)
		}
	}
}

// Discovery must advertise only what the server actually issues — no email/profile
// claims or scopes it never populates — and S256-only PKCE.
func TestBuildMetadataAdvertisesOnlyIssuedClaims(t *testing.T) {
	md := BuildMetadata("https://issuer.test")
	for _, c := range md.ClaimsSupported {
		switch c {
		case "email", "email_verified", "name", "profile":
			t.Fatalf("discovery advertises unissued claim %q", c)
		}
	}
	for _, s := range md.ScopesSupported {
		if s == "email" || s == "profile" {
			t.Fatalf("discovery advertises unissued scope %q", s)
		}
	}
	if len(md.CodeChallengeMethodsSupported) != 1 || md.CodeChallengeMethodsSupported[0] != "S256" {
		t.Fatalf("must advertise S256-only PKCE, got %v", md.CodeChallengeMethodsSupported)
	}
}
