package sdk_test

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	legantcrypto "github.com/legant-dev/legant/internal/crypto"
	"github.com/legant-dev/legant/internal/delegation"
	"github.com/legant-dev/legant/sdk"
)

const (
	testIssuer = "https://legant.test"
	testAud    = "https://finance-api.test/"
	testKID    = "test-key-1"
)

// mintToken builds a delegation grant with the REAL internal signer and returns
// the composite token plus the public key that verifies it. The SDK is then used
// to verify — proving the standalone SDK and Legant's internals agree on the wire
// format. If the claim shape ever drifts, this test fails.
func mintToken(t *testing.T) (string, *rsa.PublicKey) {
	t.Helper()
	key, err := legantcrypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now()
	max := 500.0
	signer := delegation.NewSigner(testIssuer, testKID, key)
	grant := delegation.NewRootGrant("user:alice", "agent:assistant",
		[]string{"expenses:read", "expenses:submit"},
		delegation.Constraints{
			MaxAmount:  &max,
			Categories: []string{"travel", "meals"},
			Tools:      []string{"report"},
			Resources:  []string{testAud},
		}, time.Hour, now)
	tok, err := signer.IssueForGrant(grant, []string{"expenses:read", "expenses:submit"}, testAud, now)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	return tok, &key.PublicKey
}

func TestSDKVerifiesInternalToken(t *testing.T) {
	tok, pub := mintToken(t)
	v := sdk.NewVerifier(testIssuer, testAud, map[string]*rsa.PublicKey{testKID: pub})

	claims, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != "user:alice" {
		t.Errorf("subject = %q, want user:alice", claims.Subject)
	}
	if got := claims.Provenance(); got != "user:alice -> agent:assistant" {
		t.Errorf("provenance = %q, want user:alice -> agent:assistant", got)
	}
	if claims.Act == nil || claims.Act.Sub != "agent:assistant" {
		t.Errorf("act = %+v, want agent:assistant", claims.Act)
	}
}

func TestSDKAuthorize(t *testing.T) {
	tok, pub := mintToken(t)
	v := sdk.NewVerifier(testIssuer, testAud, map[string]*rsa.PublicKey{testKID: pub})
	claims, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	tests := []struct {
		name    string
		action  sdk.Action
		wantErr bool
	}{
		{"in-bounds travel expense", sdk.Action{Scope: "expenses:submit", Amount: 120, Category: "travel"}, false},
		{"read scope present", sdk.Action{Scope: "expenses:read"}, false},
		{"over max_amount", sdk.Action{Scope: "expenses:submit", Amount: 900, Category: "travel"}, true},
		{"category not allowed", sdk.Action{Scope: "expenses:submit", Amount: 50, Category: "office"}, true},
		{"scope never delegated", sdk.Action{Scope: "expenses:approve"}, true},
		{"tool allowed", sdk.Action{Scope: "expenses:read", Tool: "report"}, false},
		{"tool not allowed", sdk.Action{Scope: "expenses:read", Tool: "delete"}, true},
		{"resource allowed", sdk.Action{Scope: "expenses:read", Resource: testAud}, false},
		{"resource not allowed", sdk.Action{Scope: "expenses:read", Resource: "https://other.test/"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := claims.Authorize(tc.action)
			if tc.wantErr != (err != nil) {
				t.Errorf("Authorize(%+v) err = %v, wantErr = %v", tc.action, err, tc.wantErr)
			}
		})
	}
}

func TestSDKTimeWindow(t *testing.T) {
	key, err := legantcrypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	signer := delegation.NewSigner(testIssuer, testKID, key)
	grant := delegation.NewRootGrant("user:alice", "agent:assistant",
		[]string{"expenses:read"},
		delegation.Constraints{
			Resources:  []string{testAud},
			TimeWindow: &delegation.TimeWindow{StartMin: 9 * 60, EndMin: 17 * 60, TZ: "UTC"},
		}, time.Hour, now)
	tok, err := signer.IssueForGrant(grant, []string{"expenses:read"}, testAud, now)
	if err != nil {
		t.Fatal(err)
	}
	v := sdk.NewVerifier(testIssuer, testAud, map[string]*rsa.PublicKey{testKID: &key.PublicKey})
	claims, err := v.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if err := claims.Authorize(sdk.Action{Scope: "expenses:read", At: time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)}); err != nil {
		t.Errorf("in-window action should pass: %v", err)
	}
	if err := claims.Authorize(sdk.Action{Scope: "expenses:read", At: time.Date(2026, 6, 15, 20, 0, 0, 0, time.UTC)}); err == nil {
		t.Error("out-of-window action should be denied by the SDK offline")
	}
}

func TestSDKAudienceCanonicalization(t *testing.T) {
	// The issuer mints the canonical aud "https://finance-api.test/" (trailing
	// slash). An integrator who constructs the audience by hand in any of these
	// equivalent forms must still verify successfully.
	tok, pub := mintToken(t)
	for _, aud := range []string{
		"https://finance-api.test/",     // exact canonical
		"https://finance-api.test",      // no trailing slash
		"https://FINANCE-API.test/",     // upper-case host
		"https://finance-api.test:443/", // explicit default port
	} {
		v := sdk.NewVerifier(testIssuer, aud, map[string]*rsa.PublicKey{testKID: pub})
		if _, err := v.Verify(tok); err != nil {
			t.Errorf("audience %q should match canonical token aud, got: %v", aud, err)
		}
	}
}

func TestSDKRejectsWrongAudience(t *testing.T) {
	tok, pub := mintToken(t)
	v := sdk.NewVerifier(testIssuer, "https://attacker.test/", map[string]*rsa.PublicKey{testKID: pub})
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("expected audience mismatch to fail verification")
	}
}

func TestSDKRejectsUnknownKID(t *testing.T) {
	tok, pub := mintToken(t)
	// Verifier holds the key under a DIFFERENT kid than the token's header.
	v := sdk.NewVerifier(testIssuer, testAud, map[string]*rsa.PublicKey{"other-kid": pub})
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("expected unknown-kid token to fail closed")
	}
}

func TestSDKRejectsWrongIssuer(t *testing.T) {
	tok, pub := mintToken(t)
	v := sdk.NewVerifier("https://not-legant.test", testAud, map[string]*rsa.PublicKey{testKID: pub})
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("expected issuer mismatch to fail verification")
	}
}

func TestParseJWKSRoundTrip(t *testing.T) {
	tok, pub := mintToken(t)

	// Publish the public key as a JWKS document, parse it back, and verify a real
	// token with the parsed key — the path a resource server takes via FetchJWKS.
	jwks, _ := json.Marshal(map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"kid": testKID,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})

	keys, err := sdk.ParseJWKS(jwks)
	if err != nil {
		t.Fatalf("parse jwks: %v", err)
	}
	if len(keys) != 1 || keys[testKID] == nil {
		t.Fatalf("expected one key under %q, got %v", testKID, keys)
	}
	v := sdk.NewVerifier(testIssuer, testAud, keys)
	if _, err := v.Verify(tok); err != nil {
		t.Errorf("verify with JWKS-parsed key: %v", err)
	}
}
