package sdk_test

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	legantcrypto "github.com/legant-dev/legant/internal/crypto"
	"github.com/legant-dev/legant/internal/delegation"
	"github.com/legant-dev/legant/sdk"
)

// signFeed builds a revocation feed JWT (same shape the issuer publishes) signed
// with the issuer's key, so the SDK verifies it under the JWKS trust root.
func signFeed(t *testing.T, key *rsa.PrivateKey, kid string, ver int64, jtis []string, now time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": testIssuer, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"ver": ver, "jtis": jtis,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRevocationFeed(t *testing.T) {
	key, err := legantcrypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	signer := delegation.NewSigner(testIssuer, testKID, key)
	keys := map[string]*rsa.PublicKey{testKID: &key.PublicKey}

	grant := delegation.NewRootGrant("user:alice", "agent:a", []string{"expenses:read"},
		delegation.Constraints{Resources: []string{testAud}}, time.Hour, now)
	tokRevoked, _ := signer.IssueForGrant(grant, []string{"expenses:read"}, testAud, now)
	tokLive, _ := signer.IssueForGrant(grant, []string{"expenses:read"}, testAud, now)

	// The jti of the to-be-revoked token, read via a plain verifier.
	plain := sdk.NewVerifier(testIssuer, testAud, keys)
	cR, err := plain.Verify(tokRevoked)
	if err != nil {
		t.Fatal(err)
	}
	jtiRevoked := cR.ID

	// Serve a feed listing the revoked jti.
	var feedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(feedBody))
	}))
	defer srv.Close()
	feedBody = signFeed(t, key, testKID, 2, []string{jtiRevoked}, now)

	feed, err := sdk.FetchRevocationFeed(context.Background(), srv.URL, testIssuer, keys)
	if err != nil {
		t.Fatal(err)
	}
	v := sdk.NewVerifier(testIssuer, testAud, keys, sdk.WithRevocationFeed(feed))

	// The revoked token is rejected offline; the live token still verifies.
	if _, err := v.Verify(tokRevoked); !errors.Is(err, sdk.ErrRevoked) {
		t.Errorf("revoked token should return ErrRevoked, got %v", err)
	}
	if _, err := v.Verify(tokLive); err != nil {
		t.Errorf("non-revoked token should verify, got %v", err)
	}

	// Anti-rollback: a feed with a lower version is rejected and the current
	// snapshot is kept (so a replayed old feed can't un-revoke).
	feedBody = signFeed(t, key, testKID, 1, nil, now)
	if err := feed.Refresh(context.Background()); err == nil {
		t.Error("a version regression must be rejected as a rollback")
	}
	if _, err := v.Verify(tokRevoked); !errors.Is(err, sdk.ErrRevoked) {
		t.Error("after a rejected rollback, the revoked token must still be revoked")
	}

	// A newer feed that no longer lists the token un-revokes it (legitimately).
	feedBody = signFeed(t, key, testKID, 3, nil, now)
	if err := feed.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(tokRevoked); err != nil {
		t.Errorf("a newer feed dropping the jti should clear the revocation, got %v", err)
	}
}

func TestRevocationFeedFailClosed(t *testing.T) {
	key, _ := legantcrypto.GenerateRSAKey(2048)
	now := time.Now()
	keys := map[string]*rsa.PublicKey{testKID: &key.PublicKey}
	signer := delegation.NewSigner(testIssuer, testKID, key)
	grant := delegation.NewRootGrant("user:alice", "agent:a", []string{"expenses:read"},
		delegation.Constraints{Resources: []string{testAud}}, time.Hour, now)
	tok, _ := signer.IssueForGrant(grant, []string{"expenses:read"}, testAud, now)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(signFeed(t, key, testKID, 1, nil, now)))
	}))
	defer srv.Close()
	feed, err := sdk.FetchRevocationFeed(context.Background(), srv.URL, testIssuer, keys)
	if err != nil {
		t.Fatal(err)
	}
	// With a 0 max-staleness, the feed is immediately "stale" → fail closed.
	v := sdk.NewVerifier(testIssuer, testAud, keys, sdk.WithRevocationFeed(feed), sdk.WithFeedFailClosed(0))
	if _, err := v.Verify(tok); err == nil {
		t.Error("fail-closed verifier must reject when the feed is stale")
	}
}
