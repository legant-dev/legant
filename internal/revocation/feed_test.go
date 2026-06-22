package revocation_test

import (
	"context"
	"crypto/rsa"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"

	legantcrypto "github.com/legant-dev/legant/internal/crypto"
	"github.com/legant-dev/legant/internal/db"
	"github.com/legant-dev/legant/internal/revocation"
	"github.com/legant-dev/legant/internal/testsupport"
	"github.com/legant-dev/legant/sdk"
)

// fixedSigner is a FeedSigner backed by one in-memory key (the production signer
// is the keystore, which also satisfies the same interface).
type fixedSigner struct {
	kid string
	key *rsa.PrivateKey
}

func (s fixedSigner) ActiveKID() string             { return s.kid }
func (s fixedSigner) ActiveSigner() *rsa.PrivateKey { return s.key }

func TestFeedBuildAndConsume(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	store := revocation.NewStore(pool, nil)

	var userID, agentID, delegationID string
	if err := pool.QueryRow(ctx, `INSERT INTO users (email,status) VALUES ('feed@x.com','active') RETURNING id::text`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO agents (name,type) VALUES ('a','ai_agent') RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO delegation_chains (delegator_id, delegatee_agent_id, scopes) VALUES ($1,$2,'{x}') RETURNING id::text`,
		userID, agentID).Scan(&delegationID); err != nil {
		t.Fatal(err)
	}

	record := func(jti string, exp time.Time) {
		t.Helper()
		err := db.WithTx(ctx, pool, func(tx pgx.Tx) error {
			return store.RecordTx(ctx, tx, revocation.Record{
				JTI: jti, DelegationID: &delegationID, Subject: "user:" + userID, AgentID: &agentID,
				ActorChain: []string{"agent:" + agentID}, Audience: "api", Scopes: []string{"x"}, ExpiresAt: exp,
			})
		})
		if err != nil {
			t.Fatalf("record %s: %v", jti, err)
		}
	}

	future := time.Now().Add(time.Hour)
	record("feed-revoked", future)
	record("feed-live", future)
	record("feed-revoked-expired", time.Now().Add(-time.Hour))
	if _, err := store.Revoke(ctx, "feed-revoked"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Revoke(ctx, "feed-revoked-expired"); err != nil {
		t.Fatal(err)
	}

	key, err := legantcrypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid, issuer = "feed-kid", "https://legant.test"
	feed := revocation.NewFeed(pool, fixedSigner{kid: kid, key: key}, issuer)

	signed, err := feed.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// The published feed verifies under the signer's public key and lists exactly
	// the revoked-and-unexpired token — not the live one, not the expired one.
	var claims revocation.FeedClaims
	if _, err := jwt.ParseWithClaims(string(signed), &claims, func(*jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(issuer)); err != nil {
		t.Fatalf("feed should verify under the signer key: %v", err)
	}
	got := map[string]bool{}
	for _, j := range claims.JTIs {
		got[j] = true
	}
	if !got["feed-revoked"] {
		t.Error("feed must list a revoked, unexpired token")
	}
	if got["feed-live"] {
		t.Error("feed must NOT list a live token")
	}
	if got["feed-revoked-expired"] {
		t.Error("feed must NOT list an already-expired token (TTL is the backstop)")
	}
	if claims.Version < 1 {
		t.Errorf("feed version must be a positive monotonic counter, got %d", claims.Version)
	}

	// End to end: the standalone SDK consumes the served feed and rejects the
	// revoked token while accepting an unknown (live) one.
	srv := httptest.NewServer(feed.Handler())
	defer srv.Close()
	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}
	rf, err := sdk.FetchRevocationFeed(ctx, srv.URL, issuer, keys)
	if err != nil {
		t.Fatal(err)
	}
	if !rf.IsRevoked("feed-revoked") {
		t.Error("SDK feed client must see the revoked token")
	}
	if rf.IsRevoked("feed-live") {
		t.Error("SDK feed client must not flag a live token")
	}
}
