package mcpgw

import (
	"context"
	"testing"
	"time"

	"github.com/legant-dev/legant/internal/revocation"
	"github.com/legant-dev/legant/internal/testsupport"
)

// TestRevocationFeedMode covers the in-memory revocation mode (WithRevocationRefresh)
// and the configurable downstream TTL — exercising tokenActive directly.
func TestRevocationFeedMode(t *testing.T) {
	pool := testsupport.DB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	future := time.Now().Add(time.Hour)
	if _, err := pool.Exec(ctx,
		`INSERT INTO exchanged_tokens (jti, subject, audience, scopes, expires_at, revoked_at)
		 VALUES ('rev-1','user','api','{x}',$1, now())`, future); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO exchanged_tokens (jti, subject, audience, scopes, expires_at)
		 VALUES ('live-1','user','api','{x}',$1)`, future); err != nil {
		t.Fatal(err)
	}

	gw, err := NewGateway("https://issuer.test", nil, revocation.NewStore(pool, nil), pool, nil, nil,
		WithRevocationRefresh(time.Minute), WithDownstreamTTL(15*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if gw.downstreamTTL != 15*time.Second {
		t.Errorf("WithDownstreamTTL not applied: %v", gw.downstreamTTL)
	}

	// Fails closed before the revoked set has loaded.
	if ok, err := gw.tokenActive(ctx, "live-1"); ok || err == nil {
		t.Error("feed mode must fail closed before the revoked set loads")
	}

	if err := gw.StartRevocationRefresh(ctx); err != nil {
		t.Fatal(err)
	}

	// After loading: a revoked token is inactive; a live one is active; a
	// validly-signed-but-unknown jti is active (only revoked jtis are tracked).
	if ok, _ := gw.tokenActive(ctx, "rev-1"); ok {
		t.Error("a revoked token must be inactive in feed mode")
	}
	if ok, _ := gw.tokenActive(ctx, "live-1"); !ok {
		t.Error("a live token must be active in feed mode")
	}
	if ok, _ := gw.tokenActive(ctx, "never-minted"); !ok {
		t.Error("an unknown jti is active in feed mode (the set holds only revoked ids)")
	}
}

// TestDefaultRevocationModeUsesStore confirms the default gateway (no feed option)
// has no in-memory cache and falls through to the per-call store.
func TestDefaultRevocationModeUsesStore(t *testing.T) {
	gw, err := NewGateway("https://issuer.test", nil, revocation.NewStore(nil, nil), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if gw.revoked != nil {
		t.Error("default mode must not allocate an in-memory revoked cache")
	}
	if gw.downstreamTTL != 60*time.Second {
		t.Errorf("default downstream TTL should be 60s, got %v", gw.downstreamTTL)
	}
}
