package main

import (
	"context"
	"fmt"
	"time"

	"github.com/legant-dev/legant/internal/config"
	"github.com/legant-dev/legant/internal/db"
	"github.com/legant-dev/legant/internal/delegation"
	"github.com/legant-dev/legant/internal/keystore"
)

// mintWithKeystore mints a delegation token signed with the SERVER's active
// keystore key — the key a running gateway and the resource servers verify
// against — rather than the offline local key. This is the operator path for
// provisioning an agent grant against a live Legant deployment (the issuer and
// signing key come from config + the DB keystore, exactly as `legant gateway`
// loads them).
func mintWithKeystore(user, agent string, scopes []string, audience string, cnst *delegation.Constraints, ttl time.Duration, now time.Time) (string, error) {
	ctx := context.Background()
	cfg, err := config.LoadGateway()
	if err != nil {
		return "", err
	}
	pool, err := db.NewPool(ctx, cfg.Database)
	if err != nil {
		return "", err
	}
	defer pool.Close()
	encKey, err := cfg.Secrets.KeyEncryptionMaterial()
	if err != nil {
		return "", err
	}
	ks, err := keystore.Open(ctx, pool, encKey, cfg.Keystore.RotationOverlap)
	if err != nil {
		return "", err
	}
	if ks.ActiveKID() == "" {
		return "", fmt.Errorf("no active signing key in the keystore (run `legant migrate up`, or start the server once)")
	}
	signer := delegation.NewSigner(cfg.Issuer.URL, ks.ActiveKID(), ks.ActiveSigner())
	return signer.IssueClaims(user, &delegation.ActClaim{Sub: agent}, scopes, audience, cnst, now.Add(ttl), now)
}
