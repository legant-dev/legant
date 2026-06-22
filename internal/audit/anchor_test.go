package audit_test

import (
	"context"
	"crypto/rsa"
	"fmt"
	"testing"

	legantcrypto "github.com/legant-dev/legant/internal/crypto"

	"github.com/legant-dev/legant/internal/audit"
	"github.com/legant-dev/legant/internal/testsupport"
)

type testSigner struct {
	kid string
	key *rsa.PrivateKey
}

func (s testSigner) ActiveKID() string             { return s.kid }
func (s testSigner) ActiveSigner() *rsa.PrivateKey { return s.key }

func TestSignedAnchorAndOffBoxCheck(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := pool.Exec(ctx, `INSERT INTO audit_events (actor_type, action) VALUES ('system', $1)`, fmt.Sprintf("e%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	key, err := legantcrypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	signer := testSigner{kid: "anchor-1", key: key}
	keys := map[string]*rsa.PublicKey{"anchor-1": &key.PublicKey}

	rec, err := audit.AnchorSigned(ctx, pool, signer)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Count != 5 {
		t.Fatalf("anchor count = %d, want 5", rec.Count)
	}
	if err := audit.VerifyAnchorSignature(rec, keys); err != nil {
		t.Fatalf("a freshly signed anchor must verify: %v", err)
	}

	// The live chain matches its own anchor.
	res, err := audit.CheckAgainstAnchor(ctx, pool, rec, keys)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("chain should match the anchor, got break %q", res.BreakKind)
	}

	// A forged signature is rejected.
	bad := rec
	if bad.Signature[0] == 'A' {
		bad.Signature = "B" + bad.Signature[1:]
	} else {
		bad.Signature = "A" + bad.Signature[1:]
	}
	if err := audit.VerifyAnchorSignature(bad, keys); err == nil {
		t.Error("a forged anchor signature must be rejected")
	}
	if _, err := audit.CheckAgainstAnchor(ctx, pool, bad, keys); err == nil {
		t.Error("CheckAgainstAnchor must reject a forged signature before touching the chain")
	}

	// Tampering a row is caught against the anchor.
	if _, err := pool.Exec(ctx, `UPDATE audit_events SET action = 'forged' WHERE seq = (SELECT min(seq) FROM audit_events)`); err != nil {
		t.Fatal(err)
	}
	res, _ = audit.CheckAgainstAnchor(ctx, pool, rec, keys)
	if res.OK {
		t.Error("a tampered row must fail the off-box anchor check")
	}
}

// The off-box anchor catches truncation even when the attacker wipes BOTH the
// tail events AND the database's own audit_anchors table.
func TestOffBoxAnchorDetectsTruncationDespiteForgedAnchorTable(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		if _, err := pool.Exec(ctx, `INSERT INTO audit_events (actor_type, action) VALUES ('system', $1)`, fmt.Sprintf("e%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	key, _ := legantcrypto.GenerateRSAKey(2048)
	signer := testSigner{kid: "anchor-1", key: key}
	keys := map[string]*rsa.PublicKey{"anchor-1": &key.PublicKey}

	rec, err := audit.AnchorSigned(ctx, pool, signer)
	if err != nil {
		t.Fatal(err)
	}

	// Attacker deletes the head event AND wipes the in-DB anchor table.
	if _, err := pool.Exec(ctx, `DELETE FROM audit_events WHERE seq = (SELECT max(seq) FROM audit_events)`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM audit_anchors`); err != nil {
		t.Fatal(err)
	}

	res, err := audit.CheckAgainstAnchor(ctx, pool, rec, keys)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.BreakKind != "truncation" {
		t.Fatalf("the off-box anchor must detect truncation; got OK=%v kind=%q", res.OK, res.BreakKind)
	}
}
