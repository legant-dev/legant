package keystore_test

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/legant-dev/legant/internal/delegation"
	"github.com/legant-dev/legant/internal/keystore"
	"github.com/legant-dev/legant/internal/testsupport"
)

func encKey() []byte   { return bytes.Repeat([]byte("0123456789abcdef"), 2) } // 32 bytes
func wrongKey() []byte { return bytes.Repeat([]byte("WRONGWRONGWRONGW"), 2) }

// The whole point of the keystore: a key generated once survives a "restart"
// (a fresh keystore instance over the same DB) instead of being regenerated, and
// a token signed by one instance verifies against another instance's keys.
func TestBootstrapAndPersistAcrossRestart(t *testing.T) {
	pool := testsupport.DB(t)
	testsupport.Truncate(t, pool, "signing_keys")
	ctx := context.Background()

	ks1, err := keystore.Open(ctx, pool, encKey(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	kid := ks1.ActiveKID()
	if kid == "" {
		t.Fatal("expected an active key after bootstrap")
	}

	ks2, err := keystore.Open(ctx, pool, encKey(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if ks2.ActiveKID() != kid {
		t.Fatalf("key did not survive restart: got %q, want %q", ks2.ActiveKID(), kid)
	}

	signer := delegation.NewSigner("https://legant.test", ks1.ActiveKID(), ks1.ActiveSigner())
	g := delegation.NewRootGrant("user:alice", "agent:a", []string{"x"}, delegation.Constraints{}, time.Hour, time.Now())
	tok, err := signer.IssueForGrant(g, []string{"x"}, "api", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	v := delegation.NewVerifier("https://legant.test", ks2.VerifierKeys())
	if _, err := v.Verify(tok, "api"); err != nil {
		t.Fatalf("token signed by instance 1 must verify on instance 2: %v", err)
	}
}

func TestRotationPublishesBothKeysDuringOverlap(t *testing.T) {
	pool := testsupport.DB(t)
	testsupport.Truncate(t, pool, "signing_keys")
	ctx := context.Background()

	ks, err := keystore.Open(ctx, pool, encKey(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	kid1 := ks.ActiveKID()

	signer1 := delegation.NewSigner("iss", kid1, ks.ActiveSigner())
	g := delegation.NewRootGrant("u", "a", []string{"x"}, delegation.Constraints{}, time.Hour, time.Now())
	tok1, err := signer1.IssueForGrant(g, []string{"x"}, "api", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	kid2, err := ks.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if kid2 == kid1 {
		t.Fatal("rotation must produce a new kid")
	}
	if ks.ActiveKID() != kid2 {
		t.Fatalf("active key after rotation should be %q, got %q", kid2, ks.ActiveKID())
	}

	keys := ks.VerifierKeys()
	if _, ok := keys[kid1]; !ok {
		t.Fatal("old key must remain published during the overlap window")
	}
	if _, ok := keys[kid2]; !ok {
		t.Fatal("new key must be published")
	}

	v := delegation.NewVerifier("iss", ks.VerifierKeys())
	if _, err := v.Verify(tok1, "api"); err != nil {
		t.Fatalf("pre-rotation token must still verify during overlap: %v", err)
	}
}

func TestWrongEncryptionKeyFailsClosed(t *testing.T) {
	pool := testsupport.DB(t)
	testsupport.Truncate(t, pool, "signing_keys")
	ctx := context.Background()

	if _, err := keystore.Open(ctx, pool, encKey(), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := keystore.Open(ctx, pool, wrongKey(), time.Hour); err == nil {
		t.Fatal("opening with the wrong key-encryption secret must fail, not silently regenerate")
	}
}

func TestReencryptRewrapsKeys(t *testing.T) {
	pool := testsupport.DB(t)
	testsupport.Truncate(t, pool, "signing_keys")
	ctx := context.Background()

	ks, err := keystore.Open(ctx, pool, encKey(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	kid := ks.ActiveKID()
	newKey := bytes.Repeat([]byte("NEWNEWNEWNEWNEWN"), 2)
	if err := ks.Reencrypt(ctx, newKey); err != nil {
		t.Fatal(err)
	}
	// Old envelope key can no longer open the store; the new one can.
	if _, err := keystore.Open(ctx, pool, encKey(), time.Hour); err == nil {
		t.Fatal("old key-encryption secret must no longer decrypt after reencrypt")
	}
	ks2, err := keystore.Open(ctx, pool, newKey, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if ks2.ActiveKID() != kid {
		t.Fatalf("reencrypt must preserve key identity: got %q, want %q", ks2.ActiveKID(), kid)
	}
}

// Two cold replicas opening against an empty table concurrently must converge on
// a single first key, not each mint their own (which would make them sign under
// different kids). The advisory-lock bootstrap guarantees this.
func TestConcurrentBootstrapConvergesOnOneKey(t *testing.T) {
	pool := testsupport.DB(t)
	testsupport.Truncate(t, pool, "signing_keys")
	ctx := context.Background()

	const n = 8
	kids := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ks, err := keystore.Open(ctx, pool, encKey(), time.Hour)
			if err != nil {
				errs[i] = err
				return
			}
			kids[i] = ks.ActiveKID()
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("replica %d: %v", i, err)
		}
	}
	for i, k := range kids {
		if k != kids[0] {
			t.Fatalf("replica %d bootstrapped a different kid: %q != %q", i, k, kids[0])
		}
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM signing_keys WHERE active AND use_type='sig'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected exactly one active key after concurrent bootstrap, got %d", count)
	}
}

func TestPruneRemovesRetiredKeepsActive(t *testing.T) {
	pool := testsupport.DB(t)
	testsupport.Truncate(t, pool, "signing_keys")
	ctx := context.Background()

	ks, err := keystore.Open(ctx, pool, encKey(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	old := ks.ActiveKID()
	newKID, err := ks.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Backdate the old key's retirement so it is eligible for pruning.
	if _, err := pool.Exec(ctx, `UPDATE signing_keys SET expires_at = now() - interval '1 hour' WHERE id=$1`, old); err != nil {
		t.Fatal(err)
	}

	pruned, err := ks.Prune(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 1 {
		t.Fatalf("expected to prune exactly the retired key, pruned %d", pruned)
	}

	keys := ks.VerifierKeys()
	if _, ok := keys[old]; ok {
		t.Fatal("retired key must be gone after prune")
	}
	if _, ok := keys[newKID]; !ok {
		t.Fatal("active key must survive prune")
	}
	if ks.ActiveKID() != newKID {
		t.Fatalf("active key changed unexpectedly: %q", ks.ActiveKID())
	}
}

// Reencrypt must re-wrap every key, not just the active one (exercises the
// multi-row transactional path).
func TestReencryptRewrapsMultipleKeys(t *testing.T) {
	pool := testsupport.DB(t)
	testsupport.Truncate(t, pool, "signing_keys")
	ctx := context.Background()

	ks, err := keystore.Open(ctx, pool, encKey(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	kid1 := ks.ActiveKID()
	kid2, err := ks.Rotate(ctx) // now two keys are published
	if err != nil {
		t.Fatal(err)
	}

	newKey := bytes.Repeat([]byte("ABCDABCDABCDABCD"), 2)
	if err := ks.Reencrypt(ctx, newKey); err != nil {
		t.Fatal(err)
	}

	ks2, err := keystore.Open(ctx, pool, newKey, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keys := ks2.VerifierKeys()
	if _, ok := keys[kid1]; !ok {
		t.Fatal("first key must survive a multi-key reencrypt")
	}
	if _, ok := keys[kid2]; !ok {
		t.Fatal("second key must survive a multi-key reencrypt")
	}
}
