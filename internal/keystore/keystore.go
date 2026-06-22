// Package keystore is the single source of signing material for Legant. It loads
// active signing keys from the database — decrypting their private keys with an
// envelope key derived from configuration — caches them in memory, and supports
// rotation. This replaces the previous behaviour of generating an ephemeral key
// on every boot, which made every issued token die on restart and caused
// replicas to sign divergently.
//
// Private keys are stored AES-256-GCM-encrypted with the key id bound as
// additional authenticated data, so a ciphertext cannot be swapped between rows
// and tampering is detected on decrypt. They are never written to disk or logs
// in plaintext.
package keystore

import (
	"context"
	"crypto/rsa"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	legantcrypto "github.com/legant-dev/legant/internal/crypto"
)

const (
	aadVersion = "legant-kek-v1"
	algorithm  = "RS256"
	useSig     = "sig"
	keyBits    = 2048

	// bootstrapAdvisoryLock is a fixed key used with pg_advisory_xact_lock so
	// that two cold replicas starting against an empty signing_keys table do not
	// each insert a different first key (which would make them sign under
	// different kids). The exact value is arbitrary but must be stable.
	bootstrapAdvisoryLock int64 = 0x7265_6765_6e74 // "legant"
)

// Key is a signing key loaded into memory.
type Key struct {
	ID        string
	Private   *rsa.PrivateKey
	Public    *rsa.PublicKey
	CreatedAt time.Time
	ExpiresAt *time.Time
}

// Keystore caches the active signing keys and mediates rotation.
type Keystore struct {
	pool    *pgxpool.Pool
	overlap time.Duration

	mu     sync.RWMutex
	encKey []byte
	active *Key            // newest active key — used for signing
	byKID  map[string]*Key // all active keys — used for verification
}

// Open loads all active signing keys. If none exist, it bootstraps one so the
// server can always start with a usable key. encKey is the envelope key used to
// decrypt private keys at rest; overlap is how long a rotated-out key stays
// published before it can be pruned.
func Open(ctx context.Context, pool *pgxpool.Pool, encKey []byte, overlap time.Duration) (*Keystore, error) {
	if len(encKey) == 0 {
		return nil, fmt.Errorf("keystore: empty key-encryption key")
	}
	ks := &Keystore{pool: pool, overlap: overlap, encKey: encKey}
	if err := ks.reload(ctx); err != nil {
		return nil, err
	}
	if ks.ActiveKID() == "" {
		if err := ks.bootstrap(ctx); err != nil {
			return nil, fmt.Errorf("bootstrapping first signing key: %w", err)
		}
		if err := ks.reload(ctx); err != nil {
			return nil, err
		}
	}
	return ks, nil
}

func aad(kid string) []byte {
	return []byte(aadVersion + "|" + kid + "|" + useSig)
}

// bootstrap creates the first signing key under a transaction-scoped advisory
// lock, re-checking inside the lock that none exists. This makes concurrent
// cold-start replicas converge on a single first key instead of each minting
// its own.
func (k *Keystore) bootstrap(ctx context.Context) error {
	tx, err := k.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, bootstrapAdvisoryLock); err != nil {
		return err
	}
	var n int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM signing_keys WHERE active = true AND use_type = 'sig'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := k.generate(ctx, tx); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// generate creates and persists a new active signing key using the given
// executor (a transaction), returning its kid. Callers reload to refresh caches.
func (k *Keystore) generate(ctx context.Context, tx pgx.Tx) (string, error) {
	priv, err := legantcrypto.GenerateRSAKey(keyBits)
	if err != nil {
		return "", err
	}
	rnd, err := legantcrypto.RandomHex(8)
	if err != nil {
		return "", err
	}
	kid := "rk_" + rnd

	privPEM := legantcrypto.MarshalPrivateKeyPEM(priv)
	pubPEM, err := legantcrypto.MarshalPublicKeyPEM(&priv.PublicKey)
	if err != nil {
		return "", err
	}

	k.mu.RLock()
	encKey := k.encKey
	k.mu.RUnlock()

	enc, err := legantcrypto.EncryptAESGCMWithAAD(privPEM, encKey, aad(kid))
	if err != nil {
		return "", err
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO signing_keys (id, algorithm, private_key, public_key, use_type, active)
		 VALUES ($1, $2, $3, $4, 'sig', true)`,
		kid, algorithm, enc, string(pubPEM),
	); err != nil {
		return "", fmt.Errorf("persisting signing key: %w", err)
	}
	return kid, nil
}

// reload rebuilds the in-memory caches from the database. The newest active key
// by created_at becomes the signing key.
func (k *Keystore) reload(ctx context.Context) error {
	k.mu.RLock()
	encKey := k.encKey
	k.mu.RUnlock()

	rows, err := k.pool.Query(ctx,
		`SELECT id, private_key, public_key, created_at, expires_at
		 FROM signing_keys WHERE active = true AND use_type = 'sig'
		 ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return fmt.Errorf("loading signing keys: %w", err)
	}
	defer rows.Close()

	byKID := make(map[string]*Key)
	var newest *Key
	for rows.Next() {
		var (
			id        string
			encPriv   []byte
			pubPEM    string
			createdAt time.Time
			expiresAt *time.Time
		)
		if err := rows.Scan(&id, &encPriv, &pubPEM, &createdAt, &expiresAt); err != nil {
			return err
		}
		privPEM, err := legantcrypto.DecryptAESGCMWithAAD(encPriv, encKey, aad(id))
		if err != nil {
			return fmt.Errorf("decrypting signing key %q (wrong key-encryption secret?): %w", id, err)
		}
		priv, err := legantcrypto.ParsePrivateKeyPEM(privPEM)
		if err != nil {
			return fmt.Errorf("parsing signing key %q: %w", id, err)
		}
		key := &Key{ID: id, Private: priv, Public: &priv.PublicKey, CreatedAt: createdAt, ExpiresAt: expiresAt}
		byKID[id] = key
		if newest == nil {
			newest = key // rows are ordered created_at DESC
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	k.mu.Lock()
	k.byKID = byKID
	k.active = newest
	k.mu.Unlock()
	return nil
}

// Reload re-reads the active signing keys from the database, picking up keys
// added or retired by another process (e.g. `legant keys rotate` followed by a
// reload signal). Safe for concurrent use.
func (k *Keystore) Reload(ctx context.Context) error {
	return k.reload(ctx)
}

// ActiveKID returns the kid of the current signing key, or "" if none.
func (k *Keystore) ActiveKID() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.active == nil {
		return ""
	}
	return k.active.ID
}

// ActiveSigner returns the current signing private key. It reflects rotation
// performed within this process, so it is safe to use directly as a Fosite
// keyGetter source.
func (k *Keystore) ActiveSigner() *rsa.PrivateKey {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.active == nil {
		return nil
	}
	return k.active.Private
}

// VerifierKeys returns every currently-trusted public key indexed by kid, for
// JWKS publication and delegation-token verification.
func (k *Keystore) VerifierKeys() map[string]*rsa.PublicKey {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make(map[string]*rsa.PublicKey, len(k.byKID))
	for kid, key := range k.byKID {
		out[kid] = key.Public
	}
	return out
}

// Rotate generates a new active signing key and schedules the previously-active
// key for retirement after the overlap window. The old key stays published in
// the JWKS until pruned, so tokens it already signed keep verifying.
func (k *Keystore) Rotate(ctx context.Context) (string, error) {
	prev := k.ActiveKID()

	tx, err := k.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	newKID, err := k.generate(ctx, tx)
	if err != nil {
		return "", err
	}
	if prev != "" && k.overlap > 0 {
		// Atomically schedule the old key's retirement with the new key's
		// insert, so a failure can never leave an orphaned key that is active
		// with no expiry (and therefore never pruned).
		if _, err := tx.Exec(ctx,
			`UPDATE signing_keys SET expires_at = now() + make_interval(secs => $2)
			 WHERE id = $1 AND expires_at IS NULL`,
			prev, k.overlap.Seconds(),
		); err != nil {
			return "", fmt.Errorf("scheduling retirement of key %q: %w", prev, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}

	if err := k.reload(ctx); err != nil {
		return "", err
	}
	return newKID, nil
}

// Prune deactivates keys whose retirement time has passed, removing them from
// the JWKS. It never deactivates the active key. Returns the number pruned.
func (k *Keystore) Prune(ctx context.Context) (int64, error) {
	active := k.ActiveKID()
	tag, err := k.pool.Exec(ctx,
		`UPDATE signing_keys SET active = false
		 WHERE active = true AND use_type = 'sig'
		   AND expires_at IS NOT NULL AND expires_at < now()
		   AND id <> $1`, active)
	if err != nil {
		return 0, err
	}
	if err := k.reload(ctx); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// Reencrypt re-wraps every signing key's private key under newEncKey, in a
// single transaction. Use when rotating the key-encryption secret. On success
// the keystore switches to newEncKey for subsequent operations.
func (k *Keystore) Reencrypt(ctx context.Context, newEncKey []byte) error {
	if len(newEncKey) == 0 {
		return fmt.Errorf("keystore: empty new key-encryption key")
	}
	k.mu.RLock()
	encKey := k.encKey
	k.mu.RUnlock()

	rows, err := k.pool.Query(ctx, `SELECT id, private_key FROM signing_keys WHERE use_type = 'sig'`)
	if err != nil {
		return err
	}
	type rec struct {
		id  string
		enc []byte
	}
	var recs []rec
	for rows.Next() {
		var r rec
		if err := rows.Scan(&r.id, &r.enc); err != nil {
			rows.Close()
			return err
		}
		recs = append(recs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	tx, err := k.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, r := range recs {
		plain, err := legantcrypto.DecryptAESGCMWithAAD(r.enc, encKey, aad(r.id))
		if err != nil {
			return fmt.Errorf("decrypting %q with current key: %w", r.id, err)
		}
		reenc, err := legantcrypto.EncryptAESGCMWithAAD(plain, newEncKey, aad(r.id))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE signing_keys SET private_key = $2 WHERE id = $1`, r.id, reenc); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	k.mu.Lock()
	k.encKey = newEncKey
	k.mu.Unlock()
	return k.reload(ctx)
}

// KeyInfo is a non-secret description of a stored key, for `legant keys list`.
type KeyInfo struct {
	ID        string
	Active    bool
	CreatedAt time.Time
	ExpiresAt *time.Time
}

// List returns metadata for all signing keys, newest first.
func (k *Keystore) List(ctx context.Context) ([]KeyInfo, error) {
	rows, err := k.pool.Query(ctx,
		`SELECT id, active, created_at, expires_at FROM signing_keys
		 WHERE use_type = 'sig' ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KeyInfo
	for rows.Next() {
		var ki KeyInfo
		if err := rows.Scan(&ki.ID, &ki.Active, &ki.CreatedAt, &ki.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, ki)
	}
	return out, rows.Err()
}
