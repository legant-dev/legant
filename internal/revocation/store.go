// Package revocation records every composite (sub/act) delegation token minted
// by the token-exchange endpoint and lets it be revoked before expiry. A
// self-contained JWT is otherwise unkillable until it expires, so resource
// servers and the introspection endpoint consult this store (a jti denylist)
// for any act-bearing token.
package revocation

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/legant-dev/legant/internal/live"
	"github.com/legant-dev/legant/internal/metrics"
)

// Record is the metadata persisted for a minted delegation token.
type Record struct {
	JTI          string
	DelegationID *string
	Subject      string
	AgentID      *string
	ActorChain   []string
	Audience     string
	Scopes       []string
	ExpiresAt    time.Time
}

type Store struct {
	pool *pgxpool.Pool
	pub  *live.Publisher // optional live-console feed; nil-safe
}

func NewStore(pool *pgxpool.Pool, pub *live.Publisher) *Store {
	return &Store{pool: pool, pub: pub}
}

// RecordTx persists a minted token within the caller's transaction, so the token
// row and its audit record commit together with the rest of the exchange.
func (s *Store) RecordTx(ctx context.Context, tx pgx.Tx, r Record) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO exchanged_tokens (jti, delegation_id, subject, agent_id, actor_chain, audience, scopes, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		r.JTI, r.DelegationID, r.Subject, r.AgentID, r.ActorChain, r.Audience, r.Scopes, r.ExpiresAt,
	)
	return err
}

// IsActive reports whether a token jti is currently valid: present, not revoked,
// not expired. An unknown jti is treated as NOT active (fail closed) — we record
// every token we mint, so a missing row means the token was never issued by us.
func (s *Store) IsActive(ctx context.Context, jti string) (bool, error) {
	var revokedAt *time.Time
	var expiresAt time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT revoked_at, expires_at FROM exchanged_tokens WHERE jti = $1`, jti,
	).Scan(&revokedAt, &expiresAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	if revokedAt != nil || time.Now().After(expiresAt) {
		return false, nil
	}
	return true, nil
}

// Revoke marks a single token revoked. Returns the number of rows changed (0 if
// already revoked or unknown).
func (s *Store) Revoke(ctx context.Context, jti string) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE exchanged_tokens SET revoked_at = now() WHERE jti = $1 AND revoked_at IS NULL`, jti)
	if err == nil && tag.RowsAffected() > 0 {
		metrics.RevocationsTotal.Add(uint64(tag.RowsAffected()), "token")
		s.pub.Publish(live.Event{Type: "revoke", Decision: "REVOKE", Reason: "token revoked", Count: int(tag.RowsAffected())})
	}
	return tag.RowsAffected(), err
}

// RevokeByDelegation marks every live token minted from a delegation revoked,
// used when the underlying delegation is revoked so its tokens die immediately.
func (s *Store) RevokeByDelegation(ctx context.Context, delegationID string) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE exchanged_tokens SET revoked_at = now() WHERE delegation_id = $1 AND revoked_at IS NULL`, delegationID)
	if err == nil && tag.RowsAffected() > 0 {
		metrics.RevocationsTotal.Add(uint64(tag.RowsAffected()), "delegation")
		s.pub.Publish(live.Event{Type: "revoke", Decision: "REVOKE", Delegation: delegationID, Reason: "delegation revoked", Count: int(tag.RowsAffected())})
	}
	return tag.RowsAffected(), err
}
