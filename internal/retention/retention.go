// Package retention implements data-retention pruning for Legant's operational
// tables. Expired sessions, used/expired email and registration tokens, terminal
// or expired org invitations, the Fosite OAuth token stores
// (access/refresh/auth-code/PKCE/OIDC-session), expired agent tokens and API
// keys, delegation tokens dead past a grace window, and aged-out audit events
// accumulate indefinitely otherwise. The prune is safe to run repeatedly
// (idempotent) and is exposed both as the `legant maintenance prune` command and
// for scheduling as a Kubernetes CronJob.
package retention

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/legant-dev/legant/internal/db"
)

// Policy controls the time-based windows. Durations of zero disable the
// corresponding age-based purge (expired-row cleanups always run).
type Policy struct {
	// TokenGrace is how long a delegation token is kept after it expires before
	// being purged. A short grace keeps revocation/introspection answers correct
	// for recently-expired tokens; the row is dead weight after that.
	TokenGrace time.Duration
	// AuditRetention is the age beyond which audit_events are deleted. Zero keeps
	// audit events forever (the safe default for compliance).
	AuditRetention time.Duration
}

// DefaultPolicy keeps dead tokens for 30 days and never auto-deletes audit.
var DefaultPolicy = Policy{TokenGrace: 30 * 24 * time.Hour, AuditRetention: 0}

// oauthTokenTables are the Fosite-managed stores whose rows become dead weight
// once expired. They are the highest-volume tables (one or more rows per login),
// so leaving them unpruned is the dominant growth source.
var oauthTokenTables = []string{
	"oauth2_auth_codes",
	"oauth2_access_tokens",
	"oauth2_refresh_tokens",
	"oauth2_pkce",
	"oauth2_oidc_sessions",
}

// Result reports how many rows each step removed (or would remove, in dry-run).
type Result struct {
	ExpiredSessions     int64
	StaleEmailTokens    int64
	ExhaustedDCRTokens  int64
	StaleInvitations    int64
	DeadExchangedTokens int64
	ExpiredOAuthTokens  int64 // sum across the Fosite token tables
	ExpiredAgentTokens  int64
	ExpiredAPIKeys      int64
	AgedAuditEvents     int64
}

// Total returns the sum of all pruned rows.
func (r Result) Total() int64 {
	return r.ExpiredSessions + r.StaleEmailTokens + r.ExhaustedDCRTokens + r.StaleInvitations +
		r.DeadExchangedTokens + r.ExpiredOAuthTokens + r.ExpiredAgentTokens + r.ExpiredAPIKeys +
		r.AgedAuditEvents
}

// Prune removes (or, when dryRun, counts) prunable rows according to the policy.
// Each step is independent; a failure returns the partial result gathered so far
// alongside the error.
func Prune(ctx context.Context, pool *pgxpool.Pool, policy Policy, dryRun bool) (Result, error) {
	now := time.Now()
	var res Result
	var err error

	step := func(dst *int64, predicateSQL, table string, args ...any) error {
		n, e := sweep(ctx, pool, dryRun, table, predicateSQL, args...)
		*dst = n
		if e != nil {
			return fmt.Errorf("prune %s: %w", table, e)
		}
		return nil
	}

	if err = step(&res.ExpiredSessions,
		`expires_at < now()`, "sessions"); err != nil {
		return res, err
	}
	if err = step(&res.StaleEmailTokens,
		`used = true OR expires_at < now()`, "email_tokens"); err != nil {
		return res, err
	}
	if err = step(&res.ExhaustedDCRTokens,
		`(expires_at IS NOT NULL AND expires_at < now()) OR used_count >= max_uses`,
		"dcr_registration_tokens"); err != nil {
		return res, err
	}
	// Invitations: terminal (accepted/revoked/expired) or past their expiry. Live
	// pending invitations are kept.
	if err = step(&res.StaleInvitations,
		`status <> 'pending' OR expires_at < now()`, "org_invitations"); err != nil {
		return res, err
	}
	if err = step(&res.DeadExchangedTokens,
		`expires_at < $1`, "exchanged_tokens", now.Add(-policy.TokenGrace)); err != nil {
		return res, err
	}
	// Fosite token stores: delete rows that have already expired (no grace —
	// expired tokens are unusable, and expired refresh tokens can't be replayed).
	// The `> to_timestamp(0)` guard excludes the Go zero-time sentinel: when a
	// token type is configured non-expiring, Fosite stores expires_at as the zero
	// time (year 1), which is < now() — without this guard a non-expiring refresh
	// token would be wrongly purged.
	for _, table := range oauthTokenTables {
		var n int64
		if err = step(&n, `expires_at > to_timestamp(0) AND expires_at < now()`, table); err != nil {
			return res, err
		}
		res.ExpiredOAuthTokens += n
	}
	// Agent tokens and API keys have a nullable expiry; NULL means "never
	// expires", so only prune rows with an expiry in the past.
	if err = step(&res.ExpiredAgentTokens,
		`expires_at IS NOT NULL AND expires_at < now()`, "agent_tokens"); err != nil {
		return res, err
	}
	if err = step(&res.ExpiredAPIKeys,
		`expires_at IS NOT NULL AND expires_at < now()`, "api_keys"); err != nil {
		return res, err
	}
	if policy.AuditRetention > 0 {
		cutoff := now.Add(-policy.AuditRetention)
		if dryRun {
			if err = step(&res.AgedAuditEvents, `created_at < $1`, "audit_events", cutoff); err != nil {
				return res, err
			}
		} else {
			n, err := pruneAuditChained(ctx, pool, cutoff)
			if err != nil {
				return res, fmt.Errorf("prune audit_events: %w", err)
			}
			res.AgedAuditEvents = n
		}
	}
	return res, nil
}

// pruneAuditChained deletes aged audit_events while keeping the hash chain
// verifiable: it records the new genesis row's prev_hash as a watermark (so a
// pruned prefix is not mistaken for tampering) atomically with the delete.
func pruneAuditChained(ctx context.Context, pool *pgxpool.Pool, cutoff time.Time) (int64, error) {
	var deleted int64
	err := db.WithTx(ctx, pool, func(tx pgx.Tx) error {
		// The prev_hash of the lowest-seq row we keep becomes the new watermark; if
		// nothing survives, the chain restarts from the empty genesis.
		var watermark string
		switch err := tx.QueryRow(ctx,
			`SELECT prev_hash FROM audit_events WHERE created_at >= $1 ORDER BY seq LIMIT 1`, cutoff).Scan(&watermark); err {
		case nil, pgx.ErrNoRows:
		default:
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM audit_events WHERE created_at < $1`, cutoff)
		if err != nil {
			return err
		}
		deleted = tag.RowsAffected()
		if deleted > 0 {
			if _, err := tx.Exec(ctx, `UPDATE audit_chain_state SET watermark = $1 WHERE id`, watermark); err != nil {
				return err
			}
		}
		return nil
	})
	return deleted, err
}

// sweep deletes rows matching predicate (or counts them when dryRun). The table
// name is a fixed internal constant at every call site — never user input — so
// interpolating it is safe.
func sweep(ctx context.Context, pool *pgxpool.Pool, dryRun bool, table, predicate string, args ...any) (int64, error) {
	if dryRun {
		var n int64
		err := pool.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE "+predicate, args...).Scan(&n)
		return n, err
	}
	tag, err := pool.Exec(ctx, "DELETE FROM "+table+" WHERE "+predicate, args...)
	return tag.RowsAffected(), err
}
