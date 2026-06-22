package revocation_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/legant-dev/legant/internal/db"
	"github.com/legant-dev/legant/internal/revocation"
	"github.com/legant-dev/legant/internal/testsupport"
)

func TestRevocationStore(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	store := revocation.NewStore(pool, nil)

	var userID, agentID, delegationID string
	if err := pool.QueryRow(ctx, `INSERT INTO users (email,status) VALUES ('r@x.com','active') RETURNING id::text`).Scan(&userID); err != nil {
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

	record := func(jti, delID string, exp time.Time) {
		t.Helper()
		err := db.WithTx(ctx, pool, func(tx pgx.Tx) error {
			return store.RecordTx(ctx, tx, revocation.Record{
				JTI: jti, DelegationID: &delID, Subject: "user:" + userID, AgentID: &agentID,
				ActorChain: []string{"agent:" + agentID}, Audience: "api", Scopes: []string{"x"}, ExpiresAt: exp,
			})
		})
		if err != nil {
			t.Fatalf("record %s: %v", jti, err)
		}
	}
	active := func(jti string) bool {
		t.Helper()
		ok, err := store.IsActive(ctx, jti)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}

	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)

	record("jti-live", delegationID, future)
	record("jti-expired", delegationID, past)

	if !active("jti-live") {
		t.Fatal("a recorded, unexpired, unrevoked token must be active")
	}
	if active("jti-expired") {
		t.Fatal("an expired token must be inactive")
	}
	if active("jti-unknown") {
		t.Fatal("an unknown jti must be inactive (fail closed)")
	}

	// Single revoke + idempotency.
	if n, _ := store.Revoke(ctx, "jti-live"); n != 1 {
		t.Fatalf("revoke should affect 1 row, got %d", n)
	}
	if active("jti-live") {
		t.Fatal("a revoked token must be inactive")
	}
	if n, _ := store.Revoke(ctx, "jti-live"); n != 0 {
		t.Fatalf("re-revoking should affect 0 rows, got %d", n)
	}

	// Cascade on a fresh delegation so the count is unambiguous.
	var del2 string
	if err := pool.QueryRow(ctx,
		`INSERT INTO delegation_chains (delegator_id, delegatee_agent_id, scopes) VALUES ($1,$2,'{x}') RETURNING id::text`,
		userID, agentID).Scan(&del2); err != nil {
		t.Fatal(err)
	}
	record("c1", del2, future)
	record("c2", del2, future)
	n, err := store.RevokeByDelegation(ctx, del2)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("cascade should revoke the 2 live tokens of the delegation, got %d", n)
	}
	if active("c1") || active("c2") {
		t.Fatal("revoking a delegation must revoke all its live tokens")
	}
}
