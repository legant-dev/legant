package audit_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/legant-dev/legant/internal/audit"
	"github.com/legant-dev/legant/internal/testsupport"
)

func insertEvents(t *testing.T, ctx context.Context, pool *pgxpool.Pool, actions ...string) []int64 {
	t.Helper()
	var ids []int64
	for _, a := range actions {
		var id int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO audit_events (actor_type, action, metadata) VALUES ('system',$1,'{"k":1}') RETURNING id`, a).Scan(&id); err != nil {
			t.Fatalf("insert %q: %v", a, err)
		}
		ids = append(ids, id)
	}
	return ids
}

func TestAuditChainVerifies(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	insertEvents(t, ctx, pool, "login", "token.exchanged", "mcp.tool.call")

	res, err := audit.Verify(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("fresh chain should verify, got break at %d (%s)", res.BreakID, res.BreakKind)
	}
	if res.Events != 3 {
		t.Errorf("events = %d, want 3", res.Events)
	}
	if res.HeadHash == "" {
		t.Error("head hash should be set")
	}
}

func TestAuditChainDetectsContentTamper(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	ids := insertEvents(t, ctx, pool, "a", "b", "c")

	// Edit the middle row's action in place without recomputing its hash.
	if _, err := pool.Exec(ctx, `UPDATE audit_events SET action='HACKED' WHERE id=$1`, ids[1]); err != nil {
		t.Fatal(err)
	}
	res, err := audit.Verify(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("expected content tamper to be detected")
	}
	if res.BreakKind != "content" || res.BreakID != ids[1] {
		t.Errorf("want content break at %d, got %s break at %d", ids[1], res.BreakKind, res.BreakID)
	}
}

func TestAuditChainDetectsDeletion(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	ids := insertEvents(t, ctx, pool, "a", "b", "c", "d")

	// Deleting a middle row breaks the LINK at the following row, whose prev_hash
	// no longer matches its new predecessor.
	if _, err := pool.Exec(ctx, `DELETE FROM audit_events WHERE id=$1`, ids[1]); err != nil {
		t.Fatal(err)
	}
	res, err := audit.Verify(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("expected deletion to be detected")
	}
	if res.BreakKind != "link" || res.BreakID != ids[2] {
		t.Errorf("want link break at %d, got %s break at %d", ids[2], res.BreakKind, res.BreakID)
	}
}

func TestAuditChainEmptyVerifies(t *testing.T) {
	pool := testsupport.DB(t)
	res, err := audit.Verify(context.Background(), pool)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Events != 0 {
		t.Errorf("empty chain should verify with 0 events, got %+v", res)
	}
}

func TestAuditChainDetectsTailTruncationViaAnchor(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	ids := insertEvents(t, ctx, pool, "a", "b", "c", "d")

	// Pin the head, then delete the NEWEST row. The internal chain still verifies
	// (no following row to break the link), but the anchor catches the truncation.
	if err := audit.Anchor(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM audit_events WHERE id=$1`, ids[3]); err != nil {
		t.Fatal(err)
	}
	res, err := audit.Verify(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("tail truncation must be detected against the pinned anchor")
	}
	if res.BreakKind != "truncation" {
		t.Errorf("break kind = %q, want truncation", res.BreakKind)
	}
}

func TestAuditChainBackfillSealsExistingRows(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	// Simulate rows that predate the chain trigger: drop the trigger, insert with
	// empty hash/seq, then re-run the migration's seal logic by reconstructing it.
	if _, err := pool.Exec(ctx, `DROP TRIGGER audit_events_chain_trg ON audit_events`); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"old1", "old2", "old3"} {
		if _, err := pool.Exec(ctx, `INSERT INTO audit_events (actor_type, action) VALUES ('system',$1)`, a); err != nil {
			t.Fatal(err)
		}
	}
	// These rows have hash='' and seq=NULL — an unsealed pre-migration state.
	var unsealed int
	pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE hash='' OR seq IS NULL`).Scan(&unsealed)
	if unsealed != 3 {
		t.Fatalf("expected 3 unsealed rows, got %d", unsealed)
	}
	// Run the same seal the up-migration's DO block runs.
	_, err := pool.Exec(ctx, `DO $$
		DECLARE r RECORD; prev TEXT := '';
		BEGIN
			FOR r IN SELECT * FROM audit_events ORDER BY id LOOP
				UPDATE audit_events SET seq = nextval('audit_events_seq'), prev_hash = prev,
					hash = audit_row_hash(prev, r.actor_type, r.actor_id, r.action, r.resource_type,
						r.resource_id, r.on_behalf_of_sub, r.actor_chain, r.delegation_id, r.grant_jti,
						r.org_id, r.ip, r.user_agent, r.metadata, r.created_at)
				WHERE id = r.id;
				SELECT hash INTO prev FROM audit_events WHERE id = r.id;
			END LOOP;
		END $$`)
	if err != nil {
		t.Fatal(err)
	}
	res, err := audit.Verify(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Events != 3 {
		t.Errorf("backfilled chain should verify with 3 events, got %+v", res)
	}
}
