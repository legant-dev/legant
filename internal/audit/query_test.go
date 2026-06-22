package audit_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/legant-dev/legant/internal/audit"
	"github.com/legant-dev/legant/internal/testsupport"
)

const delID = "11111111-1111-1111-1111-111111111111"

func mustExec(t *testing.T, ctx context.Context, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func TestAuditQuery(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()

	mustExec(t, ctx, pool, `INSERT INTO audit_events (actor_type, actor_id, action, on_behalf_of_sub, delegation_id, grant_jti)
		VALUES ('agent','a1','token.exchanged','user:alice',$1,'jti1')`, delID)
	mustExec(t, ctx, pool, `INSERT INTO audit_events (actor_type, action, on_behalf_of_sub)
		VALUES ('agent','mcp.tool.call','user:alice')`)
	mustExec(t, ctx, pool, `INSERT INTO audit_events (actor_type, action, on_behalf_of_sub)
		VALUES ('user','delegation.revoked','user:bob')`)

	// No filter → all three, newest first.
	all, total, err := audit.Query(ctx, pool, audit.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(all) != 3 {
		t.Fatalf("expected 3 events, got %d (total %d)", len(all), total)
	}
	if all[0].Seq == nil || all[len(all)-1].Seq == nil || *all[0].Seq <= *all[len(all)-1].Seq {
		t.Error("events should be ordered newest (highest seq) first")
	}

	// Filter by action returns the exchange row with full provenance.
	ev, total, _ := audit.Query(ctx, pool, audit.Filter{Action: "token.exchanged"})
	if total != 1 || len(ev) != 1 {
		t.Fatalf("action filter: got %d", total)
	}
	e := ev[0]
	if e.OnBehalfOf != "user:alice" || e.GrantJTI != "jti1" || e.DelegationID == nil || *e.DelegationID != delID {
		t.Errorf("provenance not returned correctly: %+v", e)
	}

	// Filter by who-acted-for-whom.
	if _, total, _ := audit.Query(ctx, pool, audit.Filter{OnBehalfOf: "user:alice"}); total != 2 {
		t.Errorf("on_behalf_of filter total = %d, want 2", total)
	}
	// Filter by delegation id.
	if _, total, _ := audit.Query(ctx, pool, audit.Filter{DelegationID: delID}); total != 1 {
		t.Errorf("delegation filter total = %d, want 1", total)
	}

	// Pagination returns distinct pages.
	p1, _, _ := audit.Query(ctx, pool, audit.Filter{Limit: 1, Offset: 0})
	p2, _, _ := audit.Query(ctx, pool, audit.Filter{Limit: 1, Offset: 1})
	if len(p1) != 1 || len(p2) != 1 || p1[0].ID == p2[0].ID {
		t.Errorf("pagination returned overlapping/empty pages: %v %v", p1, p2)
	}
}

func TestAuditHandler(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	mustExec(t, ctx, pool, `INSERT INTO audit_events (actor_type, action, on_behalf_of_sub) VALUES ('agent','mcp.tool.call','user:alice')`)
	mustExec(t, ctx, pool, `INSERT INTO audit_events (actor_type, action, on_behalf_of_sub) VALUES ('user','login','user:bob')`)

	router := chi.NewRouter()
	router.Mount("/audit", audit.NewHandler(pool).Routes())

	// List with a filter.
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit?on_behalf_of_sub=user:alice", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list returned %d", rec.Code)
	}
	var listResp struct {
		Events []audit.Event `json:"events"`
		Total  int64         `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatal(err)
	}
	if listResp.Total != 1 || len(listResp.Events) != 1 || listResp.Events[0].Action != "mcp.tool.call" {
		t.Errorf("filtered list wrong: %+v", listResp)
	}

	// Verify endpoint.
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit/verify", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("verify returned %d", rec.Code)
	}
	var vResp struct {
		OK     bool  `json:"ok"`
		Events int64 `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &vResp); err != nil {
		t.Fatal(err)
	}
	if !vResp.OK || vResp.Events != 2 {
		t.Errorf("verify endpoint: %+v", vResp)
	}
}
