package agent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/legant-dev/legant/internal/agent"
	"github.com/legant-dev/legant/internal/authz"
	"github.com/legant-dev/legant/internal/testsupport"
)

type harness struct {
	pool        *pgxpool.Pool
	router      chi.Router
	sessionUser string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	pool := testsupport.DB(t)
	testsupport.Truncate(t, pool, "users", "orgs")

	h := &harness{pool: pool}
	svc := agent.NewService(pool)
	handler := agent.NewHandler(svc, nil)
	a := authz.NewAuthenticator(pool, func(r *http.Request) (string, bool) {
		if h.sessionUser == "" {
			return "", false
		}
		return h.sessionUser, true
	}, nil, nil)

	// Mirror the production wiring: authenticate, require admin-capable, then the
	// org-scoped agent routes.
	root := chi.NewRouter()
	root.Group(func(r chi.Router) {
		r.Use(a.Require)
		r.Use(authz.RequireAdmin)
		r.Mount("/agents", handler.Routes())
	})
	h.router = root
	return h
}

func (h *harness) do(t *testing.T, method, path, asUser string, body any) *httptest.ResponseRecorder {
	t.Helper()
	h.sessionUser = asUser
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

func (h *harness) user(t *testing.T, email string, super bool) string {
	t.Helper()
	var id string
	if err := h.pool.QueryRow(context.Background(),
		`INSERT INTO users (email, is_superadmin, status) VALUES ($1,$2,'active') RETURNING id::text`,
		email, super).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (h *harness) org(t *testing.T, slug, userID, role string) string {
	t.Helper()
	var orgID string
	if err := h.pool.QueryRow(context.Background(),
		`INSERT INTO orgs (slug, name) VALUES ($1,$1) RETURNING id::text`, slug).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(context.Background(),
		`INSERT INTO org_members (org_id, user_id, role) VALUES ($1,$2,$3)`, orgID, userID, role); err != nil {
		t.Fatal(err)
	}
	return orgID
}

func (h *harness) agent(t *testing.T, orgID, name string) string {
	t.Helper()
	var id string
	if err := h.pool.QueryRow(context.Background(),
		`INSERT INTO agents (org_id, name, type) VALUES ($1,$2,'ai_agent') RETURNING id::text`,
		orgID, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (h *harness) token(t *testing.T, agentID string) string {
	t.Helper()
	var id string
	if err := h.pool.QueryRow(context.Background(),
		`INSERT INTO agent_tokens (agent_id, token_hash, name) VALUES ($1,$2,'t') RETURNING id::text`,
		agentID, "hash_"+agentID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// The core M2 exit criterion: cross-org agent access returns 404/403 on both the
// read path and every write path.
func TestAgentTenantIsolation(t *testing.T) {
	h := newHarness(t)

	adminA := h.user(t, "admin-a@example.com", false)
	adminB := h.user(t, "admin-b@example.com", false)
	memberA := h.user(t, "member-a@example.com", false)
	orgA := h.org(t, "org-a", adminA, "admin")
	orgB := h.org(t, "org-b", adminB, "admin")
	h.pool.Exec(context.Background(), `INSERT INTO org_members (org_id, user_id, role) VALUES ($1,$2,'member')`, orgA, memberA)

	// mixed is an admin of org A but only a member of org B — the case that
	// exercises the read-vs-write split within a single authorized principal.
	mixed := h.user(t, "mixed@example.com", false)
	h.pool.Exec(context.Background(), `INSERT INTO org_members (org_id, user_id, role) VALUES ($1,$2,'admin')`, orgA, mixed)
	h.pool.Exec(context.Background(), `INSERT INTO org_members (org_id, user_id, role) VALUES ($1,$2,'member')`, orgB, mixed)

	agentA := h.agent(t, orgA, "agent-a")
	agentB := h.agent(t, orgB, "agent-b")
	tokB := h.token(t, agentB)

	cases := []struct {
		name, method, path, user string
		body                     any
		want                     int
	}{
		{"own agent read", http.MethodGet, "/agents/" + agentA, adminA, nil, http.StatusOK},
		{"cross-org read hidden", http.MethodGet, "/agents/" + agentB, adminA, nil, http.StatusNotFound},
		{"cross-org update hidden", http.MethodPut, "/agents/" + agentB, adminA, map[string]any{"name": "x"}, http.StatusNotFound},
		{"cross-org token mint hidden", http.MethodPost, "/agents/" + agentB + "/tokens", adminA, map[string]any{"name": "t"}, http.StatusNotFound},
		{"cross-org token delete hidden", http.MethodDelete, "/agents/" + agentB + "/tokens/" + tokB, adminA, nil, http.StatusNotFound},
		{"plain member blocked from admin group", http.MethodGet, "/agents", memberA, nil, http.StatusForbidden},
		{"org-member reads agent in that org", http.MethodGet, "/agents/" + agentB, mixed, nil, http.StatusOK},
		{"org-member cannot write agent in that org", http.MethodPut, "/agents/" + agentB, mixed, map[string]any{"name": "x"}, http.StatusForbidden},
		{"create in other org forbidden", http.MethodPost, "/agents", adminA, map[string]any{"name": "n", "type": "ai_agent", "org_id": orgB}, http.StatusForbidden},
		{"create global forbidden for non-superadmin", http.MethodPost, "/agents", adminA, map[string]any{"name": "n", "type": "ai_agent"}, http.StatusForbidden},
		{"create in own org allowed", http.MethodPost, "/agents", adminA, map[string]any{"name": "n", "type": "ai_agent", "org_id": orgA}, http.StatusCreated},
		{"cross-org delegation hidden", http.MethodPost, "/agents/delegations", adminA, map[string]any{"delegatee_agent_id": agentB, "scopes": []string{"x"}}, http.StatusNotFound},
		{"own-org delegation allowed", http.MethodPost, "/agents/delegations", adminA, map[string]any{"delegatee_agent_id": agentA, "scopes": []string{"x"}}, http.StatusCreated},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := h.do(t, c.method, c.path, c.user, c.body)
			if rec.Code != c.want {
				t.Fatalf("%s %s as %s: got %d, want %d (body: %s)", c.method, c.path, c.user, rec.Code, c.want, rec.Body.String())
			}
		})
	}

	// The token-delete binding: even within the same org, deleting agentA's URL
	// with agentB's token id must affect nothing (A4 binds agent_id).
	tokA := h.token(t, agentA)
	if rec := h.do(t, http.MethodDelete, "/agents/"+agentA+"/tokens/"+tokB, adminA, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete returns 204 even when id doesn't match the agent, got %d", rec.Code)
	}
	var stillThere bool
	h.pool.QueryRow(context.Background(), `SELECT exists(SELECT 1 FROM agent_tokens WHERE id=$1)`, tokB).Scan(&stillThere)
	if !stillThere {
		t.Fatal("agentB's token must NOT be deleted via agentA's path")
	}
	_ = tokA
}

func TestListIsOrgScoped(t *testing.T) {
	h := newHarness(t)
	adminA := h.user(t, "la@example.com", false)
	adminB := h.user(t, "lb@example.com", false)
	orgA := h.org(t, "list-a", adminA, "admin")
	orgB := h.org(t, "list-b", adminB, "admin")
	h.agent(t, orgA, "a1")
	h.agent(t, orgA, "a2")
	h.agent(t, orgB, "b1")

	rec := h.do(t, http.MethodGet, "/agents", adminA, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status %d", rec.Code)
	}
	var resp struct {
		Total int64 `json:"total"`
		Data  []struct {
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 2 || len(resp.Data) != 2 {
		t.Fatalf("org A admin should see only org A's 2 agents, got total=%d len=%d", resp.Total, len(resp.Data))
	}
	for _, a := range resp.Data {
		if a.Name == "b1" {
			t.Fatal("org A admin must not see org B's agent")
		}
	}
}
