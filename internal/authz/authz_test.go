package authz_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/legant-dev/legant/internal/authz"
	"github.com/legant-dev/legant/internal/testsupport"
)

func seedUser(t *testing.T, pool *pgxpool.Pool, email string, superadmin bool) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(),
		`INSERT INTO users (email, is_superadmin, status) VALUES ($1, $2, 'active') RETURNING id::text`,
		email, superadmin).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func seedOrgMember(t *testing.T, pool *pgxpool.Pool, slug, userID, role string) string {
	t.Helper()
	var orgID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO orgs (slug, name) VALUES ($1, $1) RETURNING id::text`, slug).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, $3)`, orgID, userID, role); err != nil {
		t.Fatal(err)
	}
	return orgID
}

// fixedSession returns a session resolver that yields a controllable user id.
func fixedSession(userID *string) authz.SessionResolver {
	return func(r *http.Request) (string, bool) {
		if *userID == "" {
			return "", false
		}
		return *userID, true
	}
}

func TestAuthenticatorBuildsUserPrincipal(t *testing.T) {
	pool := testsupport.DB(t)
	testsupport.Truncate(t, pool, "users", "orgs")

	superID := seedUser(t, pool, "super@example.com", true)
	adminID := seedUser(t, pool, "admin@example.com", false)
	orgID := seedOrgMember(t, pool, "acme", adminID, "admin")

	var sessionUser string
	a := authz.NewAuthenticator(pool, fixedSession(&sessionUser), nil, nil)

	sessionUser = superID
	p, ok := a.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil))
	if !ok {
		t.Fatal("superadmin should authenticate")
	}
	if !p.IsSuperadmin || !p.AdminCapable() {
		t.Fatalf("expected superadmin+admin-capable, got %+v", p)
	}
	if !p.CanAccessOrg("any-org-id") {
		t.Fatal("superadmin must access any org")
	}

	sessionUser = adminID
	p, ok = a.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil))
	if !ok {
		t.Fatal("org admin should authenticate")
	}
	if p.IsSuperadmin {
		t.Fatal("org admin must not be superadmin")
	}
	if role, ok := p.RoleIn(orgID); !ok || role != "admin" {
		t.Fatalf("expected admin role in org, got %q ok=%v", role, ok)
	}
	if !p.AdminCapable() {
		t.Fatal("org admin must be admin-capable")
	}
	if !p.CanAccessOrg(orgID) || p.CanAccessOrg("other-org") {
		t.Fatal("org admin must access only their org")
	}
}

func TestRequireRejectsUnauthenticated(t *testing.T) {
	pool := testsupport.DB(t)
	var none string
	a := authz.NewAuthenticator(pool, fixedSession(&none), nil, nil)

	h := a.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not run for an unauthenticated request")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("401 must carry a WWW-Authenticate challenge")
	}
}

func TestSpoofedUserHeaderIsIgnored(t *testing.T) {
	pool := testsupport.DB(t)
	var none string
	a := authz.NewAuthenticator(pool, fixedSession(&none), nil, nil)

	h := a.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("a forged X-User-ID must not authenticate anyone")
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/delegations", nil)
	req.Header.Set("X-User-ID", "00000000-0000-0000-0000-000000000001")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("X-User-ID must not be trusted; want 401, got %d", rec.Code)
	}
}

func TestRequireAdminForbidsPlainMember(t *testing.T) {
	pool := testsupport.DB(t)
	testsupport.Truncate(t, pool, "users", "orgs")

	memberID := seedUser(t, pool, "member@example.com", false)
	seedOrgMember(t, pool, "members-org", memberID, "member")

	var sessionUser string
	a := authz.NewAuthenticator(pool, fixedSession(&sessionUser), nil, nil)
	sessionUser = memberID

	h := a.Require(authz.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("a plain member must not reach the admin handler")
	})))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("plain member should be forbidden from admin API; want 403, got %d", rec.Code)
	}
}

func TestAuthenticatorAgentAndBearerPaths(t *testing.T) {
	pool := testsupport.DB(t)
	testsupport.Truncate(t, pool, "users", "orgs")

	userID := seedUser(t, pool, "bearer-user@example.com", false)
	var agentID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO agents (name, type) VALUES ('a','ai_agent') RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatal(err)
	}

	var none string
	a := authz.NewAuthenticator(pool,
		fixedSession(&none), // no session, force the bearer/agent paths
		func(ctx context.Context, token string) (string, []string, string, bool) {
			if token == "legant_at_good" {
				return agentID, []string{"s1"}, "tok1", true
			}
			return "", nil, "", false
		},
		func(ctx context.Context, token string) (string, []string, bool) {
			if token == "opaque-access-token" {
				return userID, []string{"read"}, true
			}
			return "", nil, false
		},
	)

	agentReq := httptest.NewRequest(http.MethodGet, "/", nil)
	agentReq.Header.Set("Authorization", "Bearer legant_at_good")
	if p, ok := a.Authenticate(agentReq); !ok || p.Type != authz.TypeAgent || p.ID != agentID {
		t.Fatalf("agent-token path should yield an agent principal, got %+v ok=%v", p, ok)
	}

	bearerReq := httptest.NewRequest(http.MethodGet, "/", nil)
	bearerReq.Header.Set("Authorization", "Bearer opaque-access-token")
	p, ok := a.Authenticate(bearerReq)
	if !ok || p.Type != authz.TypeUser || p.ID != userID {
		t.Fatalf("bearer path should yield a user principal, got %+v ok=%v", p, ok)
	}
	if len(p.Scopes) != 1 || p.Scopes[0] != "read" {
		t.Fatalf("bearer scopes not carried through: %v", p.Scopes)
	}
}

func TestAuthenticatedRequestIgnoresForgedUserHeader(t *testing.T) {
	pool := testsupport.DB(t)
	testsupport.Truncate(t, pool, "users", "orgs")

	memberID := seedUser(t, pool, "real-member@example.com", false)
	superID := seedUser(t, pool, "the-super@example.com", true)

	var sessionUser string
	a := authz.NewAuthenticator(pool, fixedSession(&sessionUser), nil, nil)
	sessionUser = memberID

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-User-ID", superID) // attacker tries to escalate to a superadmin
	p, ok := a.Authenticate(req)
	if !ok {
		t.Fatal("the real session user should authenticate")
	}
	if p.ID != memberID || p.IsSuperadmin {
		t.Fatal("a forged X-User-ID must be ignored; identity comes from the session")
	}
}

func TestSuperadminVsAdminBoundary(t *testing.T) {
	pool := testsupport.DB(t)
	testsupport.Truncate(t, pool, "users", "orgs")

	adminID := seedUser(t, pool, "orgadmin@example.com", false)
	seedOrgMember(t, pool, "b3org", adminID, "admin")
	superID := seedUser(t, pool, "super-b3@example.com", true)

	var sessionUser string
	a := authz.NewAuthenticator(pool, fixedSession(&sessionUser), nil, nil)
	ok200 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	serve := func(h http.Handler) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/x", nil))
		return rec.Code
	}

	// An org-admin must be blocked from superadmin-only routes but allowed on
	// admin-capable routes.
	sessionUser = adminID
	if code := serve(a.Require(authz.RequireSuperadmin(ok200))); code != http.StatusForbidden {
		t.Fatalf("org-admin on a superadmin route: want 403, got %d", code)
	}
	if code := serve(a.Require(authz.RequireAdmin(ok200))); code != http.StatusOK {
		t.Fatalf("org-admin on an admin route: want 200, got %d", code)
	}

	// A superadmin passes both.
	sessionUser = superID
	if code := serve(a.Require(authz.RequireSuperadmin(ok200))); code != http.StatusOK {
		t.Fatalf("superadmin on a superadmin route: want 200, got %d", code)
	}
}
