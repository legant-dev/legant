package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/legant-dev/legant/internal/auth"
	"github.com/legant-dev/legant/internal/delegation"
	"github.com/legant-dev/legant/internal/delegation/chains"
	"github.com/legant-dev/legant/internal/keystore"
	"github.com/legant-dev/legant/internal/revocation"
	"github.com/legant-dev/legant/internal/testsupport"
)

const (
	xchgIssuer   = "https://legant.test"
	xchgResource = "https://finance.example/" // already canonical (trailing slash)
)

type xchgFixture struct {
	pool         *pgxpool.Pool
	ks           *keystore.Keystore
	rev          *revocation.Store
	exch         *auth.TokenExchanger
	userID       string
	agentID      string
	delegationID string
}

func setupExchange(t *testing.T, grantScopes []string, constraints delegation.Constraints) *xchgFixture {
	t.Helper()
	pool := testsupport.DB(t)
	testsupport.Truncate(t, pool, "users", "orgs", "signing_keys")
	ctx := context.Background()

	ks, err := keystore.Open(ctx, pool, bytes.Repeat([]byte("k"), 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ch := chains.NewService(pool, nil)
	rev := revocation.NewStore(pool, nil)

	var userID, agentID string
	if err := pool.QueryRow(ctx, `INSERT INTO users (email,status) VALUES ('u@x.com','active') RETURNING id::text`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO agents (name,type) VALUES ('a','ai_agent') RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatal(err)
	}
	// Resource left empty here so the test's Constraints fully control the
	// audience allow-list (the resource-fold behaviour is covered separately).
	_, delegationID, err := ch.GrantConsent(ctx, chains.ConsentRequest{
		UserID: userID, AgentID: agentID, Scopes: grantScopes,
		Constraints: constraints, Resource: "", TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	exch := auth.NewTokenExchanger(xchgIssuer, 5*time.Minute, ks, ch, rev, pool, nil,
		func(ctx context.Context, token string) (string, bool) {
			return agentID, token == "agent-tok"
		},
		func(ctx context.Context, token string) (string, []string, bool) {
			if token != "user-tok" {
				return "", nil, false
			}
			// the subject token's own scope ceiling
			return userID, []string{"expenses:read", "expenses:submit"}, true
		},
	)
	return &xchgFixture{pool: pool, ks: ks, rev: rev, exch: exch, userID: userID, agentID: agentID, delegationID: delegationID}
}

func (f *xchgFixture) exchange(t *testing.T, scope, resource, subjectTok, actorTok string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"grant_type":         {auth.TokenExchangeGrantType},
		"subject_token":      {subjectTok},
		"subject_token_type": {auth.AccessTokenType},
		"actor_token":        {actorTok},
		"actor_token_type":   {auth.AgentTokenType},
		"resource":           {resource},
		"scope":              {scope},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	f.exch.Handle(rec, req)
	return rec
}

func TestTokenExchangeEndToEnd(t *testing.T) {
	f := setupExchange(t, []string{"expenses:read", "expenses:submit"},
		delegation.Constraints{Resources: []string{xchgResource}})
	ctx := context.Background()

	rec := f.exchange(t, "expenses:read", xchgResource, "user-tok", "agent-tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("exchange failed: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
		ExpiresIn       int    `json:"expires_in"`
		Scope           string `json:"scope"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.TokenType != "Bearer" || resp.Scope != "expenses:read" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.ExpiresIn <= 0 || resp.ExpiresIn > 300 {
		t.Fatalf("TTL not clamped to <=5m: %d", resp.ExpiresIn)
	}

	// The minted token is a delegation (sub=user, act=agent), NOT impersonation.
	claims, err := delegation.NewVerifier(xchgIssuer, f.ks.VerifierKeys()).Verify(resp.AccessToken, xchgResource)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user:"+f.userID {
		t.Fatalf("subject should be the user, got %q", claims.Subject)
	}
	if claims.Act == nil || claims.Act.Sub != "agent:"+f.agentID {
		t.Fatalf("act must name the agent (delegation, not impersonation), got %+v", claims.Act)
	}

	// The exchange recorded an audit line with full provenance.
	var auditSub string
	var auditChain []string
	if err := f.pool.QueryRow(ctx,
		`SELECT on_behalf_of_sub, actor_chain FROM audit_events WHERE grant_jti = $1 AND action = 'token.exchanged'`,
		claims.ID).Scan(&auditSub, &auditChain); err != nil {
		t.Fatalf("audit row not found: %v", err)
	}
	if auditSub != "user:"+f.userID || len(auditChain) == 0 {
		t.Fatalf("audit provenance incomplete: sub=%q chain=%v", auditSub, auditChain)
	}

	// Introspection: active before revoke, inactive after.
	if r, ok := f.exch.IntrospectDelegation(ctx, resp.AccessToken); !ok || r["active"] != true {
		t.Fatalf("token should introspect active, got %v", r)
	}
	if _, err := f.rev.Revoke(ctx, claims.ID); err != nil {
		t.Fatal(err)
	}
	if r, _ := f.exch.IntrospectDelegation(ctx, resp.AccessToken); r["active"] != false {
		t.Fatalf("revoked token must introspect inactive, got %v", r)
	}
}

func TestExchangeRateLimit(t *testing.T) {
	f := setupExchange(t, []string{"expenses:read"},
		delegation.Constraints{Resources: []string{xchgResource}, Rate: &delegation.RateLimit{MaxPerHour: 2}})

	// The first two mints are within the cap.
	for i := 1; i <= 2; i++ {
		if rec := f.exchange(t, "expenses:read", xchgResource, "user-tok", "agent-tok"); rec.Code != http.StatusOK {
			t.Fatalf("mint %d should succeed, got %d %s", i, rec.Code, rec.Body.String())
		}
	}
	// The third exceeds max_per_hour=2 and is rejected.
	rec := f.exchange(t, "expenses:read", xchgResource, "user-tok", "agent-tok")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("third mint should be rate-limited (429), got %d %s", rec.Code, rec.Body.String())
	}
}

func TestExchangeScopeCeiling(t *testing.T) {
	f := setupExchange(t, []string{"expenses:read"}, // delegation only grants read
		delegation.Constraints{Resources: []string{xchgResource}})

	// Requesting submit (in the subject token but NOT the delegation) is dropped.
	rec := f.exchange(t, "expenses:submit", xchgResource, "user-tok", "agent-tok")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("scope beyond the delegation must be rejected, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestExchangeEmptyResourcesDenied(t *testing.T) {
	f := setupExchange(t, []string{"expenses:read"}, delegation.Constraints{}) // no Resources
	rec := f.exchange(t, "expenses:read", xchgResource, "user-tok", "agent-tok")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty Resources must fail closed (deny), got %d", rec.Code)
	}
	var resp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["error"] != "invalid_target" {
		t.Fatalf("expected invalid_target, got %v", resp["error"])
	}
}

func TestExchangeWrongResourceDenied(t *testing.T) {
	f := setupExchange(t, []string{"expenses:read"},
		delegation.Constraints{Resources: []string{xchgResource}})
	rec := f.exchange(t, "expenses:read", "https://evil.example", "user-tok", "agent-tok")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a resource outside the delegation must be denied, got %d", rec.Code)
	}
}

// RFC 8707: more than one resource indicator must be rejected, not silently
// truncated to the first (which would allow audience confusion).
func TestExchangeRejectsMultipleResources(t *testing.T) {
	f := setupExchange(t, []string{"expenses:read"},
		delegation.Constraints{Resources: []string{xchgResource}})

	form := url.Values{
		"grant_type":    {auth.TokenExchangeGrantType},
		"subject_token": {"user-tok"},
		"actor_token":   {"agent-tok"},
		"scope":         {"expenses:read"},
	}
	form["resource"] = []string{xchgResource, "https://evil.example/"}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = req.ParseForm()
	rec := httptest.NewRecorder()
	f.exch.Handle(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("multiple resource indicators must be rejected, got %d", rec.Code)
	}
	var resp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["error"] != "invalid_target" {
		t.Fatalf("want invalid_target, got %v", resp["error"])
	}
}

func TestExchangeBadActorToken(t *testing.T) {
	f := setupExchange(t, []string{"expenses:read"},
		delegation.Constraints{Resources: []string{xchgResource}})
	rec := f.exchange(t, "expenses:read", xchgResource, "user-tok", "wrong-agent-tok")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid actor token must be 401, got %d", rec.Code)
	}
}

// The critical binding: the minted token is for the user the SUBJECT TOKEN
// belongs to, and a delegation must exist from that exact user to the agent. An
// agent holding a token for an unrelated user (who never delegated) gets nothing.
func TestExchangeRejectsSubjectFromUnrelatedUser(t *testing.T) {
	f := setupExchange(t, []string{"expenses:read"},
		delegation.Constraints{Resources: []string{xchgResource}})
	ctx := context.Background()

	var otherUser string
	if err := f.pool.QueryRow(ctx,
		`INSERT INTO users (email,status) VALUES ('other@x.com','active') RETURNING id::text`).Scan(&otherUser); err != nil {
		t.Fatal(err)
	}
	// Subject token resolves to a user with no delegation to this agent.
	exch := auth.NewTokenExchanger(xchgIssuer, 5*time.Minute, f.ks, chains.NewService(f.pool, nil), f.rev, f.pool, nil,
		func(ctx context.Context, token string) (string, bool) { return f.agentID, token == "agent-tok" },
		func(ctx context.Context, token string) (string, []string, bool) {
			return otherUser, []string{"expenses:read"}, true
		},
	)

	form := url.Values{
		"grant_type":    {auth.TokenExchangeGrantType},
		"subject_token": {"user-tok"},
		"actor_token":   {"agent-tok"},
		"resource":      {xchgResource},
		"scope":         {"expenses:read"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = req.ParseForm()
	rec := httptest.NewRecorder()
	exch.Handle(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("an agent must not mint a token for a user who did not delegate to it; want 403, got %d %s", rec.Code, rec.Body.String())
	}
}

// A consent carrying a resource (but no explicit resources constraint) must
// produce a delegation that is exchangeable for that resource.
func TestConsentResourceFoldedIntoConstraints(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	ks, err := keystore.Open(ctx, pool, bytes.Repeat([]byte("k"), 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ch := chains.NewService(pool, nil)
	rev := revocation.NewStore(pool, nil)

	var userID, agentID string
	pool.QueryRow(ctx, `INSERT INTO users (email,status) VALUES ('f@x.com','active') RETURNING id::text`).Scan(&userID)
	pool.QueryRow(ctx, `INSERT INTO agents (name,type) VALUES ('a','ai_agent') RETURNING id::text`).Scan(&agentID)
	if _, _, err := ch.GrantConsent(ctx, chains.ConsentRequest{
		UserID: userID, AgentID: agentID, Scopes: []string{"x"}, Resource: xchgResource, TTL: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}

	exch := auth.NewTokenExchanger(xchgIssuer, 5*time.Minute, ks, ch, rev, pool, nil,
		func(ctx context.Context, tok string) (string, bool) { return agentID, tok == "a" },
		func(ctx context.Context, tok string) (string, []string, bool) { return userID, []string{"x"}, true },
	)
	form := url.Values{
		"grant_type": {auth.TokenExchangeGrantType}, "subject_token": {"u"},
		"actor_token": {"a"}, "resource": {xchgResource}, "scope": {"x"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = req.ParseForm()
	rec := httptest.NewRecorder()
	exch.Handle(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("a consent resource should make the delegation exchangeable, got %d %s", rec.Code, rec.Body.String())
	}
}

// TestTokenExchangeStampsOrgInAudit verifies the mint audit row carries the
// delegation's org, so per-tenant audit/billing can attribute the event.
func TestTokenExchangeStampsOrgInAudit(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	ks, err := keystore.Open(ctx, pool, bytes.Repeat([]byte("k"), 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ch := chains.NewService(pool, nil)
	rev := revocation.NewStore(pool, nil)

	var userID, orgID, agentID string
	if err := pool.QueryRow(ctx, `INSERT INTO users (email,status) VALUES ('orgaudit@x.com','active') RETURNING id::text`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO orgs (slug,name) VALUES ('tx-acme','Acme') RETURNING id::text`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO agents (name,type,org_id) VALUES ('a','ai_agent',$1) RETURNING id::text`, orgID).Scan(&agentID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ch.GrantConsent(ctx, chains.ConsentRequest{
		UserID: userID, AgentID: agentID, OrgID: orgID, Scopes: []string{"expenses:read"},
		Constraints: delegation.Constraints{Resources: []string{xchgResource}}, TTL: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}

	exch := auth.NewTokenExchanger(xchgIssuer, 5*time.Minute, ks, ch, rev, pool, nil,
		func(ctx context.Context, tok string) (string, bool) { return agentID, tok == "agent-tok" },
		func(ctx context.Context, tok string) (string, []string, bool) {
			return userID, []string{"expenses:read"}, true
		},
	)
	form := url.Values{
		"grant_type": {auth.TokenExchangeGrantType}, "subject_token": {"user-tok"},
		"actor_token": {"agent-tok"}, "resource": {xchgResource}, "scope": {"expenses:read"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = req.ParseForm()
	rec := httptest.NewRecorder()
	exch.Handle(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("exchange should succeed, got %d %s", rec.Code, rec.Body.String())
	}

	var auditOrg *string
	if err := pool.QueryRow(ctx,
		`SELECT org_id::text FROM audit_events WHERE action='token.exchanged' ORDER BY id DESC LIMIT 1`).Scan(&auditOrg); err != nil {
		t.Fatalf("mint must write an audit row: %v", err)
	}
	if auditOrg == nil || *auditOrg != orgID {
		t.Fatalf("mint audit org_id should be %s, got %v", orgID, auditOrg)
	}
}
