package retention_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/legant-dev/legant/internal/audit"
	"github.com/legant-dev/legant/internal/retention"
	"github.com/legant-dev/legant/internal/testsupport"
)

func TestPruneAuditKeepsChainVerifiable(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()

	// Five hash-chained audit events: three old, two recent.
	for _, age := range []string{"400 days", "399 days", "398 days", "2 hours", "1 minute"} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO audit_events (actor_type, action, created_at) VALUES ('system','e', now() - $1::interval)`, age); err != nil {
			t.Fatal(err)
		}
	}
	if res, err := audit.Verify(ctx, pool); err != nil || !res.OK {
		t.Fatalf("pre-prune chain must verify, got %+v err %v", res, err)
	}

	// Prune audit events older than a year — deletes the genesis side of the chain.
	res, err := retention.Prune(ctx, pool, retention.Policy{AuditRetention: 365 * 24 * time.Hour}, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.AgedAuditEvents != 3 {
		t.Fatalf("pruned %d audit rows, want 3", res.AgedAuditEvents)
	}

	// The remaining chain must STILL verify (the watermark covers the pruned prefix).
	if r, err := audit.Verify(ctx, pool); err != nil || !r.OK {
		t.Fatalf("chain must still verify after audit prune, got %+v err %v", r, err)
	}
	// And tampering a surviving row is still detected.
	if _, err := pool.Exec(ctx, `UPDATE audit_events SET action='HACK' WHERE seq=(SELECT min(seq) FROM audit_events)`); err != nil {
		t.Fatal(err)
	}
	if r, _ := audit.Verify(ctx, pool); r.OK {
		t.Error("tampering a surviving row after prune must still be detected")
	}
}

func TestPrune(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()

	// A user + agent + delegation so exchanged_tokens FKs are satisfiable.
	var userID, agentID, delegationID string
	if err := pool.QueryRow(ctx, `INSERT INTO users (email,status) VALUES ('p@x.com','active') RETURNING id::text`).Scan(&userID); err != nil {
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

	// Seed prunable and non-prunable rows across every table.
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	// sessions: one expired, one live.
	exec(`INSERT INTO sessions (id,user_id,expires_at) VALUES ('s-old',$1, now() - interval '1 hour')`, userID)
	exec(`INSERT INTO sessions (id,user_id,expires_at) VALUES ('s-live',$1, now() + interval '1 hour')`, userID)
	// email_tokens: one used, one expired, one live-unused.
	exec(`INSERT INTO email_tokens (user_id,type,token_hash,email,used,expires_at) VALUES ($1,'magic_link','h1','p@x.com',true, now() + interval '1 hour')`, userID)
	exec(`INSERT INTO email_tokens (user_id,type,token_hash,email,used,expires_at) VALUES ($1,'verification','h2','p@x.com',false, now() - interval '1 hour')`, userID)
	exec(`INSERT INTO email_tokens (user_id,type,token_hash,email,used,expires_at) VALUES ($1,'password_reset','h3','p@x.com',false, now() + interval '1 hour')`, userID)
	// dcr tokens: one exhausted, one expired, one live.
	exec(`INSERT INTO dcr_registration_tokens (token_hash,max_uses,used_count,expires_at) VALUES ('d1',1,1, now() + interval '1 hour')`)
	exec(`INSERT INTO dcr_registration_tokens (token_hash,max_uses,used_count,expires_at) VALUES ('d2',5,0, now() - interval '1 hour')`)
	exec(`INSERT INTO dcr_registration_tokens (token_hash,max_uses,used_count,expires_at) VALUES ('d3',5,0, now() + interval '1 hour')`)
	// exchanged_tokens: one long-dead, one recently-expired (within grace), one live.
	exch := func(jti string, expiresAt string) {
		exec(`INSERT INTO exchanged_tokens (jti,delegation_id,subject,agent_id,audience,scopes,expires_at)
		      VALUES ($1,$2,'user','`+agentID+`'::uuid,'api','{x}', `+expiresAt+`)`, jti, delegationID)
	}
	exch("t-dead", "now() - interval '40 days'")
	exch("t-recent", "now() - interval '1 hour'")
	exch("t-live", "now() + interval '1 hour'")
	// Fosite token stores need a client row (FK). Seed one expired + one live row
	// in each of the five tables.
	exec(`INSERT INTO oauth2_clients (id, secret_hash, name) VALUES ('c1','x','test-client')`)
	for _, table := range []string{"oauth2_auth_codes", "oauth2_access_tokens", "oauth2_refresh_tokens", "oauth2_pkce", "oauth2_oidc_sessions"} {
		exec(`INSERT INTO `+table+` (signature, request_id, client_id, session_data, requested_at, expires_at)
		      VALUES ($1,'r','c1','\x00', now(), now() - interval '1 hour')`, table+"-old")
		exec(`INSERT INTO `+table+` (signature, request_id, client_id, session_data, requested_at, expires_at)
		      VALUES ($1,'r','c1','\x00', now(), now() + interval '1 hour')`, table+"-live")
	}
	// agent_tokens: one expired, one never-expiring (NULL), one live.
	exec(`INSERT INTO agent_tokens (agent_id, token_hash, expires_at) VALUES ($1,'at-exp', now() - interval '1 hour')`, agentID)
	exec(`INSERT INTO agent_tokens (agent_id, token_hash, expires_at) VALUES ($1,'at-null', NULL)`, agentID)
	exec(`INSERT INTO agent_tokens (agent_id, token_hash, expires_at) VALUES ($1,'at-live', now() + interval '1 hour')`, agentID)
	// api_keys: one expired, one never-expiring (NULL), one live.
	exec(`INSERT INTO api_keys (key_hash,key_prefix,name,expires_at) VALUES ('ak-exp','p1','k', now() - interval '1 hour')`)
	exec(`INSERT INTO api_keys (key_hash,key_prefix,name,expires_at) VALUES ('ak-null','p2','k', NULL)`)
	exec(`INSERT INTO api_keys (key_hash,key_prefix,name,expires_at) VALUES ('ak-live','p3','k', now() + interval '1 hour')`)
	// org + invitations: one pending-live (kept), one expired-pending, one accepted.
	var orgID string
	if err := pool.QueryRow(ctx, `INSERT INTO orgs (slug,name) VALUES ('o','o') RETURNING id::text`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO org_invitations (org_id,email,token,status,expires_at) VALUES ($1,'a@x.com','i1','pending', now() + interval '1 day')`, orgID)
	exec(`INSERT INTO org_invitations (org_id,email,token,status,expires_at) VALUES ($1,'b@x.com','i2','pending', now() - interval '1 day')`, orgID)
	exec(`INSERT INTO org_invitations (org_id,email,token,status,expires_at) VALUES ($1,'c@x.com','i3','accepted', now() + interval '1 day')`, orgID)
	// audit_events: one old, one recent.
	exec(`INSERT INTO audit_events (actor_type,action,created_at) VALUES ('system','old', now() - interval '400 days')`)
	exec(`INSERT INTO audit_events (actor_type,action,created_at) VALUES ('system','new', now())`)

	policy := retention.Policy{TokenGrace: 30 * 24 * time.Hour, AuditRetention: 365 * 24 * time.Hour}

	// Dry-run must report the same counts it would delete, without deleting.
	dry, err := retention.Prune(ctx, pool, policy, true)
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	assertCounts(t, "dry-run", dry)
	if got := count(t, ctx, pool, "sessions"); got != 2 {
		t.Errorf("dry-run deleted rows: sessions=%d, want 2", got)
	}

	// Real prune.
	res, err := retention.Prune(ctx, pool, policy, false)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	assertCounts(t, "prune", res)

	// Survivors: the live/within-grace rows remain.
	checks := []struct {
		table string
		want  int64
	}{
		{"sessions", 1},
		{"email_tokens", 1},
		{"dcr_registration_tokens", 1},
		{"org_invitations", 1},  // live pending survives
		{"exchanged_tokens", 2}, // t-recent (within grace) + t-live
		{"oauth2_access_tokens", 1},
		{"oauth2_refresh_tokens", 1},
		{"agent_tokens", 2}, // live + never-expiring survive
		{"api_keys", 2},     // live + never-expiring survive
		{"audit_events", 1},
	}
	for _, c := range checks {
		if got := count(t, ctx, pool, c.table); got != c.want {
			t.Errorf("%s remaining = %d, want %d", c.table, got, c.want)
		}
	}

	// Second run is a no-op (idempotent).
	again, err := retention.Prune(ctx, pool, policy, false)
	if err != nil {
		t.Fatalf("second prune: %v", err)
	}
	if again.Total() != 0 {
		t.Errorf("second prune removed %d rows, want 0", again.Total())
	}
}

func TestPruneKeepsNonExpiringOAuthTokens(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO oauth2_clients (id, secret_hash, name) VALUES ('c1','x','t')`); err != nil {
		t.Fatal(err)
	}
	// A non-expiring refresh token is stored by Fosite with the Go zero time
	// ('0001-01-01'), which is < now(). It must NOT be pruned.
	if _, err := pool.Exec(ctx,
		`INSERT INTO oauth2_refresh_tokens (signature, request_id, client_id, session_data, requested_at, expires_at)
		 VALUES ('rt-forever','r','c1','\x00', now(), '0001-01-01 00:00:00+00')`); err != nil {
		t.Fatal(err)
	}
	res, err := retention.Prune(ctx, pool, retention.DefaultPolicy, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExpiredOAuthTokens != 0 {
		t.Errorf("ExpiredOAuthTokens = %d, want 0 (zero-time = non-expiring)", res.ExpiredOAuthTokens)
	}
	if got := count(t, ctx, pool, "oauth2_refresh_tokens"); got != 1 {
		t.Errorf("non-expiring refresh token was pruned: remaining=%d", got)
	}
}

func TestPruneAuditDisabledByDefault(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`INSERT INTO audit_events (actor_type,action,created_at) VALUES ('system','ancient', now() - interval '5000 days')`); err != nil {
		t.Fatal(err)
	}
	// DefaultPolicy has AuditRetention == 0, so audit is never auto-deleted.
	res, err := retention.Prune(ctx, pool, retention.DefaultPolicy, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.AgedAuditEvents != 0 {
		t.Errorf("AgedAuditEvents = %d, want 0 (audit retention disabled)", res.AgedAuditEvents)
	}
	if got := count(t, ctx, pool, "audit_events"); got != 1 {
		t.Errorf("audit row deleted despite disabled retention: remaining=%d", got)
	}
}

func assertCounts(t *testing.T, label string, r retention.Result) {
	t.Helper()
	want := retention.Result{
		ExpiredSessions:     1,
		StaleEmailTokens:    2, // used + expired
		ExhaustedDCRTokens:  2, // exhausted + expired
		StaleInvitations:    2, // expired-pending + accepted; live pending survives
		DeadExchangedTokens: 1, // only the 40-day-old token
		ExpiredOAuthTokens:  5, // one expired row in each of the five Fosite tables
		ExpiredAgentTokens:  1, // expired; NULL and live survive
		ExpiredAPIKeys:      1, // expired; NULL and live survive
		AgedAuditEvents:     1,
	}
	if r != want {
		t.Errorf("%s counts = %+v, want %+v", label, r, want)
	}
}

func count(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table string) int64 {
	t.Helper()
	var n int64
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
