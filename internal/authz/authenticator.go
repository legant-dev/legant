package authz

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AgentTokenPrefix marks an opaque agent token presented as a bearer credential.
const AgentTokenPrefix = "legant_at_"

// Resolver functions are injected by the server so this package needs no
// dependency on auth/agent (which themselves depend on authz).
type (
	// SessionResolver returns the user id for a request's session cookie.
	SessionResolver func(r *http.Request) (userID string, ok bool)
	// AgentTokenResolver validates an opaque agent token.
	AgentTokenResolver func(ctx context.Context, token string) (agentID string, scopes []string, tokenID string, ok bool)
	// BearerResolver validates an OAuth2 access token (e.g. via introspection).
	BearerResolver func(ctx context.Context, token string) (userID string, scopes []string, ok bool)
)

// Authenticator resolves a request to a Principal using, in order: a session
// cookie, an agent bearer token, or an OAuth2 access token. It loads org
// membership and superadmin status from the database to populate the Principal.
type Authenticator struct {
	pool    *pgxpool.Pool
	session SessionResolver
	agent   AgentTokenResolver
	bearer  BearerResolver
}

func NewAuthenticator(pool *pgxpool.Pool, session SessionResolver, agent AgentTokenResolver, bearer BearerResolver) *Authenticator {
	return &Authenticator{pool: pool, session: session, agent: agent, bearer: bearer}
}

// Authenticate resolves the request to a Principal, or returns ok=false.
func (a *Authenticator) Authenticate(r *http.Request) (*Principal, bool) {
	ctx := r.Context()

	if a.session != nil {
		if uid, ok := a.session(r); ok {
			if p, err := a.userPrincipal(ctx, uid, "session"); err == nil {
				return p, true
			}
		}
	}

	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		return nil, false
	}
	token := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))

	if strings.HasPrefix(token, AgentTokenPrefix) {
		if a.agent == nil {
			return nil, false
		}
		if aid, scopes, tid, ok := a.agent(ctx, token); ok {
			if p, err := a.agentPrincipal(ctx, aid, scopes, tid); err == nil {
				return p, true
			}
		}
		return nil, false
	}

	if a.bearer != nil {
		if uid, scopes, ok := a.bearer(ctx, token); ok {
			if p, err := a.userPrincipal(ctx, uid, "bearer"); err == nil {
				p.Scopes = scopes
				return p, true
			}
		}
	}
	return nil, false
}

// Require is middleware that rejects unauthenticated requests with 401 and
// attaches the Principal to the context for downstream handlers.
func (a *Authenticator) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := a.Authenticate(r)
		if !ok {
			challenge(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

// RequireSuperadmin is middleware (placed after Require) that allows only
// platform superadmins. Use it for global resources that are not org-scoped
// (e.g. user and client management), so an org-admin cannot reach across tenants.
func RequireSuperadmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := FromContext(r.Context())
		if !ok {
			challenge(w)
			return
		}
		if !p.IsSuperadmin {
			forbidden(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAdmin is middleware (placed after Require) that allows only
// admin-capable principals: a superadmin, or an owner/admin of some org. Use it
// for org-scoped resources whose handlers further restrict by the caller's orgs.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := FromContext(r.Context())
		if !ok {
			challenge(w)
			return
		}
		if !p.AdminCapable() {
			forbidden(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// AuthenticateActor validates an agent token and returns the agent Principal.
// Used by the RFC 8693 token-exchange endpoint to authenticate the acting agent.
func (a *Authenticator) AuthenticateActor(ctx context.Context, token string) (*Principal, error) {
	if a.agent == nil {
		return nil, fmt.Errorf("agent authentication not configured")
	}
	aid, scopes, tid, ok := a.agent(ctx, token)
	if !ok {
		return nil, fmt.Errorf("invalid agent token")
	}
	return a.agentPrincipal(ctx, aid, scopes, tid)
}

func (a *Authenticator) userPrincipal(ctx context.Context, userID, method string) (*Principal, error) {
	p := &Principal{Type: TypeUser, ID: userID, OrgRoles: map[string]string{}, AuthMethod: method}
	if err := a.pool.QueryRow(ctx,
		`SELECT is_superadmin FROM users WHERE id = $1 AND status = 'active'`, userID,
	).Scan(&p.IsSuperadmin); err != nil {
		return nil, fmt.Errorf("loading user %s: %w", userID, err)
	}
	rows, err := a.pool.Query(ctx, `SELECT org_id::text, role FROM org_members WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var orgID, role string
		if err := rows.Scan(&orgID, &role); err != nil {
			return nil, err
		}
		p.OrgRoles[orgID] = role
	}
	return p, rows.Err()
}

func (a *Authenticator) agentPrincipal(ctx context.Context, agentID string, scopes []string, tokenID string) (*Principal, error) {
	p := &Principal{
		Type:       TypeAgent,
		ID:         agentID,
		OrgRoles:   map[string]string{},
		Scopes:     scopes,
		AuthMethod: "agent_token",
	}
	var orgID *string
	if err := a.pool.QueryRow(ctx, `SELECT org_id::text FROM agents WHERE id = $1`, agentID).Scan(&orgID); err != nil {
		return nil, fmt.Errorf("loading agent %s: %w", agentID, err)
	}
	if orgID != nil {
		p.OrgRoles[*orgID] = "agent"
	}
	return p, nil
}

func challenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="legant"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
}

func forbidden(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"forbidden"}`))
}
