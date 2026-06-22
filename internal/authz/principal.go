// Package authz models the authenticated caller (a Principal) and the
// authorization decisions made about it. It is deliberately free of imports on
// the auth/agent packages so those packages can depend on it without a cycle;
// the concrete authentication wiring is injected (see Authenticator).
package authz

import (
	"context"
)

// Type distinguishes the kind of caller behind a request.
type Type string

const (
	TypeUser  Type = "user"
	TypeAgent Type = "agent"
)

// Principal is the authenticated identity behind a request: who they are, which
// organizations they belong to and with what role, and how they authenticated.
// It replaces the previously-trusted, spoofable X-User-ID header.
type Principal struct {
	Type         Type
	ID           string            // user id / agent id / client id
	OrgRoles     map[string]string // org_id -> role ("owner" | "admin" | "member" | "agent")
	IsSuperadmin bool
	Scopes       []string // granted scopes, for token/agent principals
	AuthMethod   string   // "session" | "bearer" | "agent_token"
}

// OrgIDs returns the organizations this principal belongs to.
func (p *Principal) OrgIDs() []string {
	ids := make([]string, 0, len(p.OrgRoles))
	for id := range p.OrgRoles {
		ids = append(ids, id)
	}
	return ids
}

// RoleIn returns the principal's role in an organization.
func (p *Principal) RoleIn(orgID string) (string, bool) {
	r, ok := p.OrgRoles[orgID]
	return r, ok
}

// CanAccessOrg reports whether the principal may access resources in orgID. A
// superadmin may access any org. An empty orgID denotes a global (org-less)
// resource, which only a superadmin may touch.
func (p *Principal) CanAccessOrg(orgID string) bool {
	if p.IsSuperadmin {
		return true
	}
	if orgID == "" {
		return false
	}
	_, ok := p.OrgRoles[orgID]
	return ok
}

// IsOrgAdmin reports whether the principal is an owner/admin of orgID (or a
// superadmin).
func (p *Principal) IsOrgAdmin(orgID string) bool {
	if p.IsSuperadmin {
		return true
	}
	role, ok := p.OrgRoles[orgID]
	return ok && (role == "owner" || role == "admin")
}

// AdminCapable reports whether the principal may reach the admin API at all —
// a superadmin, or an owner/admin of at least one organization.
func (p *Principal) AdminCapable() bool {
	if p.IsSuperadmin {
		return true
	}
	for _, role := range p.OrgRoles {
		if role == "owner" || role == "admin" {
			return true
		}
	}
	return false
}

type ctxKey struct{}

// WithPrincipal stores the principal on the context.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext retrieves the principal placed on the context by the authenticator.
func FromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(*Principal)
	return p, ok
}
