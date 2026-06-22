package org

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

// ---- Org types ----

type Org struct {
	ID        string                 `json:"id"`
	Slug      string                 `json:"slug"`
	Name      string                 `json:"name"`
	ParentID  *string                `json:"parent_id,omitempty"`
	Settings  map[string]interface{} `json:"settings"`
	Status    string                 `json:"status"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

type CreateOrgRequest struct {
	Slug     string                 `json:"slug" validate:"required"`
	Name     string                 `json:"name" validate:"required"`
	ParentID *string                `json:"parent_id"`
	Settings map[string]interface{} `json:"settings"`
}

type UpdateOrgRequest struct {
	Name     *string                `json:"name"`
	Slug     *string                `json:"slug"`
	Settings map[string]interface{} `json:"settings"`
}

type Member struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	UserID      string    `json:"user_id"`
	Role        string    `json:"role"`
	Email       string    `json:"email,omitempty"`
	DisplayName string    `json:"display_name,omitempty"`
	AvatarURL   string    `json:"avatar_url,omitempty"`
	UserStatus  string    `json:"user_status,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type AddMemberRequest struct {
	UserID string `json:"user_id" validate:"required"`
	Role   string `json:"role" validate:"required"`
}

type UpdateMemberRequest struct {
	Role string `json:"role" validate:"required"`
}

// ---- SSO types ----

type SSOConnection struct {
	ID        string                 `json:"id"`
	OrgID     string                 `json:"org_id"`
	Provider  string                 `json:"provider"`
	Config    map[string]interface{} `json:"config"`
	Domain    string                 `json:"domain"`
	Enabled   bool                   `json:"enabled"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

type CreateSSORequest struct {
	Provider string                 `json:"provider" validate:"required"`
	Config   map[string]interface{} `json:"config" validate:"required"`
	Domain   string                 `json:"domain"`
	Enabled  bool                   `json:"enabled"`
}

type UpdateSSORequest struct {
	Provider *string                `json:"provider"`
	Config   map[string]interface{} `json:"config"`
	Domain   *string                `json:"domain"`
	Enabled  *bool                  `json:"enabled"`
}

// ---- Invitation types ----

type Invitation struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	Token     string    `json:"token,omitempty"`
	Status    string    `json:"status"`
	InviterID string    `json:"inviter_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type CreateInvitationRequest struct {
	Email string `json:"email" validate:"required,email"`
	Role  string `json:"role" validate:"required"`
}

// ---- Org CRUD ----

func (s *Service) CreateOrg(ctx context.Context, req CreateOrgRequest) (*Org, error) {
	if req.Slug == "" || req.Name == "" {
		return nil, fmt.Errorf("slug and name are required")
	}

	settingsJSON, _ := json.Marshal(req.Settings)
	if req.Settings == nil {
		settingsJSON = []byte("{}")
	}

	var org Org
	err := s.pool.QueryRow(ctx,
		`INSERT INTO orgs (slug, name, parent_id, settings) VALUES ($1, $2, $3, $4)
		 RETURNING id, slug, name, parent_id, settings, status, created_at, updated_at`,
		req.Slug, req.Name, req.ParentID, settingsJSON,
	).Scan(&org.ID, &org.Slug, &org.Name, &org.ParentID, &org.Settings, &org.Status, &org.CreatedAt, &org.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("creating org: %w", err)
	}
	return &org, nil
}

func (s *Service) GetOrg(ctx context.Context, id string) (*Org, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, fmt.Errorf("invalid org ID")
	}
	var org Org
	err := s.pool.QueryRow(ctx,
		`SELECT id, slug, name, parent_id, settings, status, created_at, updated_at FROM orgs WHERE id = $1`, id,
	).Scan(&org.ID, &org.Slug, &org.Name, &org.ParentID, &org.Settings, &org.Status, &org.CreatedAt, &org.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("org not found")
		}
		return nil, fmt.Errorf("getting org: %w", err)
	}
	return &org, nil
}

func (s *Service) ListOrgs(ctx context.Context, limit, offset int) ([]Org, int64, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx,
		`SELECT id, slug, name, parent_id, settings, status, created_at, updated_at
		 FROM orgs WHERE status = 'active' ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var orgs []Org
	for rows.Next() {
		var o Org
		if err := rows.Scan(&o.ID, &o.Slug, &o.Name, &o.ParentID, &o.Settings, &o.Status, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, 0, err
		}
		orgs = append(orgs, o)
	}

	var total int64
	s.pool.QueryRow(ctx, `SELECT count(*) FROM orgs WHERE status = 'active'`).Scan(&total)

	return orgs, total, nil
}

func (s *Service) UpdateOrg(ctx context.Context, id string, req UpdateOrgRequest) (*Org, error) {
	existing, err := s.GetOrg(ctx, id)
	if err != nil {
		return nil, err
	}

	name := existing.Name
	if req.Name != nil {
		name = *req.Name
	}
	slug := existing.Slug
	if req.Slug != nil {
		slug = *req.Slug
	}
	settingsJSON, _ := json.Marshal(existing.Settings)
	if req.Settings != nil {
		settingsJSON, _ = json.Marshal(req.Settings)
	}

	var org Org
	err = s.pool.QueryRow(ctx,
		`UPDATE orgs SET name = $2, slug = $3, settings = $4, updated_at = now() WHERE id = $1
		 RETURNING id, slug, name, parent_id, settings, status, created_at, updated_at`,
		id, name, slug, settingsJSON,
	).Scan(&org.ID, &org.Slug, &org.Name, &org.ParentID, &org.Settings, &org.Status, &org.CreatedAt, &org.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("updating org: %w", err)
	}
	return &org, nil
}

func (s *Service) DeleteOrg(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE orgs SET status = 'suspended', updated_at = now() WHERE id = $1`, id)
	return err
}

// ---- Membership ----

func (s *Service) AddMember(ctx context.Context, orgID string, req AddMemberRequest) (*Member, error) {
	if req.Role != "owner" && req.Role != "admin" && req.Role != "member" {
		return nil, fmt.Errorf("role must be owner, admin, or member")
	}

	var m Member
	err := s.pool.QueryRow(ctx,
		`INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, $3)
		 RETURNING id, org_id, user_id, role, created_at`,
		orgID, req.UserID, req.Role,
	).Scan(&m.ID, &m.OrgID, &m.UserID, &m.Role, &m.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("adding member: %w", err)
	}
	return &m, nil
}

func (s *Service) ListMembers(ctx context.Context, orgID string, limit, offset int) ([]Member, int64, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx,
		`SELECT om.id, om.org_id, om.user_id, om.role, u.email, u.display_name, u.avatar_url, u.status, om.created_at
		 FROM org_members om JOIN users u ON u.id = om.user_id
		 WHERE om.org_id = $1 ORDER BY om.created_at DESC LIMIT $2 OFFSET $3`,
		orgID, limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var members []Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.ID, &m.OrgID, &m.UserID, &m.Role, &m.Email, &m.DisplayName, &m.AvatarURL, &m.UserStatus, &m.CreatedAt); err != nil {
			return nil, 0, err
		}
		members = append(members, m)
	}

	var total int64
	s.pool.QueryRow(ctx, `SELECT count(*) FROM org_members WHERE org_id = $1`, orgID).Scan(&total)

	return members, total, nil
}

func (s *Service) UpdateMemberRole(ctx context.Context, orgID, userID, role string) error {
	if role != "owner" && role != "admin" && role != "member" {
		return fmt.Errorf("role must be owner, admin, or member")
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE org_members SET role = $3 WHERE org_id = $1 AND user_id = $2`,
		orgID, userID, role,
	)
	return err
}

func (s *Service) RemoveMember(ctx context.Context, orgID, userID string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM org_members WHERE org_id = $1 AND user_id = $2`,
		orgID, userID,
	)
	return err
}

// ---- SSO Connections ----

func (s *Service) CreateSSO(ctx context.Context, orgID string, req CreateSSORequest) (*SSOConnection, error) {
	if req.Provider != "saml" && req.Provider != "oidc" {
		return nil, fmt.Errorf("provider must be saml or oidc")
	}

	configJSON, _ := json.Marshal(req.Config)

	var sso SSOConnection
	err := s.pool.QueryRow(ctx,
		`INSERT INTO sso_connections (org_id, provider, config, domain, enabled) VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, org_id, provider, config, domain, enabled, created_at, updated_at`,
		orgID, req.Provider, configJSON, req.Domain, req.Enabled,
	).Scan(&sso.ID, &sso.OrgID, &sso.Provider, &sso.Config, &sso.Domain, &sso.Enabled, &sso.CreatedAt, &sso.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("creating SSO connection: %w", err)
	}
	return &sso, nil
}

func (s *Service) ListSSO(ctx context.Context, orgID string) ([]SSOConnection, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, org_id, provider, config, domain, enabled, created_at, updated_at
		 FROM sso_connections WHERE org_id = $1 ORDER BY created_at DESC`,
		orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var connections []SSOConnection
	for rows.Next() {
		var c SSOConnection
		if err := rows.Scan(&c.ID, &c.OrgID, &c.Provider, &c.Config, &c.Domain, &c.Enabled, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		connections = append(connections, c)
	}
	return connections, nil
}

func (s *Service) GetSSO(ctx context.Context, id string) (*SSOConnection, error) {
	var c SSOConnection
	err := s.pool.QueryRow(ctx,
		`SELECT id, org_id, provider, config, domain, enabled, created_at, updated_at
		 FROM sso_connections WHERE id = $1`, id,
	).Scan(&c.ID, &c.OrgID, &c.Provider, &c.Config, &c.Domain, &c.Enabled, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("SSO connection not found")
		}
		return nil, err
	}
	return &c, nil
}

func (s *Service) UpdateSSO(ctx context.Context, id string, req UpdateSSORequest) (*SSOConnection, error) {
	existing, err := s.GetSSO(ctx, id)
	if err != nil {
		return nil, err
	}

	provider := existing.Provider
	if req.Provider != nil {
		provider = *req.Provider
	}
	domain := existing.Domain
	if req.Domain != nil {
		domain = *req.Domain
	}
	enabled := existing.Enabled
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	configJSON, _ := json.Marshal(existing.Config)
	if req.Config != nil {
		configJSON, _ = json.Marshal(req.Config)
	}

	var sso SSOConnection
	err = s.pool.QueryRow(ctx,
		`UPDATE sso_connections SET provider = $2, config = $3, domain = $4, enabled = $5, updated_at = now()
		 WHERE id = $1
		 RETURNING id, org_id, provider, config, domain, enabled, created_at, updated_at`,
		id, provider, configJSON, domain, enabled,
	).Scan(&sso.ID, &sso.OrgID, &sso.Provider, &sso.Config, &sso.Domain, &sso.Enabled, &sso.CreatedAt, &sso.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("updating SSO connection: %w", err)
	}
	return &sso, nil
}

func (s *Service) DeleteSSO(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sso_connections WHERE id = $1`, id)
	return err
}
