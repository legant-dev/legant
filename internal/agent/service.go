package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	legantcrypto "github.com/legant-dev/legant/internal/crypto"
)

type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

// ---- Agent types ----

type Agent struct {
	ID          string                 `json:"id"`
	OrgID       *string                `json:"org_id,omitempty"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"`
	OwnerID     *string                `json:"owner_id,omitempty"`
	Status      string                 `json:"status"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

type CreateAgentRequest struct {
	OrgID       *string                `json:"org_id"`
	Name        string                 `json:"name" validate:"required"`
	Description string                 `json:"description"`
	Type        string                 `json:"type" validate:"required"` // service, ai_agent, mcp_server
	OwnerID     *string                `json:"owner_id"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type UpdateAgentRequest struct {
	Name        *string                `json:"name"`
	Description *string                `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type AgentToken struct {
	ID          string                 `json:"id"`
	AgentID     string                 `json:"agent_id"`
	Name        string                 `json:"name"`
	Scopes      []string               `json:"scopes"`
	Permissions map[string]interface{} `json:"permissions"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time             `json:"last_used_at,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
}

type CreateAgentTokenRequest struct {
	Name        string                 `json:"name" validate:"required"`
	Scopes      []string               `json:"scopes"`
	Permissions map[string]interface{} `json:"permissions"`
	ExpiresAt   *time.Time             `json:"expires_at"`
}

type CreateAgentTokenResponse struct {
	AgentToken
	PlainToken string `json:"token"` // returned only once at creation
}

type Delegation struct {
	ID               string                 `json:"id"`
	DelegatorID      string                 `json:"delegator_id"`
	DelegateeAgentID string                 `json:"delegatee_agent_id"`
	Scopes           []string               `json:"scopes"`
	Constraints      map[string]interface{} `json:"constraints"`
	Active           bool                   `json:"active"`
	CreatedAt        time.Time              `json:"created_at"`
	ExpiresAt        *time.Time             `json:"expires_at,omitempty"`
}

type CreateDelegationRequest struct {
	DelegateeAgentID string                 `json:"delegatee_agent_id" validate:"required"`
	Scopes           []string               `json:"scopes" validate:"required"`
	Constraints      map[string]interface{} `json:"constraints"`
	ExpiresAt        *time.Time             `json:"expires_at"`
}

// ---- Agent CRUD ----

func (s *Service) Create(ctx context.Context, req CreateAgentRequest) (*Agent, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if req.Type != "service" && req.Type != "ai_agent" && req.Type != "mcp_server" {
		return nil, fmt.Errorf("type must be service, ai_agent, or mcp_server")
	}

	metadataJSON, _ := json.Marshal(req.Metadata)
	if req.Metadata == nil {
		metadataJSON = []byte("{}")
	}

	var a Agent
	err := s.pool.QueryRow(ctx,
		`INSERT INTO agents (org_id, name, description, type, owner_id, metadata)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, org_id, name, description, type, owner_id, status, metadata, created_at, updated_at`,
		req.OrgID, req.Name, req.Description, req.Type, req.OwnerID, metadataJSON,
	).Scan(&a.ID, &a.OrgID, &a.Name, &a.Description, &a.Type, &a.OwnerID, &a.Status, &a.Metadata, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("creating agent: %w", err)
	}
	return &a, nil
}

func (s *Service) GetByID(ctx context.Context, id string) (*Agent, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, fmt.Errorf("invalid agent ID")
	}
	var a Agent
	err := s.pool.QueryRow(ctx,
		`SELECT id, org_id, name, description, type, owner_id, status, metadata, created_at, updated_at
		 FROM agents WHERE id = $1`, id,
	).Scan(&a.ID, &a.OrgID, &a.Name, &a.Description, &a.Type, &a.OwnerID, &a.Status, &a.Metadata, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("agent not found")
		}
		return nil, err
	}
	return &a, nil
}

// List returns agents visible to the caller. When includeAll is false (a
// non-superadmin), results are restricted to agents in the given organizations;
// org-less (global) agents are visible only to superadmins.
func (s *Service) List(ctx context.Context, orgIDs []string, includeAll bool, limit, offset int) ([]Agent, int64, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}

	where := "status != 'revoked'"
	var filterArgs []any
	if !includeAll {
		where += " AND org_id = ANY($1::uuid[])"
		filterArgs = append(filterArgs, orgIDs)
	}

	listArgs := append(append([]any{}, filterArgs...), limit, offset)
	query := fmt.Sprintf(
		`SELECT id, org_id, name, description, type, owner_id, status, metadata, created_at, updated_at
		 FROM agents WHERE %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		where, len(filterArgs)+1, len(filterArgs)+2,
	)
	rows, err := s.pool.Query(ctx, query, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var agents []Agent
	for rows.Next() {
		var a Agent
		if err := rows.Scan(&a.ID, &a.OrgID, &a.Name, &a.Description, &a.Type, &a.OwnerID, &a.Status, &a.Metadata, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, 0, err
		}
		agents = append(agents, a)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	var total int64
	if err := s.pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM agents WHERE %s`, where), filterArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	return agents, total, nil
}

func (s *Service) Update(ctx context.Context, id string, req UpdateAgentRequest) (*Agent, error) {
	existing, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	name := existing.Name
	if req.Name != nil {
		name = *req.Name
	}
	desc := existing.Description
	if req.Description != nil {
		desc = *req.Description
	}
	metadataJSON, _ := json.Marshal(existing.Metadata)
	if req.Metadata != nil {
		metadataJSON, _ = json.Marshal(req.Metadata)
	}

	var a Agent
	err = s.pool.QueryRow(ctx,
		`UPDATE agents SET name = $2, description = $3, metadata = $4, updated_at = now() WHERE id = $1
		 RETURNING id, org_id, name, description, type, owner_id, status, metadata, created_at, updated_at`,
		id, name, desc, metadataJSON,
	).Scan(&a.ID, &a.OrgID, &a.Name, &a.Description, &a.Type, &a.OwnerID, &a.Status, &a.Metadata, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("updating agent: %w", err)
	}
	return &a, nil
}

func (s *Service) Revoke(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE agents SET status = 'revoked', updated_at = now() WHERE id = $1`, id)
	return err
}

// ---- Agent Tokens ----

func (s *Service) CreateToken(ctx context.Context, agentID string, req CreateAgentTokenRequest) (*CreateAgentTokenResponse, error) {
	// Verify agent exists and is active
	agent, err := s.GetByID(ctx, agentID)
	if err != nil {
		return nil, err
	}
	if agent.Status != "active" {
		return nil, fmt.Errorf("agent is %s", agent.Status)
	}

	// Generate token: legant_at_<random>
	random, err := legantcrypto.RandomHex(32)
	if err != nil {
		return nil, err
	}
	plainToken := "legant_at_" + random

	// Hash for storage
	hash := sha256.Sum256([]byte(plainToken))
	tokenHash := hex.EncodeToString(hash[:])

	permJSON, _ := json.Marshal(req.Permissions)
	if req.Permissions == nil {
		permJSON = []byte("{}")
	}

	if req.Scopes == nil {
		req.Scopes = []string{}
	}

	var t AgentToken
	err = s.pool.QueryRow(ctx,
		`INSERT INTO agent_tokens (agent_id, token_hash, name, scopes, permissions, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, agent_id, name, scopes, permissions, expires_at, last_used_at, created_at`,
		agentID, tokenHash, req.Name, req.Scopes, permJSON, req.ExpiresAt,
	).Scan(&t.ID, &t.AgentID, &t.Name, &t.Scopes, &t.Permissions, &t.ExpiresAt, &t.LastUsedAt, &t.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("creating token: %w", err)
	}

	return &CreateAgentTokenResponse{AgentToken: t, PlainToken: plainToken}, nil
}

func (s *Service) ListTokens(ctx context.Context, agentID string) ([]AgentToken, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, agent_id, name, scopes, permissions, expires_at, last_used_at, created_at
		 FROM agent_tokens WHERE agent_id = $1 ORDER BY created_at DESC`,
		agentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []AgentToken
	for rows.Next() {
		var t AgentToken
		if err := rows.Scan(&t.ID, &t.AgentID, &t.Name, &t.Scopes, &t.Permissions, &t.ExpiresAt, &t.LastUsedAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, nil
}

// RevokeToken deletes a token, binding it to its agent so a caller authorized
// for one agent cannot delete another agent's token by id.
func (s *Service) RevokeToken(ctx context.Context, agentID, tokenID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM agent_tokens WHERE id = $1 AND agent_id = $2`, tokenID, agentID)
	return err
}

// ValidateToken validates an agent token and returns the agent.
// Used by the agent auth middleware.
func (s *Service) ValidateToken(ctx context.Context, plainToken string) (*Agent, *AgentToken, error) {
	hash := sha256.Sum256([]byte(plainToken))
	tokenHash := hex.EncodeToString(hash[:])

	var t AgentToken
	var agentID string
	// Expiry is evaluated in SQL: an expired token simply does not match, which
	// avoids ever treating an unparseable expires_at as "valid forever".
	err := s.pool.QueryRow(ctx,
		`SELECT id, agent_id, name, scopes, permissions, expires_at, last_used_at, created_at
		 FROM agent_tokens WHERE token_hash = $1 AND (expires_at IS NULL OR expires_at > now())`,
		tokenHash,
	).Scan(&t.ID, &agentID, &t.Name, &t.Scopes, &t.Permissions, &t.ExpiresAt, &t.LastUsedAt, &t.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil, fmt.Errorf("invalid token")
		}
		return nil, nil, err
	}
	t.AgentID = agentID

	// Update last used
	s.pool.Exec(ctx, `UPDATE agent_tokens SET last_used_at = now() WHERE id = $1`, t.ID)

	agent, err := s.GetByID(ctx, agentID)
	if err != nil {
		return nil, nil, err
	}
	if agent.Status != "active" {
		return nil, nil, fmt.Errorf("agent is %s", agent.Status)
	}

	return agent, &t, nil
}

// ---- Delegation Chains ----

// CreateDelegation records a user's delegation to an agent. orgID is the
// delegatee agent's organization (resolved and authorized by the caller); it is
// stored so the delegation can be governed and audited per tenant.
func (s *Service) CreateDelegation(ctx context.Context, delegatorID, orgID string, req CreateDelegationRequest) (*Delegation, error) {
	if req.DelegateeAgentID == "" || len(req.Scopes) == 0 {
		return nil, fmt.Errorf("delegatee_agent_id and scopes are required")
	}

	// Verify agent exists
	_, err := s.GetByID(ctx, req.DelegateeAgentID)
	if err != nil {
		return nil, fmt.Errorf("agent not found: %w", err)
	}

	constraintsJSON, _ := json.Marshal(req.Constraints)
	if req.Constraints == nil {
		constraintsJSON = []byte("{}")
	}

	var orgArg any
	if orgID != "" {
		orgArg = orgID
	}

	var d Delegation
	err = s.pool.QueryRow(ctx,
		`INSERT INTO delegation_chains (delegator_id, delegatee_agent_id, scopes, constraints, expires_at, org_id)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, delegator_id, delegatee_agent_id, scopes, constraints, active, created_at, expires_at`,
		delegatorID, req.DelegateeAgentID, req.Scopes, constraintsJSON, req.ExpiresAt, orgArg,
	).Scan(&d.ID, &d.DelegatorID, &d.DelegateeAgentID, &d.Scopes, &d.Constraints, &d.Active, &d.CreatedAt, &d.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("creating delegation: %w", err)
	}
	return &d, nil
}

func (s *Service) ListDelegationsByAgent(ctx context.Context, agentID string) ([]Delegation, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, delegator_id, delegatee_agent_id, scopes, constraints, active, created_at, expires_at
		 FROM delegation_chains WHERE delegatee_agent_id = $1 AND active = true ORDER BY created_at DESC`,
		agentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var delegations []Delegation
	for rows.Next() {
		var d Delegation
		if err := rows.Scan(&d.ID, &d.DelegatorID, &d.DelegateeAgentID, &d.Scopes, &d.Constraints, &d.Active, &d.CreatedAt, &d.ExpiresAt); err != nil {
			return nil, err
		}
		delegations = append(delegations, d)
	}
	return delegations, nil
}

// RevokeDelegation deactivates a delegation. When delegatorFilter is non-empty
// (a user revoking their own), the update is scoped to that delegator so one
// tenant cannot revoke another's delegation by guessing ids. Returns the number
// of rows affected so the caller can distinguish "not found / not yours" (0).
func (s *Service) RevokeDelegation(ctx context.Context, id, delegatorFilter string) (int64, error) {
	if delegatorFilter != "" {
		tag, err := s.pool.Exec(ctx,
			`UPDATE delegation_chains SET active = false WHERE id = $1 AND delegator_id = $2`, id, delegatorFilter)
		return tag.RowsAffected(), err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE delegation_chains SET active = false WHERE id = $1`, id)
	return tag.RowsAffected(), err
}

// Scope resolution for token exchange lives in internal/delegation/chains
// (ResolveGrantChain), which builds a typed delegation.Grant; the old
// map-based GetEffectiveScopes was removed to avoid a second, divergent path.
