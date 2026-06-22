// Package chains is the database adapter for delegation grants: it hydrates a
// stored delegation into the pure delegation.Grant the signer mints from, and
// records the consent that authorizes a root delegation.
package chains

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/legant-dev/legant/internal/db"
	"github.com/legant-dev/legant/internal/delegation"
	"github.com/legant-dev/legant/internal/live"
	"github.com/legant-dev/legant/internal/mcpauth"
	"github.com/legant-dev/legant/internal/metrics"
)

// validateAndCanonicalize checks a constraint set is well-formed and rewrites its
// resource audiences into RFC 8707 canonical form before they are persisted, so
// the stored allow-list matches the canonical resource the exchange authorizes
// (and the canonical aud it mints).
func validateAndCanonicalize(c *delegation.Constraints) error {
	if c.TimeWindow != nil {
		if err := c.TimeWindow.Validate(); err != nil {
			return err
		}
	}
	if c.Rate != nil && c.Rate.MaxPerHour < 0 {
		return fmt.Errorf("rate max_per_hour must not be negative")
	}
	if c.MaxAmount != nil && *c.MaxAmount < 0 {
		return fmt.Errorf("max_amount must not be negative")
	}
	for i, r := range c.Resources {
		canon, err := mcpauth.CanonicalizeResource(r)
		if err != nil {
			return fmt.Errorf("invalid resource %q: %w", r, err)
		}
		c.Resources[i] = canon
	}
	return nil
}

type Service struct {
	pool *pgxpool.Pool
	pub  *live.Publisher // optional live-console feed; nil-safe
}

func NewService(pool *pgxpool.Pool, pub *live.Publisher) *Service {
	return &Service{pool: pool, pub: pub}
}

// maxChainWalk bounds how far ResolveGrantChain / cycle checks walk up parents,
// as a backstop against corrupt data; legitimate chains are bounded by
// delegation.DefaultMaxDepth.
const maxChainWalk = 32

type chainLink struct {
	delegatorType string
	delegatorID   string
	delegatee     string
	scopes        []string
	constraints   []byte
	expiresAt     *time.Time
}

// ResolveGrantChain resolves the full delegation chain ending at the leaf agent
// and rooted at userID, returning a delegation.Grant (with its parent chain
// reconstructed) ready to mint from, plus the leaf delegation id. It supports
// multi-hop: user -> agent -> sub-agent -> ... -> leaf. Every link must still be
// active and unexpired, and the chain must be rooted at the given user.
func (s *Service) ResolveGrantChain(ctx context.Context, agentID, userID string) (*delegation.Grant, string, error) {
	// The most recent active, unexpired delegation to the leaf agent.
	var leafID string
	err := s.pool.QueryRow(ctx,
		`SELECT id::text FROM delegation_chains
		 WHERE delegatee_agent_id = $1 AND active = true AND (expires_at IS NULL OR expires_at > now())
		 ORDER BY created_at DESC, id DESC LIMIT 1`, agentID).Scan(&leafID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, "", fmt.Errorf("no active delegation to agent")
		}
		return nil, "", err
	}

	// Walk leaf -> root, requiring every link to still be active and unexpired.
	var chain []chainLink // leaf-first
	id := leafID
	for i := 0; id != "" && i < maxChainWalk; i++ {
		var l chainLink
		var parentID *string
		err := s.pool.QueryRow(ctx,
			`SELECT delegator_type, delegator_id::text, delegatee_agent_id::text, scopes, constraints, expires_at, parent_delegation_id::text
			 FROM delegation_chains
			 WHERE id = $1 AND active = true AND (expires_at IS NULL OR expires_at > now())`, id,
		).Scan(&l.delegatorType, &l.delegatorID, &l.delegatee, &l.scopes, &l.constraints, &l.expiresAt, &parentID)
		if err != nil {
			if err == pgx.ErrNoRows {
				return nil, "", fmt.Errorf("delegation chain is broken (a link was revoked or expired)")
			}
			return nil, "", err
		}
		chain = append(chain, l)
		if parentID != nil {
			id = *parentID
		} else {
			id = ""
		}
	}

	root := chain[len(chain)-1]
	if root.delegatorType != "user" || root.delegatorID != userID {
		return nil, "", fmt.Errorf("delegation chain is not rooted at this user")
	}

	// Reconstruct the Grant chain root -> leaf with parent pointers, so the minted
	// token's act claim records the full provenance.
	var parent *delegation.Grant
	for i := len(chain) - 1; i >= 0; i-- {
		l := chain[i]
		var c delegation.Constraints
		if len(l.constraints) > 0 {
			if err := json.Unmarshal(l.constraints, &c); err != nil {
				return nil, "", fmt.Errorf("decoding delegation constraints: %w", err)
			}
		}
		exp := time.Now().Add(365 * 24 * time.Hour)
		if l.expiresAt != nil {
			exp = *l.expiresAt
		}
		parent = &delegation.Grant{
			Delegator:   l.delegatorType + ":" + l.delegatorID,
			Delegatee:   "agent:" + l.delegatee,
			Scopes:      l.scopes,
			Constraints: c,
			ExpiresAt:   exp,
			Parent:      parent,
		}
	}
	return parent, leafID, nil
}

// Redelegate lets an agent re-delegate an attenuated slice of a delegation it
// holds to a sub-agent. It enforces the chain invariants: only the holder may
// re-delegate, scopes must be a subset of the parent's, constraints are tightened
// against the parent, depth is bounded, and the sub-agent must not already appear
// in the chain (no cycles). Returns the new child delegation id.
func (s *Service) Redelegate(ctx context.Context, parentDelegationID, delegatorAgentID, delegateeAgentID string, scopes []string, c delegation.Constraints, ttl time.Duration) (string, error) {
	if delegateeAgentID == "" || len(scopes) == 0 {
		return "", fmt.Errorf("delegatee agent and scopes are required")
	}
	if err := validateAndCanonicalize(&c); err != nil {
		return "", err
	}

	var (
		pDelegatee   string
		pScopes      []string
		pConstraints []byte
		pDepth       int
		pOrg         *string
		pExp         *time.Time
	)
	err := s.pool.QueryRow(ctx,
		`SELECT delegatee_agent_id::text, scopes, constraints, depth, org_id::text, expires_at
		 FROM delegation_chains
		 WHERE id = $1 AND active = true AND (expires_at IS NULL OR expires_at > now())`, parentDelegationID,
	).Scan(&pDelegatee, &pScopes, &pConstraints, &pDepth, &pOrg, &pExp)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", fmt.Errorf("parent delegation not found or inactive")
		}
		return "", err
	}
	if pDelegatee != delegatorAgentID {
		return "", fmt.Errorf("only the holder of a delegation may re-delegate it")
	}
	if !delegation.IsSubset(scopes, pScopes) {
		return "", fmt.Errorf("re-delegated scopes exceed the parent delegation")
	}
	if pDepth+1 >= delegation.DefaultMaxDepth {
		return "", fmt.Errorf("maximum delegation depth exceeded")
	}
	inChain, err := s.agentInChain(ctx, parentDelegationID, delegateeAgentID)
	if err != nil {
		return "", err
	}
	if inChain {
		return "", fmt.Errorf("cycle: agent is already in the delegation chain")
	}
	// The delegatee must be an active agent in the SAME organization as the parent
	// delegation — an agent cannot hand authority to an inactive or cross-tenant
	// agent.
	var delegateeOK bool
	if err := s.pool.QueryRow(ctx,
		`SELECT exists(SELECT 1 FROM agents WHERE id = $1 AND status = 'active'
		   AND (org_id::text = $2 OR ($2 IS NULL AND org_id IS NULL)))`,
		delegateeAgentID, pOrg).Scan(&delegateeOK); err != nil {
		return "", err
	}
	if !delegateeOK {
		return "", fmt.Errorf("delegatee agent not found, inactive, or not in the delegation's organization")
	}

	var pc delegation.Constraints
	if len(pConstraints) > 0 {
		_ = json.Unmarshal(pConstraints, &pc)
	}
	childConstraints := delegation.Tighten(pc, c)
	childJSON, _ := json.Marshal(childConstraints)

	exp := time.Now().Add(ttl)
	if pExp != nil && exp.After(*pExp) {
		exp = *pExp
	}

	var childID string
	err = s.pool.QueryRow(ctx,
		`INSERT INTO delegation_chains
		   (delegator_type, delegator_id, delegatee_agent_id, scopes, constraints, parent_delegation_id, depth, org_id, expires_at)
		 VALUES ('agent', $1, $2, $3, $4, $5, $6, $7, $8) RETURNING id::text`,
		delegatorAgentID, delegateeAgentID, scopes, childJSON, parentDelegationID, pDepth+1, pOrg, exp,
	).Scan(&childID)
	if err != nil {
		return "", fmt.Errorf("creating re-delegation: %w", err)
	}
	metrics.DelegationsTotal.Inc("redelegate")
	return childID, nil
}

// agentInChain reports whether candidateAgentID already appears as a delegatee
// anywhere from startDelegationID up to the root.
func (s *Service) agentInChain(ctx context.Context, startDelegationID, candidateAgentID string) (bool, error) {
	id := startDelegationID
	for i := 0; id != "" && i < maxChainWalk; i++ {
		var delegatee string
		var parentID *string
		if err := s.pool.QueryRow(ctx,
			`SELECT delegatee_agent_id::text, parent_delegation_id::text FROM delegation_chains WHERE id = $1`, id,
		).Scan(&delegatee, &parentID); err != nil {
			return false, err
		}
		if delegatee == candidateAgentID {
			return true, nil
		}
		if parentID != nil {
			id = *parentID
		} else {
			id = ""
		}
	}
	return false, nil
}

// ConsentRequest is a user's approval to delegate to an agent.
type ConsentRequest struct {
	UserID      string
	AgentID     string
	OrgID       string
	Scopes      []string
	Constraints delegation.Constraints
	Resource    string
	TTL         time.Duration
}

// GrantConsent records a consent receipt and the root delegation it authorizes,
// in one transaction. Returns the new consent and delegation ids.
func (s *Service) GrantConsent(ctx context.Context, req ConsentRequest) (consentID, delegationID string, err error) {
	if req.UserID == "" || req.AgentID == "" || len(req.Scopes) == 0 {
		return "", "", fmt.Errorf("user, agent, and scopes are required")
	}
	// Fold the consent's resource into the constraints so the stored delegation is
	// directly exchangeable for it: the exchange treats an empty Resources list as
	// "deny all audiences", so a resource-scoped consent must carry it.
	if len(req.Constraints.Resources) == 0 && req.Resource != "" {
		req.Constraints.Resources = []string{req.Resource}
	}
	if err := validateAndCanonicalize(&req.Constraints); err != nil {
		return "", "", err
	}
	constraintsJSON, _ := json.Marshal(req.Constraints)

	var orgArg any
	if req.OrgID != "" {
		orgArg = req.OrgID
	}
	var expiresAt *time.Time
	if req.TTL > 0 {
		t := time.Now().Add(req.TTL)
		expiresAt = &t
	}

	err = db.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`INSERT INTO delegation_consents (user_id, agent_id, org_id, scopes, constraints, resource)
			 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id::text`,
			req.UserID, req.AgentID, orgArg, req.Scopes, constraintsJSON, req.Resource,
		).Scan(&consentID); err != nil {
			return fmt.Errorf("recording consent: %w", err)
		}
		if err := tx.QueryRow(ctx,
			`INSERT INTO delegation_chains (delegator_id, delegatee_agent_id, scopes, constraints, expires_at, org_id, consent_id)
			 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id::text`,
			req.UserID, req.AgentID, req.Scopes, constraintsJSON, expiresAt, orgArg, consentID,
		).Scan(&delegationID); err != nil {
			return fmt.Errorf("creating root delegation: %w", err)
		}
		return nil
	})
	if err == nil {
		metrics.DelegationsTotal.Inc("consent")
	}
	return consentID, delegationID, err
}

// UserDelegation is a row of a user's granted (root) delegations, for the
// self-service management UI.
type UserDelegation struct {
	ID          string
	AgentID     string
	AgentName   string
	Scopes      []string
	Constraints delegation.Constraints
	CreatedAt   time.Time
	ExpiresAt   *time.Time
	Active      bool
}

// ListUserDelegations returns the root delegations a user has granted (most
// recent first). Re-delegations made by agents are not the user's to manage and
// are excluded.
func (s *Service) ListUserDelegations(ctx context.Context, userID string) ([]UserDelegation, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT d.id::text, d.delegatee_agent_id::text, coalesce(a.name,''),
		       d.scopes, d.constraints, d.created_at, d.expires_at, d.active
		FROM delegation_chains d
		JOIN agents a ON a.id = d.delegatee_agent_id
		WHERE d.delegator_id = $1 AND d.delegator_type = 'user'
		ORDER BY d.created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []UserDelegation
	for rows.Next() {
		var d UserDelegation
		var cJSON []byte
		if err := rows.Scan(&d.ID, &d.AgentID, &d.AgentName, &d.Scopes, &cJSON, &d.CreatedAt, &d.ExpiresAt, &d.Active); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(cJSON, &d.Constraints)
		out = append(out, d)
	}
	return out, rows.Err()
}

// RevokeDelegationTree revokes a user's root delegation and its entire subtree:
// every descendant re-delegation is deactivated and every live token minted from
// any of them is revoked, atomically. Only the user who granted the root may
// revoke it. Returns the count of delegations and tokens revoked.
func (s *Service) RevokeDelegationTree(ctx context.Context, delegationID, userID string) (int, int64, error) {
	var delegationsRevoked int
	var tokensRevoked int64

	err := db.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		var owned bool
		if err := tx.QueryRow(ctx,
			`SELECT exists(SELECT 1 FROM delegation_chains
			   WHERE id = $1 AND delegator_id = $2 AND delegator_type = 'user')`,
			delegationID, userID).Scan(&owned); err != nil {
			return err
		}
		if !owned {
			return fmt.Errorf("delegation not found or not yours to revoke")
		}

		const tree = `WITH RECURSIVE tree AS (
			SELECT id FROM delegation_chains WHERE id = $1
			UNION ALL
			SELECT c.id FROM delegation_chains c JOIN tree t ON c.parent_delegation_id = t.id
		)`
		tag, err := tx.Exec(ctx, tree+`
			UPDATE delegation_chains SET active = false
			WHERE id IN (SELECT id FROM tree) AND active = true`, delegationID)
		if err != nil {
			return err
		}
		delegationsRevoked = int(tag.RowsAffected())

		tag2, err := tx.Exec(ctx, tree+`
			UPDATE exchanged_tokens SET revoked_at = now()
			WHERE delegation_id IN (SELECT id FROM tree) AND revoked_at IS NULL`, delegationID)
		if err != nil {
			return err
		}
		tokensRevoked = tag2.RowsAffected()

		_, err = tx.Exec(ctx,
			`INSERT INTO audit_events (actor_type, actor_id, action, resource_type, resource_id, metadata)
			 VALUES ('user', $2, 'delegation.revoked', 'delegation', $1, $3)`,
			delegationID, userID,
			[]byte(fmt.Sprintf(`{"delegations_revoked":%d,"tokens_revoked":%d}`, delegationsRevoked, tokensRevoked)))
		return err
	})
	if err == nil {
		if tokensRevoked > 0 {
			metrics.RevocationsTotal.Add(uint64(tokensRevoked), "delegation")
		}
		// Announce the tree revoke (after commit, so a rolled-back tree is never
		// shown). The console refreshes its graph snapshot on this event.
		s.pub.Publish(live.Event{
			Type: "revoke", Decision: "REVOKE", Delegation: delegationID, Count: int(tokensRevoked),
			Reason: fmt.Sprintf("%d delegation(s), %d token(s) killed", delegationsRevoked, tokensRevoked),
		})
	}
	return delegationsRevoked, tokensRevoked, err
}
