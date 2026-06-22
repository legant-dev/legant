package org

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	legantcrypto "github.com/legant-dev/legant/internal/crypto"
)

func (s *Service) CreateInvitation(ctx context.Context, orgID, inviterID string, req CreateInvitationRequest) (*Invitation, error) {
	if req.Email == "" {
		return nil, fmt.Errorf("email is required")
	}
	if req.Role != "owner" && req.Role != "admin" && req.Role != "member" {
		req.Role = "member"
	}

	token, err := legantcrypto.RandomHex(32)
	if err != nil {
		return nil, fmt.Errorf("generating token: %w", err)
	}

	var inviterPtr *string
	if inviterID != "" {
		inviterPtr = &inviterID
	}

	var inv Invitation
	err = s.pool.QueryRow(ctx,
		`INSERT INTO org_invitations (org_id, email, role, token, inviter_id)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, org_id, email, role, token, status, inviter_id, created_at, expires_at`,
		orgID, req.Email, req.Role, token, inviterPtr,
	).Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.Role, &inv.Token, &inv.Status, &inviterPtr, &inv.CreatedAt, &inv.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("creating invitation: %w", err)
	}
	if inviterPtr != nil {
		inv.InviterID = *inviterPtr
	}

	return &inv, nil
}

func (s *Service) ListInvitations(ctx context.Context, orgID string) ([]Invitation, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, org_id, email, role, '', status, COALESCE(inviter_id::text, ''), created_at, expires_at
		 FROM org_invitations WHERE org_id = $1 AND status = 'pending'
		 ORDER BY created_at DESC`,
		orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var invitations []Invitation
	for rows.Next() {
		var inv Invitation
		if err := rows.Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.Role, &inv.Token, &inv.Status, &inv.InviterID, &inv.CreatedAt, &inv.ExpiresAt); err != nil {
			return nil, err
		}
		invitations = append(invitations, inv)
	}
	return invitations, nil
}

func (s *Service) RevokeInvitation(ctx context.Context, inviteID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE org_invitations SET status = 'revoked' WHERE id = $1 AND status = 'pending'`,
		inviteID,
	)
	return err
}

// AcceptInvitation accepts an invitation by token and adds the user to the org.
func (s *Service) AcceptInvitation(ctx context.Context, token, userID string) error {
	var orgID, role, status string
	var expiresAt time.Time
	var inviteID string

	err := s.pool.QueryRow(ctx,
		`SELECT id, org_id, role, status, expires_at FROM org_invitations WHERE token = $1`,
		token,
	).Scan(&inviteID, &orgID, &role, &status, &expiresAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return fmt.Errorf("invitation not found")
		}
		return err
	}

	if status != "pending" {
		return fmt.Errorf("invitation is %s", status)
	}

	if time.Now().After(expiresAt) {
		s.pool.Exec(ctx, `UPDATE org_invitations SET status = 'expired' WHERE id = $1`, inviteID)
		return fmt.Errorf("invitation has expired")
	}

	// Add user as member
	_, err = s.AddMember(ctx, orgID, AddMemberRequest{
		UserID: userID,
		Role:   role,
	})
	if err != nil {
		return fmt.Errorf("adding member: %w", err)
	}

	// Mark invitation as accepted
	_, err = s.pool.Exec(ctx,
		`UPDATE org_invitations SET status = 'accepted' WHERE id = $1`,
		inviteID,
	)
	return err
}
