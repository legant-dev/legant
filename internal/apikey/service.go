package apikey

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	legantcrypto "github.com/legant-dev/legant/internal/crypto"
)

type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

type APIKey struct {
	ID         string     `json:"id"`
	OrgID      *string    `json:"org_id,omitempty"`
	OwnerID    *string    `json:"owner_id,omitempty"`
	OwnerType  string     `json:"owner_type"`
	KeyPrefix  string     `json:"key_prefix"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

type CreateAPIKeyRequest struct {
	OrgID     *string    `json:"org_id"`
	OwnerID   *string    `json:"owner_id"`
	OwnerType string     `json:"owner_type"` // user, agent, org
	Name      string     `json:"name" validate:"required"`
	Scopes    []string   `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type CreateAPIKeyResponse struct {
	APIKey
	Key string `json:"key"` // returned only once
}

func (s *Service) Create(ctx context.Context, req CreateAPIKeyRequest) (*CreateAPIKeyResponse, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if req.OwnerType == "" {
		req.OwnerType = "user"
	}
	if req.Scopes == nil {
		req.Scopes = []string{}
	}

	// Generate key: legant_<random>
	random, err := legantcrypto.RandomHex(32)
	if err != nil {
		return nil, err
	}
	key := "legant_" + random
	prefix := key[:14] // legant_ + first 8 hex chars

	hash := sha256.Sum256([]byte(key))
	keyHash := hex.EncodeToString(hash[:])

	var k APIKey
	err = s.pool.QueryRow(ctx,
		`INSERT INTO api_keys (org_id, owner_id, owner_type, key_hash, key_prefix, name, scopes, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING id, org_id, owner_id, owner_type, key_prefix, name, scopes, last_used_at, expires_at, created_at`,
		req.OrgID, req.OwnerID, req.OwnerType, keyHash, prefix, req.Name, req.Scopes, req.ExpiresAt,
	).Scan(&k.ID, &k.OrgID, &k.OwnerID, &k.OwnerType, &k.KeyPrefix, &k.Name, &k.Scopes, &k.LastUsedAt, &k.ExpiresAt, &k.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("creating API key: %w", err)
	}

	return &CreateAPIKeyResponse{APIKey: k, Key: key}, nil
}

func (s *Service) List(ctx context.Context, orgID string, limit, offset int) ([]APIKey, error) {
	if limit <= 0 {
		limit = 50
	}

	rows, err := s.pool.Query(ctx,
		`SELECT id, org_id, owner_id, owner_type, key_prefix, name, scopes, last_used_at, expires_at, created_at
		 FROM api_keys WHERE org_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		orgID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []APIKey
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.OrgID, &k.OwnerID, &k.OwnerType, &k.KeyPrefix, &k.Name, &k.Scopes, &k.LastUsedAt, &k.ExpiresAt, &k.CreatedAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func (s *Service) Revoke(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM api_keys WHERE id = $1`, id)
	return err
}
