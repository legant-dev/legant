package client

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/legant-dev/legant/internal/credential"
	legantcrypto "github.com/legant-dev/legant/internal/crypto"
)

type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

type Client struct {
	ID                      string                 `json:"id"`
	Name                    string                 `json:"name"`
	RedirectURIs            []string               `json:"redirect_uris"`
	GrantTypes              []string               `json:"grant_types"`
	ResponseTypes           []string               `json:"response_types"`
	Scopes                  []string               `json:"scopes"`
	Audience                []string               `json:"audience"`
	Public                  bool                   `json:"public"`
	TokenEndpointAuthMethod string                 `json:"token_endpoint_auth_method"`
	Metadata                map[string]interface{} `json:"metadata"`
	CreatedAt               time.Time              `json:"created_at"`
	UpdatedAt               time.Time              `json:"updated_at"`
}

type CreateClientRequest struct {
	Name                    string                 `json:"name" validate:"required"`
	RedirectURIs            []string               `json:"redirect_uris"`
	GrantTypes              []string               `json:"grant_types"`
	ResponseTypes           []string               `json:"response_types"`
	Scopes                  []string               `json:"scopes"`
	Audience                []string               `json:"audience"`
	Public                  bool                   `json:"public"`
	TokenEndpointAuthMethod string                 `json:"token_endpoint_auth_method"`
	Metadata                map[string]interface{} `json:"metadata"`
}

type CreateClientResponse struct {
	Client
	Secret string `json:"client_secret"`
}

type UpdateClientRequest struct {
	Name                    *string                `json:"name"`
	RedirectURIs            []string               `json:"redirect_uris"`
	GrantTypes              []string               `json:"grant_types"`
	Scopes                  []string               `json:"scopes"`
	TokenEndpointAuthMethod *string                `json:"token_endpoint_auth_method"`
	Metadata                map[string]interface{} `json:"metadata"`
}

func (s *Service) Create(ctx context.Context, req CreateClientRequest) (*CreateClientResponse, error) {
	clientID, err := legantcrypto.RandomString(24)
	if err != nil {
		return nil, fmt.Errorf("generating client ID: %w", err)
	}

	var secretHash string
	var secret string

	if !req.Public {
		secret, err = legantcrypto.RandomString(48)
		if err != nil {
			return nil, fmt.Errorf("generating client secret: %w", err)
		}
		secretHash, err = credential.HashPassword(secret)
		if err != nil {
			return nil, fmt.Errorf("hashing client secret: %w", err)
		}
	}

	if req.GrantTypes == nil {
		req.GrantTypes = []string{"authorization_code"}
	}
	if req.ResponseTypes == nil {
		req.ResponseTypes = []string{"code"}
	}
	// Array columns are NOT NULL; a nil slice would encode as SQL NULL.
	if req.RedirectURIs == nil {
		req.RedirectURIs = []string{}
	}
	if req.Audience == nil {
		req.Audience = []string{}
	}
	if req.Scopes == nil {
		req.Scopes = []string{"openid", "profile", "email"}
	}
	if req.TokenEndpointAuthMethod == "" {
		if req.Public {
			req.TokenEndpointAuthMethod = "none"
		} else {
			req.TokenEndpointAuthMethod = "client_secret_basic"
		}
	}

	metadataJSON, _ := json.Marshal(req.Metadata)
	if req.Metadata == nil {
		metadataJSON = []byte("{}")
	}

	var c Client
	err = s.pool.QueryRow(ctx,
		`INSERT INTO oauth2_clients (id, secret_hash, name, redirect_uris, grant_types, response_types, scopes, audience, public, token_endpoint_auth_method, metadata)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		 RETURNING id, name, redirect_uris, grant_types, response_types, scopes, audience, public, token_endpoint_auth_method, metadata, created_at, updated_at`,
		clientID, secretHash, req.Name, req.RedirectURIs, req.GrantTypes, req.ResponseTypes,
		req.Scopes, req.Audience, req.Public, req.TokenEndpointAuthMethod, metadataJSON,
	).Scan(&c.ID, &c.Name, &c.RedirectURIs, &c.GrantTypes, &c.ResponseTypes,
		&c.Scopes, &c.Audience, &c.Public, &c.TokenEndpointAuthMethod, &c.Metadata,
		&c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("creating client: %w", err)
	}

	return &CreateClientResponse{Client: c, Secret: secret}, nil
}

func (s *Service) GetByID(ctx context.Context, id string) (*Client, error) {
	var c Client
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, redirect_uris, grant_types, response_types, scopes, audience, public, token_endpoint_auth_method, metadata, created_at, updated_at
		 FROM oauth2_clients WHERE id = $1`, id,
	).Scan(&c.ID, &c.Name, &c.RedirectURIs, &c.GrantTypes, &c.ResponseTypes,
		&c.Scopes, &c.Audience, &c.Public, &c.TokenEndpointAuthMethod, &c.Metadata,
		&c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("client not found")
		}
		return nil, fmt.Errorf("getting client: %w", err)
	}
	return &c, nil
}

func (s *Service) List(ctx context.Context, limit, offset int) ([]Client, int64, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}

	rows, err := s.pool.Query(ctx,
		`SELECT id, name, redirect_uris, grant_types, response_types, scopes, audience, public, token_endpoint_auth_method, metadata, created_at, updated_at
		 FROM oauth2_clients ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var clients []Client
	for rows.Next() {
		var c Client
		if err := rows.Scan(&c.ID, &c.Name, &c.RedirectURIs, &c.GrantTypes, &c.ResponseTypes,
			&c.Scopes, &c.Audience, &c.Public, &c.TokenEndpointAuthMethod, &c.Metadata,
			&c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, 0, err
		}
		clients = append(clients, c)
	}

	var total int64
	s.pool.QueryRow(ctx, `SELECT count(*) FROM oauth2_clients`).Scan(&total)

	return clients, total, nil
}

func (s *Service) Delete(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM oauth2_clients WHERE id = $1`, id)
	return err
}

func (s *Service) RotateSecret(ctx context.Context, id string) (string, error) {
	secret, err := legantcrypto.RandomString(48)
	if err != nil {
		return "", err
	}
	hash, err := credential.HashPassword(secret)
	if err != nil {
		return "", err
	}
	_, err = s.pool.Exec(ctx,
		`UPDATE oauth2_clients SET secret_hash = $2, updated_at = now() WHERE id = $1`,
		id, hash)
	if err != nil {
		return "", err
	}
	return secret, nil
}
