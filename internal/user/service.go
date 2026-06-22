package user

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/legant-dev/legant/internal/credential"
)

type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

type User struct {
	ID            string                 `json:"id"`
	Email         string                 `json:"email"`
	EmailVerified bool                   `json:"email_verified"`
	DisplayName   string                 `json:"display_name"`
	AvatarURL     string                 `json:"avatar_url"`
	Status        string                 `json:"status"`
	Metadata      map[string]interface{} `json:"metadata"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
}

type CreateUserRequest struct {
	Email       string                 `json:"email" validate:"required,email"`
	Password    string                 `json:"password" validate:"required,min=8"`
	DisplayName string                 `json:"display_name"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type UpdateUserRequest struct {
	Email         *string                `json:"email"`
	DisplayName   *string                `json:"display_name"`
	AvatarURL     *string                `json:"avatar_url"`
	EmailVerified *bool                  `json:"email_verified"`
	Metadata      map[string]interface{} `json:"metadata"`
}

type ListParams struct {
	Limit  int
	Offset int
}

func (s *Service) Create(ctx context.Context, req CreateUserRequest) (*User, error) {
	metadataJSON, err := json.Marshal(req.Metadata)
	if err != nil {
		metadataJSON = []byte("{}")
	}

	var user User
	err = s.pool.QueryRow(ctx,
		`INSERT INTO users (email, display_name, metadata) VALUES ($1, $2, $3)
		 RETURNING id, email, email_verified, display_name, avatar_url, status, metadata, created_at, updated_at`,
		req.Email, req.DisplayName, metadataJSON,
	).Scan(&user.ID, &user.Email, &user.EmailVerified, &user.DisplayName,
		&user.AvatarURL, &user.Status, &user.Metadata, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("creating user: %w", err)
	}

	// Hash and store password
	hash, err := credential.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	_, err = s.pool.Exec(ctx,
		`INSERT INTO credentials (user_id, type, data) VALUES ($1, 'password', $2)`,
		user.ID, []byte(hash),
	)
	if err != nil {
		return nil, fmt.Errorf("storing credential: %w", err)
	}

	return &user, nil
}

func (s *Service) GetByID(ctx context.Context, id string) (*User, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	var user User
	err := s.pool.QueryRow(ctx,
		`SELECT id, email, email_verified, display_name, avatar_url, status, metadata, created_at, updated_at
		 FROM users WHERE id = $1`, id,
	).Scan(&user.ID, &user.Email, &user.EmailVerified, &user.DisplayName,
		&user.AvatarURL, &user.Status, &user.Metadata, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("getting user: %w", err)
	}

	return &user, nil
}

func (s *Service) List(ctx context.Context, params ListParams) ([]User, int64, error) {
	if params.Limit <= 0 {
		params.Limit = 50
	}
	if params.Limit > 100 {
		params.Limit = 100
	}

	rows, err := s.pool.Query(ctx,
		`SELECT id, email, email_verified, display_name, avatar_url, status, metadata, created_at, updated_at
		 FROM users WHERE status != 'deleted' ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		params.Limit, params.Offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("listing users: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.EmailVerified, &u.DisplayName,
			&u.AvatarURL, &u.Status, &u.Metadata, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, 0, err
		}
		users = append(users, u)
	}

	var total int64
	s.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE status != 'deleted'`).Scan(&total)

	return users, total, nil
}

func (s *Service) Update(ctx context.Context, id string, req UpdateUserRequest) (*User, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	// Build dynamic update
	existing, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	email := existing.Email
	if req.Email != nil {
		email = *req.Email
	}
	displayName := existing.DisplayName
	if req.DisplayName != nil {
		displayName = *req.DisplayName
	}
	avatarURL := existing.AvatarURL
	if req.AvatarURL != nil {
		avatarURL = *req.AvatarURL
	}
	emailVerified := existing.EmailVerified
	if req.EmailVerified != nil {
		emailVerified = *req.EmailVerified
	}

	metadataJSON, _ := json.Marshal(existing.Metadata)
	if req.Metadata != nil {
		metadataJSON, _ = json.Marshal(req.Metadata)
	}

	var user User
	err = s.pool.QueryRow(ctx,
		`UPDATE users SET email = $2, display_name = $3, avatar_url = $4, email_verified = $5, metadata = $6, updated_at = now()
		 WHERE id = $1
		 RETURNING id, email, email_verified, display_name, avatar_url, status, metadata, created_at, updated_at`,
		id, email, displayName, avatarURL, emailVerified, metadataJSON,
	).Scan(&user.ID, &user.Email, &user.EmailVerified, &user.DisplayName,
		&user.AvatarURL, &user.Status, &user.Metadata, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("updating user: %w", err)
	}

	return &user, nil
}

func (s *Service) Delete(ctx context.Context, id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return fmt.Errorf("invalid user ID")
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET status = 'deleted', updated_at = now() WHERE id = $1`, id)
	return err
}

func (s *Service) Suspend(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET status = 'suspended', updated_at = now() WHERE id = $1`, id)
	return err
}

func (s *Service) Activate(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET status = 'active', updated_at = now() WHERE id = $1`, id)
	return err
}
