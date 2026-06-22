package email

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/legant-dev/legant/internal/credential"
	legantcrypto "github.com/legant-dev/legant/internal/crypto"
)

// Service handles email-related flows: verification, password reset, magic links.
// For MVP, it logs emails to stdout. Production should integrate SMTP/SendGrid/SES.
type Service struct {
	pool      *pgxpool.Pool
	issuerURL string
}

func NewService(pool *pgxpool.Pool, issuerURL string) *Service {
	return &Service{pool: pool, issuerURL: issuerURL}
}

// ---- Email Verification ----

// VerifyEmail confirms an email address using the token.
func (s *Service) VerifyEmail(ctx context.Context, token string) error {
	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	var userID, email string
	var expiresAt time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT user_id, email, expires_at FROM email_tokens
		 WHERE token_hash = $1 AND type = 'verification' AND used = false`,
		tokenHash,
	).Scan(&userID, &email, &expiresAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return fmt.Errorf("invalid or expired token")
		}
		return err
	}

	if time.Now().After(expiresAt) {
		return fmt.Errorf("token has expired")
	}

	// Mark email as verified
	_, err = s.pool.Exec(ctx,
		`UPDATE users SET email_verified = true, updated_at = now() WHERE id = $1 AND email = $2`,
		userID, email,
	)
	if err != nil {
		return err
	}

	// Mark token as used
	s.pool.Exec(ctx, `UPDATE email_tokens SET used = true WHERE token_hash = $1`, tokenHash)

	return nil
}

// ---- Password Reset ----

// SendPasswordResetEmail creates a reset token and "sends" an email.
func (s *Service) SendPasswordResetEmail(ctx context.Context, email string) error {
	// Check if user exists
	var userID string
	err := s.pool.QueryRow(ctx,
		`SELECT id FROM users WHERE email = $1 AND status = 'active'`, email,
	).Scan(&userID)
	if err != nil {
		// Don't reveal whether user exists
		slog.Info("email: password reset requested for unknown email", "email", email)
		return nil
	}

	token, err := legantcrypto.RandomHex(32)
	if err != nil {
		return err
	}

	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	_, err = s.pool.Exec(ctx,
		`INSERT INTO email_tokens (user_id, type, token_hash, email, expires_at)
		 VALUES ($1, 'password_reset', $2, $3, $4)`,
		userID, tokenHash, email, time.Now().Add(1*time.Hour),
	)
	if err != nil {
		return fmt.Errorf("storing reset token: %w", err)
	}

	link := fmt.Sprintf("%s/reset-password?token=%s", s.issuerURL, token)
	slog.Info("email: password reset",
		"to", email,
		"link", link,
	)

	return nil
}

// ResetPassword changes the password using a reset token.
func (s *Service) ResetPassword(ctx context.Context, token, newPassword string) error {
	if len(newPassword) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	var userID string
	var expiresAt time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT user_id, expires_at FROM email_tokens
		 WHERE token_hash = $1 AND type = 'password_reset' AND used = false`,
		tokenHash,
	).Scan(&userID, &expiresAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return fmt.Errorf("invalid or expired token")
		}
		return err
	}

	if time.Now().After(expiresAt) {
		return fmt.Errorf("token has expired")
	}

	// Hash new password
	passwordHash, err := credential.HashPassword(newPassword)
	if err != nil {
		return err
	}

	// Update password credential
	_, err = s.pool.Exec(ctx,
		`UPDATE credentials SET data = $1, updated_at = now()
		 WHERE user_id = $2 AND type = 'password'`,
		[]byte(passwordHash), userID,
	)
	if err != nil {
		return err
	}

	// Mark token as used
	s.pool.Exec(ctx, `UPDATE email_tokens SET used = true WHERE token_hash = $1`, tokenHash)

	// Invalidate all sessions
	s.pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)

	return nil
}

// ---- Magic Link ----

// SendMagicLink creates a one-time login token and "sends" an email.
func (s *Service) SendMagicLink(ctx context.Context, email string) error {
	var userID string
	err := s.pool.QueryRow(ctx,
		`SELECT id FROM users WHERE email = $1 AND status = 'active'`, email,
	).Scan(&userID)
	if err != nil {
		slog.Info("email: magic link requested for unknown email", "email", email)
		return nil
	}

	token, err := legantcrypto.RandomHex(32)
	if err != nil {
		return err
	}

	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	_, err = s.pool.Exec(ctx,
		`INSERT INTO email_tokens (user_id, type, token_hash, email, expires_at)
		 VALUES ($1, 'magic_link', $2, $3, $4)`,
		userID, tokenHash, email, time.Now().Add(15*time.Minute),
	)
	if err != nil {
		return fmt.Errorf("storing magic link token: %w", err)
	}

	link := fmt.Sprintf("%s/magic-login?token=%s", s.issuerURL, token)
	slog.Info("email: magic link",
		"to", email,
		"link", link,
	)

	return nil
}

// ValidateMagicLink validates a magic link token and returns the user ID.
func (s *Service) ValidateMagicLink(ctx context.Context, token string) (string, error) {
	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	var userID string
	var expiresAt time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT user_id, expires_at FROM email_tokens
		 WHERE token_hash = $1 AND type = 'magic_link' AND used = false`,
		tokenHash,
	).Scan(&userID, &expiresAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", fmt.Errorf("invalid or expired token")
		}
		return "", err
	}

	if time.Now().After(expiresAt) {
		return "", fmt.Errorf("token has expired")
	}

	// Mark as used
	s.pool.Exec(ctx, `UPDATE email_tokens SET used = true WHERE token_hash = $1`, tokenHash)

	return userID, nil
}
