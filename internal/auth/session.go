package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	legantcrypto "github.com/legant-dev/legant/internal/crypto"
)

const (
	sessionCookieName = "legant_session"
	csrfCookieName    = "legant_csrf"
	sessionIDLength   = 32
)

type SessionManager struct {
	pool         *pgxpool.Pool
	cookieSecret []byte
	lifetime     time.Duration
	secure       bool
}

type Session struct {
	ID           string
	UserID       string
	IP           string
	UserAgent    string
	CreatedAt    time.Time
	LastActiveAt time.Time
	ExpiresAt    time.Time
}

func NewSessionManager(pool *pgxpool.Pool, cookieSecret string, lifetime time.Duration, secure bool) *SessionManager {
	return &SessionManager{
		pool:         pool,
		cookieSecret: []byte(cookieSecret),
		lifetime:     lifetime,
		secure:       secure,
	}
}

func (sm *SessionManager) Create(ctx context.Context, userID string, r *http.Request) (*Session, error) {
	sessionID, err := legantcrypto.RandomHex(sessionIDLength)
	if err != nil {
		return nil, fmt.Errorf("generating session ID: %w", err)
	}

	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	expiresAt := time.Now().Add(sm.lifetime)

	var ipStr *string
	if ip != "" {
		ipStr = &ip
	}

	_, err = sm.pool.Exec(ctx,
		`INSERT INTO sessions (id, user_id, ip, user_agent, data, expires_at)
		 VALUES ($1, $2, $3::inet, $4, '{}', $5)`,
		sessionID, userID, ipStr, r.UserAgent(), expiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}

	return &Session{
		ID:        sessionID,
		UserID:    userID,
		IP:        ip,
		UserAgent: r.UserAgent(),
		ExpiresAt: expiresAt,
	}, nil
}

func (sm *SessionManager) Get(ctx context.Context, r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, fmt.Errorf("no session cookie")
	}

	sessionID, err := sm.verifySignedCookie(cookie.Value)
	if err != nil {
		return nil, fmt.Errorf("invalid session cookie: %w", err)
	}

	var s Session
	err = sm.pool.QueryRow(ctx,
		`SELECT id, user_id::text, created_at, last_active_at, expires_at
		 FROM sessions WHERE id = $1 AND expires_at > now()`,
		sessionID,
	).Scan(&s.ID, &s.UserID, &s.CreatedAt, &s.LastActiveAt, &s.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}

	// Update last active
	sm.pool.Exec(ctx, `UPDATE sessions SET last_active_at = now() WHERE id = $1`, sessionID)

	return &s, nil
}

func (sm *SessionManager) SetCookie(w http.ResponseWriter, session *Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sm.signCookie(session.ID),
		Path:     "/",
		HttpOnly: true,
		Secure:   sm.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sm.lifetime.Seconds()),
	})
	// A readable companion cookie carrying the CSRF token, so same-origin browser
	// code can echo it back as a hidden form field or an X-CSRF-Token header. It is
	// NOT HttpOnly by design (the page must read it); cross-site code can neither
	// read it (same-origin policy) nor set the custom header cross-origin.
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    sm.CSRFToken(session),
		Path:     "/",
		HttpOnly: false,
		Secure:   sm.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sm.lifetime.Seconds()),
	})
}

// CSRFToken returns the synchronizer token bound to a session: an HMAC of the
// session id under the cookie secret. It is stable for the session's lifetime and
// requires no extra storage.
func (sm *SessionManager) CSRFToken(s *Session) string {
	mac := hmac.New(sha256.New, sm.cookieSecret)
	mac.Write([]byte("csrf:" + s.ID))
	return hex.EncodeToString(mac.Sum(nil))
}

// ValidateCSRF reports whether a state-changing request carries the correct CSRF
// token for its session, taken from the X-CSRF-Token header (JSON/fetch clients)
// or a csrf_token form field (HTML forms). It only reads the form body for
// form-encoded requests, so it never consumes a JSON body the handler will parse.
func (sm *SessionManager) ValidateCSRF(r *http.Request, s *Session) bool {
	got := r.Header.Get("X-CSRF-Token")
	if got == "" && strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		got = r.PostFormValue("csrf_token")
	}
	if got == "" {
		return false
	}
	return hmac.Equal([]byte(got), []byte(sm.CSRFToken(s)))
}

func (sm *SessionManager) Delete(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil
	}

	sessionID, err := sm.verifySignedCookie(cookie.Value)
	if err == nil {
		sm.pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, sessionID)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: "", Path: "/", MaxAge: -1})
	return nil
}

func (sm *SessionManager) signCookie(value string) string {
	mac := hmac.New(sha256.New, sm.cookieSecret)
	mac.Write([]byte(value))
	sig := hex.EncodeToString(mac.Sum(nil))
	return value + "." + sig
}

func (sm *SessionManager) verifySignedCookie(signed string) (string, error) {
	// Find the last dot separator
	for i := len(signed) - 1; i >= 0; i-- {
		if signed[i] == '.' {
			value := signed[:i]
			sig := signed[i+1:]

			mac := hmac.New(sha256.New, sm.cookieSecret)
			mac.Write([]byte(value))
			expected := hex.EncodeToString(mac.Sum(nil))

			if !hmac.Equal([]byte(sig), []byte(expected)) {
				return "", fmt.Errorf("invalid signature")
			}
			return value, nil
		}
	}
	return "", fmt.Errorf("no signature found")
}
