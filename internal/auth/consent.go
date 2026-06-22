package auth

import (
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/legant-dev/legant/internal/credential"
)

type ConsentHandler struct {
	pool           *pgxpool.Pool
	sessionManager *SessionManager
	templates      *template.Template
}

func NewConsentHandler(pool *pgxpool.Pool, sessionManager *SessionManager, templates *template.Template) *ConsentHandler {
	return &ConsentHandler{
		pool:           pool,
		sessionManager: sessionManager,
		templates:      templates,
	}
}

// LoginPage renders the login form.
func (ch *ConsentHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Query": r.URL.RawQuery,
		"Error": r.URL.Query().Get("error"),
	}
	ch.templates.ExecuteTemplate(w, "login.html", data)
}

// LoginSubmit handles the login form submission.
func (ch *ConsentHandler) LoginSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	redirectQuery := r.FormValue("query")

	if email == "" || password == "" {
		http.Redirect(w, r, "/login?error=missing_credentials&"+redirectQuery, http.StatusFound)
		return
	}

	userID, err := ch.authenticateUser(ctx, email, password)
	if err != nil {
		slog.Warn("login failed", "email", email, "error", err)
		http.Redirect(w, r, "/login?error=invalid_credentials&"+redirectQuery, http.StatusFound)
		return
	}

	// Create session
	session, err := ch.sessionManager.Create(ctx, userID, r)
	if err != nil {
		slog.Error("session creation failed", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	ch.sessionManager.SetCookie(w, session)

	// Redirect back to authorize endpoint
	if redirectQuery != "" {
		http.Redirect(w, r, "/oauth2/authorize?"+redirectQuery, http.StatusFound)
	} else {
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// RegisterPage renders the registration form.
func (ch *ConsentHandler) RegisterPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Query": r.URL.RawQuery,
		"Error": r.URL.Query().Get("error"),
	}
	ch.templates.ExecuteTemplate(w, "register.html", data)
}

// RegisterSubmit handles the registration form submission.
func (ch *ConsentHandler) RegisterSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	displayName := r.FormValue("display_name")
	redirectQuery := r.FormValue("query")

	if email == "" || password == "" {
		http.Redirect(w, r, "/register?error=missing_fields&"+redirectQuery, http.StatusFound)
		return
	}

	if len(password) < 8 {
		http.Redirect(w, r, "/register?error=password_too_short&"+redirectQuery, http.StatusFound)
		return
	}

	// Hash password
	hash, err := credential.HashPassword(password)
	if err != nil {
		slog.Error("password hashing failed", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Create user
	var userID string
	err = ch.pool.QueryRow(ctx,
		`INSERT INTO users (email, display_name) VALUES ($1, $2) RETURNING id`,
		email, displayName,
	).Scan(&userID)
	if err != nil {
		slog.Error("user creation failed", "error", err)
		http.Redirect(w, r, "/register?error=email_taken&"+redirectQuery, http.StatusFound)
		return
	}

	// Store password credential
	_, err = ch.pool.Exec(ctx,
		`INSERT INTO credentials (user_id, type, data) VALUES ($1, 'password', $2)`,
		userID, []byte(hash),
	)
	if err != nil {
		slog.Error("credential creation failed", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Create session
	session, err := ch.sessionManager.Create(ctx, userID, r)
	if err != nil {
		slog.Error("session creation failed", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	ch.sessionManager.SetCookie(w, session)

	if redirectQuery != "" {
		http.Redirect(w, r, "/oauth2/authorize?"+redirectQuery, http.StatusFound)
	} else {
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// LogoutHandler handles POST /logout.
func (ch *ConsentHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	ch.sessionManager.Delete(r.Context(), w, r)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (ch *ConsentHandler) authenticateUser(ctx context.Context, email, password string) (string, error) {
	var userID, status string
	err := ch.pool.QueryRow(ctx,
		`SELECT id, status FROM users WHERE email = $1`, email,
	).Scan(&userID, &status)
	if err != nil {
		return "", fmt.Errorf("user not found")
	}

	if status != "active" {
		return "", fmt.Errorf("user is %s", status)
	}

	var credData []byte
	err = ch.pool.QueryRow(ctx,
		`SELECT data FROM credentials WHERE user_id = $1 AND type = 'password' ORDER BY created_at DESC LIMIT 1`,
		userID,
	).Scan(&credData)
	if err != nil {
		return "", fmt.Errorf("no password credential")
	}

	ok, err := credential.VerifyPassword(password, string(credData))
	if err != nil || !ok {
		return "", fmt.Errorf("invalid password")
	}

	// Update last used
	ch.pool.Exec(ctx,
		`UPDATE credentials SET last_used_at = now() WHERE user_id = $1 AND type = 'password'`,
		userID,
	)

	return userID, nil
}
