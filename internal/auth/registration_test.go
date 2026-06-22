package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/legant-dev/legant/internal/auth"
	"github.com/legant-dev/legant/internal/client"
	"github.com/legant-dev/legant/internal/testsupport"
)

func TestDynamicClientRegistration(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	reg := auth.NewRegistrar(pool, client.NewService(pool))

	tok, err := auth.MintRegistrationToken(ctx, pool, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	register := func(bearer string, body any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/oauth2/register", bytes.NewReader(b))
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		reg.Register(rec, req)
		return rec
	}

	// No initial access token → 401.
	if rec := register("", map[string]any{"client_name": "x"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("registration without a token must be 401, got %d", rec.Code)
	}

	// A malformed request (non-https redirect) → 400, and must NOT consume the
	// single-use token.
	if rec := register(tok, map[string]any{
		"client_name":   "x",
		"redirect_uris": []string{"http://evil.example/cb"},
	}); rec.Code != http.StatusBadRequest {
		t.Fatalf("non-https redirect must be 400, got %d %s", rec.Code, rec.Body.String())
	}

	// A valid registration → 201 with client_id + secret (token still had its use).
	rec := register(tok, map[string]any{
		"client_name":   "my agent",
		"redirect_uris": []string{"https://app.example.com/callback"},
		"grant_types":   []string{"authorization_code"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("valid registration must be 201, got %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ClientID == "" || resp.ClientSecret == "" {
		t.Fatalf("registration response missing client_id/secret: %s", rec.Body.String())
	}

	// Privileged grant types are rejected (validated before the token is claimed).
	if rec := register(tok, map[string]any{
		"client_name":   "privileged",
		"redirect_uris": []string{"https://app.example.com/callback"},
		"grant_types":   []string{"client_credentials"},
	}); rec.Code != http.StatusBadRequest {
		t.Fatalf("client_credentials via DCR must be rejected, got %d %s", rec.Code, rec.Body.String())
	}

	// The token was single-use → a second valid registration is rejected.
	if rec := register(tok, map[string]any{
		"client_name":   "second",
		"redirect_uris": []string{"https://app.example.com/callback"},
	}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("an exhausted token must be 401, got %d", rec.Code)
	}
}
