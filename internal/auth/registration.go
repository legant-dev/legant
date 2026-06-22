package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/legant-dev/legant/internal/client"
	legantcrypto "github.com/legant-dev/legant/internal/crypto"
)

const registrationTokenPrefix = "legant_rt_"

// Registrar implements RFC 7591 dynamic client registration, gated by an initial
// access token so the endpoint cannot be used to create clients anonymously.
type Registrar struct {
	pool    *pgxpool.Pool
	clients *client.Service
}

func NewRegistrar(pool *pgxpool.Pool, clients *client.Service) *Registrar {
	return &Registrar{pool: pool, clients: clients}
}

type registrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// Register handles POST /oauth2/register.
func (rg *Registrar) Register(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx := r.Context()

	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		writeJSONResponse(w, http.StatusUnauthorized,
			map[string]any{"error": "invalid_token", "error_description": "an initial access token is required"})
		return
	}
	bearer := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))

	var req registrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		regError(w, "invalid_client_metadata", "invalid request body")
		return
	}
	// Strict redirect_uri validation (exact, absolute, https or loopback).
	for _, u := range req.RedirectURIs {
		if err := validateRedirectURI(u); err != nil {
			regError(w, "invalid_redirect_uri", err.Error())
			return
		}
	}
	// Restrict registered clients to the interactive grant set — DCR must not be a
	// side door to client_credentials / token-exchange / implicit grants.
	if err := validateGrantMetadata(&req); err != nil {
		regError(w, "invalid_client_metadata", err.Error())
		return
	}
	if hasGrant(req.GrantTypes, "authorization_code") && len(req.RedirectURIs) == 0 {
		regError(w, "invalid_redirect_uri", "authorization_code clients require at least one redirect_uri")
		return
	}

	// Consume a use of the initial access token only after the request is
	// well-formed, so a malformed request can't burn the token.
	orgID, ok := rg.claimRegistrationToken(ctx, bearer)
	if !ok {
		writeJSONResponse(w, http.StatusUnauthorized,
			map[string]any{"error": "invalid_token", "error_description": "invalid or exhausted initial access token"})
		return
	}

	public := req.TokenEndpointAuthMethod == "none"
	created, err := rg.clients.Create(ctx, client.CreateClientRequest{
		Name:                    req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		Scopes:                  strings.Fields(req.Scope),
		Public:                  public,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		Metadata:                map[string]interface{}{"dcr": true, "org_id": orgID},
	})
	if err != nil {
		regError(w, "invalid_client_metadata", "could not register client")
		return
	}

	resp := map[string]any{
		"client_id":                  created.ID,
		"client_id_issued_at":        time.Now().Unix(),
		"client_secret_expires_at":   0, // secrets do not expire (rotate via the admin API)
		"client_name":                created.Name,
		"redirect_uris":              created.RedirectURIs,
		"grant_types":                created.GrantTypes,
		"response_types":             created.ResponseTypes,
		"token_endpoint_auth_method": created.TokenEndpointAuthMethod,
		"scope":                      strings.Join(created.Scopes, " "),
	}
	if created.Secret != "" {
		resp["client_secret"] = created.Secret
	}
	writeJSONResponse(w, http.StatusCreated, resp)
}

// claimRegistrationToken atomically consumes one use of a valid initial access
// token, returning the org it is scoped to (if any).
func (rg *Registrar) claimRegistrationToken(ctx context.Context, token string) (orgID string, ok bool) {
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])
	var org *string
	err := rg.pool.QueryRow(ctx,
		`UPDATE dcr_registration_tokens SET used_count = used_count + 1
		 WHERE token_hash = $1 AND (expires_at IS NULL OR expires_at > now()) AND used_count < max_uses
		 RETURNING org_id::text`, hash).Scan(&org)
	if err != nil {
		return "", false
	}
	if org != nil {
		return *org, true
	}
	return "", true
}

// MintRegistrationToken creates an initial access token, returning the plaintext
// (shown once). Used by the `legant dcr issue-token` command.
func MintRegistrationToken(ctx context.Context, pool *pgxpool.Pool, maxUses int, ttl time.Duration) (string, error) {
	raw, err := legantcrypto.RandomHex(24)
	if err != nil {
		return "", err
	}
	token := registrationTokenPrefix + raw
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])

	var expires *time.Time
	if ttl > 0 {
		t := time.Now().Add(ttl)
		expires = &t
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO dcr_registration_tokens (token_hash, max_uses, expires_at) VALUES ($1, $2, $3)`,
		hash, maxUses, expires); err != nil {
		return "", err
	}
	return token, nil
}

// validateGrantMetadata restricts dynamically-registered clients to safe grant
// and response types and supported auth methods, defaulting empties.
func validateGrantMetadata(req *registrationRequest) error {
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}
	allowedGrants := map[string]bool{"authorization_code": true, "refresh_token": true}
	for _, g := range req.GrantTypes {
		if !allowedGrants[g] {
			return fmt.Errorf("grant_type %q is not permitted via dynamic registration", g)
		}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	for _, rt := range req.ResponseTypes {
		if rt != "code" {
			return fmt.Errorf("response_type %q is not permitted", rt)
		}
	}
	allowedAuth := map[string]bool{"": true, "none": true, "client_secret_basic": true, "client_secret_post": true}
	if !allowedAuth[req.TokenEndpointAuthMethod] {
		return fmt.Errorf("token_endpoint_auth_method %q is not supported", req.TokenEndpointAuthMethod)
	}
	return nil
}

func hasGrant(grants []string, g string) bool {
	for _, x := range grants {
		if x == g {
			return true
		}
	}
	return false
}

func validateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("redirect_uri must be an absolute URI")
	}
	if u.Fragment != "" {
		return fmt.Errorf("redirect_uri must not contain a fragment")
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	if u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
		return nil
	}
	return fmt.Errorf("redirect_uri must use https (http allowed only for loopback)")
}

func regError(w http.ResponseWriter, code, desc string) {
	writeJSONResponse(w, http.StatusBadRequest, map[string]any{"error": code, "error_description": desc})
}
