package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
)

// Storage implements all fosite storage interfaces needed for our OAuth2/OIDC flows:
// - fosite.Storage (ClientManager)
// - oauth2.CoreStorage (AuthorizeCodeStorage, AccessTokenStorage, RefreshTokenStorage)
// - oauth2.TokenRevocationStorage
// - pkce.PKCERequestStorage
// - openid.OpenIDConnectRequestStorage
type Storage struct {
	pool *pgxpool.Pool
	cimd *CIMDResolver
}

func NewStorage(pool *pgxpool.Pool) *Storage {
	return &Storage{pool: pool}
}

// SetCIMDResolver enables resolving CIMD (https-URL) client ids by fetching the
// client metadata document instead of looking the client up in the database.
func (s *Storage) SetCIMDResolver(r *CIMDResolver) { s.cimd = r }

// ---- ClientManager ----

func (s *Storage) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	var (
		clientID      string
		secretHash    string
		name          string
		redirectURIs  []string
		grantTypes    []string
		responseTypes []string
		scopes        []string
		audience      []string
		public        bool
		authMethod    string
	)

	err := s.pool.QueryRow(ctx,
		`SELECT id, secret_hash, name, redirect_uris, grant_types, response_types, scopes, audience, public, token_endpoint_auth_method
		 FROM oauth2_clients WHERE id = $1`, id,
	).Scan(&clientID, &secretHash, &name, &redirectURIs, &grantTypes, &responseTypes, &scopes, &audience, &public, &authMethod)
	if err != nil {
		if err == pgx.ErrNoRows {
			// A client_id that is an https URL is a Client ID Metadata Document.
			// Resolve it only when there is no DB row, so a registered client can
			// never be shadowed by an attacker-hosted document.
			if s.cimd != nil && IsCIMD(id) {
				return s.cimd.Resolve(ctx, id)
			}
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("getting client: %w", err)
	}

	return &fosite.DefaultOpenIDConnectClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            clientID,
			Secret:        []byte(secretHash),
			RedirectURIs:  redirectURIs,
			GrantTypes:    grantTypes,
			ResponseTypes: responseTypes,
			Scopes:        scopes,
			Audience:      audience,
			Public:        public,
		},
		TokenEndpointAuthMethod: authMethod,
	}, nil
}

func (s *Storage) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	// For simplicity, we don't track JTIs yet. Return nil to allow all.
	return nil
}

func (s *Storage) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	// For simplicity, we don't track JTIs yet.
	return nil
}

// ---- AuthorizeCodeStorage ----

func (s *Storage) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	data, err := marshalSession(request)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO oauth2_auth_codes (signature, request_id, client_id, session_data, requested_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		code, request.GetID(), request.GetClient().GetID(), data,
		request.GetRequestedAt(), request.GetSession().GetExpiresAt(fosite.AuthorizeCode),
	)
	return err
}

func (s *Storage) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	var (
		requestID   string
		clientID    string
		sessionData []byte
		requestedAt time.Time
		active      bool
	)
	err := s.pool.QueryRow(ctx,
		`SELECT request_id, client_id, session_data, requested_at, active FROM oauth2_auth_codes WHERE signature = $1`, code,
	).Scan(&requestID, &clientID, &sessionData, &requestedAt, &active)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	sess, err := unmarshalSession(sessionData)
	if err != nil {
		return nil, err
	}

	req := &fosite.Request{
		ID:          requestID,
		Client:      client,
		Session:     sess,
		RequestedAt: requestedAt,
	}

	if !active {
		return req, fosite.ErrInvalidatedAuthorizeCode
	}

	return req, nil
}

func (s *Storage) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	_, err := s.pool.Exec(ctx, `UPDATE oauth2_auth_codes SET active = false WHERE signature = $1`, code)
	return err
}

// ---- AccessTokenStorage ----

func (s *Storage) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	data, err := marshalSession(request)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO oauth2_access_tokens (signature, request_id, client_id, session_data, requested_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		signature, request.GetID(), request.GetClient().GetID(), data,
		request.GetRequestedAt(), request.GetSession().GetExpiresAt(fosite.AccessToken),
	)
	return err
}

func (s *Storage) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getTokenSession(ctx, "oauth2_access_tokens", signature)
}

func (s *Storage) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM oauth2_access_tokens WHERE signature = $1`, signature)
	return err
}

// ---- RefreshTokenStorage ----

func (s *Storage) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, request fosite.Requester) error {
	data, err := marshalSession(request)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO oauth2_refresh_tokens (signature, request_id, client_id, session_data, requested_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		signature, request.GetID(), request.GetClient().GetID(), data,
		request.GetRequestedAt(), request.GetSession().GetExpiresAt(fosite.RefreshToken),
	)
	return err
}

func (s *Storage) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getTokenSession(ctx, "oauth2_refresh_tokens", signature)
}

func (s *Storage) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM oauth2_refresh_tokens WHERE signature = $1`, signature)
	return err
}

func (s *Storage) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	// Revoke old refresh token and associated access tokens
	_, err := s.pool.Exec(ctx, `UPDATE oauth2_refresh_tokens SET active = false WHERE request_id = $1`, requestID)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `DELETE FROM oauth2_access_tokens WHERE request_id = $1`, requestID)
	return err
}

// ---- TokenRevocationStorage ----

func (s *Storage) RevokeRefreshToken(ctx context.Context, requestID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE oauth2_refresh_tokens SET active = false WHERE request_id = $1`, requestID)
	return err
}

func (s *Storage) RevokeAccessToken(ctx context.Context, requestID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM oauth2_access_tokens WHERE request_id = $1`, requestID)
	return err
}

// ---- PKCERequestStorage ----

func (s *Storage) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	data, err := marshalSession(requester)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO oauth2_pkce (signature, request_id, client_id, session_data, requested_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		signature, requester.GetID(), requester.GetClient().GetID(), data,
		requester.GetRequestedAt(), requester.GetSession().GetExpiresAt(fosite.AuthorizeCode),
	)
	return err
}

func (s *Storage) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getTokenSession(ctx, "oauth2_pkce", signature)
}

func (s *Storage) DeletePKCERequestSession(ctx context.Context, signature string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM oauth2_pkce WHERE signature = $1`, signature)
	return err
}

// ---- OpenIDConnectRequestStorage ----

func (s *Storage) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) error {
	data, err := marshalSession(requester)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO oauth2_oidc_sessions (signature, request_id, client_id, session_data, requested_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		authorizeCode, requester.GetID(), requester.GetClient().GetID(), data,
		requester.GetRequestedAt(), requester.GetSession().GetExpiresAt(fosite.IDToken),
	)
	return err
}

func (s *Storage) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	req, err := s.getTokenSession(ctx, "oauth2_oidc_sessions", authorizeCode)
	if err != nil {
		if err == fosite.ErrNotFound {
			return nil, openid.ErrNoSessionFound
		}
		return nil, err
	}
	return req, nil
}

func (s *Storage) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM oauth2_oidc_sessions WHERE signature = $1`, authorizeCode)
	return err
}

// ---- Helpers ----

func (s *Storage) getTokenSession(ctx context.Context, table string, signature string) (fosite.Requester, error) {
	var (
		requestID   string
		clientID    string
		sessionData []byte
		requestedAt time.Time
		active      bool
	)
	query := fmt.Sprintf(`SELECT request_id, client_id, session_data, requested_at, active FROM %s WHERE signature = $1`, table)
	err := s.pool.QueryRow(ctx, query, signature).Scan(&requestID, &clientID, &sessionData, &requestedAt, &active)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	if !active {
		return nil, fosite.ErrInactiveToken
	}

	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	sess, err := unmarshalSession(sessionData)
	if err != nil {
		return nil, err
	}

	return &fosite.Request{
		ID:          requestID,
		Client:      client,
		Session:     sess,
		RequestedAt: requestedAt,
	}, nil
}

// sessionWrapper wraps the request data for serialization.
type sessionWrapper struct {
	Session  *openid.DefaultSession `json:"session"`
	Scopes   []string               `json:"scopes"`
	Audience []string               `json:"audience"`
	Form     map[string][]string    `json:"form"`
}

func marshalSession(request fosite.Requester) ([]byte, error) {
	sess, ok := request.GetSession().(*openid.DefaultSession)
	if !ok {
		return nil, fmt.Errorf("session is not *openid.DefaultSession")
	}

	wrapper := sessionWrapper{
		Session:  sess,
		Scopes:   []string(request.GetGrantedScopes()),
		Audience: []string(request.GetGrantedAudience()),
	}
	if r, ok := request.(*fosite.Request); ok && r.Form != nil {
		wrapper.Form = r.Form
	}

	return json.Marshal(wrapper)
}

func unmarshalSession(data []byte) (*openid.DefaultSession, error) {
	var wrapper sessionWrapper
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("unmarshaling session: %w", err)
	}
	return wrapper.Session, nil
}
