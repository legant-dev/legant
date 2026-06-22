package auth

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/ory/fosite"
)

type Handler struct {
	provider       fosite.OAuth2Provider
	sessionManager *SessionManager
	exchanger      *TokenExchanger // optional RFC 8693 token-exchange grant
}

func NewHandler(provider fosite.OAuth2Provider, sessionManager *SessionManager) *Handler {
	return &Handler{
		provider:       provider,
		sessionManager: sessionManager,
	}
}

// SetExchanger enables the RFC 8693 token-exchange grant on the token endpoint
// and delegation-token introspection.
func (h *Handler) SetExchanger(ex *TokenExchanger) { h.exchanger = ex }

// AuthorizeHandler handles GET /oauth2/authorize
// It checks for an existing session and either shows the login page or proceeds with consent.
func (h *Handler) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ar, err := h.provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		slog.Error("authorize request error", "error", err)
		h.provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Check for existing session
	session, err := h.sessionManager.Get(ctx, r)
	if err != nil {
		// No session - redirect to login with the authorize request params
		loginURL := "/login?" + r.URL.RawQuery
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// User is authenticated, create OAuth2 session and grant
	oauthSession := NewSession(session.UserID)

	// Grant requested scopes
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}

	// Grant requested audience
	for _, aud := range ar.GetRequestedAudience() {
		ar.GrantAudience(aud)
	}

	response, err := h.provider.NewAuthorizeResponse(ctx, ar, oauthSession)
	if err != nil {
		slog.Error("authorize response error", "error", err)
		h.provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	h.provider.WriteAuthorizeResponse(ctx, w, ar, response)
}

// TokenHandler handles POST /oauth2/token
func (h *Handler) TokenHandler(w http.ResponseWriter, r *http.Request) {
	// Token responses must never be cached (OAuth 2.1 / RFC 6749 §5.1).
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// Branch the RFC 8693 token-exchange grant before Fosite, which rejects
	// unknown grant types. Parse the form exactly once here.
	if h.exchanger != nil {
		if err := r.ParseForm(); err == nil && r.PostForm.Get("grant_type") == TokenExchangeGrantType {
			h.exchanger.Handle(w, r)
			return
		}
	}

	ctx := r.Context()
	session := NewSession("")

	ar, err := h.provider.NewAccessRequest(ctx, r, session)
	if err != nil {
		slog.Error("access request error", "error", err)
		h.provider.WriteAccessError(ctx, w, ar, err)
		return
	}

	// Grant requested scopes for client credentials
	if ar.GetGrantTypes().ExactOne("client_credentials") {
		for _, scope := range ar.GetRequestedScopes() {
			ar.GrantScope(scope)
		}
	}

	response, err := h.provider.NewAccessResponse(ctx, ar)
	if err != nil {
		slog.Error("access response error", "error", err)
		h.provider.WriteAccessError(ctx, w, ar, err)
		return
	}

	h.provider.WriteAccessResponse(ctx, w, ar, response)
}

// RevokeHandler handles POST /oauth2/revoke
func (h *Handler) RevokeHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	err := h.provider.NewRevocationRequest(ctx, r)
	if err != nil {
		slog.Error("revocation error", "error", err)
	}
	h.provider.WriteRevocationResponse(ctx, w, err)
}

// IntrospectHandler handles POST /oauth2/introspect
func (h *Handler) IntrospectHandler(w http.ResponseWriter, r *http.Request) {
	// Composite delegation tokens aren't Fosite-issued, so introspect them via
	// the exchanger (signature + revocation store) before falling back to Fosite.
	if h.exchanger != nil {
		if err := r.ParseForm(); err == nil {
			if resp, ok := h.exchanger.IntrospectDelegation(r.Context(), r.PostForm.Get("token")); ok {
				writeJSONResponse(w, http.StatusOK, resp)
				return
			}
		}
	}

	ctx := r.Context()
	session := NewSession("")

	ir, err := h.provider.NewIntrospectionRequest(ctx, r, session)
	if err != nil {
		slog.Error("introspection error", "error", err)
		h.provider.WriteIntrospectionError(ctx, w, err)
		return
	}

	h.provider.WriteIntrospectionResponse(ctx, w, ir)
}

// UserinfoHandler handles GET /oauth2/userinfo
func (h *Handler) UserinfoHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := NewSession("")

	tokenType, ar, err := h.provider.IntrospectToken(ctx, fosite.AccessTokenFromRequest(r), fosite.AccessToken, session)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	_ = tokenType

	sess := ar.GetSession()
	claims := map[string]interface{}{
		"sub": sess.GetSubject(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(claims)
}
