package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/legant-dev/legant/internal/db"
	"github.com/legant-dev/legant/internal/delegation"
	"github.com/legant-dev/legant/internal/delegation/chains"
	"github.com/legant-dev/legant/internal/keystore"
	"github.com/legant-dev/legant/internal/live"
	"github.com/legant-dev/legant/internal/mcpauth"
	"github.com/legant-dev/legant/internal/metrics"
	"github.com/legant-dev/legant/internal/revocation"
)

// RFC 8693 + Legant token-type identifiers.
const (
	TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
	AccessTokenType        = "urn:ietf:params:oauth:token-type:access_token"
	AgentTokenType         = "urn:legant:params:oauth:token-type:agent-token"
)

// errRateLimited aborts the record transaction when the delegation's rolling-hour
// rate cap is reached; the handler maps it to a 429 (the token is discarded).
var errRateLimited = errors.New("delegation rate limit exceeded")

// Resolvers injected by the server so this package needs no dependency on authz.
type (
	// ActorResolver authenticates the acting agent from its presented token.
	ActorResolver func(ctx context.Context, token string) (agentID string, ok bool)
	// SubjectResolver validates the subject (user) token and returns the user id
	// and the scopes that token was granted (the scope ceiling).
	SubjectResolver func(ctx context.Context, token string) (userID string, scopes []string, ok bool)
)

// TokenExchanger implements the RFC 8693 token-exchange grant: it turns a user's
// subject token plus an agent's actor token into a short-lived composite
// delegation JWT (sub = user, act = agent), bounded by the delegation's scopes,
// constraints, and expiry, recorded for revocation, and audited.
type TokenExchanger struct {
	issuer         string
	ttl            time.Duration
	keys           *keystore.Keystore
	chains         *chains.Service
	revocation     *revocation.Store
	pool           *pgxpool.Pool
	pub            *live.Publisher // optional live-console feed; nil-safe
	resolveActor   ActorResolver
	resolveSubject SubjectResolver
}

func NewTokenExchanger(issuer string, ttl time.Duration, keys *keystore.Keystore, ch *chains.Service, rev *revocation.Store, pool *pgxpool.Pool, pub *live.Publisher, actor ActorResolver, subject SubjectResolver) *TokenExchanger {
	return &TokenExchanger{
		issuer: issuer, ttl: ttl, keys: keys, chains: ch, revocation: rev, pool: pool, pub: pub,
		resolveActor: actor, resolveSubject: subject,
	}
}

// Handle processes a token-exchange request. The caller (TokenHandler) has
// already parsed the form and set no-store headers.
func (x *TokenExchanger) Handle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	form := r.PostForm

	// Record the outcome of every exchange attempt; flipped to "success" only on
	// the path that actually mints and records a token.
	outcome := "error"
	defer func() { metrics.TokenExchangesTotal.Inc(outcome) }()

	subjectToken := form.Get("subject_token")
	actorToken := form.Get("actor_token")
	resources := form["resource"]
	requested := strings.Fields(form.Get("scope"))

	if subjectToken == "" || actorToken == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "subject_token and actor_token are required")
		return
	}
	if t := form.Get("subject_token_type"); t != "" && t != AccessTokenType {
		oauthError(w, http.StatusBadRequest, "invalid_request", "unsupported subject_token_type")
		return
	}
	if t := form.Get("actor_token_type"); t != "" && t != AgentTokenType {
		oauthError(w, http.StatusBadRequest, "invalid_request", "unsupported actor_token_type")
		return
	}
	// RFC 8707: a single resource indicator. Multiple values are rejected rather
	// than silently truncated, which would allow audience confusion.
	if len(resources) > 1 {
		oauthError(w, http.StatusBadRequest, "invalid_target", "only a single resource indicator is supported")
		return
	}
	resource := ""
	if len(resources) == 1 {
		resource = resources[0]
	}
	if resource == "" {
		oauthError(w, http.StatusBadRequest, "invalid_target", "a single resource indicator is required")
		return
	}

	// The actor token IS the agent's credential — authenticating it establishes
	// which agent the act claim names; it cannot be forged without the token.
	agentID, ok := x.resolveActor(ctx, actorToken)
	if !ok {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "invalid actor token")
		return
	}
	userID, subjectScopes, ok := x.resolveSubject(ctx, subjectToken)
	if !ok {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid subject token")
		return
	}

	grant, delegationID, err := x.chains.ResolveGrantChain(ctx, agentID, userID)
	if err != nil {
		oauthError(w, http.StatusForbidden, "invalid_grant", "no delegation authorizes this agent to act for this user")
		return
	}

	// Scope ceiling: never exceed the delegation, never exceed the subject token.
	effective := delegation.Attenuate(subjectScopes, delegation.Attenuate(grant.Scopes, requested))
	if len(effective) == 0 {
		oauthError(w, http.StatusBadRequest, "invalid_scope", "requested scopes exceed the delegation or the subject token")
		return
	}

	// RFC 8707: canonicalize the requested resource and require it be explicitly
	// permitted by the delegation. An empty Resources list denies all audiences.
	canonResource, err := mcpauth.CanonicalizeResource(resource)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_target", "invalid resource indicator")
		return
	}
	allowed := false
	for _, r := range grant.Constraints.Resources {
		if mcpauth.ResourceMatches(canonResource, r) {
			allowed = true
			break
		}
	}
	if !allowed {
		oauthError(w, http.StatusBadRequest, "invalid_target", "resource not permitted by the delegation")
		return
	}

	// Clamp the lifetime: min(now+ttl, grant expiry).
	now := time.Now()
	exp := now.Add(x.ttl)
	if grant.ExpiresAt.Before(exp) {
		exp = grant.ExpiresAt
	}
	if !exp.After(now) {
		// The delegation expired between resolution and now — never mint a token
		// that is already invalid.
		oauthError(w, http.StatusForbidden, "invalid_grant", "delegation has expired")
		return
	}
	grant.ExpiresAt = exp
	grant.Scopes = effective

	signer := delegation.NewSigner(x.issuer, x.keys.ActiveKID(), x.keys.ActiveSigner())
	token, err := signer.IssueForGrant(grant, effective, canonResource, now)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "could not mint token")
		return
	}

	// Self-verify to extract the jti + provenance (and as a sanity check).
	claims, err := delegation.NewVerifier(x.issuer, x.keys.VerifierKeys()).Verify(token, canonResource)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "minted token failed self-verification")
		return
	}

	// Record the token and its audit line atomically — and enforce the rate cap in
	// the SAME transaction under a per-delegation advisory lock, so concurrent
	// exchanges for one delegation cannot all slip past a stale count (TOCTOU).
	rateLimited := false
	err = db.WithTx(ctx, x.pool, func(tx pgx.Tx) error {
		if grant.Constraints.Rate != nil && grant.Constraints.Rate.MaxPerHour > 0 {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, delegationID); err != nil {
				return err
			}
			var minted int
			if err := tx.QueryRow(ctx,
				`SELECT count(*) FROM exchanged_tokens WHERE delegation_id = $1 AND issued_at > now() - interval '1 hour'`,
				delegationID).Scan(&minted); err != nil {
				return err
			}
			if minted >= grant.Constraints.Rate.MaxPerHour {
				rateLimited = true
				return errRateLimited
			}
		}
		if err := x.revocation.RecordTx(ctx, tx, revocation.Record{
			JTI: claims.ID, DelegationID: &delegationID, Subject: claims.Subject,
			AgentID: &agentID, ActorChain: claims.ActorChain(), Audience: canonResource,
			Scopes: effective, ExpiresAt: exp,
		}); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO audit_events
			   (actor_type, actor_id, action, resource_type, resource_id, on_behalf_of_sub, actor_chain, delegation_id, grant_jti, org_id)
			 VALUES ('agent', $1, 'token.exchanged', 'token', $2, $3, $4, $5, $2,
			         (SELECT org_id FROM delegation_chains WHERE id = $5::uuid))`,
			agentID, claims.ID, claims.Subject, claims.ActorChain(), delegationID,
		)
		return err
	})
	if rateLimited {
		oauthError(w, http.StatusTooManyRequests, "invalid_grant", "delegation rate limit exceeded; retry later")
		return
	}
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "could not record minted token")
		return
	}

	outcome = "success"
	metrics.TokensMintedTotal.Inc("exchange")
	// Announce the mint to the live console (after the tx committed, so a
	// rolled-back exchange is never shown). Provenance is the in-token chain.
	leaf := ""
	if c := claims.ActorChain(); len(c) > 0 {
		leaf = c[0]
	}
	x.pub.Publish(live.Event{
		Type: "mint", Decision: "MINT", Subject: claims.Subject, Actor: leaf,
		Provenance: claims.Provenance(), Upstream: canonResource, Delegation: delegationID,
	})
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"access_token":      token,
		"issued_token_type": AccessTokenType,
		"token_type":        "Bearer",
		"expires_in":        int(time.Until(exp).Seconds()),
		"scope":             strings.Join(effective, " "),
	})
}

// IntrospectDelegation answers RFC 7662 introspection for a composite delegation
// token: it verifies the signature (kid-aware) and consults the revocation store.
// Returns ok=false when the token is not one of ours (so the caller can fall back
// to Fosite introspection of normal access tokens).
func (x *TokenExchanger) IntrospectDelegation(ctx context.Context, token string) (map[string]any, bool) {
	claims, err := delegation.NewVerifier(x.issuer, x.keys.VerifierKeys()).VerifyAny(token)
	if err != nil || claims.Act == nil {
		return nil, false
	}
	active, err := x.revocation.IsActive(ctx, claims.ID)
	if err != nil {
		metrics.RevocationCheckErrorsTotal.Inc("introspection")
		active = false
	}
	resp := map[string]any{"active": active}
	if active {
		resp["sub"] = claims.Subject
		resp["scope"] = claims.Scope
		resp["aud"] = claims.Audience
		resp["exp"] = claims.ExpiresAt.Unix()
		resp["jti"] = claims.ID
		resp["act"] = claims.Act
		resp["client_id"] = actorOf(claims.Act)
	}
	return resp, true
}

func actorOf(a *delegation.ActClaim) string {
	if a == nil {
		return ""
	}
	return a.Sub
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSONResponse(w, status, map[string]any{"error": code, "error_description": desc})
}

func writeJSONResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
