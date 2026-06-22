package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// This file is the resource-server INTEGRATION layer: drop-in net/http (and
// chi-compatible) middleware so a backend becomes a Legant-protected resource
// server in a few lines, instead of wiring Verify/Authorize by hand. It is the
// delegation-aware analog of a generic OIDC JWT middleware — it understands the
// act delegation chain, the constraint dimensions, RFC 8707 audience
// canonicalization, and the signed revocation feed, none of which a plain
// access-token middleware models.

type ctxKey int

const claimsCtxKey ctxKey = 0

// ClaimsFrom returns the verified Claims stored by Authenticate, if any.
func ClaimsFrom(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsCtxKey).(*Claims)
	return c, ok
}

// MustClaims returns the verified Claims or panics — use only inside handlers
// mounted behind Authenticate (where the claims are guaranteed present).
func MustClaims(ctx context.Context) *Claims {
	c, ok := ClaimsFrom(ctx)
	if !ok {
		panic("sdk: no Legant claims in context (is Authenticate mounted?)")
	}
	return c
}

// Authenticate verifies the request's Bearer token with v and, on success, stores
// the Claims in the request context for downstream handlers (read them with
// ClaimsFrom). On any verification failure it writes 401 with an RFC 6750
// WWW-Authenticate challenge and does NOT call the next handler. It does not
// authorize a specific action — compose RequireScope / RequireAction for that, or
// call Claims.Authorize inside the handler.
//
// Revocation behavior follows how v was built: WithRevocationFeed makes a revoked
// token 401 here; WithFeedFailClosed couples availability to the feed. Without a
// feed, revocation is bounded by the token's TTL. Choose deliberately.
func Authenticate(v *Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok, err := bearer(r)
			if err != nil {
				challenge(w, http.StatusUnauthorized, "invalid_request", err.Error())
				return
			}
			claims, err := v.Verify(tok)
			if err != nil {
				challenge(w, http.StatusUnauthorized, "invalid_token", err.Error())
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsCtxKey, claims)))
		})
	}
}

// RequireScope authorizes that the request's token carries scope. Mount it AFTER
// Authenticate. For per-request constraints (amount/resource/tool/time), use
// RequireAction instead, or call Claims.Authorize in the handler.
func RequireScope(scope string) func(http.Handler) http.Handler {
	return RequireAction(func(*http.Request) Action { return Action{Scope: scope} })
}

// RequireAction derives an Action from each request and authorizes it against the
// verified token, writing 403 on denial. Mount it AFTER Authenticate.
//
//	r.With(sdk.Authenticate(v), sdk.RequireAction(func(r *http.Request) sdk.Action {
//	    return sdk.Action{Scope: "warehouse:query", Resource: r.URL.Query().Get("schema")}
//	})).Get("/query", handler)
func RequireAction(action func(*http.Request) Action) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFrom(r.Context())
			if !ok {
				challenge(w, http.StatusUnauthorized, "invalid_token", "no verified token (mount Authenticate first)")
				return
			}
			if err := claims.Authorize(action(r)); err != nil {
				challenge(w, http.StatusForbidden, "insufficient_scope", err.Error())
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// bearer extracts the token from an Authorization: Bearer header.
func bearer(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", fmt.Errorf("missing Authorization header")
	}
	const p = "Bearer "
	if len(h) <= len(p) || !strings.EqualFold(h[:len(p)], p) {
		return "", fmt.Errorf("Authorization header is not a Bearer token")
	}
	return strings.TrimSpace(h[len(p):]), nil
}

// challenge writes an RFC 6750 error response.
func challenge(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error=%q, error_description=%q`, code, desc))
	http.Error(w, code+": "+desc, status)
}

// ---- self-hosted MCP server helper ----------------------------------------

// MCPToolName extracts the tool name from a JSON-RPC MCP "tools/call" request
// body, for resource servers that ARE an MCP server (rather than sitting behind
// the gateway). Pair it with Claims.Authorize to gate a tool before dispatch:
//
//	name, _ := sdk.MCPToolName(body)
//	if err := claims.Authorize(sdk.Action{Scope: toolScopes[name], Tool: name}); err != nil { ... }
func MCPToolName(body []byte) (string, error) {
	var req struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return "", fmt.Errorf("not a JSON-RPC request: %w", err)
	}
	if req.Method != "tools/call" {
		return "", fmt.Errorf("not a tools/call (method=%q)", req.Method)
	}
	if req.Params.Name == "" {
		return "", fmt.Errorf("tools/call missing params.name")
	}
	return req.Params.Name, nil
}
