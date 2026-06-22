// Package mcpgw is the MCP auth-gateway: a reverse proxy that enforces per-tool
// delegation in front of MCP servers. It verifies the inbound delegated token,
// authorizes the specific tool against the token's scope and constraints, mints
// a fresh minimally-scoped downstream token bound to the upstream (never
// forwarding the inbound token — confused-deputy protection), proxies the call,
// and audits it with the full sub/act provenance chain.
package mcpgw

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/legant-dev/legant/internal/delegation"
	"github.com/legant-dev/legant/internal/keystore"
	"github.com/legant-dev/legant/internal/live"
	"github.com/legant-dev/legant/internal/mcpauth"
	"github.com/legant-dev/legant/internal/metrics"
	"github.com/legant-dev/legant/internal/revocation"
)

// Upstream describes a registered MCP server the gateway fronts.
type Upstream struct {
	Slug string `json:"slug"` // path segment: /mcp/{slug}
	// InboundAudience is the audience an inbound delegated token MUST carry to be
	// accepted for this slug. It is per-upstream so a token bound to one upstream
	// cannot be replayed against another even when their tool scopes overlap.
	InboundAudience string            `json:"inbound_audience"`
	URL             string            `json:"url"`         // upstream MCP server endpoint
	ResourceID      string            `json:"resource_id"` // the upstream's resource indicator (downstream token aud)
	ToolScopes      map[string]string `json:"tool_scopes"` // tool name -> required scope
}

// Gateway fronts one or more MCP upstreams.
type Gateway struct {
	issuer        string
	keys          *keystore.Keystore
	revocation    *revocation.Store
	pool          *pgxpool.Pool
	pub           *live.Publisher // optional live-console feed; nil-safe
	upstreams     map[string]*Upstream
	client        *http.Client
	downstreamTTL time.Duration
	maxBody       int64
	revRefresh    time.Duration // >0 → in-memory revocation feed mode
	revoked       *revokedCache // nil unless revRefresh > 0

	upMu            sync.RWMutex
	staticUpstreams []*Upstream // from config; the always-present base for refreshes
}

// GatewayOption tunes a Gateway at construction.
type GatewayOption func(*Gateway)

// WithDownstreamTTL caps the lifetime of the per-call downstream token the gateway
// mints (still clamped to the inbound token's expiry). Zero keeps the 60s default.
func WithDownstreamTTL(d time.Duration) GatewayOption {
	return func(g *Gateway) {
		if d > 0 {
			g.downstreamTTL = d
		}
	}
}

// WithRevocationRefresh switches revocation checks from a per-call store lookup
// (Tier A, instant) to an in-memory set of revoked-but-unexpired token ids
// refreshed on the given interval (Tier B). It avoids a database round-trip per
// call for high-QPS gateways, at the cost of a revoke taking effect within the
// interval. Call StartRevocationRefresh to begin refreshing.
func WithRevocationRefresh(d time.Duration) GatewayOption {
	return func(g *Gateway) { g.revRefresh = d }
}

func NewGateway(issuer string, keys *keystore.Keystore, rev *revocation.Store, pool *pgxpool.Pool, pub *live.Publisher, upstreams []*Upstream, opts ...GatewayOption) (*Gateway, error) {
	m, err := buildUpstreamMap(upstreams)
	if err != nil {
		return nil, err
	}
	g := &Gateway{
		issuer: issuer, keys: keys, revocation: rev, pool: pool, pub: pub,
		upstreams: m, staticUpstreams: upstreams, client: &http.Client{Timeout: 30 * time.Second},
		downstreamTTL: 60 * time.Second, maxBody: 1 << 20,
	}
	for _, o := range opts {
		o(g)
	}
	if g.revRefresh > 0 {
		g.revoked = &revokedCache{set: map[string]struct{}{}}
	}
	return g, nil
}

// buildUpstreamMap indexes upstreams by slug, requiring a non-empty and unique
// inbound_audience per upstream (a shared inbound audience would collapse
// cross-upstream token isolation).
func buildUpstreamMap(upstreams []*Upstream) (map[string]*Upstream, error) {
	m := make(map[string]*Upstream, len(upstreams))
	seen := map[string]bool{}
	for _, u := range upstreams {
		if u.InboundAudience == "" {
			return nil, fmt.Errorf("mcpgw: upstream %q has no inbound_audience", u.Slug)
		}
		if seen[u.InboundAudience] {
			return nil, fmt.Errorf("mcpgw: duplicate inbound_audience %q across upstreams", u.InboundAudience)
		}
		seen[u.InboundAudience] = true
		m[u.Slug] = u
	}
	return m, nil
}

func (g *Gateway) upstream(slug string) (*Upstream, bool) {
	g.upMu.RLock()
	defer g.upMu.RUnlock()
	u, ok := g.upstreams[slug]
	return u, ok
}

// RefreshUpstreams rebuilds the live upstream set from the static config base plus
// the DB registry. Static upstreams win on a slug or inbound-audience collision;
// a DB upstream that would duplicate an inbound audience is skipped (isolation is
// never weakened). The swap is atomic.
func (g *Gateway) RefreshUpstreams(ctx context.Context, store *UpstreamStore) error {
	dbUps, err := store.List(ctx)
	if err != nil {
		return err
	}
	merged, err := buildUpstreamMap(g.staticUpstreams)
	if err != nil {
		return err
	}
	seenAud := map[string]bool{}
	for _, u := range merged {
		seenAud[u.InboundAudience] = true
	}
	for _, u := range dbUps {
		if u.InboundAudience == "" {
			continue
		}
		if _, slugDup := merged[u.Slug]; slugDup || seenAud[u.InboundAudience] {
			slog.Warn("gateway: skipping DB upstream that collides with a static one", "slug", u.Slug, "audience", u.InboundAudience)
			continue
		}
		seenAud[u.InboundAudience] = true
		merged[u.Slug] = u
	}
	g.upMu.Lock()
	g.upstreams = merged
	g.upMu.Unlock()
	return nil
}

// StartUpstreamRefresh loads the DB registry once (synchronously) and then merges
// it on the given interval until ctx is cancelled. A no-op if store is nil.
func (g *Gateway) StartUpstreamRefresh(ctx context.Context, store *UpstreamStore, interval time.Duration) error {
	if store == nil {
		return nil
	}
	if err := g.RefreshUpstreams(ctx, store); err != nil {
		return err
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := g.RefreshUpstreams(ctx, store); err != nil {
					slog.Error("gateway upstream refresh failed", "error", err)
				}
			}
		}
	}()
	return nil
}

// revokedCache is the in-memory set of revoked-but-unexpired token ids used in
// feed mode. `loaded` guards against treating tokens as active before the first
// successful refresh (fail closed until loaded).
type revokedCache struct {
	mu     sync.RWMutex
	set    map[string]struct{}
	loaded bool
}

func (c *revokedCache) contains(jti string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.set[jti]
	return ok
}

func (c *revokedCache) ready() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.loaded
}

func (c *revokedCache) swap(set map[string]struct{}) {
	c.mu.Lock()
	c.set, c.loaded = set, true
	c.mu.Unlock()
}

// tokenActive reports whether an inbound token is still valid for revocation. In
// the default mode it consults the store per call (instant). In feed mode it
// checks the in-memory revoked set (a validly-signed, unexpired token that is not
// in the set is active); it fails closed until the set has loaded once.
func (g *Gateway) tokenActive(ctx context.Context, jti string) (bool, error) {
	if g.revoked != nil {
		if !g.revoked.ready() {
			return false, fmt.Errorf("revocation cache not yet loaded")
		}
		return !g.revoked.contains(jti), nil
	}
	return g.revocation.IsActive(ctx, jti)
}

func (g *Gateway) refreshRevoked(ctx context.Context) error {
	rows, err := g.pool.Query(ctx,
		`SELECT jti FROM exchanged_tokens WHERE revoked_at IS NOT NULL AND expires_at > now()`)
	if err != nil {
		return err
	}
	defer rows.Close()
	set := map[string]struct{}{}
	for rows.Next() {
		var jti string
		if err := rows.Scan(&jti); err != nil {
			return err
		}
		set[jti] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	g.revoked.swap(set)
	return nil
}

// StartRevocationRefresh loads the revoked set once (synchronously, so the gateway
// fails closed if it can't reach the DB at startup) and then refreshes it on the
// configured interval until ctx is cancelled. A no-op unless feed mode is enabled.
func (g *Gateway) StartRevocationRefresh(ctx context.Context) error {
	if g.revoked == nil {
		return nil
	}
	if err := g.refreshRevoked(ctx); err != nil {
		return fmt.Errorf("initial revocation-set load: %w", err)
	}
	go func() {
		t := time.NewTicker(g.revRefresh)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := g.refreshRevoked(ctx); err != nil {
					metrics.RevocationCheckErrorsTotal.Inc("gateway")
					slog.Error("gateway revocation-set refresh failed", "error", err)
				}
			}
		}
	}()
	return nil
}

type jsonRPCRequest struct {
	Method string `json:"method"`
	Params struct {
		Name string `json:"name"`
	} `json:"params"`
}

// Routes returns the gateway router, to mount under /mcp.
func (g *Gateway) Routes() chi.Router {
	r := chi.NewRouter()
	r.Get("/{slug}/.well-known/oauth-protected-resource", g.metadata)
	r.Post("/{slug}", g.handle)
	return r
}

func (g *Gateway) metadata(w http.ResponseWriter, r *http.Request) {
	up, ok := g.upstream(chi.URLParam(r, "slug"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	mcpauth.ProtectedResourceMetadataHandler(up.ResourceID, g.issuer)(w, r)
}

func (g *Gateway) handle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	up, ok := g.upstream(chi.URLParam(r, "slug"))
	if !ok {
		http.NotFound(w, r)
		return
	}

	// Record the call's decision under this upstream. Defaults to "error"; each
	// branch sets the specific outcome before returning.
	decision := "error"
	// Live-console fields, populated as the request flows; the deferred publish
	// fires once per call. We only stream tool calls and denials (evProv is set
	// once the token verifies), so handshake/ping/tools-list don't flood the feed.
	var evTool, evActor, evProv, evReason string
	defer func() {
		metrics.GatewayCallsTotal.Inc(up.Slug, decision)
		// Only stream genuine authorization outcomes. Skip "error" (an internal
		// 500/502 upstream/gateway fault — not an authz denial) and the noise of
		// handshake/ping/tools-list (evTool empty on an allow).
		if evProv == "" || decision == "error" || (evTool == "" && decision == "allow") {
			return
		}
		d := "DENY"
		if decision == "allow" {
			d = "ALLOW"
		}
		g.pub.Publish(live.Event{
			Type: "decision", Decision: d, Tool: evTool, Upstream: up.Slug,
			Actor: evActor, Provenance: evProv, Reason: evReason,
		})
	}()

	// Verify the inbound delegated token: kid-aware signature, issuer, and that it
	// is bound to THIS gateway (aud == gateway resource id), plus revocation.
	metaURL := g.metadataURL(r, up.Slug)
	token := bearer(r)
	if token == "" {
		decision = "unauthorized"
		mcpauth.Challenge(w, http.StatusUnauthorized, metaURL, "", "")
		return
	}
	claims, err := delegation.NewVerifier(g.issuer, g.keys.VerifierKeys()).Verify(token, up.InboundAudience)
	if err != nil {
		decision = "unauthorized"
		mcpauth.Challenge(w, http.StatusUnauthorized, metaURL, "invalid_token", "token verification failed")
		return
	}
	if c := claims.ActorChain(); len(c) > 0 {
		evActor = c[0]
	}
	evProv = claims.Provenance()
	// Revocation is checked for EVERY token, not only act-bearing ones.
	active, err := g.tokenActive(ctx, claims.ID)
	if err != nil {
		metrics.RevocationCheckErrorsTotal.Inc("gateway")
		slog.Error("gateway revocation check failed", "error", err, "jti", claims.ID)
	}
	if !active {
		decision = "unauthorized"
		evReason = "token revoked or unknown"
		mcpauth.Challenge(w, http.StatusUnauthorized, metaURL, "invalid_token", "token revoked or unknown")
		return
	}

	// Buffer the body (rejecting oversized).
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, g.maxBody))
	if err != nil {
		http.Error(w, `{"error":"request body too large or unreadable"}`, http.StatusRequestEntityTooLarge)
		return
	}
	// Reject any object with duplicate keys at any depth. Authorization reads the
	// nested params.name, so a duplicate key (top-level OR inside params) could let
	// the upstream's JSON parser resolve a different tool than the gateway
	// authorized (a parser-differential confused-deputy). Rejecting duplicates
	// closes that hole while forwarding the body verbatim, preserving number
	// fidelity (re-marshaling through interface{} would not).
	if hasDuplicateKeys(body) {
		decision = "deny"
		evReason = "duplicate JSON keys"
		http.Error(w, `{"error":"duplicate JSON keys are not permitted"}`, http.StatusBadRequest)
		return
	}
	// A single tools/call object is required. A JSON-RPC batch (top-level array) is
	// intentionally not supported — it would let one request smuggle multiple tool
	// calls past a single per-tool authorization — and fails this decode.
	var rpc jsonRPCRequest
	if err := json.Unmarshal(body, &rpc); err != nil {
		http.Error(w, `{"error":"invalid JSON-RPC (a single tools/call object is required)"}`, http.StatusBadRequest)
		return
	}

	// tools/call is gated per tool below. Every other MCP method (handshake,
	// discovery, keepalive) carries no tool authority and is handled — verified and
	// proxied, with tools/list filtered to the delegated tools — by
	// handleNonToolCall. Unmodeled methods are default-denied there.
	if rpc.Method != "tools/call" {
		g.handleNonToolCall(ctx, w, r, up, claims, body, rpc.Method, &decision)
		return
	}
	evTool = rpc.Params.Name
	requiredScope, ok := up.ToolScopes[rpc.Params.Name]
	if !ok {
		decision = "deny"
		evReason = "tool not delegated"
		http.Error(w, `{"error":"unknown or disallowed tool"}`, http.StatusForbidden)
		return
	}
	// Resource binding is enforced by the audience; the per-tool check is scope +
	// tool + any value constraints.
	if err := claims.Authorize(delegation.Action{Scope: requiredScope, Tool: rpc.Params.Name}); err != nil {
		decision = "deny"
		evReason = "forbidden (scope/constraint)"
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}

	// Mint a fresh downstream token: preserve sub + act provenance, narrow scope
	// AND the tool allow-list to exactly this tool, audience = upstream, lifetime
	// clamped to the inbound token's expiry (never extend authority). The inbound
	// token is never forwarded.
	now := time.Now()
	exp := now.Add(g.downstreamTTL)
	if claims.ExpiresAt != nil && exp.After(claims.ExpiresAt.Time) {
		exp = claims.ExpiresAt.Time
	}
	signer := delegation.NewSigner(g.issuer, g.keys.ActiveKID(), g.keys.ActiveSigner())
	downstream, err := signer.IssueClaims(claims.Subject, claims.Act, []string{requiredScope},
		up.ResourceID, downstreamConstraints(claims.Constraints, rpc.Params.Name), exp, now)
	if err != nil {
		http.Error(w, `{"error":"could not mint downstream token"}`, http.StatusInternalServerError)
		return
	}
	// The downstream token is ephemeral (≤ downstreamTTL, clamped to the inbound
	// expiry) and is verified offline by the upstream, which never introspects it.
	// It is therefore intentionally NOT recorded in the revocation store — there is
	// no consumer for per-call jti rows, and revoking the inbound delegation
	// already stops new downstream tokens from being minted.
	metrics.TokensMintedTotal.Inc("gateway")

	resp, err := g.forward(ctx, r, up, downstream, body, "")
	if err != nil {
		http.Error(w, `{"error":"upstream unreachable"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	g.audit(ctx, claims, up.Slug, rpc.Params.Name, resp.StatusCode)
	decision = "allow"
	streamResponse(w, resp)
}

// handleNonToolCall serves MCP methods other than tools/call. Discovery,
// handshake, and keepalive methods carry no tool authority, so the gateway mints
// a delegation-scoped downstream token (no single-tool narrowing) and proxies.
// tools/list is additionally FILTERED so the agent only discovers the tools it is
// permitted to call. Anything not modeled is default-denied.
func (g *Gateway) handleNonToolCall(ctx context.Context, w http.ResponseWriter, r *http.Request, up *Upstream, claims *delegation.DelegationClaims, body []byte, method string, decision *string) {
	if method != "tools/list" && !isPassthrough(method) {
		*decision = "deny"
		http.Error(w, `{"error":"method not permitted through the gateway"}`, http.StatusForbidden)
		return
	}
	now := time.Now()
	exp := now.Add(g.downstreamTTL)
	if claims.ExpiresAt != nil && exp.After(claims.ExpiresAt.Time) {
		exp = claims.ExpiresAt.Time
	}
	downstream, err := g.mint(claims, strings.Fields(claims.Scope), up.ResourceID, discoveryConstraints(claims.Constraints), exp, now)
	if err != nil {
		http.Error(w, `{"error":"could not mint downstream token"}`, http.StatusInternalServerError)
		return
	}
	// Force a non-streaming JSON tools/list so the response can be parsed and
	// filtered; the agent must not be able to make the upstream stream past the
	// filter. Other methods keep the client's Accept (they may legitimately stream).
	accept := ""
	if method == "tools/list" {
		accept = "application/json"
	}
	resp, err := g.forward(ctx, r, up, downstream, body, accept)
	if err != nil {
		http.Error(w, `{"error":"upstream unreachable"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if method == "tools/list" {
		out, tooBig := readCapped(resp.Body, g.maxBody)
		if tooBig {
			http.Error(w, `{"error":"upstream tools/list response too large"}`, http.StatusBadGateway)
			return
		}
		// FAIL CLOSED: if the response can't be parsed and filtered (e.g. an SSE
		// frame or garbage), reject it rather than forwarding the upstream's full,
		// unfiltered tool catalog — filtering is the only control on tool discovery.
		filtered, ok := filterToolsList(out, up, claims)
		if !ok {
			http.Error(w, `{"error":"upstream returned an unfilterable tools/list"}`, http.StatusBadGateway)
			return
		}
		g.audit(ctx, claims, up.Slug, "tools/list", resp.StatusCode)
		*decision = "allow"
		copyResponseHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(filtered)
		return
	}

	// Handshake / keepalive / discovery: audit the method (with provenance) and
	// stream the response.
	g.audit(ctx, claims, up.Slug, "mcp:"+method, resp.StatusCode)
	*decision = "allow"
	streamResponse(w, resp)
}

// readCapped reads up to max bytes; it reports tooBig (rather than silently
// truncating, which io.LimitReader does) when the source exceeds the cap.
func readCapped(r io.Reader, max int64) (data []byte, tooBig bool) {
	data, _ = io.ReadAll(io.LimitReader(r, max+1))
	if int64(len(data)) > max {
		return nil, true
	}
	return data, false
}

// isPassthrough reports whether an MCP method is forwarded without per-tool
// authorization: the initialize handshake, keepalive, notifications, and the
// non-tool discovery lists.
func isPassthrough(method string) bool {
	if strings.HasPrefix(method, "notifications/") {
		return true
	}
	switch method {
	case "initialize", "ping", "prompts/list", "resources/list", "resources/templates/list", "logging/setLevel":
		return true
	}
	return false
}

// mint signs a fresh downstream token preserving sub/act provenance, bound to the
// upstream audience, and counts it.
func (g *Gateway) mint(claims *delegation.DelegationClaims, scopes []string, aud string, cnst *delegation.Constraints, exp, now time.Time) (string, error) {
	signer := delegation.NewSigner(g.issuer, g.keys.ActiveKID(), g.keys.ActiveSigner())
	tok, err := signer.IssueClaims(claims.Subject, claims.Act, scopes, aud, cnst, exp, now)
	if err == nil {
		metrics.TokensMintedTotal.Inc("gateway")
	}
	return tok, err
}

// forward issues the upstream MCP request with the downstream token. acceptOverride,
// when non-empty, pins the upstream Accept header (used to force a non-streaming
// JSON tools/list so it can be filtered); otherwise the client's Accept is
// forwarded so the upstream may stream. Mcp-Session-Id is forwarded for session
// continuity.
func (g *Gateway) forward(ctx context.Context, r *http.Request, up *Upstream, downstream string, body []byte, acceptOverride string) (*http.Response, error) {
	upReq, err := http.NewRequestWithContext(ctx, http.MethodPost, up.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	upReq.Header.Set("Content-Type", "application/json")
	switch {
	case acceptOverride != "":
		upReq.Header.Set("Accept", acceptOverride)
	case r.Header.Get("Accept") != "":
		upReq.Header.Set("Accept", r.Header.Get("Accept"))
	default:
		upReq.Header.Set("Accept", "application/json, text/event-stream")
	}
	if sid := r.Header.Get("Mcp-Session-Id"); sid != "" {
		upReq.Header.Set("Mcp-Session-Id", sid)
	}
	upReq.Header.Set("Authorization", "Bearer "+downstream)
	return g.client.Do(upReq)
}

// streamResponse proxies the upstream response, flushing per chunk for an SSE
// (text/event-stream) body so streamed MCP results reach the client promptly.
func streamResponse(w http.ResponseWriter, resp *http.Response) {
	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if flusher, ok := w.(http.Flusher); ok && mediaType == "text/event-stream" {
		buf := make([]byte, 4096)
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				flusher.Flush()
			}
			if rerr != nil {
				return
			}
		}
	}
	_, _ = io.Copy(w, resp.Body)
}

// filterToolsList rewrites a tools/list response to include only the tools this
// delegation may call (mapped to a scope AND authorized by the token), so the
// agent's tool discovery reflects exactly what it was delegated. It returns
// ok=false (FAIL CLOSED) when the body is not a parseable JSON-RPC object, so a
// streamed/garbled/truncated response can never leak the upstream's full catalog.
// A valid response that simply carries no tools array (e.g. a JSON-RPC error) is
// passed through unchanged — there are no tools to leak.
func filterToolsList(body []byte, up *Upstream, claims *delegation.DelegationClaims) ([]byte, bool) {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, false
	}
	resultRaw, ok := env["result"]
	if !ok {
		return body, true
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(resultRaw, &result); err != nil {
		return nil, false
	}
	toolsRaw, ok := result["tools"]
	if !ok {
		return body, true
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(toolsRaw, &tools); err != nil {
		return nil, false
	}
	kept := make([]json.RawMessage, 0, len(tools))
	for _, t := range tools {
		var meta struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(t, &meta); err != nil {
			continue
		}
		scope, ok := up.ToolScopes[meta.Name]
		if !ok {
			continue
		}
		if err := claims.Authorize(delegation.Action{Scope: scope, Tool: meta.Name}); err != nil {
			continue
		}
		kept = append(kept, t)
	}
	newTools, err := json.Marshal(kept)
	if err != nil {
		return nil, false
	}
	result["tools"] = newTools
	newResult, err := json.Marshal(result)
	if err != nil {
		return nil, false
	}
	env["result"] = newResult
	out, err := json.Marshal(env)
	if err != nil {
		return nil, false
	}
	return out, true
}

// discoveryConstraints copies the inbound constraints for a non-tool-call
// downstream token, dropping only the Resources list (the audience already binds
// the resource).
func discoveryConstraints(c *delegation.Constraints) *delegation.Constraints {
	if c == nil {
		return nil
	}
	out := *c
	out.Resources = nil
	return &out
}

var hopByHop = map[string]bool{
	"connection": true, "proxy-connection": true, "keep-alive": true,
	"transfer-encoding": true, "te": true, "trailer": true, "upgrade": true,
	"content-length": true,
}

func copyResponseHeaders(dst, src http.Header) {
	for k, vs := range src {
		if hopByHop[strings.ToLower(k)] {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// downstreamConstraints tightens the inbound constraints for the downstream
// token: the tool allow-list collapses to exactly the called tool, and the
// Resources list is dropped (the downstream audience already binds the resource,
// and forwarding it would leak the other audiences the user delegated).
func downstreamConstraints(c *delegation.Constraints, tool string) *delegation.Constraints {
	if c == nil {
		return nil
	}
	out := *c
	out.Tools = []string{tool}
	out.Resources = nil
	return &out
}

func (g *Gateway) metadataURL(r *http.Request, slug string) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host + "/mcp/" + slug + "/.well-known/oauth-protected-resource"
}

func (g *Gateway) audit(ctx context.Context, claims *delegation.DelegationClaims, slug, tool string, status int) {
	if _, err := g.pool.Exec(ctx,
		`INSERT INTO audit_events
		   (actor_type, action, resource_type, resource_id, on_behalf_of_sub, actor_chain, grant_jti, metadata, org_id)
		 VALUES ('agent', 'mcp.tool.call', 'tool', $1, $2, $3, $4, $5,
		         (SELECT dc.org_id FROM exchanged_tokens et
		            JOIN delegation_chains dc ON dc.id = et.delegation_id
		          WHERE et.jti = $4))`,
		slug+"/"+tool, claims.Subject, claims.ActorChain(), claims.ID,
		[]byte(fmt.Sprintf(`{"upstream_status":%d}`, status)),
	); err != nil {
		slog.Error("gateway audit write failed", "error", err, "jti", claims.ID)
	}
}

// errDuplicateKey signals that a JSON object contained a repeated key.
var errDuplicateKey = errors.New("duplicate json key")

// hasDuplicateKeys reports whether the JSON document contains an object with a
// repeated key at any depth. Malformed JSON is not treated as a duplicate (the
// caller's Unmarshal reports the parse error instead).
func hasDuplicateKeys(data []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	return scanDuplicateKeys(dec) == errDuplicateKey
}

func scanDuplicateKeys(dec *json.Decoder) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil // scalar value
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			name, _ := key.(string)
			if seen[name] {
				return errDuplicateKey
			}
			seen[name] = true
			if err := scanDuplicateKeys(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token() // closing '}'
		return err
	case '[':
		for dec.More() {
			if err := scanDuplicateKeys(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token() // closing ']'
		return err
	}
	return nil
}

func bearer(r *http.Request) string {
	const p = "Bearer "
	a := r.Header.Get("Authorization")
	if len(a) > len(p) && a[:len(p)] == p {
		return a[len(p):]
	}
	return ""
}
