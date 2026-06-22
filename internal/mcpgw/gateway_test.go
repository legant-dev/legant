package mcpgw_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/legant-dev/legant/internal/db"
	"github.com/legant-dev/legant/internal/delegation"
	"github.com/legant-dev/legant/internal/keystore"
	"github.com/legant-dev/legant/internal/mcpgw"
	"github.com/legant-dev/legant/internal/revocation"
	"github.com/legant-dev/legant/internal/testsupport"
)

const (
	gwIssuer     = "https://legant.test"
	gwResourceID = "https://gateway.legant.test/mcp/weather"
	upResourceID = "https://weather-mcp.example/"
)

func TestGatewayEndToEnd(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	ks, err := keystore.Open(ctx, pool, bytes.Repeat([]byte("k"), 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rev := revocation.NewStore(pool, nil)

	// Mock upstream MCP server: it independently verifies the DOWNSTREAM token it
	// receives (against its OWN resource id) — proving the gateway minted a fresh,
	// audience-rebound token rather than forwarding the inbound one.
	var downstreamScope, provenance string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		claims, err := delegation.NewVerifier(gwIssuer, ks.VerifierKeys()).Verify(tok, upResourceID)
		if err != nil {
			http.Error(w, "bad downstream token", http.StatusUnauthorized)
			return
		}
		downstreamScope = claims.Scope
		provenance = claims.Provenance()
		_, _ = w.Write([]byte(`{"result":"sunny"}`))
	}))
	defer upstream.Close()

	// A second upstream with the SAME tool and scope, but a distinct inbound
	// audience — used to prove cross-upstream isolation.
	const gw2Audience = "https://gateway.legant.test/mcp/weather2"
	gw, err := mcpgw.NewGateway(gwIssuer, ks, rev, pool, nil, []*mcpgw.Upstream{
		{Slug: "weather", InboundAudience: gwResourceID, URL: upstream.URL, ResourceID: upResourceID,
			ToolScopes: map[string]string{"get_weather": "weather:read"}},
		{Slug: "weather2", InboundAudience: gw2Audience, URL: upstream.URL, ResourceID: upResourceID,
			ToolScopes: map[string]string{"get_weather": "weather:read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Mount("/mcp", gw.Routes())

	mint := func(scopes, tools []string, aud string) (token, jti string) {
		now := time.Now()
		signer := delegation.NewSigner(gwIssuer, ks.ActiveKID(), ks.ActiveSigner())
		c := &delegation.Constraints{Tools: tools}
		tok, err := signer.IssueClaims("user:U", &delegation.ActClaim{Sub: "agent:A"}, scopes, aud, c, now.Add(time.Hour), now)
		if err != nil {
			t.Fatal(err)
		}
		claims, err := delegation.NewVerifier(gwIssuer, ks.VerifierKeys()).Verify(tok, aud)
		if err != nil {
			t.Fatal(err)
		}
		_ = db.WithTx(ctx, pool, func(tx pgx.Tx) error {
			return rev.RecordTx(ctx, tx, revocation.Record{
				JTI: claims.ID, Subject: claims.Subject, ActorChain: claims.ActorChain(),
				Audience: aud, Scopes: scopes, ExpiresAt: now.Add(time.Hour),
			})
		})
		return tok, claims.ID
	}

	call := func(token, tool string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"method": "tools/call", "params": map[string]any{"name": tool}})
		req := httptest.NewRequest(http.MethodPost, "/mcp/weather", bytes.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	// An org'd delegation behind the inbound token, so the tool-call audit can be
	// tenant-stamped (the gateway resolves org via the inbound jti's delegation).
	var orgID, delegatorID, delegateeAgentID, delegationID string
	if err := pool.QueryRow(ctx, `INSERT INTO orgs (slug,name) VALUES ('gw-acme','Acme') RETURNING id::text`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO users (email,status) VALUES ('gw@x.com','active') RETURNING id::text`).Scan(&delegatorID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO agents (name,type,org_id) VALUES ('gw-a','ai_agent',$1) RETURNING id::text`, orgID).Scan(&delegateeAgentID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO delegation_chains (delegator_type,delegator_id,delegatee_agent_id,scopes,org_id) VALUES ('user',$1,$2,'{weather:read}',$3) RETURNING id::text`,
		delegatorID, delegateeAgentID, orgID).Scan(&delegationID); err != nil {
		t.Fatal(err)
	}

	// Happy path: a token scoped to weather:read can call get_weather, the upstream
	// receives a narrowed downstream token, and provenance is preserved.
	tok, jti := mint([]string{"weather:read"}, []string{"get_weather"}, gwResourceID)
	if _, err := pool.Exec(ctx, `UPDATE exchanged_tokens SET delegation_id=$1 WHERE jti=$2`, delegationID, jti); err != nil {
		t.Fatal(err)
	}
	rec := call(tok, "get_weather")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d %s", rec.Code, rec.Body.String())
	}
	// The tool call is audited and tenant-stamped with the inbound delegation's org.
	var auditOrg *string
	if err := pool.QueryRow(ctx,
		`SELECT org_id::text FROM audit_events WHERE action='mcp.tool.call' ORDER BY id DESC LIMIT 1`).Scan(&auditOrg); err != nil {
		t.Fatalf("gateway tool call must write an audit row: %v", err)
	}
	if auditOrg == nil || *auditOrg != orgID {
		t.Fatalf("gateway audit org_id should be %s, got %v", orgID, auditOrg)
	}
	if !strings.Contains(rec.Body.String(), "sunny") {
		t.Fatalf("upstream result not proxied: %s", rec.Body.String())
	}
	if downstreamScope != "weather:read" {
		t.Fatalf("downstream token scope = %q, want weather:read", downstreamScope)
	}
	if provenance != "user:U -> agent:A" {
		t.Fatalf("provenance not preserved downstream: %q", provenance)
	}

	// Cross-upstream isolation: a token bound to the "weather" slug's audience must
	// NOT be accepted by "weather2", even though they share the same tool + scope.
	{
		body, _ := json.Marshal(map[string]any{"method": "tools/call", "params": map[string]any{"name": "get_weather"}})
		req := httptest.NewRequest(http.MethodPost, "/mcp/weather2", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("a token for one upstream must not be accepted by another; want 401, got %d", rec.Code)
		}
	}

	// Unknown tool → default-deny 403.
	if rec := call(tok, "delete_everything"); rec.Code != http.StatusForbidden {
		t.Fatalf("unknown tool must be 403, got %d", rec.Code)
	}
	// A token lacking the tool's scope → 403.
	tokNoScope, _ := mint([]string{"other:read"}, []string{"get_weather"}, gwResourceID)
	if rec := call(tokNoScope, "get_weather"); rec.Code != http.StatusForbidden {
		t.Fatalf("missing scope must be 403, got %d", rec.Code)
	}
	// A token bound to a different audience → 401 (not for this gateway).
	tokWrongAud, _ := mint([]string{"weather:read"}, []string{"get_weather"}, "https://other.example/")
	if rec := call(tokWrongAud, "get_weather"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong audience must be 401, got %d", rec.Code)
	}
	// No token → 401 with a challenge.
	if rec := call("", "get_weather"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token must be 401, got %d", rec.Code)
	}
	// Revoking the inbound token → 401.
	if _, err := rev.Revoke(ctx, jti); err != nil {
		t.Fatal(err)
	}
	if rec := call(tok, "get_weather"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token must be 401, got %d", rec.Code)
	}
}

func TestGatewayMCPMethods(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	ks, err := keystore.Open(ctx, pool, bytes.Repeat([]byte("k"), 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rev := revocation.NewStore(pool, nil)

	// Upstream MCP server: answers the handshake/discovery methods and streams SSE
	// for a tool call when the client accepts it. It independently verifies the
	// DOWNSTREAM token it receives (confused-deputy: a fresh token bound to its own
	// resource id), and records provenance + the tools/list Accept header.
	var sawProvenance, sawListAccept string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var rpc struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &rpc)
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		dc, verr := delegation.NewVerifier(gwIssuer, ks.VerifierKeys()).Verify(tok, upResourceID)
		if verr != nil {
			http.Error(w, "bad downstream token", http.StatusUnauthorized)
			return
		}
		sawProvenance = dc.Provenance()
		if rpc.Method == "tools/list" {
			sawListAccept = r.Header.Get("Accept")
		}
		switch rpc.Method {
		case "initialize":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{}}}`))
		case "ping":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{}}`))
		case "tools/list":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"get_weather"},{"name":"delete_all_data"},{"name":"admin_secret"}]}}`))
		case "tools/call":
			if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte("data: {\"chunk\":1}\n\n"))
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				_, _ = w.Write([]byte("data: {\"chunk\":2}\n\n"))
				return
			}
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":4,"result":{"content":"sunny"}}`))
		default:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":9,"result":{}}`))
		}
	}))
	defer upstream.Close()

	gw, err := mcpgw.NewGateway(gwIssuer, ks, rev, pool, nil, []*mcpgw.Upstream{
		{Slug: "weather", InboundAudience: gwResourceID, URL: upstream.URL, ResourceID: upResourceID,
			ToolScopes: map[string]string{"get_weather": "weather:read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Mount("/mcp", gw.Routes())

	now := time.Now()
	signer := delegation.NewSigner(gwIssuer, ks.ActiveKID(), ks.ActiveSigner())
	tok, err := signer.IssueClaims("user:U", &delegation.ActClaim{Sub: "agent:A"}, []string{"weather:read"},
		gwResourceID, &delegation.Constraints{Tools: []string{"get_weather"}}, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := delegation.NewVerifier(gwIssuer, ks.VerifierKeys()).Verify(tok, gwResourceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.WithTx(ctx, pool, func(tx pgx.Tx) error {
		return rev.RecordTx(ctx, tx, revocation.Record{
			JTI: claims.ID, Subject: claims.Subject, ActorChain: claims.ActorChain(),
			Audience: gwResourceID, Scopes: []string{"weather:read"}, ExpiresAt: now.Add(time.Hour),
		})
	}); err != nil {
		t.Fatal(err)
	}

	call := func(method, accept string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method,
			"params": map[string]any{"name": "get_weather"}})
		req := httptest.NewRequest(http.MethodPost, "/mcp/weather", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	// Handshake + keepalive pass through (verified, no per-tool authz).
	if rec := call("initialize", ""); rec.Code != http.StatusOK {
		t.Fatalf("initialize should pass through, got %d %s", rec.Code, rec.Body.String())
	}
	if rec := call("ping", ""); rec.Code != http.StatusOK {
		t.Fatalf("ping should pass through, got %d", rec.Code)
	}

	// tools/list is FILTERED to only the delegated tool — the agent never even sees
	// the tools it cannot call.
	rec := call("tools/list", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("tools/list should pass, got %d", rec.Code)
	}
	out := rec.Body.String()
	if !strings.Contains(out, "get_weather") {
		t.Errorf("tools/list must keep the delegated tool: %s", out)
	}
	if strings.Contains(out, "delete_all_data") || strings.Contains(out, "admin_secret") {
		t.Errorf("tools/list must hide un-delegated tools, got: %s", out)
	}
	// The gateway must force a non-streaming JSON tools/list so it can be filtered.
	if sawListAccept != "application/json" {
		t.Errorf("tools/list upstream Accept = %q, want application/json", sawListAccept)
	}
	// The upstream verified a FRESH downstream token bound to itself, preserving
	// provenance (confused-deputy protection on non-tool-call methods too).
	if sawProvenance != "user:U -> agent:A" {
		t.Errorf("downstream provenance = %q, want user:U -> agent:A", sawProvenance)
	}

	// An unmodeled method is default-denied.
	if rec := call("resources/read", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("unmodeled method must be 403, got %d", rec.Code)
	}

	// SSE: a streaming tool response is proxied with its event-stream content type.
	sse := call("tools/call", "text/event-stream")
	if sse.Code != http.StatusOK {
		t.Fatalf("streaming tools/call should be 200, got %d", sse.Code)
	}
	if ct := sse.Header().Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Errorf("SSE content-type must be preserved, got %q", ct)
	}
	if !strings.Contains(sse.Body.String(), "chunk") {
		t.Errorf("SSE body must stream through, got %q", sse.Body.String())
	}
}

func TestGatewayToolsListFailsClosed(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	ks, err := keystore.Open(ctx, pool, bytes.Repeat([]byte("k"), 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rev := revocation.NewStore(pool, nil)

	// A non-compliant (or hostile) upstream that frames tools/list as SSE, ignoring
	// the gateway's application/json Accept. The full, unfiltered catalog must NEVER
	// reach the agent.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"tools\":[{\"name\":\"get_weather\"},{\"name\":\"admin_secret\"}]}}\n\n"))
	}))
	defer upstream.Close()

	gw, err := mcpgw.NewGateway(gwIssuer, ks, rev, pool, nil, []*mcpgw.Upstream{
		{Slug: "weather", InboundAudience: gwResourceID, URL: upstream.URL, ResourceID: upResourceID,
			ToolScopes: map[string]string{"get_weather": "weather:read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Mount("/mcp", gw.Routes())

	now := time.Now()
	signer := delegation.NewSigner(gwIssuer, ks.ActiveKID(), ks.ActiveSigner())
	tok, _ := signer.IssueClaims("user:U", &delegation.ActClaim{Sub: "agent:A"}, []string{"weather:read"},
		gwResourceID, &delegation.Constraints{Tools: []string{"get_weather"}}, now.Add(time.Hour), now)
	claims, _ := delegation.NewVerifier(gwIssuer, ks.VerifierKeys()).Verify(tok, gwResourceID)
	if err := db.WithTx(ctx, pool, func(tx pgx.Tx) error {
		return rev.RecordTx(ctx, tx, revocation.Record{JTI: claims.ID, Subject: claims.Subject,
			ActorChain: claims.ActorChain(), Audience: gwResourceID, Scopes: []string{"weather:read"}, ExpiresAt: now.Add(time.Hour)})
	}); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
	req := httptest.NewRequest(http.MethodPost, "/mcp/weather", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// Fail closed: a 5xx, and crucially the leaked tool name must NOT appear.
	if rec.Code < 500 {
		t.Errorf("an unfilterable tools/list must fail closed (5xx), got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "admin_secret") {
		t.Errorf("un-delegated tool leaked through an SSE-framed tools/list: %s", rec.Body.String())
	}
}

func TestGatewayHardening(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	ks, err := keystore.Open(ctx, pool, bytes.Repeat([]byte("k"), 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rev := revocation.NewStore(pool, nil)

	reached := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	defer upstream.Close()

	gw, err := mcpgw.NewGateway(gwIssuer, ks, rev, pool, nil, []*mcpgw.Upstream{
		{Slug: "weather", InboundAudience: gwResourceID, URL: upstream.URL, ResourceID: upResourceID,
			ToolScopes: map[string]string{"get_weather": "weather:read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Mount("/mcp", gw.Routes())

	now := time.Now()
	signer := delegation.NewSigner(gwIssuer, ks.ActiveKID(), ks.ActiveSigner())
	tok, err := signer.IssueClaims("user:U", &delegation.ActClaim{Sub: "agent:A"}, []string{"weather:read"},
		gwResourceID, &delegation.Constraints{Tools: []string{"get_weather"}}, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := delegation.NewVerifier(gwIssuer, ks.VerifierKeys()).Verify(tok, gwResourceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.WithTx(ctx, pool, func(tx pgx.Tx) error {
		return rev.RecordTx(ctx, tx, revocation.Record{
			JTI: claims.ID, Subject: claims.Subject, ActorChain: claims.ActorChain(),
			Audience: gwResourceID, Scopes: []string{"weather:read"}, ExpiresAt: now.Add(time.Hour),
		})
	}); err != nil {
		t.Fatal(err)
	}

	post := func(rawBody string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/mcp/weather", strings.NewReader(rawBody))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	// A duplicate `name` inside params must be rejected (400) before the upstream
	// is reached — otherwise the upstream's parser could pick the OTHER tool than
	// the one the gateway authorized (parser-differential confused deputy).
	if rec := post(`{"method":"tools/call","params":{"name":"get_weather","name":"delete_everything"}}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate key must be 400, got %d %s", rec.Code, rec.Body.String())
	}
	if reached {
		t.Fatal("upstream was reached despite a duplicate-key request")
	}

	// Fail closed when the revocation store errors: dropping the table makes
	// IsActive() return an error, and the request must be denied (401), never
	// allowed through.
	if _, err := pool.Exec(ctx, `DROP TABLE exchanged_tokens`); err != nil {
		t.Fatal(err)
	}
	if rec := post(`{"method":"tools/call","params":{"name":"get_weather"}}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revocation-store error must fail closed with 401, got %d", rec.Code)
	}
	if reached {
		t.Fatal("upstream was reached despite a revocation-store error")
	}
}
