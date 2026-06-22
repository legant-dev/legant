// Command mcp-gateway is a runnable, self-contained demonstration of Legant's
// MCP auth-gateway: an AI agent calls an MCP server *through* Legant, which
// enforces per-tool delegation and mints a fresh, narrowly-scoped downstream
// token (confused-deputy protection) rather than forwarding the agent's token.
//
// No database, no Docker. Run it with:
//
//	go run ./examples/mcp-gateway
//
// It runs three roles in one process: the agent (holds a delegated token), the
// Legant gateway (verifies + authorizes per tool + re-mints downstream), and an
// upstream MCP "weather" server (independently verifies the downstream token).
//
// The production gateway (internal/mcpgw) adds DB-backed revocation and audit;
// this demo shows the core verify -> authorize -> re-mint -> proxy flow.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	legantcrypto "github.com/legant-dev/legant/internal/crypto"
	"github.com/legant-dev/legant/internal/delegation"
)

const (
	issuer      = "https://legant.local"
	gatewayAud  = "https://gateway.legant.local/mcp/weather" // inbound token audience
	upstreamAud = "https://weather-mcp.example/"             // downstream token audience
	keyID       = "demo-key-1"
)

func main() {
	key, err := legantcrypto.GenerateRSAKey(2048)
	must(err)
	signer := delegation.NewSigner(issuer, keyID, key)
	verifier := delegation.NewSingleKeyVerifier(issuer, keyID, &key.PublicKey)

	// ---- Upstream MCP server: trusts Legant's key, enforces aud + scope. ----
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		claims, err := verifier.Verify(tok, upstreamAud) // MUST be bound to THIS server
		if err != nil {
			http.Error(w, `{"error":"bad downstream token"}`, http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": "72°F and sunny",
			"_token_the_upstream_saw": map[string]any{
				"sub":   claims.Subject,
				"chain": claims.Provenance(),
				"scope": claims.Scope,
				"aud":   upstreamAud,
			},
		})
	}))
	defer upstream.Close()

	toolScopes := map[string]string{"get_weather": "weather:read"}

	// ---- Legant gateway: verify inbound -> authorize tool -> re-mint -> proxy. ----
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		claims, err := verifier.Verify(tok, gatewayAud) // inbound token bound to the gateway
		if err != nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var rpc struct {
			Method string `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &rpc)

		scope, ok := toolScopes[rpc.Params.Name]
		if rpc.Method != "tools/call" || !ok {
			http.Error(w, `{"error":"unknown or disallowed tool"}`, http.StatusForbidden)
			return
		}
		if err := claims.Authorize(delegation.Action{Scope: scope, Tool: rpc.Params.Name}); err != nil {
			http.Error(w, `{"error":"forbidden — not delegated this tool/scope"}`, http.StatusForbidden)
			return
		}

		// Confused-deputy protection: mint a FRESH token bound to the upstream,
		// narrowed to exactly this tool, preserving sub/act provenance. The inbound
		// token is never forwarded.
		now := time.Now()
		downstream, err := signer.IssueClaims(claims.Subject, claims.Act, []string{scope},
			upstreamAud, &delegation.Constraints{Tools: []string{rpc.Params.Name}}, now.Add(time.Minute), now)
		must(err)

		upReq, _ := http.NewRequest(http.MethodPost, upstream.URL, bytes.NewReader(body))
		upReq.Header.Set("Authorization", "Bearer "+downstream)
		upReq.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(upReq)
		if err != nil {
			http.Error(w, `{"error":"upstream unreachable"}`, http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer gateway.Close()

	// ---- The agent's delegated token: Alice delegated "weather:read" + the
	//      get_weather tool to her weather assistant, bound to the gateway. ----
	now := time.Now()
	grant := delegation.NewRootGrant("user:alice", "agent:weather-assistant",
		[]string{"weather:read"},
		delegation.Constraints{Tools: []string{"get_weather"}, Resources: []string{gatewayAud}},
		time.Hour, now)
	agentToken, err := signer.IssueForGrant(grant, []string{"weather:read"}, gatewayAud, now)
	must(err)

	banner("Legant MCP gateway demo — an agent calling an MCP server on a user's behalf")
	fmt.Println("  Legant gateway: ", gateway.URL, "  upstream MCP:", upstream.URL)
	fmt.Println("  Alice delegated to agent:weather-assistant → scope=weather:read, tool=get_weather, bound to the gateway")
	fmt.Println()

	section("1. Agent calls get_weather through the gateway  (expected: APPROVED)")
	callTool(gateway.URL, agentToken, "get_weather")

	section("2. Agent tries an un-delegated tool  (expected: DENIED — default-deny)")
	callTool(gateway.URL, agentToken, "delete_all_data")

	section("3. A forged/un-bound token  (expected: DENIED — wrong audience)")
	// A token bound to a different audience must not be accepted by the gateway.
	otherGrant := delegation.NewRootGrant("user:alice", "agent:weather-assistant", []string{"weather:read"},
		delegation.Constraints{Tools: []string{"get_weather"}, Resources: []string{"https://elsewhere/"}}, time.Hour, now)
	otherToken, _ := signer.IssueForGrant(otherGrant, []string{"weather:read"}, "https://elsewhere/", now)
	callTool(gateway.URL, otherToken, "get_weather")

	fmt.Println()
	banner("Done — the upstream never saw Alice's gateway token; the gateway minted a fresh, tool-scoped one")
	fmt.Println("  Note the `aud` and `chain` the upstream reports: a distinct downstream token,")
	fmt.Println("  bound to the upstream, that still proves it acts for user:alice via the assistant.")
}

func callTool(gatewayURL, token, tool string) {
	body, _ := json.Marshal(map[string]any{"method": "tools/call", "params": map[string]any{"name": tool}})
	req, _ := http.NewRequest(http.MethodPost, gatewayURL, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	must(err)
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)

	mark := "✅"
	if resp.StatusCode >= 400 {
		mark = "❌"
	}
	fmt.Printf("    %s tools/call %-18s -> %d\n", mark, tool, resp.StatusCode)
	var pretty bytes.Buffer
	if json.Indent(&pretty, out, "        ", "  ") == nil {
		fmt.Println("        " + strings.ReplaceAll(pretty.String(), "\n", "\n        "))
	} else {
		fmt.Println("        " + strings.TrimSpace(string(out)))
	}
}

func banner(s string) {
	line := strings.Repeat("=", 78)
	fmt.Println(line)
	fmt.Println("  " + s)
	fmt.Println(line)
}

func section(s string) {
	fmt.Println()
	fmt.Println("── " + s + " " + strings.Repeat("─", max(0, 74-len(s))))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
