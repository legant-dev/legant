package main

import (
	"bufio"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/legant-dev/legant/internal/ccguard"
	"github.com/legant-dev/legant/sdk"
)

// The proxy is a Legant resource server that guards a REAL kubernetes MCP server.
// It spawns mcp-server-kubernetes as a PRIVATE child over stdio (the agent can
// never reach it directly), and exposes a small HTTP surface the agent must call
// with a Legant delegation token. Every call is verified and authorized OFFLINE
// with the public SDK — the same verify+authorize the gateway and every Legant
// resource server use. This is the offline-verify pattern from the middleware kit,
// applied in front of a real tool server.

// toolScope maps each kubernetes MCP tool to the capability scope it needs.
// Tools NOT in this map are unknown to the guard and are refused outright.
var toolScope = map[string]string{
	"kubectl_get":     "cluster:read",
	"kubectl_logs":    "logs:read",
	"kubectl_scale":   "deploy:scale",
	"kubectl_rollout": "deploy:restart",
	// Destructive / flag-injectable tools are intentionally mapped to scopes the
	// incident grant never holds, so they are both filtered from tools/list and
	// refused if called by name (cf. CVE-2026-47250's kubectl_generic surface).
	"kubectl_delete":  "deploy:delete",
	"kubectl_generic": "cluster:admin",
	"exec_in_pod":     "pod:exec",
	"kubectl_patch":   "deploy:patch",
	"kubectl_apply":   "deploy:apply",
}

// mutating tools are subject to the change-freeze; reads always pass.
var mutating = map[string]bool{
	"kubectl_scale": true, "kubectl_rollout": true, "kubectl_delete": true,
	"kubectl_generic": true, "exec_in_pod": true, "kubectl_patch": true, "kubectl_apply": true,
}

type proxy struct {
	verifier *sdk.Verifier
	dir      string // .legant dir (for the live revocation feed file)
	issuer   string
	keys     map[string]*rsa.PublicKey
	mcp      *mcpStdio
	frozen   atomic.Bool
}

func runProxy(args []string) {
	fs := newFlagSet("proxy")
	addr := fs.String("addr", "127.0.0.1:7070", "listen address")
	dir := fs.String("dir", ".legant", "Legant offline setup dir (JWKS + feed)")
	issuer := fs.String("issuer", ccguard.DefaultIssuer, "token issuer")
	audience := fs.String("audience", "k8s-mcp://prod-cluster", "this resource server's audience")
	mcpCmd := fs.String("mcp", "npx -y mcp-server-kubernetes@3.9.2", "command that starts the kubernetes MCP server (stdio)")
	_ = fs.Parse(args)

	jb, err := os.ReadFile(filepath.Join(*dir, "jwks.json"))
	must(err)
	keys, err := sdk.ParseJWKS(jb)
	must(err)

	ctx := context.Background()
	mcp, err := startMCP(ctx, *mcpCmd)
	must(err)
	defer mcp.close()

	p := &proxy{
		verifier: sdk.NewVerifier(*issuer, *audience, keys),
		dir:      *dir, issuer: *issuer, keys: keys, mcp: mcp,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/tools/list", p.handleList)
	mux.HandleFunc("/tools/call", p.handleCall)
	mux.HandleFunc("/admin/freeze", p.handleFreeze) // demo control: declare/lift a change freeze
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })

	fmt.Printf("legant-guarded k8s MCP proxy listening on %s (guarding a real mcp-server-kubernetes)\n", *addr)
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	must(srv.ListenAndServe())
}

// authorize verifies the bearer token, checks the live revocation feed, and
// authorizes the action. It returns the claims on success or an (httpStatus,
// reason) on failure.
func (p *proxy) authorize(r *http.Request, action sdk.Action) (*sdk.Claims, int, string) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims, err := p.verifier.Verify(tok)
	if err != nil {
		return nil, http.StatusUnauthorized, err.Error()
	}
	// Tier-B revocation: re-read the signed feed file each call so a `legant revoke`
	// mid-incident takes effect immediately, offline.
	if feed, err := ccguard.LoadSignedFeedFile(filepath.Join(p.dir, "feed.jwt"), p.issuer, p.keys); err == nil {
		if claims.ID != "" && feed.IsRevoked(claims.ID) {
			return nil, http.StatusUnauthorized, "token revoked"
		}
	}
	if action.Scope != "" {
		if err := claims.Authorize(action); err != nil {
			return nil, http.StatusForbidden, err.Error()
		}
	}
	return claims, 0, ""
}

func (p *proxy) handleList(w http.ResponseWriter, r *http.Request) {
	// Verify the token (no specific action) to identify the delegation.
	claims, status, reason := p.authorize(r, sdk.Action{})
	if claims == nil {
		http.Error(w, reason, status)
		return
	}
	all, err := p.mcp.listToolDefs()
	if err != nil {
		http.Error(w, "upstream tools/list failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	// Filter to the tools this delegation may actually call, returning the FULL tool
	// definitions (name + description + inputSchema) so a live LLM driver gets real
	// schemas; the deterministic driver just reads the names.
	kept := make([]json.RawMessage, 0, len(all))
	for _, t := range all {
		scope, ok := toolScope[t.Name]
		if !ok {
			continue
		}
		if claims.Authorize(sdk.Action{Scope: scope, Tool: t.Name}) == nil {
			kept = append(kept, t.Raw)
		}
	}
	writeJSON(w, map[string]any{"tools": kept})
}

func (p *proxy) handleCall(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tool string         `json:"tool"`
		Args map[string]any `json:"args"`
	}
	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &req)

	scope, known := toolScope[req.Tool]
	if !known {
		http.Error(w, "denied: tool not permitted by this guard", http.StatusForbidden)
		return
	}
	ns, _ := req.Args["namespace"].(string)
	action := sdk.Action{
		Scope:    scope,
		Tool:     req.Tool,
		Resource: "k8s://" + ns,
		Amount:   asFloat(req.Args["replicas"]), // replica cap rides through MaxAmount
		At:       time.Now(),
	}
	claims, status, reason := p.authorize(r, action)
	if claims == nil {
		http.Error(w, "denied: "+reason, status)
		return
	}
	// Change-freeze: a cluster-wide deploy-window policy enforced here, so reads
	// keep working while writes are frozen.
	if p.frozen.Load() && mutating[req.Tool] {
		http.Error(w, "denied: deploy change-freeze in effect", http.StatusForbidden)
		return
	}
	result, err := p.mcp.callTool(req.Tool, req.Args)
	if err != nil {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "by": claims.Provenance(), "result": result})
}

func (p *proxy) handleFreeze(w http.ResponseWriter, r *http.Request) {
	on := r.URL.Query().Get("on") == "true"
	p.frozen.Store(on)
	writeJSON(w, map[string]any{"frozen": on})
}

// ---- a minimal MCP stdio client for the kubernetes MCP server ----------------

type mcpStdio struct {
	mu     sync.Mutex
	stdin  io.WriteCloser
	out    *bufio.Reader
	nextID int
	cmd    *exec.Cmd
}

func startMCP(ctx context.Context, command string) (*mcpStdio, error) {
	fields := strings.Fields(command)
	cmd := exec.CommandContext(ctx, fields[0], fields[1:]...)
	cmd.Env = os.Environ()
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	m := &mcpStdio{stdin: stdin, out: bufio.NewReaderSize(stdout, 1<<20), cmd: cmd}
	// MCP handshake.
	if _, err := m.rpc("initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "legant-proxy", "version": "0"},
	}); err != nil {
		return nil, fmt.Errorf("MCP initialize: %w", err)
	}
	if err := m.notify("notifications/initialized"); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *mcpStdio) close() {
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
	}
}

func (m *mcpStdio) notify(method string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.writeLine(map[string]any{"jsonrpc": "2.0", "method": method})
}

// rpc sends a request and reads stdout until the matching response arrives,
// skipping notifications/log lines. One request in flight at a time (mutex).
func (m *mcpStdio) rpc(method string, params any) (json.RawMessage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	id := m.nextID
	if err := m.writeLine(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
		return nil, err
	}
	for {
		line, err := m.out.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		line = []byte(strings.TrimSpace(string(line)))
		if len(line) == 0 {
			continue
		}
		var msg struct {
			ID     *int            `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if json.Unmarshal(line, &msg) != nil {
			continue // not a JSON-RPC line (log noise)
		}
		if msg.ID == nil || *msg.ID != id {
			continue // a notification or another id
		}
		if len(msg.Error) > 0 {
			return nil, fmt.Errorf("%s", string(msg.Error))
		}
		return msg.Result, nil
	}
}

func (m *mcpStdio) writeLine(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = m.stdin.Write(append(b, '\n'))
	return err
}

// toolDef is one MCP tool's full definition plus its name, for filtering.
type toolDef struct {
	Name string
	Raw  json.RawMessage
}

func (m *mcpStdio) listToolDefs() ([]toolDef, error) {
	res, err := m.rpc("tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	var r struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(res, &r); err != nil {
		return nil, err
	}
	defs := make([]toolDef, 0, len(r.Tools))
	for _, raw := range r.Tools {
		var meta struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(raw, &meta) != nil {
			continue
		}
		defs = append(defs, toolDef{Name: meta.Name, Raw: raw})
	}
	return defs, nil
}

func (m *mcpStdio) callTool(name string, args map[string]any) (string, error) {
	res, err := m.rpc("tools/call", map[string]any{"name": name, "arguments": args})
	if err != nil {
		return "", err
	}
	var r struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(res, &r); err != nil {
		return string(res), nil
	}
	var sb strings.Builder
	for _, c := range r.Content {
		sb.WriteString(c.Text)
	}
	return sb.String(), nil
}
