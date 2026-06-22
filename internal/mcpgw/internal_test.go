package mcpgw

import (
	"strings"
	"testing"

	"github.com/legant-dev/legant/internal/delegation"
)

func TestHasDuplicateKeys(t *testing.T) {
	cases := []struct {
		name, body string
		want       bool
	}{
		{"no duplicates", `{"a":1,"b":2}`, false},
		{"top-level dup", `{"a":1,"a":2}`, true},
		{"nested dup in params", `{"method":"tools/call","params":{"name":"x","name":"y"}}`, true},
		{"dup inside array element", `{"items":[{"a":1,"a":2}]}`, true},
		{"array, no dup", `[{"a":1},{"a":2}]`, false},
		{"malformed is not a duplicate", `{not json`, false},
	}
	for _, c := range cases {
		if got := hasDuplicateKeys([]byte(c.body)); got != c.want {
			t.Errorf("%s: hasDuplicateKeys=%v, want %v", c.name, got, c.want)
		}
	}
}

func TestIsPassthrough(t *testing.T) {
	for _, m := range []string{"initialize", "ping", "prompts/list", "resources/list", "resources/templates/list", "notifications/initialized"} {
		if !isPassthrough(m) {
			t.Errorf("%q should be a passthrough method", m)
		}
	}
	// Data-accessing methods must NOT be passthrough (they default-deny).
	for _, m := range []string{"tools/call", "resources/read", "prompts/get", "resources/subscribe", "admin/delete"} {
		if isPassthrough(m) {
			t.Errorf("%q must not be passthrough (default-deny)", m)
		}
	}
}

func TestFilterToolsList(t *testing.T) {
	up := &Upstream{ToolScopes: map[string]string{"get_weather": "weather:read"}}
	claims := &delegation.DelegationClaims{
		Scope:       "weather:read",
		Constraints: &delegation.Constraints{Tools: []string{"get_weather"}},
	}

	// Filters the catalog down to exactly the delegated tool.
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_weather"},{"name":"delete_all_data"},{"name":"admin_secret"}]}}`)
	out, ok := filterToolsList(body, up, claims)
	if !ok {
		t.Fatal("a valid tools/list must parse (ok=true)")
	}
	s := string(out)
	if !strings.Contains(s, "get_weather") {
		t.Errorf("delegated tool must remain: %s", s)
	}
	if strings.Contains(s, "delete_all_data") || strings.Contains(s, "admin_secret") {
		t.Errorf("un-delegated tools must be filtered out: %s", s)
	}

	// FAIL CLOSED: an SSE-framed / non-JSON body must not pass through verbatim.
	if _, ok := filterToolsList([]byte("event: message\ndata: {\"result\":{\"tools\":[{\"name\":\"admin_secret\"}]}}\n\n"), up, claims); ok {
		t.Error("a non-JSON tools/list must fail closed (ok=false), never leak the catalog")
	}

	// A JSON-RPC error envelope carries no tools, so it passes through unchanged.
	errEnv := []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
	if _, ok := filterToolsList(errEnv, up, claims); !ok {
		t.Error("an error envelope (no tools) should pass through (ok=true)")
	}
}
