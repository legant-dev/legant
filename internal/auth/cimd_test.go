package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/legant-dev/legant/internal/auth"
)

func TestCIMDResolve(t *testing.T) {
	docClientID := ""
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":     docClientID,
			"client_name":   "My MCP Client",
			"redirect_uris": []string{"https://app.example.com/cb"},
		})
	}))
	defer srv.Close()

	// srv.Client() trusts the test certificate; SSRF hardening is exercised in the
	// safehttp package's own tests.
	resolver := auth.NewCIMDResolver(srv.Client())
	ctx := context.Background()

	// Valid: the document self-identifies with the URL it was fetched from.
	docClientID = srv.URL
	c, err := resolver.Resolve(ctx, srv.URL)
	if err != nil {
		t.Fatalf("valid CIMD should resolve: %v", err)
	}
	if !c.IsPublic() {
		t.Fatal("CIMD clients must be public (no secret)")
	}
	if c.GetID() != srv.URL {
		t.Fatalf("client id = %q, want %q", c.GetID(), srv.URL)
	}
	if len(c.GetRedirectURIs()) != 1 || c.GetRedirectURIs()[0] != "https://app.example.com/cb" {
		t.Fatalf("redirect URIs not carried through: %v", c.GetRedirectURIs())
	}

	// Mismatch: the document claims a different client_id than its URL → reject.
	docClientID = "https://attacker.example/impersonate"
	if _, err := resolver.Resolve(ctx, srv.URL); err == nil {
		t.Fatal("a document whose client_id != its URL must be rejected")
	}

	// A non-URL client id is not CIMD.
	if auth.IsCIMD("regular-client-id") {
		t.Fatal("a plain client id must not be treated as CIMD")
	}
	if _, err := resolver.Resolve(ctx, "regular-client-id"); err == nil {
		t.Fatal("resolving a non-CIMD id must error")
	}
}
