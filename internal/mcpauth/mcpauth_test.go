package mcpauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCanonicalizeResource(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{"https://API.Example.com", "https://api.example.com/", false}, // empty path → "/"
		{"https://api.example.com/", "https://api.example.com/", false},
		{"https://api.example.com:443/path", "https://api.example.com/path", false},
		{"https://api.example.com/a?b=c", "https://api.example.com/a?b=c", false},
		{"http://localhost:8080/mcp", "http://localhost:8080/mcp", false},
		{"https://api.example.com/a#frag", "", true},    // fragment rejected
		{"https://user:pw@api.example.com/x", "", true}, // userinfo rejected
		{"http://api.example.com", "", true},            // non-loopback http rejected
		{"/relative/path", "", true},                    // not absolute
		{"not a url at all", "", true},
		{"", "", true},
	}
	for _, c := range cases {
		got, err := CanonicalizeResource(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q: expected error, got %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%q: got %q, want %q", c.in, got, c.want)
		}
	}
}

func TestResourceMatches(t *testing.T) {
	if !ResourceMatches("https://API.example.com:443", "https://api.example.com") {
		t.Fatal("semantically-equal resources must match after canonicalization")
	}
	if ResourceMatches("https://a.example", "https://b.example") {
		t.Fatal("different hosts must not match")
	}
	if ResourceMatches("not-a-url", "https://a.example") {
		t.Fatal("an invalid requested resource must never match")
	}
}

func TestProtectedResourceMetadata(t *testing.T) {
	rec := httptest.NewRecorder()
	ProtectedResourceMetadataHandler("https://rs.example", "https://issuer.example")(
		rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil))

	var doc ProtectedResourceMetadata
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Resource != "https://rs.example" {
		t.Fatalf("resource = %q", doc.Resource)
	}
	if len(doc.AuthorizationServers) != 1 || doc.AuthorizationServers[0] != "https://issuer.example" {
		t.Fatalf("authorization_servers = %v", doc.AuthorizationServers)
	}
	if len(doc.BearerMethodsSupported) != 1 || doc.BearerMethodsSupported[0] != "header" {
		t.Fatalf("tokens must be header-only, got %v", doc.BearerMethodsSupported)
	}
}

func TestChallenge(t *testing.T) {
	rec := httptest.NewRecorder()
	Challenge(rec, http.StatusUnauthorized, "https://rs/.well-known/oauth-protected-resource", "", "")
	h := rec.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(h, "Bearer ") || !strings.Contains(h, "resource_metadata=") {
		t.Fatalf("bare challenge malformed: %q", h)
	}
	if strings.Contains(h, "error=") {
		t.Fatalf("a no-credentials challenge must not include error: %q", h)
	}

	rec2 := httptest.NewRecorder()
	Challenge(rec2, http.StatusUnauthorized, "", "invalid_token", "the token expired")
	h2 := rec2.Header().Get("WWW-Authenticate")
	if !strings.Contains(h2, `error="invalid_token"`) || !strings.Contains(h2, `error_description="the token expired"`) {
		t.Fatalf("error challenge malformed: %q", h2)
	}
}
