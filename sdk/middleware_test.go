package sdk_test

import (
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/legant-dev/legant/sdk"
)

func mwVerifier(t *testing.T) (*sdk.Verifier, string) {
	t.Helper()
	tok, pub := mintToken(t)
	return sdk.NewVerifier(testIssuer, testAud, map[string]*rsa.PublicKey{testKID: pub}), tok
}

func TestAuthenticateMiddleware(t *testing.T) {
	v, tok := mwVerifier(t)
	var sawSubject string
	h := sdk.Authenticate(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := sdk.MustClaims(r.Context())
		sawSubject = c.Subject
		w.WriteHeader(http.StatusOK)
	}))

	// No token → 401.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: code=%d want 401", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), "Bearer") {
		t.Errorf("missing Bearer challenge: %q", rec.Header().Get("WWW-Authenticate"))
	}

	// Garbage token → 401.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: code=%d want 401", rec.Code)
	}

	// Valid token → 200, claims in context.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid token: code=%d want 200", rec.Code)
	}
	if sawSubject != "user:alice" {
		t.Errorf("subject in context = %q, want user:alice", sawSubject)
	}
}

func TestRequireActionMiddleware(t *testing.T) {
	v, tok := mwVerifier(t)
	// The token allows category travel/meals, MaxAmount 500, resource testAud.
	protected := func(action func(*http.Request) sdk.Action) http.Handler {
		return sdk.Authenticate(v)(sdk.RequireAction(action)(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })))
	}

	cases := []struct {
		name   string
		action sdk.Action
		want   int
	}{
		{"in-scope in-budget", sdk.Action{Scope: "expenses:submit", Amount: 100, Category: "travel", Resource: testAud}, 200},
		{"over budget", sdk.Action{Scope: "expenses:submit", Amount: 9000, Resource: testAud}, 403},
		{"wrong category", sdk.Action{Scope: "expenses:submit", Category: "gambling", Resource: testAud}, 403},
		{"missing scope", sdk.Action{Scope: "expenses:delete", Resource: testAud}, 403},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			act := c.action
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			protected(func(*http.Request) sdk.Action { return act }).ServeHTTP(rec, req)
			if rec.Code != c.want {
				t.Fatalf("%s: code=%d want %d", c.name, rec.Code, c.want)
			}
		})
	}
}

func TestMCPToolName(t *testing.T) {
	name, err := sdk.MCPToolName([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"kubectl_scale","arguments":{}}}`))
	if err != nil || name != "kubectl_scale" {
		t.Fatalf("got (%q, %v), want (kubectl_scale, nil)", name, err)
	}
	if _, err := sdk.MCPToolName([]byte(`{"method":"tools/list"}`)); err == nil {
		t.Fatal("expected error for non-tools/call")
	}
}
