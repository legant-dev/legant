// Command agent-obo is a runnable, self-contained demonstration of Legant's
// agent-identity wedge: an AI agent acting *on behalf of* a human user with
// scoped, constrained, auditable delegation — RFC 8693 style.
//
// It needs no database and no Docker. Run it with:
//
//	go run ./examples/agent-obo
//
// The program plays three roles in one process:
//
//   - Legant        — mints composite (sub/act) delegation tokens (the signer)
//   - The agent    — exchanges a delegation for a token and calls an API
//   - Finance API  — an independent resource server that holds ONLY Legant's
//     public key and enforces scope + constraints on every call
//
// Watch how authority can only ever narrow as it flows user -> agent -> sub-agent,
// and how the resource server can prove who is really behind each request.
package main

import (
	"bytes"
	"encoding/base64"
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
	issuer     = "https://legant.local"
	financeAud = "finance-api"
	keyID      = "demo-key-1"
)

func money(v float64) *float64 { return &v }

func main() {
	// ---- Legant: one signing key, shared as JWKS in the real server. ----
	key, err := legantcrypto.GenerateRSAKey(2048)
	must(err)
	signer := delegation.NewSigner(issuer, keyID, key)

	// ---- Finance API: a separate service that trusts Legant's public key. ----
	api := newFinanceAPI(delegation.NewSingleKeyVerifier(issuer, keyID, &key.PublicKey))
	srv := httptest.NewServer(api)
	defer srv.Close()

	now := time.Now()

	banner("Legant demo — an AI agent acting on behalf of a user")
	fmt.Println("  Legant issuer:   ", issuer)
	fmt.Println("  Finance API at: ", srv.URL, "(trusts only Legant's public key)")
	fmt.Println()

	// =====================================================================
	// 1. Alice delegates a narrow, constrained slice of her authority to her
	//    "Expense Assistant" agent.
	// =====================================================================
	section("1. Alice delegates to her Expense Assistant agent")
	aliceGrant := delegation.NewRootGrant(
		"user:alice", "agent:expense-assistant",
		[]string{"expenses:read", "expenses:submit"},
		delegation.Constraints{
			MaxAmount:  money(500),
			Categories: []string{"travel", "meals"},
			Resources:  []string{financeAud},
		},
		time.Hour, now,
	)
	fmt.Println("  grant: user:alice -> agent:expense-assistant")
	fmt.Println("    scopes:      expenses:read expenses:submit")
	fmt.Println("    constraints: max_amount=500, categories=[travel meals], audience=finance-api, ttl=1h")
	fmt.Println()
	fmt.Println("  Agent performs an RFC 8693 token exchange and receives this token:")
	tok, err := signer.IssueForGrant(aliceGrant, []string{"expenses:read", "expenses:submit"}, financeAud, now)
	must(err)
	printTokenBody(tok)

	// =====================================================================
	// 2. Happy path: a $120 travel expense — within scope and constraints.
	// =====================================================================
	section("2. Agent submits a $120 travel expense  (expected: APPROVED)")
	call(srv.URL, http.MethodPost, "/expenses", tok, map[string]any{"amount": 120.0, "category": "travel"})

	// =====================================================================
	// 3. Constraint enforcement: amount over the delegated ceiling.
	// =====================================================================
	section("3. Agent submits a $900 travel expense  (expected: DENIED — max_amount)")
	call(srv.URL, http.MethodPost, "/expenses", tok, map[string]any{"amount": 900.0, "category": "travel"})

	// =====================================================================
	// 4. Constraint enforcement: category outside the allow-list.
	// =====================================================================
	section("4. Agent submits an $80 office-supplies expense  (expected: DENIED — category)")
	call(srv.URL, http.MethodPost, "/expenses", tok, map[string]any{"amount": 80.0, "category": "office"})

	// =====================================================================
	// 5. Scope enforcement: an action that was never delegated.
	// =====================================================================
	section("5. Agent tries to APPROVE an expense  (expected: DENIED — scope not delegated)")
	call(srv.URL, http.MethodPost, "/expenses/approve", tok, map[string]any{"id": "exp_123"})

	// =====================================================================
	// 6. Re-delegation: the assistant hands a *narrower* grant to a sub-agent.
	//    The OCR agent may only read — it cannot submit or approve. The token
	//    records the full provenance: alice -> assistant -> ocr.
	// =====================================================================
	section("6. Assistant re-delegates read-only to a Receipt-OCR sub-agent")
	ocrGrant, err := aliceGrant.Delegate(
		"agent:receipt-ocr",
		[]string{"expenses:read"}, // narrower than the assistant's scopes
		delegation.Constraints{},
		time.Hour, now, delegation.DefaultMaxDepth,
	)
	must(err)
	fmt.Println("  grant: agent:expense-assistant -> agent:receipt-ocr  (scopes: expenses:read)")
	ocrTok, err := signer.IssueForGrant(ocrGrant, []string{"expenses:read"}, financeAud, now)
	must(err)
	fmt.Println()
	fmt.Println("  Sub-agent reads expenses  (expected: APPROVED, provenance shows 3 hops):")
	call(srv.URL, http.MethodGet, "/expenses", ocrTok, nil)
	fmt.Println("  Sub-agent tries to submit  (expected: DENIED — submit was not re-delegated):")
	call(srv.URL, http.MethodPost, "/expenses", ocrTok, map[string]any{"amount": 10.0, "category": "travel"})

	// =====================================================================
	// 7. Attenuation is enforced at delegation time too: the assistant cannot
	//    hand out authority it never had.
	// =====================================================================
	section("7. Assistant tries to re-delegate APPROVE rights it doesn't hold")
	if _, err := aliceGrant.Delegate("agent:receipt-ocr", []string{"expenses:approve"},
		delegation.Constraints{}, time.Hour, now, delegation.DefaultMaxDepth); err != nil {
		fmt.Println("  ❌ rejected by Legant before any token was minted:")
		fmt.Println("     ", err)
	} else {
		fmt.Println("  ⚠️  unexpectedly allowed — this would be a privilege-escalation bug")
	}

	fmt.Println()
	banner("Done — every decision above was enforced by signature + scope + constraints")
	fmt.Println("  The Finance API never talked to a database or to Legant at request time.")
	fmt.Println("  It verified the token offline and learned exactly who acted for whom.")
}

// ---- Finance API: an independent resource server -------------------------

type financeAPI struct {
	v   *delegation.Verifier
	mux *http.ServeMux
}

func newFinanceAPI(v *delegation.Verifier) *financeAPI {
	a := &financeAPI{v: v, mux: http.NewServeMux()}
	a.mux.HandleFunc("GET /expenses", a.guard("expenses:read", a.listExpenses))
	a.mux.HandleFunc("POST /expenses", a.guard("expenses:submit", a.submitExpense))
	a.mux.HandleFunc("POST /expenses/approve", a.guard("expenses:approve", a.approveExpense))
	return a
}

func (a *financeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.mux.ServeHTTP(w, r) }

// guard verifies the bearer token and enforces the scope + constraints for the
// operation before the handler runs. This is the resource server's PDP.
func (a *financeAPI) guard(requiredScope string, next func(http.ResponseWriter, *http.Request, *delegation.DelegationClaims)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		claims, err := a.v.Verify(raw, financeAud)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="finance-api", error="invalid_token"`)
			writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "unauthenticated", "reason": err.Error()})
			return
		}

		act := delegation.Action{Scope: requiredScope}
		if r.Method == http.MethodPost && r.Body != nil {
			var body struct {
				Amount   float64 `json:"amount"`
				Category string  `json:"category"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			act.Amount, act.Category = body.Amount, body.Category
		}

		if err := claims.Authorize(act); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"status":     "denied",
				"reason":     err.Error(),
				"provenance": claims.Provenance(),
			})
			return
		}
		next(w, r, claims)
	}
}

func (a *financeAPI) submitExpense(w http.ResponseWriter, r *http.Request, c *delegation.DelegationClaims) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "approved",
		"action":     "expense submitted",
		"provenance": c.Provenance(),
	})
}

func (a *financeAPI) listExpenses(w http.ResponseWriter, r *http.Request, c *delegation.DelegationClaims) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "approved",
		"action":     "expenses listed",
		"provenance": c.Provenance(),
	})
}

func (a *financeAPI) approveExpense(w http.ResponseWriter, r *http.Request, c *delegation.DelegationClaims) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "approved",
		"action":     "expense approved",
		"provenance": c.Provenance(),
	})
}

// ---- the agent's side of the call ----------------------------------------

func call(baseURL, method, path, token string, body map[string]any) {
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, baseURL+path, reader)
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	must(err)
	defer resp.Body.Close()

	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &out)

	mark := "✅"
	if resp.StatusCode >= 400 {
		mark = "❌"
	}
	fmt.Printf("    %s Finance API %s %s -> %d %s\n", mark, method, path, resp.StatusCode, out["status"])
	if reason, ok := out["reason"]; ok {
		fmt.Printf("         reason:     %s\n", reason)
	}
	if prov, ok := out["provenance"]; ok {
		fmt.Printf("         acted-for:  %s\n", prov)
	}
}

// ---- presentation helpers ------------------------------------------------

func printTokenBody(tok string) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return
	}
	var pretty bytes.Buffer
	_ = json.Indent(&pretty, payload, "    ", "  ")
	fmt.Println("    " + strings.ReplaceAll(pretty.String(), "\n", "\n    "))
	fmt.Println()
}

func banner(s string) {
	line := strings.Repeat("=", 72)
	fmt.Println(line)
	fmt.Println("  " + s)
	fmt.Println(line)
}

func section(s string) {
	fmt.Println()
	fmt.Println("── " + s + " " + strings.Repeat("─", max(0, 68-len(s))))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
