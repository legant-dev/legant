// Command charter is a self-contained, runnable demonstration of an agent-run
// "company" where the ORG CHART IS THE AUTHORITY GRAPH. A founder grants a CEO
// agent a budget; the CEO re-delegates thinner slices to Growth and Ops agents,
// which re-delegate again — and every dollar is bounded by a delegation no agent
// can exceed. Lower a parent's budget and the whole subtree's authority shrinks,
// because re-delegation can only ever ATTENUATE (a child is never looser than its
// parent). Over-budget spend is rejected OFFLINE at the ad platform with the full
// founder -> CEO -> Growth -> Bid provenance.
//
// No database, no Docker:
//
//	go run ./examples/charter
//	# or
//	make demo-charter
package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	legantcrypto "github.com/legant-dev/legant/internal/crypto"
	"github.com/legant-dev/legant/internal/delegation"
	"github.com/legant-dev/legant/sdk"
)

const issuer = "https://legant.local"

var adsResID = "https://ads.example/"

// node is one seat in the org chart — an agent and the grant that bounds it.
type node struct {
	name     string
	grant    *delegation.Grant
	children []*node
}

func main() {
	key, err := legantcrypto.GenerateRSAKey(2048)
	must(err)
	signer := delegation.NewSigner(issuer, "charter-1", key)
	keys := map[string]*rsa.PublicKey{"charter-1": &key.PublicKey}

	// The ad platform: a resource server that enforces the spend constraints
	// offline from the signed token via the public SDK.
	ads := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		claims, err := sdk.NewVerifier(issuer, adsResID, keys).Verify(tok)
		if err != nil {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		var req struct {
			Amount float64 `json:"amount"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &req)
		if err := claims.Authorize(sdk.Action{Scope: "spend", Amount: req.Amount, Category: "ads", Resource: adsResID}); err != nil {
			http.Error(w, fmt.Sprintf("DECLINED: %s   (%s)", err.Error(), claims.Provenance()), http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(fmt.Sprintf("APPROVED $%.0f   (%s)", req.Amount, claims.Provenance())))
	}))
	defer ads.Close()

	now := time.Now()
	money := func(v float64) *float64 { return &v }

	// Build the org. NewRootGrant: founder -> CEO. Delegate: CEO -> Growth/Ops,
	// Growth -> Bid. Each Delegate enforces scopes ⊆ parent and Tighten(constraints).
	ceo := delegation.NewRootGrant("user:founder", "agent:CEO", []string{"spend"},
		delegation.Constraints{MaxAmount: money(2000), Categories: []string{"hosting", "ads", "contractors"}, Resources: []string{adsResID}},
		7*24*time.Hour, now)
	growth := mustDelegate(ceo, "agent:Growth", money(500), []string{"ads"})
	ops := mustDelegate(ceo, "agent:Ops", money(800), []string{"hosting", "contractors"})
	bid := mustDelegate(growth, "agent:Bid", money(200), []string{"ads"})

	org := &node{"founder", ceo, []*node{
		{"CEO", ceo, []*node{
			{"Growth", growth, []*node{{"Bid", bid, nil}}},
			{"Ops", ops, nil},
		}},
	}}

	spend := func(label string, g *delegation.Grant, amount float64) {
		tok, err := signer.IssueForGrant(g, []string{"spend"}, adsResID, time.Now())
		if err != nil {
			fmt.Printf("    ❌ %-22s -> cannot mint (%v)\n", label, err)
			return
		}
		st, body := post(ads.URL, tok, amount)
		mark := "✅"
		if st >= 400 {
			mark = "❌"
		}
		fmt.Printf("    %s %-22s -> %s\n", mark, label, body)
	}

	banner("Charter — an agent-run company where the org chart IS the authority graph")
	fmt.Println("  Every seat's spending power is a delegation no agent can exceed; re-delegation")
	fmt.Println("  can only ever ATTENUATE. Caps are cryptographic, enforced offline at the ad platform.")

	section("1. The org chart (= the authority graph)")
	printOrg(org, "", true, true)

	section("2. Spending within the chain")
	spend("Bid: $150 ad", bid, 150)
	spend("Growth: $300 ad", growth, 300)

	section("3. A rogue/over-budget spend  (expected: declined with full provenance)")
	spend("Bid: $400 ad", bid, 400) // over Bid's $200 cap

	section("4. The founder drags Growth's weekly budget $500 -> $50")
	fmt.Println("    Re-delegating Growth (and its subtree) at the new cap — Bid INHERITS the lower limit:")
	growth = mustDelegate(ceo, "agent:Growth", money(50), []string{"ads"})
	bid = mustDelegate(growth, "agent:Bid", money(200), []string{"ads"}) // requests 200, Tighten clamps to 50
	org = &node{"founder", ceo, []*node{
		{"CEO", ceo, []*node{
			{"Growth", growth, []*node{{"Bid", bid, nil}}},
			{"Ops", ops, nil},
		}},
	}}
	printOrg(org, "", true, true)

	section("5. The same $150 Bid spend now bounces — the whole subtree shrank")
	spend("Bid: $150 ad", bid, 150) // now over the inherited $50 cap

	fmt.Println()
	banner("Done — watch an AI company whose spending limits are cryptographic, not vibes")
	fmt.Println("  Drop one parent's budget and every sub-agent beneath it is instantly bounded by the")
	fmt.Println("  lower cap — escalation is impossible because a child can never out-spend its parent.")
}

func printOrg(n *node, prefix string, isRoot, last bool) {
	if isRoot {
		fmt.Printf("    %s\n", n.name)
	} else {
		branch, next := "├─ ", "│  "
		if last {
			branch, next = "└─ ", "   "
		}
		fmt.Printf("    %s%s%-9s %s\n", prefix, branch, n.name, capLabel(n.grant))
		prefix += next
	}
	for i, c := range n.children {
		printOrg(c, prefix, false, i == len(n.children)-1)
	}
}

func capLabel(g *delegation.Grant) string {
	amt := "∞"
	if g.Constraints.MaxAmount != nil {
		amt = fmt.Sprintf("$%.0f", *g.Constraints.MaxAmount)
	}
	return fmt.Sprintf("≤ %-6s %v", amt, g.Constraints.Categories)
}

func mustDelegate(parent *delegation.Grant, agent string, max *float64, cats []string) *delegation.Grant {
	g, err := parent.Delegate(agent, []string{"spend"},
		delegation.Constraints{MaxAmount: max, Categories: cats}, 7*24*time.Hour, time.Now(), delegation.DefaultMaxDepth)
	must(err)
	return g
}

func post(url, token string, amount float64) (int, string) {
	body, _ := json.Marshal(map[string]any{"amount": amount})
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 502, "ad platform unreachable"
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(out))
}

func banner(s string) {
	line := strings.Repeat("=", 90)
	fmt.Println(line)
	fmt.Println("  " + s)
	fmt.Println(line)
}

func section(s string) {
	fmt.Println()
	fmt.Println("── " + s + " " + strings.Repeat("─", max(0, 86-len(s))))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
