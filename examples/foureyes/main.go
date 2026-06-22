// Command foureyes demonstrates SEGREGATION OF DUTIES (the "four-eyes" / maker-
// checker rule) as a property of the token. A treasury agent may PREPARE a
// transfer under one human's authority, but EXECUTING it is structurally
// unreachable unless the token's provenance names a SECOND, DISTINCT human — so an
// agent (or a single insider) can never both raise and release the same payment.
//
// Three things stack, all enforced OFFLINE at the treasury resource server:
//
//  1. Tools — the prepare token carries Tools=[prepare_transfer]; it literally
//     cannot call execute_transfer (a signed-token constraint, not a UI gate).
//  2. MaxAmount — prepare and execute are both capped; the cap binds even a
//     fully co-signed transfer.
//  3. Two-distinct-principals — execute_transfer requires ≥2 distinct human
//     principals in the RFC 8693 sub/act chain; one human (even repeated) is
//     refused, so you cannot approve your own request.
//
// No database, no Docker:
//
//	go run ./examples/foureyes
//	# or
//	make demo-foureyes
//
// NOTE (honest): Legant's sub/act is a LINEAR delegation chain, not an independent
// co-signature scheme. This encodes maker-checker as "the execute authority's
// provenance must contain two distinct humans," enforced offline by the RS over
// the signed chain. For true independent dual-control over one transfer object,
// pair this with an approval record the second human signs — Legant carries and
// verifies the principals; the application defines the workflow.
package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	legantcrypto "github.com/legant-dev/legant/internal/crypto"
	"github.com/legant-dev/legant/internal/delegation"
	"github.com/legant-dev/legant/sdk"
)

const (
	issuer      = "https://legant.acme.internal"
	treasuryAud = "https://treasury.acme.internal"
)

type feedPublisher struct {
	key     *rsa.PrivateKey
	kid     string
	server  *httptest.Server
	mu      sync.Mutex
	revoked map[string]struct{}
	version int64
}

func newFeedPublisher(key *rsa.PrivateKey, kid string) *feedPublisher {
	p := &feedPublisher{key: key, kid: kid, revoked: map[string]struct{}{}, version: 1}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte(p.sign()))
	}))
	return p
}

func (p *feedPublisher) sign() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	jtis := make([]string, 0, len(p.revoked))
	for j := range p.revoked {
		jtis = append(jtis, j)
	}
	sort.Strings(jtis)
	now := time.Now()
	claims := jwt.MapClaims{"iss": issuer, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "ver": p.version, "jtis": jtis}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = p.kid
	s, _ := tok.SignedString(p.key)
	return s
}

func (p *feedPublisher) revoke(jtis ...string) {
	p.mu.Lock()
	for _, j := range jtis {
		p.revoked[j] = struct{}{}
	}
	p.version++
	p.mu.Unlock()
}

// distinctHumans returns the distinct human principals (sub starting "user:") in a
// token's provenance — the subject plus every actor in the act chain.
func distinctHumans(c *sdk.Claims) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if strings.HasPrefix(p, "user:") && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	add(c.Subject)
	for a := c.Act; a != nil; a = a.Act {
		add(a.Sub)
	}
	return out
}

// newTreasury authorizes each operation OFFLINE: scope, tool, and amount via the
// SDK; then, for execute_transfer ONLY, applies the four-eyes rule over the signed
// provenance — at least two distinct human principals must appear in the chain.
func newTreasury(keys map[string]*rsa.PublicKey, feed *sdk.RevocationFeed) *httptest.Server {
	v := sdk.NewVerifier(issuer, treasuryAud, keys, sdk.WithRevocationFeed(feed))
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		claims, err := v.Verify(tok)
		if err != nil {
			http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}
		var req struct {
			Scope, Tool string
			Amount      float64
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		if err := claims.Authorize(sdk.Action{Scope: req.Scope, Tool: req.Tool, Amount: req.Amount}); err != nil {
			http.Error(w, "denied: "+err.Error(), http.StatusForbidden)
			return
		}
		if req.Tool == "execute_transfer" {
			if humans := distinctHumans(claims); len(humans) < 2 {
				http.Error(w, fmt.Sprintf("denied: four-eyes — execute needs two distinct humans, chain has %v", humans), http.StatusForbidden)
				return
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "by": claims.Provenance()})
	}))
}

func main() {
	ctx := context.Background()
	key, err := legantcrypto.GenerateRSAKey(2048)
	must(err)
	signer := delegation.NewSigner(issuer, "fe-1", key)
	keys := map[string]*rsa.PublicKey{"fe-1": &key.PublicKey}

	pub := newFeedPublisher(key, "fe-1")
	defer pub.server.Close()
	feed, err := sdk.FetchRevocationFeed(ctx, pub.server.URL, issuer, keys)
	must(err)
	tr := newTreasury(keys, feed)
	defer tr.Close()
	now := time.Now()
	cap250k := 250_000.0

	call := func(token, scope, tool string, amount float64) (int, string) {
		body, _ := json.Marshal(map[string]any{"scope": scope, "tool": tool, "amount": amount})
		req, _ := http.NewRequest(http.MethodPost, tr.URL, strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, e := http.DefaultClient.Do(req)
		if e != nil {
			return 502, "unreachable"
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, strings.TrimSpace(string(out))
	}
	rep := func(label, token, scope, tool string, amount float64) {
		st, b := call(token, scope, tool, amount)
		report(label, st, b)
	}

	banner("four-eyes — segregation of duties as a property of the token")
	fmt.Println("  A treasury agent may PREPARE a transfer; EXECUTING it requires a SECOND distinct human.")

	// The requester (Jordan) delegates PREPARE authority to the agent: prepare tool
	// only, ≤ $250k. This token literally cannot execute.
	prep, _ := signer.IssueClaims("user:jordan", &delegation.ActClaim{Sub: "agent:treasury-bot"},
		[]string{"transfer:prepare", "transfer:execute"}, treasuryAud,
		&delegation.Constraints{Tools: []string{"prepare_transfer"}, MaxAmount: &cap250k}, now.Add(time.Hour), now)

	section("1. The prepare token — native Tools + MaxAmount constraints")
	rep("Jordan's agent prepares an $80k transfer", prep, "transfer:prepare", "prepare_transfer", 80_000)
	rep("…prepares a $400k transfer (over the cap)", prep, "transfer:prepare", "prepare_transfer", 400_000)
	rep("…tries to EXECUTE with the prepare token", prep, "transfer:execute", "execute_transfer", 80_000)
	fmt.Println("    The prepare token holds Tools=[prepare_transfer]; execute_transfer is unreachable.")

	section("2. Execute requires two DISTINCT humans  (you can't approve your own)")
	// A single-human execute token (Jordan alone).
	solo, _ := signer.IssueClaims("user:jordan", &delegation.ActClaim{Sub: "agent:treasury-bot"},
		[]string{"transfer:execute"}, treasuryAud,
		&delegation.Constraints{Tools: []string{"execute_transfer"}, MaxAmount: &cap250k}, now.Add(time.Hour), now)
	rep("execute with Jordan only in the chain", solo, "transfer:execute", "execute_transfer", 80_000)

	// Self-approval: Jordan delegating "to himself" then to the agent — still one
	// distinct human, so the distinctness check refuses it.
	selfG := delegation.NewRootGrant("user:jordan", "user:jordan", []string{"transfer:execute"},
		delegation.Constraints{Tools: []string{"execute_transfer"}, MaxAmount: &cap250k}, time.Hour, now)
	selfLeaf, err := selfG.Delegate("agent:treasury-bot", []string{"transfer:execute"}, delegation.Constraints{}, time.Hour, now, delegation.DefaultMaxDepth)
	must(err)
	selfTok, err := signer.IssueForGrant(selfLeaf, []string{"transfer:execute"}, treasuryAud, now)
	must(err)
	rep("execute with Jordan 'approving' his own request", selfTok, "transfer:execute", "execute_transfer", 80_000)

	section("3. A genuinely co-signed transfer  (Jordan raised, Morgan approved)")
	// Morgan, the approver, releases Jordan's transfer to the agent: the execute
	// token's provenance now names two distinct humans.
	coG := delegation.NewRootGrant("user:jordan", "user:morgan", []string{"transfer:execute"},
		delegation.Constraints{Tools: []string{"execute_transfer"}, MaxAmount: &cap250k}, time.Hour, now)
	coLeaf, err := coG.Delegate("agent:treasury-bot", []string{"transfer:execute"}, delegation.Constraints{}, time.Hour, now, delegation.DefaultMaxDepth)
	must(err)
	coTok, err := signer.IssueForGrant(coLeaf, []string{"transfer:execute"}, treasuryAud, now)
	must(err)
	coJTI := jtiOf(coTok)
	rep("execute a $200k transfer (Jordan -> Morgan -> agent)", coTok, "transfer:execute", "execute_transfer", 200_000)
	rep("…but $400k still exceeds the cap, even co-signed", coTok, "transfer:execute", "execute_transfer", 400_000)

	section("4. Pull the approval — revoke Morgan's co-sign offline")
	pub.revoke(coJTI)
	must(feed.Refresh(ctx))
	rep("the revoked co-signed token, replayed", coTok, "transfer:execute", "execute_transfer", 200_000)

	fmt.Println()
	banner("Done — raise and release are different humans, enforced offline, per action")
	fmt.Println("  The agent cannot self-serve: execute is unreachable from any token whose signed")
	fmt.Println("  provenance lacks a second distinct human, the amount cap binds even a co-signed")
	fmt.Println("  transfer, and an approval is revocable in one signed-feed entry. (Legant carries the")
	fmt.Println("  verifiable principals; the maker-checker workflow is the application's to define.)")
}

func report(label string, st int, body string) {
	mark := "✅"
	if st >= 400 {
		mark = "❌"
	}
	fmt.Printf("    %s %-50s -> %d  %s\n", mark, label, st, oneline(body))
}

func jtiOf(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		JTI string `json:"jti"`
	}
	_ = json.Unmarshal(raw, &c)
	return c.JTI
}

func oneline(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 52 {
		s = s[:52] + "…"
	}
	return s
}

func banner(s string) {
	line := strings.Repeat("=", 100)
	fmt.Println(line)
	fmt.Println("  " + s)
	fmt.Println(line)
}

func section(s string) {
	fmt.Println()
	fmt.Println("── " + s + " " + strings.Repeat("─", max(0, 90-len(s))))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
