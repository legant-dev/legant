// Command splice demonstrates MONOTONIC ATTENUATION across a multi-hop agent
// delegation chain — the property that "a sub-agent can only ever do LESS than
// its parent" — and how Legant enforces it where the standards punt. A "planner"
// agent delegates a sub-task to a "worker" sub-agent (another host). The Feb-2026
// IETF "delegation chain splicing" concern is that a compromised intermediary can
// WIDEN the child's authority (add a tool, raise a cap, pivot to another
// audience) because RFC 8693 treats prior actors as informational and A2A leaves
// sub-agent scope to implementers.
//
// Legant's delegation.Delegate() applies Tighten() — intersect the allow-lists,
// take the min cap — and REFUSES to mint a child that exceeds its parent at all;
// the worker resource server then enforces what's left, offline. A "naive" system
// that just signs whatever a caller requests would hand the worker exactly the
// over-broad token the splicing attack wants.
//
// No database, no Docker:
//
//	go run ./examples/splice
//	# or
//	make demo-splice
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
	issuer    = "https://legant.platform.internal"
	docsvcAud = "docsvc://team" // the document-service resource server
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

// docService is the worker's resource server. It authorizes each operation
// OFFLINE from the token: scope (the op), amount (how many docs), and resource
// (which workspace) — so the worker can never exceed the slice it actually holds.
func newDocService(keys map[string]*rsa.PublicKey, feed *sdk.RevocationFeed) *httptest.Server {
	v := sdk.NewVerifier(issuer, docsvcAud, keys, sdk.WithRevocationFeed(feed))
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		claims, err := v.Verify(tok)
		if err != nil {
			http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}
		var req struct {
			Op        string `json:"op"`
			Count     int    `json:"count"`
			Workspace string `json:"workspace"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		if err := claims.Authorize(sdk.Action{Scope: req.Op, Amount: float64(req.Count), Resource: req.Workspace}); err != nil {
			http.Error(w, "denied: "+err.Error(), http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "chain": claims.Provenance()})
	}))
}

// mintFromGrant signs a token carrying a grant's full sub/act provenance.
func mintFromGrant(signer *delegation.Signer, g *delegation.Grant, now time.Time) (string, string) {
	var act *delegation.ActClaim
	for _, a := range g.ActorChainRootToLeaf() {
		act = &delegation.ActClaim{Sub: a, Act: act}
	}
	cnst := g.Constraints
	t, err := signer.IssueClaims(g.RootDelegator(), act, g.Scopes, docsvcAud, &cnst, g.ExpiresAt, now)
	must(err)
	return t, jtiOf(t)
}

func main() {
	ctx := context.Background()
	key, err := legantcrypto.GenerateRSAKey(2048)
	must(err)
	signer := delegation.NewSigner(issuer, "splice-1", key)
	keys := map[string]*rsa.PublicKey{"splice-1": &key.PublicKey}

	pub := newFeedPublisher(key, "splice-1")
	defer pub.server.Close()
	feed, err := sdk.FetchRevocationFeed(ctx, pub.server.URL, issuer, keys)
	must(err)
	svc := newDocService(keys, feed)
	defer svc.Close()
	now := time.Now()

	call := func(token, op string, count int, workspace string) (int, string) {
		body, _ := json.Marshal(map[string]any{"op": op, "count": count, "workspace": workspace})
		req, _ := http.NewRequest(http.MethodPost, svc.URL, strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, e := http.DefaultClient.Do(req)
		if e != nil {
			return 502, "unreachable"
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, strings.TrimSpace(string(out))
	}
	rep := func(label, token, op string, count int, ws string) {
		st, body := call(token, op, count, ws)
		report(label, st, body)
	}

	maxDocs := 50.0
	// The user delegates to the planner: read+summarize ≤ 50 docs, ONLY in team-a.
	planner := delegation.NewRootGrant("user:lead", "agent:planner",
		[]string{"docs:read", "docs:summarize"},
		delegation.Constraints{MaxAmount: &maxDocs, Resources: []string{"workspace://team-a"}},
		time.Hour, now)

	banner("Splice — a sub-agent can only ever do LESS than its parent (enforced at mint)")
	fmt.Println("  user:lead -> agent:planner   may: read+summarize ≤ 50 docs, in workspace team-a only")

	section("1. A legitimate, ATTENUATED hand-off to a worker sub-agent")
	worker, err := planner.Delegate("agent:worker", []string{"docs:summarize"},
		delegation.Constraints{MaxAmount: ptr(20)}, time.Hour, now, delegation.DefaultMaxDepth)
	must(err)
	fmt.Printf("    chain: %s   (summarize ≤ 20, team-a)\n", grantChain(worker))
	wTok, wJTI := mintFromGrant(signer, worker, now)
	rep("worker summarizes 15 docs in team-a", wTok, "docs:summarize", 15, "workspace://team-a")

	section("2. Splicing attempts — a compromised intermediary tries to WIDEN the child")
	// (a) add a capability the parent never held → refused at delegation time.
	if _, e := planner.Delegate("agent:worker", []string{"docs:summarize", "docs:delete"},
		delegation.Constraints{}, time.Hour, now, delegation.DefaultMaxDepth); e != nil {
		report("(a) add docs:delete the parent lacked", 403, "refused at mint: "+e.Error())
	}
	// (b) raise the cap → Tighten takes the MIN; the child stays at the parent's 50.
	wideCap, _ := planner.Delegate("agent:worker", []string{"docs:summarize"},
		delegation.Constraints{MaxAmount: ptr(500)}, time.Hour, now, delegation.DefaultMaxDepth)
	capTok, _ := mintFromGrant(signer, wideCap, now)
	rep("(b) child asked for 500-doc cap → process 300 docs", capTok, "docs:summarize", 300, "workspace://team-a")
	// (c) pivot to a workspace the parent can't touch → Tighten → deny-all (neither).
	pivot, _ := planner.Delegate("agent:worker", []string{"docs:summarize"},
		delegation.Constraints{Resources: []string{"workspace://team-b"}}, time.Hour, now, delegation.DefaultMaxDepth)
	pivTok, _ := mintFromGrant(signer, pivot, now)
	rep("(c) cross-workspace pivot → summarize in team-b", pivTok, "docs:summarize", 5, "workspace://team-b")
	rep("(c) …and the spliced token can't even use team-a", pivTok, "docs:summarize", 5, "workspace://team-a")

	section("3. The danger WITHOUT mint-time attenuation  (a naive system)")
	fmt.Println("    A system that just signs whatever a caller requests hands the worker the")
	fmt.Println("    over-broad token the splicing attack wanted — and the resource server honors it:")
	naive := &delegation.ActClaim{Sub: "agent:worker", Act: &delegation.ActClaim{Sub: "agent:planner"}}
	naiveTok, _ := signer.IssueClaims("user:lead", naive, []string{"docs:delete"},
		docsvcAud, &delegation.Constraints{Resources: []string{"workspace://team-b"}}, now.Add(time.Hour), now)
	rep("naive-minted worker DELETES 40 docs in team-b", naiveTok, "docs:delete", 40, "workspace://team-b")

	section("4. Revoke the planner's delegation — the worker subtree dies offline")
	pub.revoke(wJTI)
	must(feed.Refresh(ctx))
	rep("worker's already-held token → summarize team-a", wTok, "docs:summarize", 5, "workspace://team-a")

	fmt.Println()
	banner("Done — widening is refused at the mint; a child is always a strict subset of its parent")
	fmt.Println("  Legant builds the act chain from VALIDATED grants and Tighten()s every dimension")
	fmt.Println("  (scope, cap, audience), so the splicing/over-broad child the standards leave open")
	fmt.Println("  simply cannot be minted — and what survives is enforced at the worker, offline.")
}

func ptr(f float64) *float64 { return &f }

func grantChain(g *delegation.Grant) string {
	parts := append([]string{g.RootDelegator()}, g.ActorChainRootToLeaf()...)
	return strings.Join(parts, " -> ")
}

func report(label string, st int, body string) {
	mark := "✅"
	if st >= 400 {
		mark = "❌"
	}
	fmt.Printf("    %s %-48s -> %d  %s\n", mark, label, st, oneline(body))
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
	if len(s) > 54 {
		s = s[:54] + "…"
	}
	return s
}

func banner(s string) {
	line := strings.Repeat("=", 92)
	fmt.Println(line)
	fmt.Println("  " + s)
	fmt.Println(line)
}

func section(s string) {
	fmt.Println()
	fmt.Println("── " + s + " " + strings.Repeat("─", max(0, 84-len(s))))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
