// Command driftstop re-enacts the Salesloft–Drift / UNC6395 OAuth-token theft
// (Aug 2025, ~700 orgs) and shows the token that survives it. The attacker stole
// the Drift integration's OAuth tokens, used them against Salesforce to run bulk
// SOQL exports, harvested secrets (AWS keys, Snowflake creds) embedded in support
// cases, and pivoted onward — dwelling ~10 days because the tokens were broad,
// long-lived, and revocable only org-wide.
//
// We replay the SAME theft twice. First with a broad OAuth service-account token
// (what was actually stolen): bulk-export and secret-harvest both succeed. Then
// with a Legant on-behalf-of token — audience-scoped to the CRM, no bulk-export
// tool, no access to the secret-bearing records, a 15-minute TTL, and a
// business-hours window — every move the attacker makes is refused OFFLINE at the
// resource server, and one signed-feed entry kills it for good.
//
// No database, no Docker:
//
//	go run ./examples/driftstop
//	# or
//	make demo-driftstop
//
// NOTE (honest): a stolen token is still presented; Legant doesn't stop the theft.
// It collapses the blast radius — the constrained token can't bulk-export, can't
// read the secret-bearing records, can't pivot audiences, expires in minutes
// instead of days, and is revocable in one signed-feed entry rather than org-wide.
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
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"

	legantcrypto "github.com/legant-dev/legant/internal/crypto"
	"github.com/legant-dev/legant/internal/delegation"
	"github.com/legant-dev/legant/sdk"
)

const (
	issuer  = "https://legant.acme.internal"
	crmAud  = "https://crm.acme.internal"  // the Salesforce-like CRM
	bulkAud = "https://bulk.acme.internal" // the Bulk-export API (a different audience)
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

// serverClock is the resource server's OWN trusted clock, used for the
// business-hours window check. In production the RS stamps the action time from
// its own clock; here we make it injectable so the "replayed at 3am" beat is
// deterministic rather than depending on the wall-clock the demo happens to run at.
var serverClock atomic.Int64 // unix nanoseconds

func setClock(t time.Time) { serverClock.Store(t.UnixNano()) }
func nowOnServer() time.Time {
	return time.Unix(0, serverClock.Load()).UTC()
}

// newResourceServer authorizes each operation OFFLINE from the token: scope, the
// MCP tool name, the target resource, and the business-hours window — against the
// server's own clock. The same handler backs both the CRM and the Bulk API; they
// differ only in the audience they accept, so a CRM-scoped token can't be replayed
// against the Bulk API (audience-pivot containment).
func newResourceServer(aud string, keys map[string]*rsa.PublicKey, feed *sdk.RevocationFeed) *httptest.Server {
	v := sdk.NewVerifier(issuer, aud, keys, sdk.WithRevocationFeed(feed))
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		claims, err := v.Verify(tok)
		if err != nil {
			http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}
		var req struct {
			Scope, Tool, Resource string
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		act := sdk.Action{Scope: req.Scope, Tool: req.Tool, Resource: req.Resource, At: nowOnServer()}
		if err := claims.Authorize(act); err != nil {
			http.Error(w, "denied: "+err.Error(), http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "by": claims.Provenance()})
	}))
}

func main() {
	ctx := context.Background()
	key, err := legantcrypto.GenerateRSAKey(2048)
	must(err)
	signer := delegation.NewSigner(issuer, "ds-1", key)
	keys := map[string]*rsa.PublicKey{"ds-1": &key.PublicKey}

	pub := newFeedPublisher(key, "ds-1")
	defer pub.server.Close()
	feed, err := sdk.FetchRevocationFeed(ctx, pub.server.URL, issuer, keys)
	must(err)

	crm := newResourceServer(crmAud, keys, feed)
	defer crm.Close()
	bulk := newResourceServer(bulkAud, keys, feed)
	defer bulk.Close()

	real := time.Now()
	// The RS clock starts at a business-hours instant (14:00 UTC) so normal calls
	// pass the window; we move it to 03:00 for the after-hours replay beat.
	business := time.Date(2026, 6, 22, 14, 0, 0, 0, time.UTC)
	threeAM := time.Date(2026, 6, 22, 3, 0, 0, 0, time.UTC)
	setClock(business)

	call := func(target *httptest.Server, token, scope, tool, resource string) (int, string) {
		body, _ := json.Marshal(map[string]any{"scope": scope, "tool": tool, "resource": resource})
		req, _ := http.NewRequest(http.MethodPost, target.URL, strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, e := http.DefaultClient.Do(req)
		if e != nil {
			return 502, "unreachable"
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, strings.TrimSpace(string(out))
	}
	rep := func(label string, target *httptest.Server, token, scope, tool, resource string) {
		st, b := call(target, token, scope, tool, resource)
		report(label, st, b)
	}

	banner("drift-stop — replay the Salesloft–Drift / UNC6395 OAuth theft on a token that survives it")
	fmt.Println("  The Drift integration's OAuth token was stolen and replayed against the CRM:")
	fmt.Println("  bulk-export everything, harvest secrets embedded in support cases, pivot onward.")

	section("1. THE STOLEN BROAD OAuth TOKEN  (what UNC6395 actually had)")
	// A classic OAuth service-account grant: broad scope, no per-action limits, no
	// window, a long life, and an audience covering every endpoint the app touches.
	broadCRM, _ := signer.IssueClaims("svc:salesforce-connector",
		&delegation.ActClaim{Sub: "app:drift"}, []string{"crm:read"}, crmAud,
		&delegation.Constraints{}, real.Add(24*time.Hour), real)
	broadBulk, _ := signer.IssueClaims("svc:salesforce-connector",
		&delegation.ActClaim{Sub: "app:drift"}, []string{"bulk:export"}, bulkAud,
		&delegation.Constraints{}, real.Add(24*time.Hour), real)
	rep("read a few contacts (looks normal)", crm, broadCRM, "crm:read", "read_record", "contacts")
	rep("BULK-EXPORT 50,000 records", bulk, broadBulk, "bulk:export", "bulk_export", "contacts")
	rep("harvest secrets in support cases", crm, broadCRM, "crm:read", "read_record", "cases.secrets")
	fmt.Println("    💥 bulk exfil + harvested AWS/Snowflake keys → the attacker pivots beyond the CRM,")
	fmt.Println("       and the token stays valid for ~10 days (revocable only org-wide).")

	section("2. THE LEGANT ON-BEHALF-OF TOKEN  (same theft, replayed)")
	// Minted for the actual rep, scoped to the CRM only: read tool only, contacts
	// only, a 15-minute life, business-hours window.
	hours := &delegation.TimeWindow{StartMin: 9 * 60, EndMin: 17 * 60, TZ: "UTC"}
	legTok, legJTI := mint(signer, "user:rep-jordan", "agent:revops-copilot",
		[]string{"crm:read"}, crmAud,
		&delegation.Constraints{Tools: []string{"read_record"}, Resources: []string{"contacts"}, TimeWindow: hours},
		real.Add(15*time.Minute), real)
	rep("the legitimate call: read contacts, in hours", crm, legTok, "crm:read", "read_record", "contacts")
	rep("attacker tries BULK-EXPORT on the CRM", crm, legTok, "crm:read", "bulk_export", "contacts")
	rep("attacker tries to harvest case secrets", crm, legTok, "crm:read", "read_record", "cases.secrets")
	rep("attacker replays it against the Bulk API", bulk, legTok, "bulk:export", "bulk_export", "contacts")

	section("3. Dwell time: the stolen Legant token replayed 16 minutes later")
	staleTok, _ := mint(signer, "user:rep-jordan", "agent:revops-copilot",
		[]string{"crm:read"}, crmAud,
		&delegation.Constraints{Tools: []string{"read_record"}, Resources: []string{"contacts"}, TimeWindow: hours},
		real.Add(-time.Minute), real.Add(-16*time.Minute)) // issued 16m ago, 15m TTL → expired
	rep("replay after the 15-min TTL (UNC6395 dwelled ~10 DAYS)", crm, staleTok, "crm:read", "read_record", "contacts")

	section("4. Off-hours: the same token replayed at 03:00")
	setClock(threeAM)
	rep("replay at 03:00, outside the business-hours window", crm, legTok, "crm:read", "read_record", "contacts")
	setClock(business)

	section("5. One signed-feed entry kills it — not an org-wide OAuth revoke")
	pub.revoke(legJTI)
	must(feed.Refresh(ctx))
	rep("the revoked token, replayed in-hours", crm, legTok, "crm:read", "read_record", "contacts")

	fmt.Println()
	banner("Done — the breach that took ~10 days to contain is refused offline, per action")
	fmt.Println("  Same theft, different token: no bulk export, no secret-bearing records, no audience")
	fmt.Println("  pivot, minutes not days of life, and a one-entry offline kill — every denial enforced")
	fmt.Println("  at the resource server with no callback to Legant. (The theft still happens; the blast")
	fmt.Println("  radius is what changes.)")
}

// mint signs a per-human on-behalf-of token and returns it with its jti.
func mint(signer *delegation.Signer, sub, agent string, scopes []string, aud string, c *delegation.Constraints, exp, now time.Time) (string, string) {
	t, err := signer.IssueClaims(sub, &delegation.ActClaim{Sub: agent}, scopes, aud, c, exp, now)
	must(err)
	return t, jtiOf(t)
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
