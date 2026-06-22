// Command oauth-breach-replay re-enacts the Salesloft–Drift / UNC6395 OAuth-token
// theft (Aug 2025) against REAL HTTP services guarded by Legant's shipped
// resource-server middleware — the same `sdk.Authenticate` + `sdk.RequireAction`
// you'd wire into your own API (see `legant snippet`). Two faithful-mock services
// stand in for a Salesforce-style CRM and its Bulk API; one is seeded with secrets
// embedded in support-case fields (the real UNC6395 secret-harvest).
//
// The SAME stolen token is replayed twice. With a broad OAuth service-account token
// (what was actually stolen) the attacker bulk-exports records and harvests AWS /
// Snowflake credentials. With a Legant on-behalf-of token — audience-scoped to the
// CRM, no bulk-export tool, a 15-minute TTL, and a business-hours window — every
// move is refused OFFLINE by the middleware, and one signed-feed entry kills it.
//
// Self-contained (real net/http listeners, no external creds, no Docker):
//
//	go run ./examples/enterprise/oauth-breach-replay
//	# or
//	make demo-breach
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
	crmAud  = "https://crm.acme.internal"
	bulkAud = "https://bulk.acme.internal"
)

// serverClock is the services' trusted clock for the business-hours window, made
// injectable so the "replayed after hours" beat is deterministic.
var serverClock atomic.Int64

func setClock(t time.Time)   { serverClock.Store(t.UnixNano()) }
func nowOnServer() time.Time { return time.Unix(0, serverClock.Load()).UTC() }

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

// caseWithSecrets is a support case whose body carries embedded credentials — the
// thing UNC6395 actually harvested from Salesforce and pivoted on.
const caseWithSecrets = `Case#4471 "prod outage": customer pasted creds — AWS_ACCESS_KEY_ID=AKIA_EXAMPLE_7H2 SNOWFLAKE_PASSWORD=Wm!nter2025`

// newCRM builds the CRM service using the SHIPPED Legant middleware. Each route is
// wrapped with sdk.Authenticate (verify the bearer + revocation feed) and
// sdk.RequireAction (authorize the delegated action: scope + tool + resource +
// business-hours window). This is exactly the integration `legant snippet` prints.
func newCRM(keys map[string]*rsa.PublicKey, feed *sdk.RevocationFeed) *httptest.Server {
	v := sdk.NewVerifier(issuer, crmAud, keys, sdk.WithRevocationFeed(feed))
	mux := http.NewServeMux()

	// Read a few contacts (the normal, legitimate use).
	mux.Handle("/query", sdk.Authenticate(v)(sdk.RequireAction(func(*http.Request) sdk.Action {
		return sdk.Action{Scope: "crm:read", Tool: "read_record", Resource: "contacts", At: nowOnServer()}
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := sdk.MustClaims(r.Context())
		writeJSON(w, map[string]any{"records": 5, "by": c.Provenance()})
	}))))

	// Bulk export (the mass exfil) — gated on a distinct tool.
	mux.Handle("/jobs/query", sdk.Authenticate(v)(sdk.RequireAction(func(*http.Request) sdk.Action {
		return sdk.Action{Scope: "crm:read", Tool: "bulk_export", Resource: "contacts", At: nowOnServer()}
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"exported": 50000, "note": "all Account/Contact/Case rows"})
	}))))

	// Read a secret-bearing support case (the harvest).
	mux.Handle("/sobjects/Case", sdk.Authenticate(v)(sdk.RequireAction(func(*http.Request) sdk.Action {
		return sdk.Action{Scope: "crm:read", Tool: "read_record", Resource: "cases.secrets", At: nowOnServer()}
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"case": caseWithSecrets})
	}))))

	return httptest.NewServer(mux)
}

// newBulkAPI is a SECOND service with a different audience (Salesforce's Bulk API
// 2.0 endpoint). A token bound to the CRM cannot be replayed here.
func newBulkAPI(keys map[string]*rsa.PublicKey, feed *sdk.RevocationFeed) *httptest.Server {
	v := sdk.NewVerifier(issuer, bulkAud, keys, sdk.WithRevocationFeed(feed))
	mux := http.NewServeMux()
	mux.Handle("/jobs", sdk.Authenticate(v)(sdk.RequireScope("bulk:export")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]any{"job": "created", "exported": 50000})
		}))))
	return httptest.NewServer(mux)
}

func main() {
	ctx := context.Background()
	key, err := legantcrypto.GenerateRSAKey(2048)
	must(err)
	signer := delegation.NewSigner(issuer, "br-1", key)
	keys := map[string]*rsa.PublicKey{"br-1": &key.PublicKey}

	pub := newFeedPublisher(key, "br-1")
	defer pub.server.Close()
	feed, err := sdk.FetchRevocationFeed(ctx, pub.server.URL, issuer, keys)
	must(err)

	crm := newCRM(keys, feed)
	bulk := newBulkAPI(keys, feed)
	defer crm.Close()
	defer bulk.Close()

	real := time.Now()
	business := time.Date(2026, 6, 24, 14, 0, 0, 0, time.UTC) // a Wednesday, 14:00
	threeAM := time.Date(2026, 6, 24, 3, 0, 0, 0, time.UTC)
	setClock(business)

	// Mint the tokens (in-process, so we control TTL + window precisely).
	mintBroad := func(aud, scope string) string {
		t, e := signer.IssueClaims("svc:salesforce-connector", &delegation.ActClaim{Sub: "app:drift"},
			[]string{scope}, aud, &delegation.Constraints{}, real.Add(24*time.Hour), real)
		must(e)
		return t
	}
	hours := &delegation.TimeWindow{StartMin: 9 * 60, EndMin: 17 * 60, TZ: "UTC"}
	mintLegant := func(issuedAt time.Time, ttl time.Duration) (string, string) {
		c := &delegation.Constraints{Tools: []string{"read_record"}, Resources: []string{"contacts"}, TimeWindow: hours}
		t, e := signer.IssueClaims("user:rep-jordan", &delegation.ActClaim{Sub: "agent:revops-copilot"},
			[]string{"crm:read"}, crmAud, c, issuedAt.Add(ttl), issuedAt)
		must(e)
		return t, jtiOf(t)
	}

	broadCRM := mintBroad(crmAud, "crm:read")
	broadBulk := mintBroad(bulkAud, "bulk:export")
	legant, legantJTI := mintLegant(real, 15*time.Minute)
	stale, _ := mintLegant(real.Add(-16*time.Minute), 15*time.Minute) // already expired

	banner("OAuth breach replay — the Salesloft–Drift / UNC6395 theft, on real Legant-guarded services")
	fmt.Println("  The stolen integration token is replayed against a CRM + its Bulk API. Same theft, two tokens.")

	section("1. THE STOLEN BROAD OAuth TOKEN  (what UNC6395 actually had)")
	rep("read a few contacts (looks normal)", crm.URL+"/query", broadCRM)
	rep("BULK-EXPORT every record", crm.URL+"/jobs/query", broadCRM)
	rep("harvest secrets from a support case", crm.URL+"/sobjects/Case", broadCRM)
	rep("pivot to the Bulk API", bulk.URL+"/jobs", broadBulk)
	fmt.Println("    💥 50k rows exfiltrated + live AWS/Snowflake creds harvested → the breach spreads,")
	fmt.Println("       and the token stays valid ~10 days (revocable only org-wide).")

	section("2. THE LEGANT ON-BEHALF-OF TOKEN  (same theft, replayed)")
	rep("the legitimate call: read contacts, in hours", crm.URL+"/query", legant)
	rep("attacker tries BULK-EXPORT", crm.URL+"/jobs/query", legant)
	rep("attacker tries to harvest case secrets", crm.URL+"/sobjects/Case", legant)
	rep("attacker replays it against the Bulk API", bulk.URL+"/jobs", legant)

	section("3. Dwell time: the stolen Legant token replayed 16 minutes later")
	rep("replay after the 15-min TTL (UNC6395 dwelled ~10 DAYS)", crm.URL+"/query", stale)

	section("4. Off-hours: the same token replayed at 03:00")
	setClock(threeAM)
	rep("replay at 03:00, outside the business-hours window", crm.URL+"/query", legant)
	setClock(business)

	section("5. One signed-feed entry kills it — not an org-wide OAuth revoke")
	pub.revoke(legantJTI)
	must(feed.Refresh(ctx))
	rep("the revoked token, replayed in-hours", crm.URL+"/query", legant)

	fmt.Println()
	banner("Done — the breach that took ~10 days to contain is refused offline, per request")
	fmt.Println("  Same theft, different token: no bulk export, no secret-bearing records, no audience pivot,")
	fmt.Println("  minutes not days of life, a business-hours window, and a one-entry offline kill — all enforced")
	fmt.Println("  by the shipped Legant middleware (`legant snippet`), no callback. (The theft still happens;")
	fmt.Println("  the blast radius is what changes.)")
}

func rep(label, url, token string) {
	st, body := get(url, token)
	mark := "✅"
	if st >= 400 {
		mark = "❌"
	}
	fmt.Printf("    %s %-50s -> %d  %s\n", mark, label, st, oneline(body))
}

func get(url, token string) (int, string) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 502, "unreachable"
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
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
	if len(s) > 58 {
		s = s[:58] + "…"
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
