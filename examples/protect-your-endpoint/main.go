// A Legant-protected resource server, wired to the OFFLINE local setup that
// `legant apply` writes into .legant/ (keys, JWKS, signed revocation feed).
//
// It loads the public JWKS and the signed revocation feed straight from disk
// (no issuer to reach, no database), builds a Verifier, and enforces the
// delegated action on every request. This is the same SDK middleware that
// `legant snippet go-chi` prints, pointed at local files instead of URLs.
//
//	go run ./examples/protect-your-endpoint        # reads ./.legant by default
//
// Override with env: LEGANT_DIR, LEGANT_ISSUER, LEGANT_AUDIENCE, LEGANT_ADDR.
package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"github.com/legant-dev/legant/sdk"
)

func main() {
	dir := envOr("LEGANT_DIR", ".legant")
	// The offline issuer that `legant apply` mints under, and THIS resource
	// server's own audience (must match the grant's `audience:`).
	issuer := envOr("LEGANT_ISSUER", "https://legant.local")
	audience := envOr("LEGANT_AUDIENCE", "warehouse://analytics")
	addr := envOr("LEGANT_ADDR", ":8080")

	// 1. The public keys, read from the local JWKS (no issuer to call).
	keys, err := sdk.ParseJWKS(mustRead(filepath.Join(dir, "jwks.json")))
	if err != nil {
		log.Fatalf("parse jwks: %v", err)
	}
	// 2. The signed revocation feed, read from the local file. Re-running the
	//    server picks up later `legant revoke`s (the feed is re-read at startup).
	feed, err := sdk.ParseRevocationFeed(mustRead(filepath.Join(dir, "feed.jwt")), issuer, keys)
	if err != nil {
		log.Fatalf("parse revocation feed: %v", err)
	}
	// 3. A verifier bound to this issuer + audience, checking the feed offline.
	v := sdk.NewVerifier(issuer, audience, keys, sdk.WithRevocationFeed(feed))

	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(sdk.Authenticate(v)) // verify the Bearer token, attach Claims
		// Authorize the delegated action per request: the scope plus the
		// resource the caller is asking for (?schema=...). A token scoped to
		// [sales, finance] is denied for ?schema=hr, all offline.
		r.With(sdk.RequireAction(func(req *http.Request) sdk.Action {
			return sdk.Action{Scope: "warehouse:query", Resource: req.URL.Query().Get("schema")}
		})).Get("/query", func(w http.ResponseWriter, req *http.Request) {
			claims := sdk.MustClaims(req.Context())
			// Provenance() names the human the agent acts for. Log it.
			_, _ = w.Write([]byte("ok, asked by " + claims.Provenance() + "\n"))
		})
	})

	log.Printf("resource server on %s  (issuer=%s audience=%s, keys+feed from %s/)", addr, issuer, audience, dir)
	log.Fatal(http.ListenAndServe(addr, r))
}

func mustRead(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read %s: %v (did you run `legant apply` yet?)", path, err)
	}
	return b
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
