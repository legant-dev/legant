# Legant resource-server SDK

`github.com/legant-dev/legant/sdk`

A self-contained client for **resource servers** and **MCP servers** that accept
Legant delegation tokens. It verifies a composite `sub`/`act` token against the
issuer's published keys and authorizes a request's scope and constraints —
entirely **offline**, with no callback to Legant and no dependency on Legant's
internal packages. Its only dependency is [`golang-jwt`](https://github.com/golang-jwt/jwt).

## Install

```bash
go get github.com/legant-dev/legant/sdk
```

## Use

```go
package main

import (
	"context"
	"net/http"
	"strings"

	"github.com/legant-dev/legant/sdk"
)

func main() {
	ctx := context.Background()

	// Fetch the issuer's signing keys once (refresh periodically in production).
	keys, err := sdk.FetchJWKS(ctx, "https://auth.example.com/.well-known/jwks.json")
	if err != nil {
		panic(err)
	}
	// audience MUST be this resource server's own identifier.
	v := sdk.NewVerifier("https://auth.example.com", "https://finance-api.example/", keys)

	http.HandleFunc("/expenses", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

		// Verify: RS256 under the token's kid, plus issuer, audience, and expiry.
		// Fails closed on an unknown kid and requires an act chain (a delegation
		// token, not a plain access token).
		claims, err := v.Verify(tok)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Authorize the concrete action: scope plus every constraint the token
		// carries (max amount, category/tool/resource allow-lists).
		if err := claims.Authorize(sdk.Action{Scope: "expenses:submit", Amount: 120, Category: "travel"}); err != nil {
			http.Error(w, "forbidden: "+err.Error(), http.StatusForbidden)
			return
		}

		// claims.Provenance() == "user:alice -> agent:assistant"
		w.Write([]byte("ok, acting for " + claims.Provenance()))
	})

	http.ListenAndServe(":9000", nil)
}
```

## What `Verify` checks

| Check | Behavior |
|---|---|
| Algorithm | RS256 only (no `none`, no alg confusion) |
| Key | Selected by the token's `kid`; **unknown kid fails closed** |
| Issuer | Must equal the configured issuer |
| Audience | Must contain this resource server's audience |
| Expiry | Required and enforced |
| Delegation | A non-nil `act` claim is required |

`Authorize` then enforces the required scope and the `cnst` constraints. Together
they are the resource server's policy decision point — no network call needed.

## Static keys

If you distribute keys out of band instead of fetching JWKS, build the verifier
directly:

```go
v := sdk.NewVerifier(issuer, audience, map[string]*rsa.PublicKey{kid: pub})
```

## Drift protection

The SDK intentionally re-implements the minimal claim shape rather than importing
Legant's internals, so external consumers get a tiny dependency surface. A
compatibility test (`sdk/verifier_test.go`) mints tokens with Legant's real
internal signer and verifies them through this SDK, failing if the wire format
ever diverges.
