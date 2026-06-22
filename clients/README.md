# Legant client SDKs

Resource-server SDKs that verify and authorize Legant delegation tokens
**offline** — no callback to Legant, no database. Any service that accepts agent
tokens (a REST API, an MCP server) imports one of these and is done.

| Language | Package | Runtime deps | Verify | Authorize (PDP) | Tier-B revocation feed |
|---|---|---|---|---|---|
| **Go** | [`sdk`](../sdk) (`github.com/legant-dev/legant/sdk`) | golang-jwt | ✓ | ✓ | ✓ |
| **TypeScript / Node** | [`typescript/`](typescript) (`@legant/sdk`) | none (built-in `crypto`) | ✓ | ✓ | ✓ |
| **Python** | [`python/`](python) (`legant-sdk`) | `cryptography` | ✓ | ✓ | ✓ |

All three do the same thing: RS256 + `kid` + `iss` + `aud` + `exp` verification
(requiring an `act` chain — a delegation token, not a plain access token), the
full constraint PDP (max amount, category / tool / resource allow-lists with the
deny-all sentinel, and time windows), provenance rendering, and the signed
`/.well-known/revoked` feed client (monotonic-version anti-rollback, fail-open to
TTL by default).

## Conformance — the three cannot drift

[`conformance/`](conformance) holds **golden vectors minted by the real Go
signer** (`vectors.json`): valid/expired/wrong-audience/tampered tokens, every
PDP dimension, audience-canonicalization variants, and a revocation-feed sequence
(revoke → rollback-rejected → un-revoke). Each SDK runs the **same** vectors, so
a behavioral divergence fails a test in that language.

```bash
go run ./clients/conformance/gen          # regenerate vectors.json (fresh key)
go test ./clients/conformance/            # Go SDK vs vectors
cd clients/typescript && npm install && npm test     # TS SDK vs vectors
cd clients/python     && python3 -m unittest discover -s tests   # Python SDK vs vectors
```
