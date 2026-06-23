# Getting started: bound your first agent

This walks the whole loop end to end: define what an agent may do, mint a token,
enforce it at a real HTTP endpoint, and revoke it. It runs fully offline. No
database, no Docker, no signup, just Go.

If you would rather watch it run first, then read:

```bash
make demo-protect
```

That runs every step below against a real chi server and prints the result.

## 0. Install

```bash
git clone https://github.com/legant-dev/legant
cd legant
go build -o legant ./cmd/legant      # or: go install github.com/legant-dev/legant/cmd/legant@latest
```

## 1. Define what the agent may do

Authority lives in a `legant.grants.yaml` file you can review in a pull request.
Scaffold one:

```bash
./legant init grants
```

For this walkthrough use the ready-made grant in
[`examples/protect-your-endpoint/grants.yaml`](../examples/protect-your-endpoint/grants.yaml):

```yaml
version: 1
audience: warehouse://analytics
grants:
  - name: alice-warehouse
    principal: user:alice                 # the human
    agent: agent:analytics-copilot         # the agent acting for her
    scopes: [warehouse:query]
    audience: warehouse://analytics        # the resource server this token is for
    constraints:
      resources: [sales, finance]          # may query only these schemas
```

That reads: alice lets her analytics copilot run `warehouse:query`, but only on
the `sales` and `finance` schemas. Every field is documented in
[GRANTS.md](GRANTS.md).

## 2. Lint and apply

`apply` is idempotent. It writes a local signing setup into `.legant/` (a key, a
public JWKS, and a signed revocation feed) and mints one signed token per grant.
No Postgres.

```bash
./legant lint  -f examples/protect-your-endpoint/grants.yaml
./legant apply -f examples/protect-your-endpoint/grants.yaml
```

```
initialized offline setup in .legant (key.pem, jwks.json, feed.jwt). Add it to .gitignore
  + alice-warehouse              agent:analytics-copilot -> warehouse://analytics  (.legant/alice-warehouse.jwt)

applied: 1 grant(s), 1 token(s) minted
```

The token is at `.legant/alice-warehouse.jwt`. Inspect the rule it carries with
`./legant show --token-file .legant/alice-warehouse.jwt`.

## 3. Ask who can do what, offline

`who-can` answers authorization questions straight from the grants file, with no
running server:

```bash
./legant who-can -f examples/protect-your-endpoint/grants.yaml --scope warehouse:query --resource finance
#   ✓ alice-warehouse  user:alice -> agent:analytics-copilot  (aud warehouse://analytics)

./legant who-can -f examples/protect-your-endpoint/grants.yaml --scope warehouse:query --resource hr
#   no declared grant permits scope="warehouse:query" resource="hr"
```

## 4. Enforce it at your own endpoint

A resource server verifies the token and the constraints offline, with no
callback to Legant. [`examples/protect-your-endpoint/main.go`](../examples/protect-your-endpoint/main.go)
is a complete chi server that reads the public keys and the signed feed straight
from `.legant/`. Run it:

```bash
go run ./examples/protect-your-endpoint &     # listens on :8080, reads ./.legant
TOKEN=$(cat .legant/alice-warehouse.jwt)
```

Call it as the agent:

```bash
curl -H "Authorization: Bearer $TOKEN" 'localhost:8080/query?schema=finance'
#   ok, asked by user:alice -> agent:analytics-copilot

curl -i -H "Authorization: Bearer $TOKEN" 'localhost:8080/query?schema=hr'
#   HTTP/1.1 403 Forbidden          (hr is not in the grant's [sales, finance])
```

The allow and the deny are both decided from the token alone. The server never
calls back to an issuer.

To generate this starter for your own framework instead of using the example:

```bash
./legant init resource-server --framework go-chi   # also: express, fastify, fastapi, flask, go-nethttp, mcp-go
```

The generated file defaults to fetching the JWKS and revocation feed from your
issuer's URLs. For the offline loop here, point it at the local files the way
`examples/protect-your-endpoint/main.go` does (`sdk.ParseJWKS` and
`sdk.ParseRevocationFeed` reading `.legant/jwks.json` and `.legant/feed.jwt`).

## 5. Revoke it

Kill the token. The resource server re-reads the signed feed when it starts, so
restart it and try again:

```bash
./legant revoke --token-file .legant/alice-warehouse.jwt
#   revoked <jti>, published feed version 2

# restart the server, then:
curl -i -H "Authorization: Bearer $TOKEN" 'localhost:8080/query?schema=finance'
#   HTTP/1.1 401 Unauthorized        (token revoked, offline, via the signed feed)
```

Revocation is tiered. A gateway can check per call; a resource server polling the
signed feed sees it within the refresh interval; and the token's own short TTL is
always the backstop. See [REVOCATION.md](REVOCATION.md).

## Where to go next

- Add more limits to the grant (a spend cap, allowed tools, a time-of-day
  window) and re-run. Every field is in [GRANTS.md](GRANTS.md).
- Understand the model (sub/act tokens, attenuation, offline verification):
  [CONCEPTS.md](CONCEPTS.md).
- Have an agent fetch a token from a running issuer via RFC 8693 instead of the
  offline `apply`: [AGENT_AUTHOR.md](AGENT_AUTHOR.md).
- Put an MCP server you do not control behind the gateway: [GATEWAY.md](GATEWAY.md).
- Govern a coding agent (Claude Code, Codex, opencode) with the same token:
  [CLAUDE_CODE.md](CLAUDE_CODE.md).
- Run the issuer as a service for production token exchange: see the README's
  "Run the issuer" section.

Legant complements your existing controls (RBAC, SPIFFE, OPA, Kyverno) rather
than replacing them, and it bounds the blast radius of a compromised or
prompt-injected agent rather than preventing the compromise. It answers a
question those tools do not: on whose behalf is this agent acting, and bounded
how.
