# Protect your own endpoint

A complete, runnable loop that bounds an agent and enforces it at your own HTTP
endpoint, fully offline. No database, no Docker, no signup: just `go`.

```bash
make demo-protect
# or: ./examples/protect-your-endpoint/run.sh
```

It defines a grant, mints a signed token, and shows the three outcomes that
matter: an allowed call, a call denied by a constraint, and a call denied after
the token is revoked.

```
2. Apply the grant (mints a signed token into .legant/, no database)
   + alice-warehouse  agent:analytics-copilot -> warehouse://analytics  (.legant/alice-warehouse.jwt)

4. Start the resource server and call it with the agent's token
   allow  (schema=finance): ok, asked by user:alice -> agent:analytics-copilot
   deny   (schema=hr):      403 (not in the grant: [sales, finance])

5. Revoke the token, restart the server, call again
   deny   (schema=finance): 401 (token revoked, killed offline via the signed feed)
```

## What the pieces are

- [`grants.yaml`](grants.yaml) declares the authority: alice lets her analytics
  copilot run `warehouse:query`, but only on the `sales` and `finance` schemas.
- [`main.go`](main.go) is the resource server. It reads the public keys and the
  signed revocation feed straight from the local `.legant/` directory that
  `legant apply` writes, builds a `Verifier`, and enforces the action on every
  request. This is the same SDK middleware `legant snippet go-chi` prints,
  pointed at local files instead of issuer URLs.

## Do it by hand

```bash
go build -o legant ./cmd/legant

# 1. Define and mint. `apply` writes keys + a JWKS + a signed feed into .legant/
#    and mints one token per grant. No Postgres.
./legant apply -f examples/protect-your-endpoint/grants.yaml

# 2. Ask the grants file directly, offline, who may do what.
./legant who-can -f examples/protect-your-endpoint/grants.yaml \
  --scope warehouse:query --resource finance     # allowed
./legant who-can -f examples/protect-your-endpoint/grants.yaml \
  --scope warehouse:query --resource hr          # no grant permits it

# 3. Run the resource server (reads ./.legant by default).
go run ./examples/protect-your-endpoint &

# 4. Call it as the agent.
TOKEN=$(cat .legant/alice-warehouse.jwt)
curl -H "Authorization: Bearer $TOKEN" 'localhost:8080/query?schema=finance'  # ok
curl -H "Authorization: Bearer $TOKEN" 'localhost:8080/query?schema=hr'       # 403

# 5. Kill the token. Restart the server so it re-reads the feed, then retry.
./legant revoke --token-file .legant/alice-warehouse.jwt
# (restart the server)
curl -H "Authorization: Bearer $TOKEN" 'localhost:8080/query?schema=finance'  # 401 revoked
```

The server reads its setup from `.legant/`. Override with `LEGANT_DIR`,
`LEGANT_ISSUER`, `LEGANT_AUDIENCE`, or `LEGANT_ADDR`.

## Going further

- Add more limits to the grant (a spend cap, allowed tools, a time-of-day
  window) and re-run: see [docs/GRANTS.md](../../docs/GRANTS.md) for every field.
- Generate this starter for your own framework:
  `legant init resource-server --framework go-chi` (also express, fastify,
  fastapi, flask, go-nethttp, mcp-go). It defaults to fetching the JWKS and feed
  from your issuer's URLs; point it at local files (as `main.go` here does) for
  the offline loop.
- For an MCP server you do not control, put it behind the
  [gateway](../../docs/GATEWAY.md) instead.
