# The MCP auth-gateway: bound an MCP server you do not control

Run `legant gateway` in front of an MCP server to enforce delegated authority on
tools you cannot modify.

The gateway is a reverse proxy that sits in front of one or more MCP servers. For
each request it verifies the inbound delegated token, filters `tools/list` down to
the tools the token may call, and authorizes each `tools/call` against the token's
scope and constraints before forwarding it. It mints a fresh, audience-bound
downstream token for the upstream (it never forwards the inbound token, which
closes the confused-deputy hole), and audits and revocation-checks every call. The
sub/act provenance (which human the agent acts for) is preserved end to end. The
model is the same one explained in [CONCEPTS.md](CONCEPTS.md).

Use the gateway when you cannot change the MCP server's code. If you own the
server, prefer the self-hosted SDK path instead: generate a verifier with
`legant snippet mcp-go` (see [GETTING_STARTED.md](GETTING_STARTED.md)) and check
the token in the server itself. That path is fully offline: it verifies from a
published JWKS and a signed revocation feed, with no issuer or database at request
time. The gateway is the opposite tradeoff. It needs a running issuer plus
Postgres (see "What it needs to run" below), and you reach for it precisely when
editing the upstream is not an option.

## A minimal legant.yaml

The gateway reads a `legant.yaml`. One upstream is enough:

```yaml
issuer:
  url: https://auth.example.com   # your running Legant issuer
server:
  host: 0.0.0.0
  port: 8080
gateway:
  upstreams:
    - slug: weather
      # The audience an inbound delegated token MUST carry to be accepted here.
      # Make it unique per upstream so a token bound to one upstream cannot be
      # replayed against another.
      inbound_audience: https://gateway.example.com/mcp/weather
      url: http://weather-mcp.internal:9000/mcp   # the upstream MCP server you do not control
      resource_id: https://weather-mcp.example.com/   # audience of the downstream token the gateway mints
      tool_scopes:
        get_weather: weather:read   # tool name -> scope the token must hold to call it
```

Every tool the upstream exposes that is not listed in `tool_scopes` is invisible
(`tools/list` drops it) and uncallable (`tools/call` returns 403). Add a line per
tool you want to expose.

You can also register upstreams at runtime in the database-backed registry; the
gateway merges that set on top of the static config every 30s. Static config wins
on a slug or inbound-audience collision, so the file is the safe place to pin the
upstreams you depend on.

## What it needs to run

This is not the offline loop. The gateway requires:

| Need | Env var | Notes |
|---|---|---|
| Postgres | `LEGANT_DATABASE_URL` | shares the issuer's database for revocation checks and the audit trail |
| Key-encryption secret | `LEGANT_SECRETS_KEY_ENCRYPTION` | must match the issuer's, so the gateway can read the published signing keys (32+ bytes) |

If `LEGANT_SECRETS_KEY_ENCRYPTION` is unset the gateway falls back to deriving the
key-encryption material from `LEGANT_SECRETS_SYSTEM` (also 32+ bytes), so at least
one of the two must be present, and it must match whatever the issuer uses.
Startup fails closed if neither is set or if the database is unreachable. Unlike
`legant serve`, the gateway does not need the Fosite system secret or the cookie
secret, because it runs no OAuth or session endpoints itself.

```bash
export LEGANT_DATABASE_URL='postgres://legant:...@db:5432/legant?sslmode=require'
export LEGANT_SECRETS_KEY_ENCRYPTION='<32+ bytes, same value the issuer uses>'
legant gateway
#   legant gateway starting  addr=0.0.0.0:8080  upstreams=1
```

The Kubernetes manifests are at
[`deployments/k8s/gateway.yaml`](../deployments/k8s/gateway.yaml) and the Helm
chart at [`deployments/charts/legant`](../deployments/charts/legant) (the
`gateway.upstreams` values render the same ConfigMap shown above).

## Where the config comes from (no --config flag)

`legant gateway` takes no config flag. Run `legant gateway --help` and the only
flag is `--help`. The `legant.yaml` is auto-discovered, in this order:

1. `./` (the current working directory)
2. `/etc/legant`
3. `$HOME/.legant`

The first `legant.yaml` found wins. In the container image the ConfigMap is
mounted at `/etc/legant/legant.yaml`, which is path 2. Locally, dropping a
`legant.yaml` in the directory you launch from is enough. Every value in the file
can also be overridden by its `LEGANT_*` environment variable (for example
`LEGANT_ISSUER_URL`, `LEGANT_SERVER_PORT`).

## Calling a tool through the gateway

The gateway serves each upstream at `/mcp/<slug>`. The caller (the agent) presents
a delegated Bearer token whose audience equals that upstream's `inbound_audience`.
In production the agent mints that token from your issuer via RFC 8693
token-exchange (see [AGENT_AUTHOR.md](AGENT_AUTHOR.md)); set the `resource`
parameter to the upstream's `inbound_audience` so the minted token is bound to
this gateway.

A filtered `tools/list`. The token above only carries `weather:read`, which maps
to `get_weather`, so that is the only tool the agent can discover, even if the
upstream exposes more:

```bash
curl -sS https://gateway.example.com/mcp/weather \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "tools": [
      { "name": "get_weather", "description": "..." }
    ]
  }
}
```

Any tool the token cannot reach is removed from that array before it leaves the
gateway. If the gateway cannot parse the upstream's `tools/list` to filter it (for
example the upstream streamed it), it fails closed and returns an error rather than
leaking the full catalog.

A `tools/call`. The gateway checks the tool against the token's scope and
constraints, then forwards it with a fresh downstream token:

```bash
curl -sS https://gateway.example.com/mcp/weather \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call",
       "params":{"name":"get_weather","arguments":{"city":"Berlin"}}}'
```

Outcomes you will see:

- No or invalid token: `401` with a `WWW-Authenticate` challenge pointing at the
  upstream's protected-resource metadata.
- Revoked token: `401` (revocation is checked on every call).
- A tool not in `tool_scopes`, or one the token's scope/constraints forbid: `403`.
- Allowed: the upstream's response, proxied back (streamed if the upstream
  streams).

## See also

- [CONCEPTS.md](CONCEPTS.md): the delegation model (sub/act tokens, attenuation,
  offline verification) the gateway enforces.
- [CLAUDE_CODE.md](CLAUDE_CODE.md): pointing Claude Code at the gateway over OAuth
  2.1, plus the local guard hook and sub-agent chains.
