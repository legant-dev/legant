# Agent author guide: getting a delegation token from a live issuer

How an agent (or its developer) exchanges credentials for a short-lived `sub`/`act` delegation token from a running Legant issuer, using RFC 8693 token exchange against `POST /oauth2/token`.

This is the live-issuer path. It needs a running Legant server (Postgres-backed). It is distinct from the offline path (`legant mint`, `legant apply`), which signs tokens from a local key with no server. For the offline loop, see [`GETTING_STARTED.md`](GETTING_STARTED.md).

## What the exchange does

The agent presents two tokens: its own actor token (the agent's credential) and the user's subject token (the user's access token). Legant resolves the delegation chain that authorizes this agent to act for this user, then mints one composite token: `sub` is the user, `act` is the agent. The token is scoped down to the intersection of the delegation's scopes, the subject token's scopes, and whatever scopes the request asked for, and it is bound to a single resource that the delegation permits. The result is an on-behalf-of token that names both parties and carries the delegated action only. For the `sub`/`act` model in detail, see [`CONCEPTS.md`](CONCEPTS.md).

The delegation must already exist before the exchange. A user records it out of band by granting consent (see [Where consent fits](#where-consent-fits)). If no delegation authorizes the agent-for-user pair, the exchange returns `403 invalid_grant`.

## The request

`POST /oauth2/token`, form-encoded. The handler (`internal/auth/token_exchange.go`) reads exactly these parameters:

```bash
curl -s -X POST https://issuer.example.com/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  --data-urlencode "subject_token=USER_SUBJECT_TOKEN_HERE" \
  --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  --data-urlencode "actor_token=AGENT_ACTOR_TOKEN_HERE" \
  --data-urlencode "actor_token_type=urn:legant:params:oauth:token-type:agent-token" \
  --data-urlencode "scope=invoices:read invoices:pay" \
  --data-urlencode "resource=https://api.example.com/mcp/billing"
```

Parameter notes, all verified against the handler:

- `grant_type` must be `urn:ietf:params:oauth:grant-type:token-exchange`. The token endpoint branches on this value before its normal OAuth path.
- `subject_token` (required) is the user's token. `actor_token` (required) is the agent's token and is itself the agent's credential: the agent named in the `act` claim is whoever that token authenticates as.
- `subject_token_type` is optional. If present it must be `urn:ietf:params:oauth:token-type:access_token`; any other value is rejected with `invalid_request`.
- `actor_token_type` is optional. If present it must be `urn:legant:params:oauth:token-type:agent-token` (a Legant-specific URN, not an IETF one); any other value is rejected.
- `scope` is a space-separated list. The issued scopes are the intersection of this list, the delegation's scopes, and the subject token's scopes. An empty intersection returns `invalid_scope`. Omitting `scope` attenuates against an empty request, which yields no scopes, so send the scopes you actually want.
- `resource` (required) is a single RFC 8707 resource indicator. Exactly one value is required: zero values returns `invalid_target`, more than one value is rejected to avoid audience confusion. The resource is canonicalized and must match one entry in the delegation's `resources` constraint; an empty `resources` list on the delegation denies all audiences.

## The response

On success the handler returns `200` with JSON:

```json
{
  "access_token": "eyJhbGciOiJSUzI1Ni...COMPOSITE_DELEGATION_JWT",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "invoices:read invoices:pay"
}
```

- `issued_token_type` is the access-token URN above.
- `token_type` is `Bearer`.
- `expires_in` is seconds until expiry. The lifetime is clamped to the smaller of the issuer's configured TTL and the delegation's own expiry, so it can be shorter than the configured TTL.
- `scope` echoes the effective (attenuated) scopes that were actually granted.

The `access_token` is a delegation JWT. Decoded, it carries `sub = user` and `act = { "sub": agent }` (the `act` claim names the acting agent; a multi-hop chain nests further `act` claims). `aud` is the canonicalized resource you requested. Verify it offline at the resource server with the Legant SDK; the issuer also records its `jti` for revocation.

## Where consent fits

The exchange handler itself runs no interactive consent step. It assumes the delegation already exists and fails closed if it does not.

The delegation is created earlier by the user, through a separate session-authenticated endpoint: `POST /consent/delegate` (`internal/server/server.go`). The request requires a logged-in user session, a same-origin request, and a valid CSRF token, and its JSON body is `{ "agent_id", "scopes", "resource", "constraints", "ttl_seconds" }`. The user must belong to the agent's organization. On success it records a consent receipt and the root delegation in one transaction and returns `{ "consent_id", "delegation_id" }`. That stored delegation is what a later token exchange resolves and attenuates against.

So the order is: user consents once (`/consent/delegate`), then the agent exchanges tokens as often as it needs (`/oauth2/token`), each exchange bounded by that consent.

## See also

- [`CONCEPTS.md`](CONCEPTS.md): the `sub`/`act` delegation model.
- [`GETTING_STARTED.md`](GETTING_STARTED.md): the offline `legant mint` / `legant apply` path (no server).
- [`GRANTS.md`](GRANTS.md): the declarative grants file and constraints.
