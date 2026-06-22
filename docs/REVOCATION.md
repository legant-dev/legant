# Revocation

How Legant kills a token that is already signed and in the wild.

## The tension

A delegation token is a self-contained, RS256-signed JWT. By construction it is
*valid until it expires* — any holder of the issuer's public key can verify it
with **no callback** to Legant. That is the whole point of offline authorization:
a resource server should not have to phone home on every call. But it is also the
problem: once minted, the token is unkillable by signature alone until its `exp`
passes.

Offline enforcement and instant revocation are only in tension if **one verifier
must be both**. Legant does not pretend a single mode squares that circle. Instead
it offers three tiers with explicit, different trade-offs, and lets you choose per
verifier. A token id (`jti`) is recorded for every minted delegation token, and
revocation is a denylist over those `jti`s — surfaced synchronously (Tier A), as a
signed offline feed (Tier B), or not at all beyond the token's own short TTL
(Tier C).

## Tiers

| | How | Latency | Coupling |
|---|---|---|---|
| **A — per-call store check**<br>(gateway + introspection) | The MCP gateway and the RFC 7662 introspection endpoint query the Postgres revocation store for the token's `jti` on **every call**. `Store.IsActive` runs `SELECT revoked_at, expires_at FROM exchanged_tokens WHERE jti=$1` and returns active only if the row exists, `revoked_at IS NULL`, and `exp` has not passed. An unknown `jti` is **not active** (fail closed). At the gateway this runs for *every* inbound token, not only `act`-bearing ones. | **Immediate.** Synchronous DB round-trip per call (one indexed point-read). The next call after the `UPDATE ... SET revoked_at=now()` commits is rejected. | **Tightest.** Every verified call requires the issuer's database to be reachable. A store error is treated as not-active: the gateway logs `RevocationCheckErrorsTotal` and rejects; introspection returns `active=false`. |
| **B — signed `/.well-known/revoked` feed**<br>(polled by the SDK, offline) | The issuer publishes a JWS-signed snapshot of revoked-but-unexpired `jti`s. The resource-server SDK pulls it on a timer and checks token ids against an in-memory set, with **no per-request callback**. Server: `SELECT jti FROM exchanged_tokens WHERE revoked_at IS NOT NULL AND expires_at > now() ORDER BY jti`, stamped with `nextval('revocation_feed_version')` and signed RS256 under the active JWKS `kid`. SDK: `RevocationFeed.Refresh` verifies the JWS (issuer + expiry required), rejects a regressing version, and atomically swaps the set; `Verify` consults it when `WithRevocationFeed` is set. | **Bounded by the poll interval.** A revoke takes effect at the resource server within the SDK's polling interval, and never later than the token's own short expiry (the backstop). Server-side, the signed bytes are reused for `cacheFor` (5s) between rebuilds. | **Loose.** Entirely offline at request time — no callback per request. The resource server only reaches the feed URL on its polling timer; verification between polls is fully offline. |
| **C — TTL-only**<br>(no feed configured) | Without `WithRevocationFeed`, the SDK does **no** revocation check: `Verify` validates RS256 signature, issuer, audience, expiry, and the presence of an `act` claim, then returns. Revocation is bounded solely by the token's short TTL. This is also the fallback the default fail-open mode reverts to when a feed is stale or unreachable. | **Up to the token's full remaining TTL** — the token simply expires. Lifetime is clamped at mint time to `min(now+ttl, grant expiry)`; the default `access_token_lifespan` is **5m**. | **Zero coupling at request time.** Fully offline — no database, no feed. The verifier behaves exactly as it did before the feed feature existed. |

Tier A and Tier B read the **same** `exchanged_tokens` table, so they are
consistent by construction: the feed is just an offline projection of the per-call
denylist.

### The endpoint

```
GET /.well-known/revoked
Content-Type: application/jwt
Cache-Control: public, max-age=5
```

The body is a single RS256-signed compact JWS whose claims are:

```jsonc
{
  "iss":  "https://issuer.example",
  "iat":  1718900000,
  "exp":  1718900060,        // iat + feedTTL (1m)
  "ver":  42,                // monotonic int64; verifiers reject a regress
  "jtis": ["...", "..."]     // sorted []string of revoked, unexpired token ids
}
```

## Tier B in two lines

The resource server fetches the feed once, polls it in the background, and hands
it to the verifier. There is no per-request callback after this.

```go
// keysByKID is the same JWKS map the Verifier uses — no new trust root.
feed, err := sdk.FetchRevocationFeed(ctx, issuer+"/.well-known/revoked", issuer, keysByKID)
if err != nil { /* handle: cannot reach feed at startup */ }
feed.StartPolling(ctx, 10*time.Second, func(err error) { log.Print(err) }) // refresh on a ticker; errors are non-fatal

v := sdk.NewVerifier(issuer, audience, keysByKID, sdk.WithRevocationFeed(feed))
claims, err := v.Verify(token) // offline; returns sdk.ErrRevoked if the jti is in the feed
```

To couple availability to freshness, opt in to fail-closed — `Verify` then rejects
when the feed is staler than the bound:

```go
v := sdk.NewVerifier(issuer, audience, keysByKID,
    sdk.WithRevocationFeed(feed),
    sdk.WithFeedFailClosed(30*time.Second), // default without this is fail-open-to-TTL
)
```

Relevant SDK surface:

- `sdk.FetchRevocationFeed(ctx, feedURL, issuer, keysByKID) (*RevocationFeed, error)` — fetch + verify once.
- `(*RevocationFeed).Refresh(ctx) error` — fetch, verify RS256 under the issuer's `kid`, enforce monotonic version, atomically swap the set.
- `(*RevocationFeed).StartPolling(ctx, interval, onError)` — background refresh on a ticker until `ctx` is cancelled; refresh errors are non-fatal and the previous snapshot is retained.
- `(*RevocationFeed).IsRevoked(jti) bool` — membership test against the latest snapshot.
- `(*RevocationFeed).Staleness() time.Duration` — time since the last successful refresh.
- `sdk.WithRevocationFeed(f)` / `sdk.WithFeedFailClosed(maxStaleness)` — enable Tier B / make it reject on staleness.
- `sdk.ErrRevoked` — sentinel returned by `Verify` when the token id is in the feed.

The feed HTTP client uses a 10s timeout and caps the response body at 8 MiB via
`io.LimitReader`.

## Safety properties

- **A stale or missing feed can only MISS a revocation, never forge one.** The feed
  is an additive denylist; `Verify` only ever *adds* a rejection — it never grants
  on the feed's say-so, and all the normal signature / issuer / audience / expiry
  checks still run first. Token expiry is the always-present backstop.
- **The revoked set stays small.** The build query filters `revoked_at IS NOT NULL
  AND expires_at > now()`, so expired tokens fall out automatically. Set size is
  bounded by revoke-rate × max TTL.
- **No new trust root.** The feed is signed with the **same** key published in the
  issuer's JWKS (`ActiveKID` / `ActiveSigner`, with the `kid` set in the JWS
  header). The SDK verifies it with the same `keysByKID` map the `Verifier`
  already uses.
- **Anti-rollback.** Each feed carries a monotonic `ver` from
  `nextval('revocation_feed_version')`. The SDK rejects a regressing version
  (`revocation feed version regressed … possible rollback`) and keeps its current
  snapshot. The JWS also requires `iss` and `exp`.
- **Default fails OPEN to TTL; fail-closed is opt-in.** Without
  `WithFeedFailClosed`, a stale or unreachable feed reverts to TTL-bounded
  revocation (Tier C) rather than rejecting valid tokens. `StartPolling` treats
  refresh errors as non-fatal and retains the previous snapshot.
- **Deterministic feed.** `jtis` is sorted (`ORDER BY jti`), so a given snapshot
  produces identical output.

## Gateway downstream tokens

The MCP gateway mints fresh, single-tool, audience-bound downstream tokens (≤60s,
clamped to the inbound token's expiry). These are **deliberately not** recorded in
the revocation store or feed. They are ephemeral by design, and revoking the
inbound delegation stops new ones from being minted — `RevokeByDelegation`
cascades to the live inbound tokens, and a whole delegation subtree can be revoked
at once.

## What is NOT claimed

Be precise about the limits so the revocation story stays honest:

- **No zero-latency offline revocation.** "Immediate" applies to **Tier A only** —
  clients that do a synchronous per-call store check (the gateway and
  `/oauth2/introspect`). For Tier B, a revoke propagates within the SDK's poll
  interval plus up to the 5s server-side feed cache (`cacheFor`). Do not generalize
  "instant" to all enforcement modes.
- **An air-gapped verifier is still bounded by the token TTL.** A resource server
  on Tier C (or a Tier B verifier whose feed is stale and not fail-closed) cannot
  learn about a revocation out of band; the token remains valid until it expires.
  The worst case equals the token's remaining TTL.
- **The 5m TTL is a configurable default, not a hard ceiling.**
  `token_exchange.access_token_lifespan` defaults to `5m` and is settable
  (`LEGANT_TOKEN_EXCHANGE_ACCESS_TOKEN_LIFESPAN`). There is no `Validate()`
  enforcing a ≤5m cap — minted tokens are clamped to `min(now+ttl, grant expiry)`,
  so raising the lifespan correspondingly enlarges the Tier-C backstop. Read it as
  "short, configurable TTL (5m by default)," not a guaranteed ≤5m invariant.
- **The feed does not authenticate or authorize — it only denies.** It cannot
  revive an expired token, validate a signature, or grant access. Every positive
  authorization decision still comes from the offline signature, issuer, audience,
  expiry, and `act`/constraint checks.
