# Legant Threat Model

Legant issues, attenuates, and audits **delegated** authority for AI agents. Its
security rests on a small set of invariants enforced at well-defined choke points.
This document records the delegation-specific threats and the mitigations baked
into the design — most surfaced and hardened through adversarial review of each
milestone.

## Trust model

- **Authorization server (`legant serve`)** holds the signing keys and the
  delegation/consent/revocation state. Compromise of its database or
  key-encryption secret is full compromise.
- **Resource servers / MCP upstreams** hold only Legant's *public* keys (JWKS).
  They verify and enforce tokens **offline** — they never need Legant's secrets
  or a callback at request time.
- **Agents** are non-human principals authenticated by an opaque agent token or
  (for the exchange) by presenting their own token as the actor.
- **Delegation, not impersonation:** every minted token has `sub` = the user and
  a non-nil `act` chain naming the acting agent(s). A token never claims to *be*
  the user.

## Threats and mitigations

| Threat | Vector | Mitigation |
|---|---|---|
| **Act-chain forgery** | An agent claims to act as another agent | The actor token *is* the agent's credential; `act` is derived from it, so `act=agent:X` requires agent X's token. |
| **Cross-user mint** | Agent presents user B's subject token against user A's delegation | The subject user id comes from the subject token, and `ResolveGrantChain` keys the delegation lookup on *that* user — no delegation, no token. (Tested.) |
| **Scope escalation** | Stale/broad delegation, or a narrow subject token | `effective = Attenuate(subjectScopes, Attenuate(grantScopes, requested))` — bounded by **both** the delegation and the subject token. Re-delegation enforces monotonic attenuation (child ⊆ parent). |
| **Audience confusion** | `resource=victim-api`, or multiple `resource` params | A single RFC 8707 resource indicator, canonicalized, required to be in the delegation's `Resources` (empty list = deny). Multiple resources → `invalid_target`. |
| **Unkillable self-contained token** | A signed JWT is valid until expiry | Tiered revocation: every minted token is recorded by `jti` and revoking a delegation cascades to its live tokens; **(A)** the gateway and introspection consult the revocation store **per call** (effect is immediate); **(B)** a signed `/.well-known/revoked` feed lets offline resource servers reject revoked tokens within their feed-refresh interval; **(C)** the token's short TTL (5m default, configurable) is the always-present backstop for a server doing neither. See *Revocation tiers* below. |
| **Key compromise / rotation** | A retired key still trusted | kid-aware verifier selects the JWK by header `kid` and fails closed on unknown kid; removing a key from the JWKS invalidates its tokens. Private keys are envelope-encrypted at rest with the kid bound as AAD. |
| **Confused deputy (gateway)** | Gateway forwards the inbound token downstream | The gateway **mints a fresh** token bound to the upstream's audience, narrowed to the one tool, exp clamped to the inbound exp — the inbound token is never forwarded. Per-upstream inbound audience prevents cross-upstream replay. |
| **SSRF** (CIMD / JWKS / metadata fetch) | Attacker-controlled URL → cloud metadata / internal hosts | Allow-list dialer: only globally-routable, non-private addresses, with explicit blocks for CGNAT / NAT64 / 6to4-embedded metadata; checked on the *resolved* IP and pinned for the dial (anti-rebind); https-only; redirect + size + time caps. |
| **DCR privilege escalation** | Dynamic registration mints a `client_credentials`/`token-exchange` client | Registration is gated by a single-use initial access token and restricted to `authorization_code`/`refresh_token` grants and `code` responses. |
| **CIMD client shadowing** | An https-URL client id resolves to an attacker-hosted doc | The database is consulted first; CIMD is a fallback only on miss, and the document must self-identify with the same URL. |
| **Forged tenant / user identity** | Spoofed `X-User-ID` / `X-Tenant-ID` headers | Removed entirely. Identity derives from the authenticated `Principal` (session / bearer / agent token); org scope from `org_members`. |
| **Cross-tenant access** | Admin of one org reaches another's resources | `/api/v1` is authenticated; global resources require superadmin; org-scoped resources (agents) are filtered to the caller's orgs on both read and write paths. |
| **Introspection info leak** | Anonymous caller reads a token's `sub`/`act`/scope | `/oauth2/introspect` requires authentication. |
| **Token-mint amplification** | Replay to mint unlimited tokens | The token and registration endpoints are rate-limited (per real client IP — the spoofable `X-Forwarded-For` rewrite is disabled). |
| **Tamper / desync at the gateway** | JSON parser-differential, hop-by-hop header smuggling | The gateway rejects any request whose JSON has duplicate keys at any depth (so the upstream can't resolve a different tool than was authorized) and strips hop-by-hop/framing headers; bodies are size-capped. |
| **Audit tampering** | Editing/deleting/reordering an audit row to hide an action | `audit_events` is hash-chained in a concurrency-safe order (each row commits to its predecessor via an in-DB SHA-256 over its immutable fields, sequenced inside the chaining lock); `legant audit verify` recomputes the chain and reports the first edited/reordered/mid-chain-deleted row. Tail truncation and a full re-seal don't break the chain internally, so verify also compares against the last **anchor** it pinned (event count + head hash) and flags a shrunken count or rewritten prefix. |
| **CSRF on state-changing UI POSTs** | Cross-site form auto-submitting to `/account/delegations/{id}/revoke` or `/consent/delegate` | Three layers: `SameSite=Lax` session cookies; an `Origin`/`Referer` host check; and a **session-bound synchronizer token** (HMAC of the session id) delivered in a readable companion cookie and required back as a `csrf_token` form field or `X-CSRF-Token` header — a cross-site page can neither read the cookie (same-origin policy) nor set the custom header cross-origin. |
| **Constraint widening on re-delegation** | Re-delegate with a disjoint allow-list to escape a restriction | Intersecting two disjoint non-empty allow-lists yields a deny-all sentinel, never the empty (unrestricted) list — a child can never gain a category/tool/resource/weekday the parent lacked. |
| **Off-hours / runaway use** | Using a delegation outside its intended window, or minting unboundedly | A `time_window` constraint (weekday + minute-of-day range in a tz) is enforced offline by the resource server and SDK; a `rate` cap (per rolling hour) is enforced by Legant at token-exchange time against the recorded mint history. |

## Defense posture

- **Verify before log / trust:** provenance is recorded only for tokens that
  verified; the resource server enforces from the signed token alone.
- **Fail closed:** unknown kid, unknown jti, empty resource allow-list, unknown
  tool, and missing constraints all deny rather than allow.
- **Transactional integrity:** a minted exchanged-token row and its audit record
  commit together, or neither does.

## Revocation tiers

"Offline enforcement" and "instant revocation" are in tension only if one verifier
must be **both**. Legant resolves this honestly by letting each resource server
pick its point on the latency/coupling curve — the worst case is never worse than
the token TTL:

| Tier | How the RS checks | Kill latency | Coupling to Legant |
|---|---|---|---|
| **A — per-call** | Gateway / introspection consult the revocation store on each request | Immediate | Online (a lookup per call) |
| **B — signed feed** | RS pulls `GET /.well-known/revoked` on a timer and checks `jti` in memory | ≤ feed refresh interval | Periodic pull only (no per-call callback) |
| **C — TTL only** | RS verifies the signed token and nothing else | ≤ token TTL (5m default, configurable) | None (fully air-gapped) |

The **feed** (Tier B) is a JWS-signed, TTL-bounded snapshot of revoked-but-unexpired
`jti`s, signed with the **same key as the JWKS** — so it introduces no new trust
root. Three properties make it safe:

- **It can only ever miss a revoke, never forge one.** A stale or unreachable feed
  falls back to Tier C (TTL); it can never *un-expire* or *un-revoke* a token, and
  the token's own expiry is the always-present floor.
- **It is small and bounded.** The set is `revoke-rate × max-TTL` in size (revoked
  tokens drop off the feed the moment they expire), so a published snapshot stays
  kilobytes regardless of total tokens issued.
- **It resists rollback/replay.** Each feed carries a monotonic `ver`; the SDK
  client rejects a regressing version, so a replayed older feed can't resurrect a
  revoked token. The optional `WithFeedFailClosed(maxStaleness)` couples
  availability to freshness for high-assurance servers; the default fails open to
  Tier C rather than rejecting valid tokens on a feed outage.

The standalone SDK ships a `RevocationFeed` client (`FetchRevocationFeed` +
`StartPolling`) and a `WithRevocationFeed` verifier option, so a Go resource server
opts into Tier B in two lines and needs no Legant dependency or callback.

## Residual risks (tracked)

- **Pure bearer tokens** are theft-vulnerable until expiry (mitigated by short
  TTL + revocation); sender-constrained tokens (DPoP/mTLS) are future work.
- **Per-process rate limiting** needs a shared backend (Redis / LISTEN-NOTIFY)
  for strict guarantees across replicas (the per-delegation rolling-hour cap is
  DB-backed and exact; only the per-IP endpoint limiter is per-process). Keystore
  reload is live (each process reloads on `SIGHUP` + a 5-minute ticker), so a
  rotation propagates without a restart, though replicas pick it up independently
  rather than in lockstep.
- **Audit is hash-chained and anchored** (`legant audit verify` pins an
  `audit_anchors` checkpoint each run and checks the next run against it). This
  catches tail truncation and re-seal across runs. An attacker with write access
  to **both** `audit_events` and `audit_anchors` can forge both *in the database*
  — so for true off-box tamper-evidence, `legant audit anchor` now **signs** a
  checkpoint with the active key (verifiable under the JWKS) and exports it
  (`--out file` / `--webhook url`) to an append-only / separate-privilege store;
  `legant audit anchor --check FILE` then validates the live chain against that
  trusted off-box copy, detecting truncation or a rewritten prefix even when the
  database's own anchor table was tampered. Audit-event retention
  (`--audit-retention`) prunes the chain's
  oldest rows and records a **watermark** (`audit_chain_state`) so `legant audit
  verify` keeps validating the remaining chain and still detects tampering beyond
  the pruned prefix — the two are no longer mutually exclusive.
- **CSRF protection on the UI** is now three layers — `SameSite=Lax`, an
  `Origin`/`Referer` check, and a session-bound synchronizer token (see the table
  above) — so it is no longer a residual gap.
- **Offline revocation latency** is bounded by the resource server's chosen tier
  (see below), never worse than the token TTL. We do **not** claim zero-latency
  offline revocation; an air-gapped verifier that polls nothing is still bounded
  by the token's short TTL (5m by default, configurable via
  `LEGANT_TOKEN_EXCHANGE_ACCESS_TOKEN_LIFESPAN` — there is no hard ≤5m ceiling, so
  raising the lifespan enlarges this backstop). Full design in
  [`REVOCATION.md`](REVOCATION.md).
- **`/metrics` is unauthenticated** by design (scrapers carry no session). It
  exposes aggregate request and delegation-activity counters labeled by bounded
  dimensions (route pattern, not raw path; outcome, not subject) — no token
  contents — but must still be restricted to the cluster, never public Ingress.
- **Data retention** (`legant maintenance prune`) deletes only expired/dead
  operational rows; audit-event purging is opt-in and off by default so the audit
  trail is never silently truncated.
