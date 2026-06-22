# Legant

Open-source delegated authorization for AI agents. Legant lets an AI agent act on
behalf of a user with authority you can scope, time-box, revoke, and audit. It's
written in Go and ships as a single self-hostable binary.

**Website and live demos:** https://legant-dev.github.io/legant/ ·
**Releases:** https://github.com/legant-dev/legant/releases

## What makes Legant different

A plain OIDC/OAuth server (Keycloak, Ory, Zitadel) can authenticate an agent and
hand it a token. It cannot express *"this agent may act for Alice, but only to
submit travel/meal expenses under $500 for the next hour, and any sub-agent it
spawns can only ever do less."* Legant's core is exactly that:

- **RFC 8693 token exchange → composite `sub`/`act` tokens.** The agent acts
  *on behalf of* the user (`sub` = user, `act` = the agent chain), never *as* the
  user. The full delegation provenance (user → agent → sub-agent) is recorded in
  the token.
- **Constraint policy enforced offline.** Fine-grained limits (max amount,
  categories, tools, resource audiences, and time-of-day/weekday windows) ride
  inside the signed token, so a resource server enforces them from the token
  alone — no callback to Legant. A rolling-hour rate cap is enforced by Legant at
  mint time (it needs shared state a resource server lacks).
- **Monotonic attenuation.** Authority can only ever *narrow* as it is
  re-delegated down a chain; escalation is rejected at delegation time.

The canonical engine for this lives in [`internal/delegation`](internal/delegation)
(pure, unit-tested) and there's a runnable, no-database demo in
[`examples/agent-obo`](examples/agent-obo) (`make demo`) that shows the whole flow
end to end. On top of this, Legant is a full OAuth 2.1 / OpenID Connect provider
(authorization code + PKCE, client credentials, refresh, discovery, JWKS,
introspection, revocation) with multi-tenancy, SSO, and SCIM as the substrate.

## Try it — the demo gallery

The fastest way to understand Legant is to run a demo. Each is a narrated,
self-contained walkthrough; the ones below need only Go (no database, no Docker)
unless noted. Clone the repo and:

```bash
make demo            # agent-on-behalf-of: the whole delegation flow, end to end
make demo-twoasks    # confused deputy closed — one shared agent, two humans, audit names the human
make demo-splice     # multi-hop attenuation: a sub-agent can only ever do LESS than its parent
make demo-driftstop  # replays the Salesloft–Drift / UNC6395 OAuth theft on a survivable token
make demo-foureyes   # segregation of duties: "execute" needs a second distinct human
make demo-blastdoor  # k8s MCP gateway: filtered tools/list, change-freeze, mid-loop kill
make demo-conductor  # one agent across an MCP fleet + a tamper-evident flight recorder
make demo-leash · demo-charter · demo-honeytool · demo-helpdesk · demo-cloudops · demo-gateway
```

**Enterprise, production-integrated** demos (real infrastructure — under
[`examples/enterprise/`](examples/enterprise)):

```bash
make demo-aisre      # AI-SRE on a REAL kind cluster + REAL mcp-server-kubernetes, guarded by Legant
make demo-breach     # the Salesloft–Drift OAuth theft replayed on the shipped RS middleware
make demo-copilot    # entitlement-preserving analytics copilot over a REAL Postgres warehouse
```

**Landing page & visual demos:** [`site/`](site) is a build-free static site
(open `site/index.html` or deploy to any static host) with a landing page, a
[revocation deep-dive](site/revocation.html), and **live in-browser replays** of
[conductor](site/demos/conductor.html), [leash](site/demos/leash.html),
[charter](site/demos/charter.html), and [honeytool](site/demos/honeytool.html).

## Status

Built and tested against Postgres (`go test -race ./...`).

| Capability | State |
|---|---|
| OAuth 2.1 / OIDC provider, multi-tenancy, SSO, SCIM, passkeys/TOTP | Built |
| Delegation core — attenuation, constraints, composite `sub`/`act` tokens | Built ([`internal/delegation`](internal/delegation)) |
| Persistent multi-key signing keystore with rotation (`legant keys …`) | Built |
| AuthZ backbone — `Principal`, RBAC, org-scoping (closed the admin API; killed `X-User-ID`) | Built |
| **RFC 8693 token-exchange endpoint** — consent → composite token → revocation → audit | Built |
| **Multi-hop delegation** — agent re-delegates an attenuated slice; full chain provenance | Built |
| MCP / OAuth 2.1 compliance — RFC 8707 resource indicators, 7591 DCR, CIMD, SSRF-hardened fetch | Built |
| **MCP auth-gateway** (`legant gateway`) — full MCP method surface (initialize/ping/notifications + tools), per-tool delegation on `tools/call`, **`tools/list` filtered to the delegated tools**, SSE streaming, confused-deputy protection | Built |
| **Resource-server SDKs** — verify + authorize delegation tokens + Tier-B revocation offline, in **Go** ([`sdk`](sdk)), **TypeScript** ([`clients/typescript`](clients/typescript)), and **Python** ([`clients/python`](clients/python)); cross-language conformance vectors | Built |
| **Drop-in RS middleware** — framework-native middleware in all three SDKs (net/http+chi · Express+Fastify · FastAPI+Flask), a self-hosted MCP-server guard, and a `legant snippet <framework>` / `legant init resource-server` generator | Built |
| **Declarative grants** — a reviewable `legant.grants.yaml` with `legant lint` / `legant apply` (idempotent reconcile + diff) / `legant who-can`, plus top-level `legant mint`/`show`/`revoke` | Built ([`internal/grants`](internal/grants)) |
| **Helm chart** — `deployments/charts/legant` (migrate pre-install hook, gateway/HPA/CronJobs/ServiceMonitor toggles, bundled Grafana dashboard) | Built |
| **Observability** — Prometheus `/metrics` (request + delegation-activity counters), Go-runtime metrics | Built |
| **Deploy** — hardened Dockerfile, Kubernetes manifests, data-retention job (`legant maintenance prune`) | Built |
| **Constraint PDP dimensions** — `time_window` (offline) + `rate` (at mint), monotonic on re-delegation | Built |
| **Tamper-evident audit** — hash-chained `audit_events` + `legant audit verify` | Built |
| **Self-service delegation UI** — users view and revoke granted delegations (and their sub-agent chains) | Built |
| **Real-time console** (`/admin/live`) — superadmin SSE dashboard: the living authority graph + a live mint/revoke/tool-call decision stream, fed across processes via Postgres NOTIFY | Built |
| **Tiered revocation** — per-call store (gateway/introspection) + signed `/.well-known/revoked` feed for offline RSes + short-TTL backstop (5m default) | Built |
| **Coding-agent guard** (`legant guard install`) — one command wires a pre-tool hook into **Claude Code, OpenAI Codex CLI, and opencode** that authorizes every tool call (read/write/edit/bash/apply_patch/MCP) offline from a delegation token: roles + allow/deny rules ("allow everything except"), catastrophic-command tripwires, sub-agent attenuation, mid-session revocation, audit. Denies via the hook layer, so it **survives bypass / `--yolo` / full-auto** | Built ([`docs/CLAUDE_CODE.md`](docs/CLAUDE_CODE.md)) |

**Endpoints:** `/oauth2/{authorize,token,revoke,introspect,userinfo,register}`, `/consent/delegate`, `/delegations/redelegate`, `/account/delegations`, `/admin/audit`, `/admin/live{,/snapshot,/events,/ingest}`, `/.well-known/{openid-configuration,oauth-authorization-server,jwks.json,revoked}`, `/metrics`, `/healthz`, `/readyz`, and (gateway mode) `/mcp/{slug}`.

**CLI:** `legant serve | gateway | init grants|resource-server | lint | apply | mint | show | revoke | who-can | snippet <framework> | guard install|uninstall|check|demo|mint|revoke|show|deny|allow|rules|ui | migrate up|down|version | keys list|rotate|prune|reencrypt | maintenance prune | audit verify|anchor | admin grant-superadmin | dcr issue-token`.

## Deployment & roles — who runs what

Legant is an **authorization server** (like Keycloak, Ory, or Auth0), so it's deployed the same way: one component is stateful infrastructure, and the rest just talk to it. There isn't a single "integration" — there are roles, and only one of them runs a server:

| Role | What they do | What they run |
|---|---|---|
| **Operator** | Stands up the issuer for an organization | `legant serve` + Postgres, in their own cloud |
| **Agent author** | Builds an AI agent that acts for a user | App code that does an RFC 8693 token exchange against the issuer |
| **Resource-server developer** | Builds an API/MCP server that *accepts* agent tokens | Just the [`sdk`](sdk) — verifies tokens **offline**, no DB, no callback |
| **User** | Delegates scoped authority to an agent | Nothing — uses the consent flow in a browser |

To *integrate* with Legant you need only the Go SDK (verify a token against the issuer's published JWKS — no Postgres, no server). Postgres is only for the issuer — the one component that holds signing keys, sessions, the revocation state, and the audit chain — and even then the bundled `docker compose` brings its own, so there's no manual install.

```
  user ──delegates──▶  ISSUER (legant serve + Postgres)  ──JWKS──▶  RESOURCE SERVER (your API)
                              ▲   mints short-lived                    verifies OFFLINE with the SDK
        AI agent ──exchange──┘   "acting-for-Alice" token             (no callback to the issuer)
```

**Self-hosted.** You run the issuer in your own infrastructure (Docker, Kubernetes — see [`deployments/`](deployments)); nothing leaves your environment.

## Quick Start

### Install the CLI

```bash
# macOS / Linux — download the latest release binary
curl -fsSL https://raw.githubusercontent.com/legant-dev/legant/main/install.sh | sh

# or with Go
go install github.com/legant-dev/legant/cmd/legant@latest
```

Then govern any coding agent in one command:

```bash
legant guard install     # Claude Code / Codex / opencode  (see docs/CLAUDE_CODE.md)
legant guard demo        # see it work, no setup
```

Container image (for running the issuer): `ghcr.io/legant-dev/legant:latest`. Releases
are cut by pushing a `v*` tag (see [`.goreleaser.yaml`](.goreleaser.yaml) +
[`.github/workflows/release.yml`](.github/workflows/release.yml)).

### Running the issuer — Prerequisites
- Go 1.26+
- PostgreSQL 16+
- Docker & Docker Compose (optional)

### Using Docker Compose

```bash
docker compose -f deployments/docker-compose.yml up -d
```

Legant will be available at `http://localhost:8080`.

### Manual Setup

```bash
# Set required environment variables
export LEGANT_DATABASE_URL="postgres://legant:legant@localhost:5432/legant?sslmode=disable"
export LEGANT_SECRETS_SYSTEM="your-32-byte-or-longer-random-secret"
export LEGANT_SECRETS_COOKIE="another-32-byte-or-longer-random-secret"
export LEGANT_ISSUER_URL="http://localhost:8080"

# Build and run
make build
./bin/legant serve
```

## API Overview

### OIDC Endpoints
| Endpoint | Description |
|---|---|
| `GET /.well-known/openid-configuration` | OIDC Discovery |
| `GET /.well-known/jwks.json` | JSON Web Key Set |
| `GET /.well-known/revoked` | Signed revocation feed — JWS snapshot of revoked, unexpired token ids (Tier B) |
| `GET /oauth2/authorize` | Authorization |
| `POST /oauth2/token` | Token |
| `POST /oauth2/revoke` | Token Revocation |
| `POST /oauth2/introspect` | Token Introspection |
| `GET /oauth2/userinfo` | UserInfo |

### Admin API
| Endpoint | Description |
|---|---|
| `GET/POST /api/v1/users` | List / Create users |
| `GET/PUT/DELETE /api/v1/users/{id}` | Get / Update / Delete user |
| `GET/POST /api/v1/clients` | List / Create OAuth2 clients |
| `DELETE /api/v1/clients/{id}` | Delete client |
| `POST /api/v1/clients/{id}/rotate-secret` | Rotate client secret |
| `GET /api/v1/audit` | Query the tamper-evident audit trail (filter by `actor_type`, `actor_id`, `action`, `on_behalf_of_sub`, `delegation_id`, `grant_jti`, `since`, `until`; paginated) |
| `GET /api/v1/audit/verify` | Verify the audit hash chain is intact |
| `GET/PUT/DELETE /api/v1/gateway/upstreams` | Manage the DB-backed MCP gateway upstream registry (the gateway refreshes from it without a redeploy) |

## Configuration

Legant is configured via environment variables (prefix `LEGANT_`), config file (`legant.yaml`), or CLI flags.

| Variable | Default | Description |
|---|---|---|
| `LEGANT_SERVER_HOST` | `0.0.0.0` | Listen host |
| `LEGANT_SERVER_PORT` | `8080` | Listen port |
| `LEGANT_DATABASE_URL` | `postgres://legant:legant@localhost:5432/legant?sslmode=disable` | PostgreSQL connection URL |
| `LEGANT_SECRETS_SYSTEM` | (required) | Fosite global HMAC secret (32+ bytes) |
| `LEGANT_SECRETS_COOKIE` | (required) | Cookie signing secret (32+ bytes) |
| `LEGANT_SECRETS_KEY_ENCRYPTION` | (derived from system) | Master key that envelope-encrypts signing keys at rest; set a distinct value in production (32+ bytes) |
| `LEGANT_DATABASE_AUTO_MIGRATE` | `false` | Apply migrations on boot. Leave off in production; run `legant migrate up` as a pre-deploy step |
| `LEGANT_KEYSTORE_ROTATION_OVERLAP` | `840h` | How long a rotated-out signing key stays published in the JWKS |
| `LEGANT_ISSUER_URL` | `http://localhost:8080` | OIDC issuer URL |
| `LEGANT_GATEWAY_DOWNSTREAM_TTL` | `60s` | Lifetime cap for the per-call token the gateway mints for an upstream (still clamped to the inbound token's expiry) |
| `LEGANT_GATEWAY_REVOCATION_REFRESH` | `0s` | `0` = check the revocation store per call (instant); `>0` = use an in-memory revoked-set refreshed on this interval (avoids a per-call DB read for high-QPS gateways; a revoke then takes effect within the interval) |

### Signing keys

Signing keys are persisted in the database (private keys envelope-encrypted), so tokens survive restarts and replicas sign consistently. Manage them with the CLI:

```bash
legant keys list                      # show keys and which is active
legant keys rotate                    # mint a new active key (old one stays published during the overlap window)
legant keys prune                     # deactivate keys whose overlap window has passed
legant keys reencrypt --new-secret …  # re-wrap all keys under a new key-encryption secret
```

A rotated-out key stays in the JWKS for the overlap window so tokens it already
signed keep verifying. A running server (and the gateway) picks up a new active
key **live, without a restart**: each process reloads the keystore on `SIGHUP`
and on a 5-minute ticker, so a `legant keys rotate` in another process propagates
on its own. Concurrent cold-start replicas converge on a single first key.

## Resource-server SDKs (Go · TypeScript · Python)

Any service that accepts Legant delegation tokens can verify and authorize them
**offline** — RS256 + `kid` + `iss` + `aud` + `exp` (requiring an `act` chain),
the full constraint PDP, and the Tier-B revocation feed — with no callback to
Legant. Three SDKs implement the identical behavior:

- **Go** — [`sdk`](sdk) (`github.com/legant-dev/legant/sdk`), depends only on golang-jwt.
- **TypeScript / Node** — [`clients/typescript`](clients/typescript) (`@legant/sdk`), **zero runtime deps** (built-in `crypto`).
- **Python** — [`clients/python`](clients/python) (`legant-sdk`), depends only on `cryptography`.

They cannot silently drift: **golden conformance vectors minted by the real Go
signer** ([`clients/conformance`](clients/conformance)) are run against all three.
The Go usage:

```go
keys, _ := sdk.FetchJWKS(ctx, "https://auth.example.com/.well-known/jwks.json")
v := sdk.NewVerifier("https://auth.example.com", "https://my-api.example/", keys)

claims, err := v.Verify(bearerToken) // RS256 + kid + iss + aud + exp, requires an act chain
if err != nil { /* 401 */ }
if err := claims.Authorize(sdk.Action{Scope: "expenses:submit", Amount: 120, Category: "travel"}); err != nil {
    /* 403 — scope or constraint denied */
}
log.Printf("acting for %s", claims.Provenance()) // "user:alice -> agent:assistant"
```

The TypeScript and Python SDKs offer the same API shape (`fetchJWKS` →
`Verifier.verify` → `claims.authorize`/`provenance`, plus `fetchRevocationFeed`);
see [`clients/`](clients) for per-language usage.

You don't have to wire it by hand. Each SDK ships middleware, and the CLI prints a
ready-to-paste integration for your framework:

```bash
legant snippet go-chi          # also: go-nethttp · express · fastify · fastapi · flask · mcp-go
legant init resource-server --framework fastapi --issuer https://auth.example.com
```

```go
// Go (net/http + chi): verify + authorize in a couple of lines
r.Use(sdk.Authenticate(v))                         // verify the bearer, attach Claims
r.With(sdk.RequireAction(func(req *http.Request) sdk.Action {
    return sdk.Action{Scope: "warehouse:query", Resource: req.URL.Query().Get("schema")}
})).Get("/query", handler)
```

The middleware is the delegation-aware analog of a generic OIDC JWT middleware — it
understands the `act` chain, the constraint dimensions, RFC 8707 audience
canonicalization, and the signed revocation feed, which a plain access-token
middleware doesn't. Equivalents ship for Express/Fastify and FastAPI/Flask.

### Authority as reviewable config

Authority doesn't have to be minted from shell history. Declare it in a
`legant.grants.yaml`, code-review it in a PR, and apply it:

```bash
legant init grants                          # writes a commented starter
legant lint  -f legant.grants.yaml          # semantic checks (escalation, bad window, typos) — CI-gateable
legant apply -f legant.grants.yaml          # idempotent: mints the signed tokens, prints a diff
legant who-can -f legant.grants.yaml --scope warehouse:query --resource finance
```

It's a fixed serialization of Legant's own constraint dimensions — not a policy DSL —
so a grant travels inside the token and verifies offline anywhere.

### Revocation, honestly

A signed JWT is valid until it expires — so how fast can you *kill* one? Legant
doesn't pretend a single answer fits every deployment. Each resource server picks
a tier, and the worst case is never worse than the token's short TTL (5m by
default, configurable — there's no hard ≤5m ceiling):

- **Tier A — per-call.** The MCP gateway and `/oauth2/introspect` consult the
  revocation store on every request, so a revoke takes effect **immediately**.
- **Tier B — signed feed.** An offline resource server polls
  `GET /.well-known/revoked` — a JWS-signed, TTL-bounded snapshot of revoked,
  unexpired `jti`s (signed with the **same key as the JWKS**, so no new trust
  root) — and rejects revoked tokens within its refresh interval, with **no
  per-request callback** to Legant. The set is bounded by `revoke-rate × TTL`, so
  it stays kilobytes; a monotonic version defeats rollback/replay.
- **Tier C — TTL only.** A fully air-gapped verifier that polls nothing is still
  bounded by the short token expiry.

Tier B is two lines in the SDK:

```go
feed, _ := sdk.FetchRevocationFeed(ctx, "https://auth.example.com/.well-known/revoked", issuer, keys)
feed.StartPolling(ctx, 10*time.Second, func(err error) { log.Print(err) }) // background refresh
v := sdk.NewVerifier(issuer, "https://my-api.example/", keys, sdk.WithRevocationFeed(feed))
// v.Verify now returns sdk.ErrRevoked for a revoked token, within ~10s of the revoke.
```

The feed can only ever *miss* a revocation (then fall back to the TTL), never
*forge* one — so a stale or unreachable feed degrades to Tier C rather than
failing a valid token. High-assurance servers can flip that with
`sdk.WithFeedFailClosed(maxStaleness)` to reject when the feed goes stale.

The full design — tier table, endpoint, safety properties, and an explicit list
of what is *not* claimed — is in [`docs/REVOCATION.md`](docs/REVOCATION.md).

## Observability

`legant serve` and `legant gateway` expose Prometheus metrics at `/metrics`
(text exposition; no client-library dependency):

- `legant_http_requests_total{method,route,code}` and
  `legant_http_request_duration_seconds` — labeled by the **route pattern**, never
  the raw path, so cardinality stays bounded.
- `legant_delegations_total{kind}`, `legant_token_exchanges_total{result}`,
  `legant_tokens_minted_total{source}`, `legant_revocations_total{kind}`,
  `legant_gateway_calls_total{upstream,decision}` — the delegation-activity
  signals raw HTTP counts can't show, from consent through mint to revocation.
- `legant_http_requests_in_flight`, Go-runtime gauges, and `legant_build_info`.

`/metrics` is unauthenticated by design (scrapers carry no session) — keep it
cluster-internal. `/healthz` is a liveness ping; `/readyz` also checks the
database, an active signing key, and that migrations are applied.

## Deployment

The recommended path is the **Helm chart** at
[`deployments/charts/legant`](deployments/charts/legant):

```bash
helm install legant ./deployments/charts/legant \
  --set issuer=https://auth.example.com --set secrets.existingSecret=legant-secrets
```

It templates everything below, runs migrations as a **pre-install/pre-upgrade hook**
(so they always complete before rollout), and bundles an optional Grafana dashboard.
The raw manifests in [`deployments/k8s`](deployments/k8s) remain a readable reference:
server + gateway Deployments (non-root, read-only rootfs, dropped capabilities), a
pre-deploy migration Job, an HPA, Prometheus ServiceMonitors, and a nightly
data-retention CronJob. See [`deployments/k8s/README.md`](deployments/k8s/README.md)
for the apply order.

Data retention is a scheduled command:

```bash
legant maintenance prune --dry-run                 # report what would be deleted
legant maintenance prune --token-grace 720h        # purge dead tokens > 30d past expiry
legant maintenance prune --audit-retention 8760h   # also purge audit events > 1y (opt-in)
```

It removes expired sessions, used/expired email and registration tokens, the
Fosite OAuth token rows (access/refresh/auth-code/PKCE/OIDC-session — the
highest-volume tables), expired agent tokens, and delegation tokens dead beyond
the grace window; audit purging is off by default.

## Architecture

- **Go** with chi router — stdlib-compatible, zero-dependency HTTP
- **Fosite** — Ory's OAuth2/OIDC engine
- **PostgreSQL** via pgx/v5 — direct driver, no ORM
- **Argon2id** — OWASP-recommended password hashing
- **Single binary** — all migrations, templates, and static assets embedded

## License

Apache 2.0
