# Changelog

All notable changes to Legant are documented here. The format is loosely based on
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
semantic versioning once it reaches `1.0`.

## [0.1.0] — 2026-06-23

The first public release. Highlights:

### Core

- RFC 8693 token exchange → composite `sub`/`act` delegation tokens, with monotonic
  attenuation (a child can only ever do less) enforced at delegation time.
- Offline-enforced constraint PDP: `max_amount`, `categories`, `tools`, `resources`
  (RFC 8707 audiences), `time_window` (offline) and `rate` (mint-time).
- Full OAuth 2.1 / OIDC provider (auth-code + PKCE, client credentials, refresh,
  discovery, JWKS, introspection, revocation), multi-tenancy, SSO, SCIM,
  passkeys/TOTP.
- Persistent envelope-encrypted signing keystore with live rotation.
- Tamper-evident hash-chained audit + `legant audit verify`.

### Integration

- **Resource-server SDKs** in Go, TypeScript, and Python — verify + authorize +
  Tier-B revocation offline, kept in lockstep by golden conformance vectors.
- **Drop-in RS middleware** in all three SDKs (net/http+chi, Express+Fastify,
  FastAPI+Flask) and a `legant snippet <framework>` / `legant init resource-server`
  generator.
- **Declarative grants** — a reviewable `legant.grants.yaml` with `legant lint` /
  `legant apply` (idempotent) / `legant who-can`, plus top-level `legant mint` /
  `show` / `revoke` verbs.
- **MCP auth-gateway** (`legant gateway`) — per-tool delegation, `tools/list`
  filtering, SSE, confused-deputy protection.
- **Coding-agent guard** (`legant guard install`) for Claude Code / Codex / opencode.

### Operations & distribution

- Tiered revocation: per-call store + signed `/.well-known/revoked` feed + TTL.
- Prometheus `/metrics`, real-time `/admin/live` SSE console.
- **Helm chart** (`deployments/charts/legant`) with a migrate pre-install hook and a
  bundled Grafana dashboard; raw k8s manifests; hardened Dockerfile; GoReleaser.

### Demos

- A gallery of self-contained, narrated walkthroughs (`make demo-*`), plus demos
  that integrate against real systems under `examples/enterprise/`: an AI-SRE on a
  real kind cluster, an OAuth-breach replay, and an entitlement-preserving copilot
  over a real Postgres warehouse.
