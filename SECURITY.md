# Security Policy

Legant is an authorization system, so we take security reports seriously and ask
that they be disclosed responsibly.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Instead, use GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab → **Report a vulnerability**.
2. Describe the issue, the affected version/commit, and a reproduction if you have one.

We aim to acknowledge a report within a few business days and to agree on a
disclosure timeline with you. We'll credit reporters who want credit.

If you cannot use private reporting, you may reach the maintainer through the
contact listed on their GitHub profile.

## Scope

Most relevant to a delegated-authorization system:

- Token forgery, signature bypass, or `kid`/issuer/audience confusion in the
  issuer or any of the resource-server SDKs (Go / TypeScript / Python).
- Constraint-enforcement bypass (a token doing more than its `sub`/`act`, scope,
  `max_amount`, `categories`, `tools`, `resources`, or `time_window` allow).
- Attenuation escalation (a re-delegated child gaining authority its parent lacks).
- Revocation bypass (a revoked token still accepted past the documented tier
  guarantees), or revocation-feed forgery/rollback.
- Confused-deputy or token-leak issues in the MCP gateway or the coding-agent guard.
- The usual web classes in the issuer's HTTP surface (authn/z, SSRF, CSRF, XSS,
  injection).

## What is intentionally *not* a vulnerability

These are documented limitations — see [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
and the per-demo "scope" notes — not security bugs:

- The signed revocation feed is near-real-time **on poll**, not zero-latency-global;
  a fully air-gapped verifier is bounded by the token's short TTL.
- The `rate` constraint is enforced at **mint time**, not offline at a resource
  server (it needs shared state).
- Legant **bounds** the blast radius of a prompt-injected agent; it does not
  *prevent* the injection.
- Legant **complements** k8s RBAC / SPIFFE / Kyverno / OPA — an agent that bypasses
  the Legant-mediated gateway/SDK (e.g. a raw kubeconfig straight to the API server)
  is contained by those layers, not by Legant.

## Supported versions

Until a `1.0` release, only the latest `main` and the most recent tagged release
receive security fixes.
